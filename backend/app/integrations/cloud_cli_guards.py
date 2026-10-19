"""The guard chain that decides whether a read-only cloud command may run.

**No model, no network, no credential, no Docker.** Everything in this module is
a pure function over a `(binary, args)` pair, so the checks can be proven
against the commands an attacker or a bug would produce rather than against the
commands a model happened to emit on the day the test was written.

The chain is ordered cheapest-first so
a routine rejection costs a regular expression and the expensive checks only
ever see input that already looks sane. `check_command` returns the **first**
rejection, which is what makes the ordering observable and therefore testable.

**Two layers are boundaries, not filters, and that distinction is the design.**
A filter inspects a value the caller can set and has to be right every time; a
boundary removes the caller's ability to express the value at all. The project
and the impersonated identity are injected at G5 out of a validated `projects`
row — the tool schema has no parameter for either — so a hallucinated project
cannot be passed rather than being caught. Same trick as `project_id` in
`agent_tools.py`.

**Nothing is ever silently rewritten.** A rejection names the layer that
refused, why, and what would fix it. A rewrite teaches the caller nothing, hides
drift between these guards and the skill that describes them to the model, and
would make the evidence appendix a lie about what actually ran.
"""

from __future__ import annotations

import dataclasses
import re

# ── G6 budgets ───────────────────────────────────────────────────────────────
# Module constants, not CONFIG_KEYS entries, because config.py fails startup when any CONFIG_KEYS entry is missing, so a
# new key breaks every existing .env.local. These are correctness bounds, not
# deployment settings — the same call `MAX_INVESTIGATION_ROUNDS` and
# `THINKING_LEVEL` already make.
MAX_CLI_COMMANDS_PER_RUN = 40
MAX_CLI_COMMANDS_PER_PILLAR = 12
CLI_COMMAND_TIMEOUT_SECONDS = 60
MAX_CLI_WALL_CLOCK_SECONDS = 600
MAX_CLI_OUTPUT_BYTES = 24_000

# ── G0 shape ─────────────────────────────────────────────────────────────────
ALLOWED_BINARIES = frozenset({"gcloud", "bq"})
MAX_ARGS = 30
MAX_TOKEN_LENGTH = 512

# ── G1 lexical ───────────────────────────────────────────────────────────────
# There is no shell — `subprocess` is always handed an argv list — so this
# cannot prevent an injection. It exists to make an attempt **loud**: a
# rejection here is an anomaly worth investigating, not a routine correction.
SHELL_METACHARACTERS = ("`", "$", ";", "|", "&", "<", ">", "\\", "\n", "\r")

# **The one syntax exception.** BigQuery requires backticks when addressing an
# `INFORMATION_SCHEMA` view because an unquoted
# `dataset.INFORMATION_SCHEMA.TABLE_STORAGE` is parsed as a table reference.
#
# So a backtick is permitted in exactly one place: the SQL statement of a
# `bq query`. It is inert there — there is no shell anywhere in this path — and
# G1's job is to make an *anomaly* loud, while a backtick inside a BigQuery
# identifier is required syntax rather than an anomaly. Every other token, every
# other binary and every other metacharacter keep the strict rule; `;` in
# particular stays banned, so a statement still cannot be chained.
_SQL_STATEMENT_RE = re.compile(r"^\s*SELECT\b", re.IGNORECASE)


def _is_bq_sql(binary: str, token: str) -> bool:
    return binary == "bq" and not token.startswith("-") and bool(_SQL_STATEMENT_RE.match(token))

# ── G2 verbs ─────────────────────────────────────────────────────────────────
# Checked first, and only so the error message can be specific: a write verb
# should be told it is a write verb rather than given a generic allowlist miss.
# The allowlist below is the actual gate.
# Only the three shapes the spec names. `create-`/`delete-` were tried and
# removed: they misfire on a *resource* called `delete-me`, and the verb scan
# below takes the first match in token order, so a resource name is reachable.
WRITE_VERB_PREFIXES = ("set-", "add-", "remove-")
WRITE_VERBS = frozenset(
    {
        "delete", "create", "update", "patch", "enable", "disable", "deploy",
        "import", "export", "ssh", "scp", "auth", "config", "components",
        "login", "revoke", "reset", "restart", "start", "stop", "move",
        "add", "remove", "set", "apply", "run", "submit", "sign", "upload",
    }
)
READ_VERBS = frozenset(
    {
        "list", "describe", "get-iam-policy", "get-ancestors",
        "search-all-iam-policies", "search-all-resources",
        "list-grantable-roles", "help", "topic",
    }
)
BQ_VERBS = frozenset({"ls", "show", "query"})

# `help` and `topic` are local-only — no network, no credential — and are what
# let the model check leaf syntax instead of hallucinating a flag.
OFFLINE_VERBS = frozenset({"help", "topic"})

# ── G3 flag policy ───────────────────────────────────────────────────────────
# The one denylist in the chain, deliberately. An allowlist would have to
# enumerate every presentational flag across every GCP service, and its failure
# mode is a caller burning its budget rediscovering that `--sort-by` is fine.
IDENTITY_FLAGS = frozenset(
    {
        "--account", "--impersonate-service-account", "--billing-project",
        "--credential-file-override", "--access-token-file",
    }
)
# **`--organization` and `--folder` are here for a sharper reason than
# `--project`.** Allowing a caller to name either could cross the report's
# validated resource boundary. The id is injected from the validated `projects`
# row's parent and from nowhere else.
TARGET_FLAGS = frozenset(
    {
        "--project", "--project_id", "--project-id",
        "--organization", "--organization-id",
        "--folder", "--folder-id",
    }
)
FILE_FLAGS = frozenset({"--flags-file", "--configuration", "--credentials-file"})

# ── G4 data reduction ────────────────────────────────────────────────────────
# Unscoped inventory commands can exhaust the model context window.
# Both spellings of bq's cap: `bq ls --max_results` and `bq query --max_rows`.
REDUCING_FLAGS = ("--limit", "--filter", "--format", "--max_rows", "--max_results")
VERBS_NEEDING_REDUCTION = frozenset(
    {"list", "search-all-iam-policies", "search-all-resources", "ls"}
)

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_@:/.,=+~^%?*\[\]{}()'\" -]+$")
# The same charset plus a backtick, for a `bq query` SQL statement only.
_SQL_TOKEN_RE = re.compile(r"^[A-Za-z0-9_@:/.,=+~^%?*\[\]{}()'\"` -]+$")


class GuardRejection(Exception):
    """Raised by the layers; converted to a structured dict by `check_command`.

    An exception rather than a return value because every layer must be able to
    stop the chain from wherever it is, and the alternative — threading an
    optional rejection through eight functions — is where an accidental
    fall-through would live.
    """

    def __init__(self, *, rejected_by: str, reason: str, fix: str) -> None:
        super().__init__(reason)
        self.rejected_by = rejected_by
        self.reason = reason
        self.fix = fix


@dataclasses.dataclass(frozen=True)
class CheckedCommand:
    """A command that survived every layer, with G5's scoping already applied.

    `argv` is what actually runs. `display` is what the trace and the evidence
    appendix record — the caller's own tokens, before injection, so a reader
    sees what the agent asked for rather than what the runner made of it.
    """

    binary: str
    argv: list[str]
    display: str
    offline: bool


def _reject(layer: str, reason: str, fix: str) -> None:
    raise GuardRejection(rejected_by=layer, reason=reason, fix=fix)


# ── G0 ───────────────────────────────────────────────────────────────────────


def _g0_shape(binary: str, args: list[str]) -> None:
    if binary not in ALLOWED_BINARIES:
        _reject(
            "G0_shape",
            f"{binary!r} is not a binary this agent can run",
            f"use one of: {', '.join(sorted(ALLOWED_BINARIES))}",
        )
    if not args:
        _reject("G0_shape", "no arguments were supplied", "supply the command's tokens in `args`")
    if len(args) > MAX_ARGS:
        _reject(
            "G0_shape",
            f"{len(args)} argument tokens, over the {MAX_ARGS} limit",
            "split this into narrower commands",
        )
    if any(not isinstance(a, str) for a in args):
        _reject("G0_shape", "every argument token must be a string", "pass args as a list of strings")


# ── G1 ───────────────────────────────────────────────────────────────────────


def _g1_lexical(binary: str, args: list[str]) -> None:
    for token in args:
        if len(token) > MAX_TOKEN_LENGTH:
            _reject(
                "G1_lexical",
                f"a token is {len(token)} characters, over the {MAX_TOKEN_LENGTH} limit",
                "shorten the token, or narrow the command",
            )
        metacharacters = SHELL_METACHARACTERS
        if _is_bq_sql(binary, token):
            metacharacters = tuple(c for c in SHELL_METACHARACTERS if c != "`")
        found = [c for c in metacharacters if c in token]
        if found:
            _reject(
                "G1_lexical",
                "a token contains shell metacharacters "
                f"({', '.join(repr(c) for c in found)}), which is treated as an anomaly",
                "remove them; commands run as argv with no shell, so they cannot do anything anyway",
            )
        if not (_TOKEN_RE if not _is_bq_sql(binary, token) else _SQL_TOKEN_RE).match(token):
            _reject(
                "G1_lexical",
                "a token contains characters outside the permitted set",
                "use plain resource names, flags and values",
            )


# ── G2 ───────────────────────────────────────────────────────────────────────


def positionals(args: list[str]) -> list[str]:
    """Every token before the first flag: the command group and its verb.

    `gcloud compute instances list --limit=5` → `["compute", "instances", "list"]`.
    """
    out: list[str] = []
    for token in args:
        if token.startswith("-"):
            break
        out.append(token)
    return out


def verb_of(args: list[str], *, allowed: frozenset[str]) -> str | None:
    """The **first** positional that names a verb, not the last positional.

    "the last token before the first flag" is the obvious rule and it is wrong:
    `gcloud projects describe my-project` ends in the resource, not the verb, so
    that rule reads `my-project` and refuses every `describe` in the playbook.
    Taking the first recognised token instead is also what keeps a resource
    *named* like a verb — `gcloud projects describe delete-me` — from being read
    as one, because the real verb is always to the left of its arguments.

    **The allowlist is scanned before the write denylist, and that ordering is
    load-bearing rather than cosmetic.** GCP command *groups* collide with write
    verbs: `gcloud run services list` and `gcloud deploy … list` both begin with
    a token on the denylist, and a denylist-first scan refuses them as writes
    even though they are ordinary reads. Scanning the allowlist first resolves
    the collision in the only direction that can be wrong safely — the denylist
    exists **only to produce a better error message**, and the allowlist is the
    actual gate, so a command that reaches the fallback is refused either way.
    `gcloud dataflow jobs run` still fails, just with an allowlist miss instead
    of a write-verb message.

    Returns None when nothing in the command names a verb at all, which G2 fails
    closed on rather than guessing.
    """
    tokens = positionals(args)
    for token in tokens:
        if token in allowed:
            return token
    for token in tokens:
        if token in WRITE_VERBS or token.startswith(WRITE_VERB_PREFIXES):
            return token
    return None


def _g2_verb(binary: str, args: list[str]) -> str:
    allowed = BQ_VERBS if binary == "bq" else READ_VERBS
    verb = verb_of(args, allowed=allowed)
    if verb is None:
        found = " ".join(positionals(args)) or "(nothing)"
        _reject(
            "G2_verb",
            f"no verb on the read allowlist appears in {found!r}",
            f"use one of: {', '.join(sorted(allowed))}",
        )
    if verb in WRITE_VERBS or verb.startswith(WRITE_VERB_PREFIXES):
        _reject(
            "G2_verb",
            f"{verb!r} is a write verb; this agent reads only",
            f"use a read verb: {', '.join(sorted(allowed))}",
        )
    if verb not in allowed:
        _reject(
            "G2_verb",
            f"{verb!r} is not on the read allowlist for {binary}",
            f"use one of: {', '.join(sorted(allowed))}",
        )
    return verb


# ── G2b ──────────────────────────────────────────────────────────────────────


def _g2b_bq_query(args: list[str]) -> None:
    """`bq query` executes SQL, and SQL is not a verb.

    Restricted to `INFORMATION_SCHEMA` because row counts and storage sizes are
    what turn "some datasets lack CMEK" into "the support-ticket history lacks
    CMEK", and
    the ticket text itself must never enter a prompt, a trace or a report.
    """
    sql = next((t for t in args if not t.startswith("-") and t != "query"), None)
    if sql is None:
        _reject("G2b_bq_query", "no SQL statement was supplied", "pass the SELECT as a token")
    if not re.match(r"^\s*SELECT\b", sql, re.IGNORECASE):
        _reject(
            "G2b_bq_query",
            "only a single SELECT is permitted",
            "rewrite the statement to begin with SELECT",
        )
    if ";" in sql:
        _reject(
            "G2b_bq_query",
            "the statement contains ';' — only one statement may be run",
            "send one SELECT with no trailing semicolon",
        )
    if "INFORMATION_SCHEMA" not in sql.upper():
        _reject(
            "G2b_bq_query",
            "only INFORMATION_SCHEMA is readable — customer rows are never queried",
            "query a metadata view, fully qualified and backticked: "
            "SELECT table_name FROM `<project>.<dataset>.INFORMATION_SCHEMA.TABLES`. "
            "For row counts and sizes use `bq show <dataset>.<table>` instead — "
            "INFORMATION_SCHEMA.TABLE_STORAGE is region-scoped and needs "
            "project-level permissions this agent does not have",
        )


# ── G3 ───────────────────────────────────────────────────────────────────────


def flag_name(token: str) -> str:
    return token.split("=", 1)[0]


def _g3_flags(args: list[str]) -> None:
    for token in args:
        if token.startswith("@"):
            _reject(
                "G3_flags",
                f"{token!r} reads a file from disk",
                "pass the value inline instead of from a file",
            )
        if not token.startswith("-"):
            continue
        name = flag_name(token)
        if name in IDENTITY_FLAGS:
            _reject(
                "G3_flags",
                f"{name} would change which identity the command runs as",
                "drop it; the project's scanner service account is injected and cannot be chosen",
            )
        if name in TARGET_FLAGS:
            _reject(
                "G3_flags",
                f"{name} would change which project or organization the command targets",
                "drop it; the report's own project — and, for an org-scoped read, its "
                "parent organization — are injected and cannot be chosen",
            )
        if name in FILE_FLAGS:
            _reject(
                "G3_flags",
                f"{name} reads configuration or credentials from disk",
                "drop it; the container's configuration is fixed",
            )


# ── G4 ───────────────────────────────────────────────────────────────────────


def _g4_reduction(verb: str, args: list[str]) -> None:
    if verb not in VERBS_NEEDING_REDUCTION:
        return
    if any(flag_name(t) in REDUCING_FLAGS for t in args if t.startswith("-")):
        return
    _reject(
        "G4_data_reduction",
        f"a bare {verb!r} returns everything, and an unbounded listing would "
        "exhaust the context window",
        'add --limit=N, --filter=... or --format="json(field,...)"',
    )


# ── G5 ───────────────────────────────────────────────────────────────────────


def _g5_scope(
    binary: str,
    verb: str,
    args: list[str],
    *,
    project_id: str,
    target_sa_email: str,
    organization_id: str | None = None,
) -> list[str]:
    """Injection, not validation — the caller had no way to supply any of this.

    Offline verbs (`help`, `topic`) are deliberately left alone: they reach no
    API, so scoping them would only add flags `gcloud help` does not accept.

    **`organization_id` replaces the project flag rather than joining it**, and
    that is not a preference — `gcloud resource-manager org-policies` accepts
    *exactly one* scope flag and rejects two:

    ```
    ERROR: (gcloud.resource-manager.org-policies.list) argument --organization:
    Exactly one of (--folder | --organization | --project) must be specified.
    ```

    That is a **usage** error, not a permission error, so it reads like a
    malformed command and sends you inspecting the argv rather than the
    injection. Before this, no org-scoped command could run at all, whatever
    permissions were granted.
    """
    if verb in OFFLINE_VERBS:
        return [binary, *args]

    if binary == "bq":
        # `bq` splits its flags: global ones come *before* the verb, and the
        # query caps come after it. Concatenating them all in front looks
        # equivalent and is not — `bq --max_rows=200 query ...` is an unknown
        # global flag, which fails as a usage error rather than a cap.
        globals_ = [f"--project_id={project_id}", "--headless", "--format=json"]
        rest = list(args)
        verb_at = rest.index(verb)
        query_flags: list[str] = []
        if verb == "query":
            query_flags = [
                "--use_legacy_sql=false",
                f"--max_rows={BQ_MAX_ROWS}",
                f"--maximum_bytes_billed={BQ_MAX_BYTES_BILLED}",
            ]
        return [
            binary,
            *globals_,
            *rest[: verb_at + 1],
            *query_flags,
            *rest[verb_at + 1 :],
        ]

    # **`--impersonate-service-account` is deliberately NOT injected.** The
    # container is handed a short-lived access token that *already is* the
    # target service account (see `cloud_cli_runner.build_container_command`),
    # and asking that account to impersonate itself needs
    # `roles/iam.serviceAccountTokenCreator` on itself and fails. The identity
    # boundary did not weaken: G3 still refuses a caller-supplied
    # `--impersonate-service-account`, and the container has no credential it
    # could exchange for a different one. `target_sa_email` stays a parameter
    # because it is what the runner mints the token for, and because G3's
    # refusal message names it.
    scope_flag = (
        f"--organization={organization_id}"
        if organization_id
        else f"--project={project_id}"
    )
    injected = [scope_flag, "--quiet"]
    if not any(flag_name(t) == "--format" for t in args if t.startswith("-")):
        injected.append("--format=json")
    return [binary, *args, *injected]


BQ_MAX_ROWS = 200
BQ_MAX_BYTES_BILLED = 100_000_000


# ── the chain ────────────────────────────────────────────────────────────────


def check_command(
    binary: str,
    args: list[str],
    *,
    project_id: str,
    target_sa_email: str,
    organization_id: str | None = None,
) -> CheckedCommand:
    """Run every layer in order and return the argv that may execute.

    Raises `GuardRejection` on the **first** layer that refuses, which is what
    makes the cheapest-first ordering an observable property rather than a
    claim: a command that fails two layers reports the cheaper one.

    `organization_id` is opt-in and only ever set by an org-scoped playbook
    step, never by a model. Passing it swaps the injected `--project` for
    `--organization`; it does **not** widen what the caller may write, since
    G3 refuses a caller-supplied `--organization` either way — and G3 runs
    before G5, so the injection cannot reject itself.

    It applies only to the commands that take a `--organization` *flag*
    (`resource-manager org-policies`, `access-context-manager`). Commands that
    take the organization as a positional — `gcloud organizations describe
    <id>` — leave this unset and substitute the id into their args, exactly as
    `projects describe {project}` already does; `--project` is a global gcloud
    flag and stays harmless there.
    """
    _g0_shape(binary, args)
    _g1_lexical(binary, args)
    verb = _g2_verb(binary, args)
    if binary == "bq" and verb == "query":
        _g2b_bq_query(args)
    _g3_flags(args)
    _g4_reduction(verb, args)
    argv = _g5_scope(
        binary,
        verb,
        args,
        project_id=project_id,
        target_sa_email=target_sa_email,
        organization_id=organization_id,
    )
    return CheckedCommand(
        binary=binary,
        argv=argv,
        display=" ".join([binary, *args]),
        offline=verb in OFFLINE_VERBS,
    )


def rejection_payload(exc: GuardRejection, *, binary: str, args: list[str]) -> dict:
    """The shape handed back to the model, and emitted as a WARNING span.

    It names the layer, the reason and the fix, so a rejected command teaches
    the caller something instead of costing it a round.
    """
    return {
        "ok": False,
        "rejected_by": exc.rejected_by,
        "reason": exc.reason,
        "fix": exc.fix,
        "command": " ".join([binary, *[a for a in args if isinstance(a, str)]]),
    }
