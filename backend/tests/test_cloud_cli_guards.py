"""The guard chain, proven against a table of inputs.

**No model, no network, no credentials, no Docker daemon.** That is the point of
testing the chain directly rather than through the agent: a chain tested through
an agent is tested against the commands a model happened to produce that day,
and this one has to hold against the commands a bug or an attacker would
produce.
"""

from __future__ import annotations

import pytest

from app.integrations import cloud_cli_guards as g

PROJECT = "synthetic-project-id"
SA = "scanner@synthetic-project.invalid"


def check(binary, args):
    return g.check_command(binary, args, project_id=PROJECT, target_sa_email=SA)


def rejection(binary, args):
    with pytest.raises(g.GuardRejection) as exc:
        check(binary, args)
    return exc.value


# ── G0 — shape ───────────────────────────────────────────────────────────────


def test_a_binary_outside_the_fixed_set_is_refused():
    r = rejection("kubectl", ["get", "pods"])
    assert r.rejected_by == "G0_shape"
    assert "kubectl" in r.reason


@pytest.mark.parametrize("binary", sorted(g.ALLOWED_BINARIES))
def test_both_permitted_binaries_are_accepted(binary):
    args = ["ls", "--max_results=10"] if binary == "bq" else ["projects", "describe", PROJECT]
    assert check(binary, args).binary == binary


def test_too_many_tokens_are_refused_before_anything_expensive_runs():
    r = rejection("gcloud", ["list"] * (g.MAX_ARGS + 1))
    assert r.rejected_by == "G0_shape"


def test_an_empty_argument_list_is_refused():
    assert rejection("gcloud", []).rejected_by == "G0_shape"


# ── G1 — lexical ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("meta", ["`", "$", ";", "|", "&", "<", ">", "\\", "\n", "\r"])
def test_every_shell_metacharacter_is_refused_as_an_anomaly(meta):
    r = rejection("gcloud", ["compute", "instances", "list", f"--filter=a{meta}b"])
    assert r.rejected_by == "G1_lexical"
    assert "anomaly" in r.reason


def test_a_legitimate_filter_expression_survives_the_lexical_check():
    """The charset has to admit what real gcloud filters look like, or the guard
    becomes the thing the caller spends its budget fighting."""
    cmd = check(
        "gcloud",
        ["compute", "instances", "list", "--filter=status=RUNNING AND name~^web-", "--limit=20"],
    )
    assert "--filter=status=RUNNING AND name~^web-" in cmd.argv


def test_an_over_long_token_is_refused():
    r = rejection("gcloud", ["compute", "instances", "list", "--filter=" + "a" * 600])
    assert r.rejected_by == "G1_lexical"


# ── G2 — verbs ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "args",
    [
        ["compute", "instances", "delete", "web-1"],
        ["projects", "create", "new-project"],
        ["iam", "service-accounts", "set-iam-policy", SA],
        ["services", "enable", "compute.googleapis.com"],
        ["auth", "login"],
        ["config", "set", "project", "other"],
    ],
)
def test_a_write_verb_is_refused_as_a_write_verb_not_a_generic_miss(args):
    """The specific message is the criterion. A caller told "not on the
    allowlist" will try three more spellings; one told "this agent reads only"
    stops."""
    r = rejection("gcloud", args)
    assert r.rejected_by == "G2_verb"
    assert "write verb" in r.reason


def test_a_verb_nobody_thought_of_is_still_refused():
    """The allowlist is the gate; the write denylist above it only shapes the
    message. A verb on neither list must fail closed."""
    r = rejection("gcloud", ["compute", "instances", "simulate-maintenance-event", "web-1"])
    assert r.rejected_by == "G2_verb"
    assert "allowlist" in r.reason


def test_a_resource_named_like_a_verb_is_not_read_as_one():
    """The verb is the first recognised positional, so `describe delete-me`
    describes a resource rather than being refused as a delete."""
    assert check("gcloud", ["projects", "describe", "delete-me"]).argv


@pytest.mark.parametrize(
    "args",
    [
        ["projects", "describe", PROJECT],
        ["projects", "get-iam-policy", PROJECT],
        ["asset", "search-all-iam-policies", "--limit=50"],
        ["asset", "search-all-resources", "--limit=50"],
        ["compute", "instances", "list", "--limit=10"],
    ],
)
def test_the_read_verbs_the_recon_playbook_needs_are_accepted(args):
    assert check("gcloud", args).argv[0] == "gcloud"


def test_a_command_that_is_all_flags_has_no_verb_and_is_refused():
    r = rejection("gcloud", ["--limit=5"])
    assert r.rejected_by == "G2_verb"


def test_help_is_accepted_and_marked_offline():
    """`help` and `topic` reach no API and need no credential — they are what
    let the model check leaf syntax instead of hallucinating a flag."""
    cmd = check("gcloud", ["help", "compute", "instances", "list"])
    assert cmd.offline is True
    assert "--impersonate-service-account=" + SA not in cmd.argv


# ── G2b — bq query ───────────────────────────────────────────────────────────


def test_a_non_select_statement_is_refused():
    r = rejection("bq", ["query", "DROP TABLE tickets"])
    assert r.rejected_by == "G2b_bq_query"
    assert "SELECT" in r.reason


def test_a_select_against_customer_rows_is_refused():
    r = rejection("bq", ["query", "SELECT subject FROM support.tickets LIMIT 10"])
    assert r.rejected_by == "G2b_bq_query"
    assert "INFORMATION_SCHEMA" in r.reason


def test_a_second_statement_is_refused_by_the_cheaper_layer():
    """Through the chain, `;` never reaches G2b — G1's charset refuses it first,
    which is the ordering doing its job rather than G2b being redundant."""
    r = rejection("bq", ["query", "SELECT 1 FROM d.INFORMATION_SCHEMA.TABLES; DROP TABLE t"])
    assert r.rejected_by == "G1_lexical"


def test_g2b_refuses_a_second_statement_on_its_own():
    """Asserted directly, because G2b is the layer that would have to hold if
    G1's charset were ever widened to admit SQL punctuation."""
    with pytest.raises(g.GuardRejection) as exc:
        g._g2b_bq_query(["query", "SELECT 1 FROM d.INFORMATION_SCHEMA.TABLES; DROP TABLE t"])
    assert exc.value.rejected_by == "G2b_bq_query"


def test_an_information_schema_select_is_accepted_and_bounded():
    cmd = check(
        "bq",
        ["query", "SELECT table_name FROM `p.support.INFORMATION_SCHEMA.TABLES`"],
    )
    assert f"--max_rows={g.BQ_MAX_ROWS}" in cmd.argv
    assert f"--maximum_bytes_billed={g.BQ_MAX_BYTES_BILLED}" in cmd.argv
    assert "--use_legacy_sql=false" in cmd.argv
    # bq splits global flags from query flags: the caps must land after `query`,
    # not in front of it, or they are unknown global flags rather than caps.
    assert cmd.argv.index("query") < cmd.argv.index("--use_legacy_sql=false")
    assert cmd.argv.index(f"--project_id={PROJECT}") < cmd.argv.index("query")


def test_a_backtick_is_permitted_in_a_bq_sql_statement_and_nowhere_else():
    """The one metacharacter exception, and it was earned rather than assumed.

    BigQuery cannot address an INFORMATION_SCHEMA view without backticks: the
    parser splits an unquoted `dataset.INFORMATION_SCHEMA.TABLES` as
    *project*.dataset.table. Three unquoted forms were tried against a real
    project — bare dataset-qualified, fully qualified four-part, and
    `--dataset_id` both before and after the verb — and all three fail. Refusing
    backticks does not make `bq query` safer, it makes it unusable.

    The exception is inert (there is no shell anywhere in this path) and it is
    narrow: the SQL statement of a `bq query`, and nothing else."""
    cmd = check(
        "bq",
        ["query", "SELECT table_name FROM `p.support.INFORMATION_SCHEMA.TABLES`"],
    )
    assert any("`" in t for t in cmd.argv)


def test_a_backtick_anywhere_else_is_still_an_anomaly():
    """Every other token, every other binary, and every other metacharacter keep
    the strict rule."""
    assert rejection("gcloud", ["projects", "describe", "`whoami`"]).rejected_by == "G1_lexical"
    assert rejection("bq", ["show", "`d.t`"]).rejected_by == "G1_lexical"
    # A flag on a bq query is not the statement.
    assert rejection(
        "bq", ["query", "--label=`x`", "SELECT 1 FROM `p.d.INFORMATION_SCHEMA.TABLES`"]
    ).rejected_by == "G1_lexical"


def test_a_semicolon_is_still_refused_inside_a_bq_statement():
    """The exception is one character wide. Statement chaining stays impossible."""
    r = rejection("bq", ["query", "SELECT 1 FROM `p.d.INFORMATION_SCHEMA.TABLES`; DROP TABLE t"])
    assert r.rejected_by == "G1_lexical"


# ── G3 — flag policy ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("flag", sorted(g.IDENTITY_FLAGS))
def test_a_flag_that_changes_identity_is_refused(flag):
    r = rejection("gcloud", ["projects", "describe", PROJECT, f"{flag}=someone@example.test"])
    assert r.rejected_by == "G3_flags"
    assert "identity" in r.reason


@pytest.mark.parametrize("flag", sorted(g.TARGET_FLAGS))
def test_a_caller_supplied_project_is_refused_rather_than_silently_overridden(flag):
    """Overriding it quietly would make the evidence appendix a lie about what
    the agent asked for."""
    r = rejection("gcloud", ["compute", "instances", "list", "--limit=5", f"{flag}=other-project"])
    assert r.rejected_by == "G3_flags"
    assert "project" in r.reason


def test_a_flag_that_reads_a_file_is_refused():
    r = rejection("gcloud", ["projects", "describe", PROJECT, "--flags-file=/etc/passwd"])
    assert r.rejected_by == "G3_flags"


def test_an_at_file_argument_is_refused():
    r = rejection("gcloud", ["projects", "describe", "@/etc/passwd"])
    assert r.rejected_by == "G3_flags"


def test_a_presentational_flag_is_not_refused():
    """The denylist covers three classes and must not creep into a de facto
    allowlist — `--sort-by` is exactly the flag a caller would waste rounds on."""
    cmd = check("gcloud", ["compute", "instances", "list", "--limit=5", "--sort-by=~creationTimestamp"])
    assert "--sort-by=~creationTimestamp" in cmd.argv


# ── G4 — data reduction ──────────────────────────────────────────────────────


def test_an_unbounded_listing_is_refused_and_the_fix_names_the_flags():
    r = rejection("gcloud", ["compute", "firewall-rules", "list"])
    assert r.rejected_by == "G4_data_reduction"
    for flag in ("--limit", "--filter", "--format"):
        assert flag in r.fix


@pytest.mark.parametrize(
    "reducer",
    ["--limit=10", "--filter=name~^web-", '--format=json(name,status)'],
)
def test_any_one_reducing_flag_satisfies_the_check(reducer):
    assert check("gcloud", ["compute", "firewall-rules", "list", reducer]).argv


def test_describe_needs_no_reduction():
    """`describe` returns one resource. Requiring a limit there would be the
    guard inventing work for the caller."""
    assert check("gcloud", ["projects", "describe", PROJECT]).argv


# ── G5 — injected scoping (a boundary) ───────────────────────────────────────


def test_the_project_is_injected_and_the_identity_is_not_a_flag():
    """`--impersonate-service-account` is deliberately no longer injected: the
    container holds a short-lived token that already *is* the scanner service
    account, and asking it to impersonate itself needs tokenCreator on itself.
    The identity boundary moved to the token — which the caller equally cannot
    set — and G3 still refuses a caller-supplied flag."""
    cmd = check("gcloud", ["projects", "describe", PROJECT])
    assert f"--project={PROJECT}" in cmd.argv
    assert "--quiet" in cmd.argv
    assert not any(t.startswith("--impersonate-service-account") for t in cmd.argv)


def test_json_is_only_defaulted_when_the_caller_gave_no_format():
    given = check("gcloud", ["compute", "instances", "list", "--format=table(name)"])
    assert given.argv.count("--format=json") == 0
    defaulted = check("gcloud", ["compute", "instances", "list", "--limit=5"])
    assert "--format=json" in defaulted.argv


def test_the_display_string_is_what_the_caller_asked_for_not_what_ran():
    """The evidence appendix records the agent's own command; recording the
    injected form would show the reader flags the agent never chose."""
    cmd = check("gcloud", ["projects", "describe", PROJECT])
    assert cmd.display == f"gcloud projects describe {PROJECT}"
    assert "--impersonate-service-account" not in cmd.display


# ── ordering, and the argv boundary ──────────────────────────────────────────


def test_a_command_failing_two_checks_reports_the_cheaper_one():
    """`--project` is a G3 violation and `;` is a G1 one. G1 must win, or the
    cheapest-first ordering is a claim rather than a property."""
    r = rejection("gcloud", ["compute", "instances", "list", "--project=x;y", "--limit=5"])
    assert r.rejected_by == "G1_lexical"


def test_a_write_verb_with_an_unbounded_listing_reports_the_verb():
    """G2 sits above G4: refusing the verb is both cheaper and more useful than
    telling a delete to add `--limit`."""
    r = rejection("gcloud", ["compute", "instances", "delete"])
    assert r.rejected_by == "G2_verb"


@pytest.mark.parametrize(
    "args",
    [
        ["projects", "describe", PROJECT],
        ["compute", "instances", "list", "--limit=5", "--filter=status=RUNNING"],
        ["asset", "search-all-iam-policies", "--limit=50", "--format=json(resource,policy)"],
    ],
)
def test_the_built_argv_never_contains_a_shell_metacharacter(args):
    """The same assertion the scanner runner's tests already make. There is no
    shell, and this proves nothing was assembled as though there were."""
    for token in check("gcloud", args).argv:
        for meta in g.SHELL_METACHARACTERS:
            assert meta not in token


# ── failure communication ────────────────────────────────────────────────────


def test_every_rejection_names_the_layer_the_reason_and_the_fix():
    """Swept across the chain rather than asserted once, so a layer added later
    without a `fix` fails here rather than reaching the model as a bare no."""
    bad = [
        ("kubectl", ["get", "pods"]),
        ("gcloud", ["compute", "instances", "list", "--filter=a;b"]),
        ("gcloud", ["compute", "instances", "delete", "web-1"]),
        ("gcloud", ["compute", "instances", "frobnicate"]),
        ("bq", ["query", "DROP TABLE t"]),
        ("gcloud", ["projects", "describe", PROJECT, "--account=x@y.z"]),
        ("gcloud", ["compute", "firewall-rules", "list"]),
    ]
    for binary, args in bad:
        exc = rejection(binary, args)
        payload = g.rejection_payload(exc, binary=binary, args=args)
        assert payload["ok"] is False
        assert payload["rejected_by"]
        assert payload["reason"]
        assert payload["fix"]
        assert payload["command"].startswith(binary)


# ── group names that collide with write verbs ────────────────────────────────


@pytest.mark.parametrize(
    "args",
    [
        ["run", "services", "list", "--limit=50"],
        ["deploy", "delivery-pipelines", "list", "--limit=10"],
        # G4 still applies uniformly — the collision fix changes which verb is
        # found, not whether the rest of the chain runs.
        ["config", "list", "--format=json"],
    ],
)
def test_a_read_under_a_group_named_like_a_write_verb_is_accepted(args):
    """`gcloud run services list` is an ordinary read whose command *group* is
    on the write denylist. A denylist-first scan refuses it — and it is in the
    recon playbook, so that refusal would silently remove Cloud Run from every
    report's live context."""
    assert check("gcloud", args).argv


def test_the_write_verb_under_such_a_group_is_still_refused():
    """The allowlist is the gate, so resolving the collision costs only the
    quality of the message, never the outcome."""
    r = rejection("gcloud", ["dataflow", "jobs", "run", "my-template"])
    assert r.rejected_by == "G2_verb"


def test_a_credential_read_is_still_refused_despite_the_group_being_scannable():
    """`gcloud auth print-access-token` names no read verb, so it falls through
    to the denylist and is refused as a write verb."""
    r = rejection("gcloud", ["auth", "print-access-token"])
    assert r.rejected_by == "G2_verb"
    assert "write verb" in r.reason
