"""The fixed set of commands every deep report runs before a model sees anything.

Public-IAM-binding search and BigQuery metadata are fixed safeguards rather
than model-selected discoveries.

Three properties fall out of running them deterministically:

- **They happen on every report**, regardless of what a model decides is
  interesting.
- **`survey` gets inventory to plan against** instead of guesses.
- **They are cacheable and reproducible**, because no model chose them.

Every listing carries a `--format` projection because unprojected inventory can
overwhelm the prompt alongside the ledger.

`bq` is deliberately absent from the fixed steps. The storage query is the other
high-yield call, but it has to name a dataset, and which datasets exist is not
known until `search-all-resources` has run. It is left to the investigator,
which the skill points at explicitly.
"""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True)
class Step:
    """One playbook command.

    `key` names it in the snapshot the model reads, so it is a word about the
    *question* ("public_iam_bindings") rather than about the command. `why`
    reaches the evidence appendix, and is written for the report's reader.
    """

    key: str
    binary: str
    args: list[str]
    why: str
    # True only for commands that take a `--organization` *flag*
    # (`resource-manager org-policies`, `access-context-manager`). G5 then
    # injects `--organization` in place of `--project`, because gcloud accepts
    # exactly one scope flag and refuses two. Commands that take the
    # organization as a positional leave this False and substitute `{org}`.
    org_scoped: bool = False

    def render(self, project_id: str, organization_id: str | None = None) -> list[str]:
        """Substitute `{project}` into the tokens.

        Needed because a *positional* project argument is not the same thing as
        the `--project` flag G5 injects. `gcloud projects describe` takes the
        project id as a positional and fails with "argument
        PROJECT_ID_OR_NUMBER: Must be specified" without it — the injected flag
        sets the quota/billing project and does not fill a positional.

        Substituting here rather than letting the guard do it keeps G5 a pure
        boundary: it appends and never rewrites what the caller wrote. The value
        is the same validated `projects` row either way, so nothing about the
        identity guarantee changes — this is the playbook naming its own target,
        not a caller supplying one.

        `{org}` substitutes the same way and for the same reason — and the id
        comes from the validated project's `parent`, never from a model. That
        matters more here than it does for `{project}`: the scanner service
        account can see other customers' organizations,
        so an organization id chosen anywhere else is a cross-customer leak.
        """
        rendered = [t.replace("{project}", project_id) for t in self.args]
        if organization_id:
            rendered = [t.replace("{org}", organization_id) for t in rendered]
        return rendered


# `--format` projections are chosen to answer the question the step exists for.
# Widening one is not free: every field lands in a prompt beside the ledger.
PLAYBOOK: list[Step] = [
    Step(
        key="project",
        binary="gcloud",
        args=["projects", "describe", "{project}"],
        why="confirm the project this report is about, and its lifecycle state",
    ),
    Step(
        key="public_iam_bindings",
        binary="gcloud",
        args=[
            "asset", "search-all-iam-policies",
            "--query=policy:allUsers OR policy:allAuthenticatedUsers",
            "--format=json(resource,policy.bindings[].role,policy.bindings[].members)",
            "--limit=100",
        ],
        # The single highest-yield call either experiment found: it returns the
        # project's complete public-binding inventory, including resource types
        # no check in the scan covers.
        why="find every resource in the project with a public IAM binding",
    ),
    Step(
        key="compute_instances",
        binary="gcloud",
        args=[
            "compute", "instances", "list",
            "--format=json(name,status,zone,networkInterfaces[].network,"
            "networkInterfaces[].accessConfigs[].natIP,serviceAccounts[].email,"
            "serviceAccounts[].scopes)",
            "--limit=50",
        ],
        # Scopes and status together are what say whether a broad service
        # account role on a VM is actually reachable.
        why="which VMs exist, whether they are running, and what identity and scopes they hold",
    ),
    Step(
        key="firewall_rules",
        binary="gcloud",
        args=[
            "compute", "firewall-rules", "list",
            "--format=json(name,network,direction,disabled,sourceRanges,allowed,targetTags)",
            "--limit=100",
        ],
        why="which ingress paths exist, and on which networks",
    ),
    Step(
        key="networks",
        binary="gcloud",
        args=["compute", "networks", "list", "--format=json(name,subnetMode)", "--limit=50"],
        # A rule is only a risk if something sits behind it; this is half of
        # the "firewall rule guarding an empty network" pattern.
        why="the networks the firewall rules and instances refer to",
    ),
    Step(
        key="sql_instances",
        binary="gcloud",
        args=[
            "sql", "instances", "list",
            "--format=json(name,state,databaseVersion,settings.ipConfiguration,"
            "settings.backupConfiguration.enabled,settings.availabilityType)",
            "--limit=50",
        ],
        # `state` and `ipConfiguration` together are what distinguish a live
        # internet path from an authorized-network entry on an instance that is
        # stopped and has no public IP at all.
        why="whether each database is running, and whether it has a public endpoint",
    ),
    Step(
        key="gke_clusters",
        binary="gcloud",
        args=[
            "container", "clusters", "list",
            "--format=json(name,status,location,privateClusterConfig,"
            "masterAuthorizedNetworksConfig)",
            "--limit=50",
        ],
        why="which clusters exist and whether their control planes are reachable",
    ),
    Step(
        key="cloud_functions",
        binary="gcloud",
        args=[
            "functions", "list",
            "--format=json(name,state,environment,serviceConfig.ingressSettings)",
            "--limit=50",
        ],
        why="which functions exist and how they can be reached",
    ),
    Step(
        key="cloud_run_services",
        binary="gcloud",
        args=[
            "run", "services", "list",
            "--format=json(metadata.name,status.url,metadata.namespace)",
            "--limit=50",
        ],
        # The scan's check coverage misses Cloud Run entirely; the public
        # bindings step catches the exposure, and this names what was exposed.
        why="which Cloud Run services exist, to pair with the public bindings above",
    ),
    Step(
        key="buckets",
        binary="gcloud",
        args=[
            "storage", "buckets", "list",
            # **snake_case, not camelCase.** `gcloud storage` returns a
            # different schema from the JSON API and from the older `gsutil`
            # surface: the field is `public_access_prevention`, and asking for
            # `iamConfiguration` returns **silence rather than an error** — the
            # projection simply yields nothing and the snapshot looks fine.
            # Use the documented snake_case field so prevention state is
            # present in the response.
            "--format=json(name,location,public_access_prevention,"
            "uniform_bucket_level_access)",
            "--limit=100",
        ],
        # Public Access Prevention is the other half of "an allUsers binding
        # that PAP overrides" — without it that pattern is unreachable.
        why="which buckets exist, and whether public access prevention is enforced on them",
    ),
    Step(
        key="datasets",
        binary="gcloud",
        args=[
            "asset", "search-all-resources",
            "--asset-types=bigquery.googleapis.com/Dataset",
            "--format=json(name,displayName,location)",
            "--limit=100",
        ],
        # Names the datasets the investigator's INFORMATION_SCHEMA query needs;
        # that query cannot be a fixed step because it has to name one.
        why="which BigQuery datasets exist, so table volumes can be checked against them",
    ),
]


# ── organization scope ───────────────────────────────────────────────────────
# Everything below runs only if `ORG_PROBE` succeeds. No grant is
# requested up front, so the pipeline asks the API what this service account can
# already do and takes the answer.


def organization_id_from(project_step_result: dict | None) -> str | None:
    """The parent organization id, read out of the `project` step's own output.

    No discovery call: `gcloud projects describe` is already playbook step 1 and
    already returns `parent`, for example —
    `{"id": "synthetic-organization-id", "type": "organization"}`.

    Returns `None` when the parent is a **folder** rather than an organization,
    or when there is no parent at all. Folder-scoped policy reads are a
    different flag and a different permission, and quietly treating a folder id
    as an organization id produces a confusing "does not exist" rather than an
    honest "not supported".
    """
    if not isinstance(project_step_result, dict):
        return None
    data = project_step_result.get("data")
    if not isinstance(data, dict):
        return None
    parent = data.get("parent")
    if not isinstance(parent, dict):
        return None
    if parent.get("type") != "organization":
        return None
    org_id = str(parent.get("id") or "").strip()
    return org_id or None


# **`gcloud organizations list` is deliberately NOT the probe.** A list could
# cross the report's validated resource boundary. The probe names only the
# parent organization derived from the project record.
ORG_PROBE = Step(
    key="organization",
    binary="gcloud",
    args=["organizations", "describe", "{org}", "--format=json(name,displayName)"],
    why="determine whether this report may read the project's parent organization",
)

ORG_PLAYBOOK: list[Step] = [
    Step(
        key="org_policies",
        binary="gcloud",
        args=[
            "resource-manager", "org-policies", "list",
            "--format=json(constraint)",
            "--limit=100",
        ],
        org_scoped=True,
        # The constraint *list* is the cheap half: it says which policies exist
        # to ask about, so the two describes below are not guesses.
        why="which organization policies are set above this project",
    ),
    Step(
        key="org_public_access_prevention",
        binary="gcloud",
        args=[
            "resource-manager", "org-policies", "describe",
            "constraints/storage.publicAccessPrevention",
            "--format=json(constraint,booleanPolicy,etag)",
        ],
        org_scoped=True,
        # The org-level half of the pattern the bucket step already covers at
        # project level: an allUsers binding that PAP overrides. Enforced at the
        # organization, it overrides every bucket in every project beneath it,
        # which can turn a critical finding into a moot one.
        why="whether public access prevention is enforced organization-wide",
    ),
    Step(
        key="org_allowed_policy_member_domains",
        binary="gcloud",
        args=[
            "resource-manager", "org-policies", "describe",
            "constraints/iam.allowedPolicyMemberDomains",
            "--format=json(constraint,listPolicy)",
        ],
        org_scoped=True,
        # Domain-restricted sharing. Where it is enforced, an `allUsers` binding
        # cannot actually be created, so a finding that reports one is reporting
        # something the organization already prevents.
        why="whether domain-restricted sharing blocks public IAM members organization-wide",
    ),
    Step(
        key="vpc_sc_policies",
        binary="gcloud",
        args=[
            "access-context-manager", "policies", "list",
            "--format=json(name,title)",
            "--limit=10",
        ],
        org_scoped=True,
        # The Access Context Manager API may be
        # not enabled, so this returns a nameable error rather than data. That
        # is a recorded gap, not a failure — the same rule the whole live-context
        # design follows.
        why="whether any VPC Service Controls perimeters exist above this project",
    ),
]
