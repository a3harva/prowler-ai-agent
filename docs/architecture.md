# Architecture

prowler agent is a local-development stack for importing and
reviewing Prowler-compatible GCP findings.

| Component | Role |
| --- | --- |
| React frontend | Browser interface |
| FastAPI API | Authentication, authorization, and application API |
| Celery worker | Scan and report jobs |
| PostgreSQL | Application data |
| Redis | Task broker and short-lived coordination |
| nginx | Local reverse proxy |
| Prowler container | Produces scan output imported by the application |

The optional integrations are Google OAuth, Freshservice, Gemini, Langfuse,
and a read-only Google Cloud CLI worker. They are disabled when their settings
are empty.

## Important boundary

The supplied Compose setup is for trusted local development. The worker uses
the host Docker socket to launch scanner containers, and local datastore ports
may be published by the development override. Do not expose this stack to the
internet or describe it as a production deployment.

For Google Application Default Credentials, the local override mounts only the
dedicated read-only JSON file named by `GCLOUD_ADC_PATH`. It must be a
least-privilege identity and must not be an entire developer gcloud profile.

Scan results and reports can contain cloud resource names, identities, network
details, and IAM configuration. They must not be committed or attached to
public issues.
