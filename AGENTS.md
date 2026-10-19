# Agent Guide

# General rules for file edits for ANY and ALL files
heredoc-based python3 << 'PY' blocks for editing files , ripgrep for search , native python libraries for json/yaml manipulation.File editing to be done with ONLY PYTHON.read with read tool.

Commands you can run : ls commands  / tree, cat / head / tail,wc -l,curl 


## Project

prowler agent is a self-hosted application for importing and
reviewing cloud-security scan findings. The application currently integrates
with Prowler-compatible GCP scans and optional Google, Freshservice, Gemini,
and Langfuse services. See [README.md](README.md),
[docs/architecture.md](docs/architecture.md), and
[docs/threat-model.md](docs/threat-model.md).

## Safety rules

- Never commit credentials, private keys, tokens, cloud exports, database
  dumps, scan output, customer data, personal data, screenshots containing real
  data, or local configuration.
- Do not read `.env.local` files. Use `.env.sample` only to learn the public
  configuration contract.
- Use only synthetic test data. Use `example.test`, documentation IP ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), and fictional
  project/resource identifiers.
- Treat scan output, reports, audit records, telemetry, backups, and Docker
  images as sensitive data.
- Do not change external cloud resources from this repository.

## Supported commands

```sh
./docker-up.sh -d                     # build and start the local stack
./docker-down.sh [--volumes]          # stop; --volumes also deletes local data
cd backend && uv run pytest           # backend tests (need PostgreSQL + Redis)
cd backend && uv run alembic upgrade head
cd frontend && bun install --frozen-lockfile && bun run build
bash scripts/oss-safety-check.sh      # leak and credential-shape check
./scripts/db-backup.sh [label]        # dump the local database
./scripts/db-restore.sh <dump>        # restore a dump
./scripts/langfuse-up.sh              # optional observability profile
```

## Development

- Backend: Python 3.12, FastAPI, PostgreSQL, Celery, and `uv`.
- Frontend: React, TypeScript, Vite, and `bun`.
- Run backend tests in a container-backed PostgreSQL environment. Run
  `cd frontend && bun run build` for the frontend build check.
- Local scanning assumes Colima with 4 CPUs and 8 GiB; `scripts/preflight.sh`
  enforces it because scans otherwise starve the control plane.

## Working conventions

- Configuration keys mirror `.env.sample` exactly. `app/config.py` fails
  startup when any key is missing, so a deleted line surfaces immediately
  rather than as a confusing `None` later. Update both together.
- Database migrations are hand-written and reviewed. Never apply unreviewed
  autogeneration; re-run autogenerate on a clean tree before trusting it.
- Do not commit to `main`; open a pull request.
- Keep changes small, tested, and documented.

## Security boundaries

- Scan output and generated reports are sensitive. Never use real scan exports
  as fixtures or issue attachments.
- The development stack gives the worker Docker-socket access and publishes
  datastore ports. Neither is safe for an untrusted deployment; see
  [docs/threat-model.md](docs/threat-model.md).
- Update `.env.sample`, the README, and the security documentation whenever a
  public configuration or data-flow contract changes.

## Contributions

- Keep changes small, tested, and documented.
- Run the repository leak checks before committing and ensure no internal
  domains, names, paths, or real infrastructure identifiers are introduced.
- See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
