# Security Policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability, credential exposure,
or data disclosure. Contact the maintainers through the repository's configured
private reporting channel — the **Report a vulnerability** button under the
repository's Security tab when it is enabled, or the maintainer contact listed
there. Include reproduction steps, affected versions or commit, and suggested
mitigations when available. Repository administrators must enable GitHub private
vulnerability reporting before publishing; until then, use the maintainer
contact configured in the Security tab.

Do not include credentials, customer data, real scan output, or personally
identifying information in a report. Use redacted or synthetic examples.

We will acknowledge a report as soon as we are able, keep you informed of the
assessment, and credit you in the fix notes unless you ask us not to.

## Supported versions

The project has no versioned releases yet. Security fixes are applied to the
current `main` branch. When releases begin, each release note will record its
support window here.

## Deployment boundary

The included Compose files are intended for **local development only**.
Production deployments must provide:

- TLS termination and HTTPS enforcement,
- network isolation and authenticated PostgreSQL and Redis,
- secret management rather than a bind-mounted environment file,
- backups, monitoring, and log retention,
- a least-privilege scan-execution boundary that does **not** grant the API or
  general worker access to the Docker socket.

Scan results and generated reports are sensitive data. Deploy the service only
where the people authorized to view that data can reach it.

## Handling secrets

- Never commit credentials, private keys, tokens, database dumps, scan output,
  or local configuration.
- Treat any secret that appeared in a published file, image layer, or archive as
  compromised and rotate it.
- Rotate the JWT signing key to invalidate all existing sessions.
- The repository's CI runs a generic leak check and Gitleaks. Operators may add
  organization-specific patterns through a local, never-committed denylist.

## Known limitations

The project has not completed an independent security review.
[docs/threat-model.md](docs/threat-model.md) records the threats that are and
are not currently defended against, including Docker-socket access and
refresh-token revocation.