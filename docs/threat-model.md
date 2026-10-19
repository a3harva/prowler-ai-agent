# Security limitations

prowler agent publishes source code for an early self-hosted application; it
does not claim that the included development deployment is production-ready.

The main known limitations are:

- the scan worker has Docker-socket access;
- refresh tokens are not backed by server-side revocation records;
- password login exists for local development;
- cookie mutations use same-site cookies and origin checks rather than a
  dedicated CSRF token;
- optional AI, support, and telemetry integrations can receive data supplied
  to them by the operator.

Scan output, generated reports, logs, backups, and configuration are sensitive.
Keep them outside Git, use only synthetic data in contributions, and do not
expose the development stack directly to the internet.

These limitations are future product/deployment work. They do not prevent the
sanitized source tree itself from being public.
