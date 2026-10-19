# Contributing

Thank you for contributing to prowler agent.

## Data rules

Use synthetic data only. Never commit local configuration, credentials, private
keys, scan exports, database backups, production logs, customer information,
personal information, or screenshots containing real data. Use reserved
domains such as `example.test`, documentation IP ranges such as
`192.0.2.0/24`, and obviously fictional project and resource identifiers.

## Development setup

- Backend: Python 3.12 with [`uv`](https://docs.astral.sh/uv/).
- Frontend: [Bun](https://bun.sh/).
- Databases: PostgreSQL and Redis from the local Compose stack.

```sh
cp .env.sample .env.local    # then replace every CHANGE_ME value
./docker-up.sh -d
```

See [README.md](README.md) for configuration and
[docs/architecture.md](docs/architecture.md) for how the pieces fit together.

## Before opening a pull request

1. Run the backend tests and the frontend build:

   ```sh
   cd backend && uv run pytest
   cd frontend && bun install --frozen-lockfile && bun run build
   ```

2. Run the leak and secret check:

   ```sh
   bash scripts/oss-safety-check.sh
   ```

3. Review the diff for identifiers, paths, domains, and data that should not be
   public.
4. Keep `.env.sample`, the README, and the security documentation accurate when
   you change configuration or external data flows.
5. Review migrations by hand; never apply unreviewed autogeneration.

## Pull request conventions

- Keep changes small, tested, and documented. One logical change per pull
  request.
- Add or update tests for behavior changes.
- Describe the security impact of any change that crosses a trust boundary and
  update [docs/threat-model.md](docs/threat-model.md) when appropriate.
- Do not commit to `main`; open a pull request.

## License

By contributing, you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE), consistent with Section 5 of that license.

## Reporting security issues

Report suspected vulnerabilities privately as described in
[SECURITY.md](SECURITY.md). Do not open a public issue for them.
