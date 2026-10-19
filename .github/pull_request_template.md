## Summary

<!-- What changes and why. Link the issue if there is one. -->

## Verification

<!-- Commands run and their results. -->

- [ ] `cd backend && uv run pytest`
- [ ] `cd frontend && bun run build`
- [ ] `bash scripts/oss-safety-check.sh`

## Checklist

- [ ] Uses only synthetic data (`example.test`, RFC 5737 IP ranges, `synthetic-*` identifiers).
- [ ] No credentials, scan output, reports, or screenshots with real data.
- [ ] `.env.sample`, README, and security docs updated if a configuration or data-flow contract changed.
- [ ] Any migration is hand-written and reviewed.
