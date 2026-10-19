# Public-source checklist

This checklist answers one question: is this source tree safe and useful to
publish? It does not certify a production deployment.

- [x] The repository has a new history that contains no objects from the
      original internal repository.
- [ ] Local-only material is outside the clean export; ignored files must not
      be treated as safe to include in a directory archive.
- [ ] Examples and tests use synthetic data and reserved domains/IP ranges;
      see `docs/synthetic-fixtures.md`.
- [ ] `bash scripts/oss-safety-check.sh` passes with an external private
      denylist, and targeted source/history checks have been reviewed.
- [x] Public documentation states that the included stack is for local
      development and is not production-ready.
- [x] `LICENSE`, `NOTICE`, `SECURITY.md`, and `CONTRIBUTING.md` are present.
- [x] CI contains the public-tree safety check and ordinary backend/frontend
      build checks.
- [ ] The publisher confirms that they have the right to publish the retained
      code under Apache-2.0.
- [ ] Create the destination repository without importing the old repository,
      push this new history, and make that destination public.

Production hardening, deployment design, SBOMs, image-digest pinning, container
scanning, and hosted branch-protection settings are useful follow-up work but
are not blockers for publishing readable source code.
