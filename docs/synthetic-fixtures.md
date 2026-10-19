# Synthetic fixture policy

All examples, tests, screenshots, and documentation in the public source tree
must use synthetic data. Never copy identifiers, measurements, tickets, output,
or narratives from an operational environment.

Use `example.test` for domains and RFC 5737 documentation ranges for IP
addresses. Cloud identifiers must be visibly non-operational placeholders, such
as `synthetic-project-id` and `synthetic-organization-id`; do not use a
plausible project, bucket, account, organization number, or dataset copied from
an environment. Use fictional resource names such as `sample_audit_dataset`.

Counts, sizes, latency, and other measurements must be small illustrative
values or generic rationale, never values attributed to a scan, ticket,
experiment, customer, identity, or deployment. Comments follow the same rule.

Before publishing, run the OSS safety check and review targeted searches for
non-reserved domains, cloud identifier shapes, and real-run provenance.
