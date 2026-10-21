---
name: first-commit
description: Apply or maintain first-commit for one-shot repository setup, staged-byte/privacy/secret validation, Git signing defaults, and hook integration. Do not use it for product-specific test or build standards.
---

# first-commit

first-commit generates starter files once; the project owns them immediately.
The [README](../../../README.md) covers use, and
[ARCHITECTURE.md](../../../ARCHITECTURE.md) covers rules, output, and policy
fields.

## Adoption and checks

1. Preview with `first-commit setup --dry-run`. Treat conflicts and
   `@no-commit` proposals as manual review, not files to overwrite.
2. Run setup only with authorization for Git initialization, local
   configuration, dependency installation, and hooks. Never stage, commit,
   change remotes, or publish without permission.
3. Run `first-commit doctor` and `first-commit check`; both are read-only.
4. Keep contributor identity in the ignored local record. Never read
   private-key contents or print matched private content.

Project tests and builds belong in project-owned hooks. Do not add project
commands or switches that turn checks off. When changing checks, keep the
security rules in ARCHITECTURE.md, add failing tests first, and run
`scripts/check full`.

To prepare a release, run `scripts/release` and follow the
[release steps](../../../CONTRIBUTING.md#release). Never tag or push; report
the printed commands to the maintainer, who runs them.
