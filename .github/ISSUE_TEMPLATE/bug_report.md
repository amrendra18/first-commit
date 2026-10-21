---
name: Bug report
about: Report a command that fails or gives a wrong result
labels: bug
---

Do not report a vulnerability here. Use private reporting as SECURITY.md
describes.

## What happened

The command you ran, exactly as typed, and what it printed. Remove secrets,
private values, and personal paths first.

```text
```

## What you expected

## Versions

- Operating system and version:
- Python (`python3 --version`):
- Git (`git --version`):
- pre-commit (`pre-commit --version`):
- first-commit (`first-commit version`):

## Doctor output

Run `first-commit doctor --format json` in the repository and paste the
output. In a clone without first-commit installed, paste the text output of
`pre-commit run first-commit-doctor --hook-stage manual --all-files` instead.
The JSON output holds the absolute path of your repository in its `repository`
field, and that path can hold your user name. Replace any part of it you do not
want to publish.

```json
```
