# Setup in an empty folder

Proves: [README, Start a project](../../README.md#start-a-project).

## What it is

`first-commit setup` turns an empty folder into a project whose first commit is already right.

## How to get to it

A person runs `first-commit setup` in an empty folder.

## Driving it

1. Snapshot the working tree into a temporary clone and commit it; the hooks use that commit as their revision.
2. Run setup in an empty scratch folder with a throwaway SSH key (the source preflight is
   skipped, because the snapshot is not on GitHub; first-run runs the real preflight).

## Proof

Setup prints `Verification: passed`. `.pre-commit-config.yaml` names the HTTPS address and the
snapshot commit as the revision and lists `first-commit-setup`. The private-values list is mode 600 and ignored.
The contributor record, `.repo-policy.json`, and the three Git hooks exist. The starter README
names the clone setup command, and its marker does not name the tool.
