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
3. Put a `first-commit` that runs the snapshot on `PATH`. In a second scratch folder that
   holds only the Gitleaks binary from step 2, run `first-commit setup --hooks installed
   --yes` with the throwaway identity in the three identity variables. Then run
   `first-commit doctor` and `pre-commit run first-commit-doctor --hook-stage manual`
   there. This journey needs no network: local hooks fetch nothing, and Gitleaks is
   already in place.

## Proof

Setup prints `Verification: passed`. `.pre-commit-config.yaml` names the HTTPS address and the
snapshot commit as the revision and lists `first-commit-setup`. The private-values list is mode 600 and ignored.
The contributor record, `.repo-policy.json`, and the three Git hooks exist. The starter README
names the clone setup command, and its marker does not name the tool.

The installed form (step 3): setup prints `Verification: passed`. `.pre-commit-config.yaml`
declares `repo: local` hooks whose entries run `first-commit hook pre-commit` and the other
stages, with no `rev:`. The three Git hooks exist. The starter README names
`first-commit setup` and not the setup hook. `first-commit doctor` exits 0 with no `hooks.`
warning, and the manual doctor hook exits 0 after it runs `first-commit doctor` from `PATH`.
