# A clone with a chosen identity file

Proves: [ARCHITECTURE, Identity sources](../../ARCHITECTURE.md#identity-sources).

## What it is

`FIRST_COMMIT_IDENTITY_FILE` chooses where the per-machine identity lives.

## How to get to it

A person sets `FIRST_COMMIT_IDENTITY_FILE` before running the setup command.

## Driving it

Steps 1 to 5 of clone-guided (step 6, the hooks without the tool, does not run here), with
`FIRST_COMMIT_IDENTITY_FILE` pointing at a file in a folder whose name has a space. Gitleaks
is copied in to save a download.

## Proof

The clone-guided proofs for steps 2 to 5 hold for the chosen file. The default identity
file has the same modification time before and after (or is absent both times).
