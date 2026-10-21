# A clone that reuses the saved identity

Proves: [ARCHITECTURE, Identity sources](../../ARCHITECTURE.md#identity-sources).

## What it is

On a machine that already has an identity file, a new clone needs no variables.

## How to get to it

In a second clone: `pre-commit install`, then the setup command alone.

## Driving it

1. Clone the project again and run `pre-commit install` (Gitleaks is copied in to save a
   download).
2. Run the setup command with no variables.
3. Commit.

## Proof

The default identity file exists before setup. Setup exits 0 and does not print
`Machine identity: saved`. The commit exits 0 and is signed.
