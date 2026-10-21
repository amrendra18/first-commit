# Setup from the real GitHub repository

Proves: [ARCHITECTURE, Security rules](../../ARCHITECTURE.md#security-rules).

## What it is

A project set up from GitHub itself: setup's source preflight reaches GitHub, and pre-commit
downloads the pinned hooks from GitHub, not from a local snapshot.

## How to get to it

A person runs setup in an empty folder, or a clone runs `pre-commit install` and the setup
hook. pre-commit downloads the hooks from the address and commit in `.pre-commit-config.yaml`.

## Driving it

The harness reads GitHub over SSH through the SSH agent of the shell that runs it, with read
commands only (`git ls-remote` and pre-commit's fetch); commits are still signed with the
throwaway key. It tries port 22, then GitHub's SSH endpoint on port 443. It tests GitHub
main, and is skipped with the reason when the shell has no SSH agent, when GitHub main is
not in the local clone, or when the product files (`src`, `.pre-commit-hooks.yaml`,
`pyproject.toml`) differ from GitHub main. `--require-github` counts
any skip as a failure.

## Proof

Setup runs with its hook source preflight turned on and exits 0. The hooks are pinned to
the SSH address and GitHub main, pre-commit's cache records the download from GitHub, and
a commit exits 0, carries an SSH signature, and runs through the downloaded hooks, which
print `first-commit staged hygiene...Passed` and
`first-commit commit-message hygiene...Passed`.
