# The first signed commit

Proves: [README, Make the first commit](../../README.md#make-the-first-commit).

## What it is

After the generated markers are removed, the first commit goes through every hook and is signed.

## How to get to it

A person removes the `@no-commit` lines and runs `git commit`.

## Driving it

1. Remove the marker lines from `README.md` and `AGENTS.md`.
2. Stage everything and commit with a message that has the four review sections: `Why:`,
   `Changes:`, `Test Plan:`, and `Risks:`.

## Proof

The commit exits 0 and carries an SSH signature. Expected hook lines:

```text
first-commit staged hygiene..............................................Passed
first-commit commit-message hygiene......................................Passed
```
