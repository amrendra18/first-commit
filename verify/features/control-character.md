# A control character blocks a commit

Proves: [README, What it does](../../README.md#what-it-does).

## What it is

A staged text file that contains a control character, such as DEL (0x7f), cannot reach a
commit.

## How to get to it

A person stages a text file that holds a control character, then tries to commit it.

## Driving it

1. In the project from the setup feature, write `control.txt` with a DEL byte (0x7f) in its
   only line.
2. Stage it and commit.

## Proof

The commit exits non-zero and reports `text.control-character` with the fix line
`Delete the control character from this line.` Cleanup (not checked): the harness unstages
and deletes the file.
