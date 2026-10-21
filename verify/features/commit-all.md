# Commits that name their files

Proves: [ARCHITECTURE, Security rules](../../ARCHITECTURE.md#security-rules).

## What it is

`git commit -a` and `git commit <path>` commit a tracked file without `git add`. Git builds a
temporary index for these commits and names it in `GIT_INDEX_FILE`. The staged hook checks
that index, so a defect in such a file cannot reach a commit.

## How to get to it

A person changes a tracked file and runs `git commit -a`, or `git commit -- <path>`, without
staging it first.

## Driving it

1. In the project from the setup feature, add a line with a DEL byte (0x7f) to `README.md`
   without staging it.
2. Run `git commit -a`, then `git commit -- README.md`.
3. Write `README.md` as its original bytes plus one clean line, and run `git commit -a`.
4. Write it as its original bytes plus a different clean line, and run
   `git commit -- README.md`.
5. Move the branch back to the commit it started at (`git reset -q`, which must exit 0) and
   restore `README.md`.

## Proof

Both commits with the DEL byte exit non-zero and report `text.control-character`. Both clean
commits exit 0, a staged-hygiene result line ends in `Passed`, and the output of
`git show HEAD:README.md` equals the written bytes. The restore in step 5 is not checked
further.
