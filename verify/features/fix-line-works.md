# A setup fix line works without the setup hook

Proves: [ARCHITECTURE, Output](../../ARCHITECTURE.md#output).

## What it is

A project may keep its own `.pre-commit-config.yaml` with only the staged, message, and push hooks and no
`first-commit-setup` hook. A fix line that names setup must then name a command that works
there: `first-commit setup`.

## How to get to it

A person installs the tool in a project whose own hook file has no setup hook. A commit stops
with a `fix:` line, and the person runs the command it names. The feature covers two cases:

1. Pinned hooks: the hook file pins the GitHub hooks, and the tool is installed from the GitHub
   address as the README's Install section does.
2. Local hooks: the hook file runs `first-commit hook ...` as local system hooks, as this
   repository does, and the tool is an editable install with no revision metadata.

## Driving it

For each case:

1. Install the tool into a new virtual environment: from the GitHub address (mapped to the
   snapshot) for pinned hooks, or with `pip install -e` from the snapshot for local hooks.
   The feature fails if the install makes no `bin/first-commit`.
2. In a new folder, write the project-owned `.pre-commit-config.yaml`, run setup (through
   the snapshot source, like the setup feature), remove the markers, and make the first commit
   with the installed tool on `PATH`.
3. Unset `user.useConfigOnly` and try a commit.
4. Read the command from the `fix:` line and run it exactly as printed.
5. Commit again.

## Proof

In both cases setup and the first commit exit 0, and the hook file declares no setup hook.
The commit stops with `git.explicit-identity`. Its fix line names a command
(`  fix: Run <command> in this checkout;`) that is not the missing `first-commit-setup` hook.
That command exits 0, and the next commit exits 0 and is signed. The installed tool is the
only `first-commit` on `PATH`, so the command that exits 0 is the tool under test.

The harness unsets `user.useConfigOnly` instead of deleting the contributor record: without a
record, `first-commit setup` asks for the identity in a terminal, and the harness has none.
