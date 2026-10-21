# The README first run in a terminal

Proves: [README, Start a project](../../README.md#start-a-project).

## What it is

The README's first run, through the installed command: a dry run, then `first-commit setup`,
which asks for the identity and for confirmation, then `first-commit doctor`.

## How to get to it

Install the tool as the README Install section says, then in an empty folder run
`"$FIRST_COMMIT" setup --dry-run`, `"$FIRST_COMMIT" setup`, and `"$FIRST_COMMIT" doctor`.

## Driving it

1. Install `first-commit[setup]` into a new environment from the HTTPS address at the snapshot
   commit (the scratch HOME maps the address to the snapshot). fix-line-works uses the same
   install.
2. Use a second scratch HOME with no identity file.
3. Run the installed `first-commit setup --dry-run` in an empty folder, with the default
   pre-commit cache setting, as on a new machine.
4. Run the installed `first-commit setup` with a pseudo-terminal (`os.openpty`) as its
   input and output. Type the name, email, and public signing-key path at the three prompts,
   then `y` at `Apply this setup? [y/N]`. Nothing is patched, so setup runs its real source
   preflight; no line of the proof checks the preflight separately.
5. Run the installed `first-commit doctor`.

## Proof

The dry run exits 0 and leaves the folder empty.

Expected dry run in an empty folder, with no saved identity:

```text
Git repository: would initialize
Files: would create .repo-policy.json, .editorconfig, .gitattributes, README.md, AGENTS.md, .pre-commit-config.yaml, .gitignore, .gitmessage
Local contributor: required
Private values: would create .local/first-commit/private-values.txt; add one private value per line
Git identity/signing: would configure
Commit template: would set commit.template
Hook source: HTTPS (https://github.com/amrendra18/first-commit)
Hook cache: pre-commit default
Signature verification: not performed; trust is not checked
Gitleaks: would download and install 8.30.0 from GitHub Releases
Hook scripts: would install
Hook environments: would install or verify; not checked (dry run)
Verification: Git-dependent checks will run after initialization; no changes made
Next action: review generated documents and remove @no-commit markers
```

The dry run's output equals this block line for line. Setup prints the four prompts in
order (the terminal driver fails when a prompt does not appear), names the typed identity
in its plan, exits 0, and prints `Verification: passed`. It prints `Machine identity: saved to` the file
`~/.config/first-commit/identity.json`, which has mode 600 and holds the typed email, and it
writes the contributor record. Doctor exits 0 and prints the WARN line for
`git.signature-verification-trust` that the README describes.
