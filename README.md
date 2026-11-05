![first-commit: No more setting up hooks by hand.](.github/banner.svg)

# first-commit

**Start a new Git project in one command, with hooks, signing, and starter
files already in place.**

Its hooks stop a secret or a private value on your machine, before it
becomes history.

[Install](#install) it, then start a project:

```sh
mkdir my-project && cd my-project && first-commit setup
```

Setup shows its plan and asks before it changes anything. Check the
[requirements](#requirements) first.

## What it does

One `setup` run in an empty folder:

1. creates starter files: `README.md`, `AGENTS.md`, `.gitignore`, a commit
   template, and the project policy file (`.repo-policy.json`);
2. turns on SSH commit signing;
3. installs Gitleaks (a secret scanner) and Git hooks through pre-commit (a
   Git hook runner), pinned to one commit of this repository.

Then the hooks check every commit and push:

| When | What is checked |
| --- | --- |
| Commit | Secrets, keys and tokens, home paths, unapproved emails, your private values, forbidden paths, dotenv files, `@no-commit` markers, text hygiene, required documents |
| Commit message | Format and review sections, secrets, private values, identity, and signing settings |
| Push | Signatures (commits since setup), plus secrets, keys, home paths, emails, private values, and file size in the pushed commits, their messages, and tags |

A finding prints a `fix:` line, never the matched text.

The hooks run locally, so `git commit --no-verify` skips them. Shared
repositories still need server-side rules; see [SECURITY.md](SECURITY.md).

## Requirements

1. macOS or Linux, Git, and Python 3.11 to 3.14. On Windows, use WSL (Windows
   Subsystem for Linux). Elsewhere, every command stops with exit 1.
2. pre-commit 3.2.0 or newer, running on Python 3.11 to 3.14. Install it with
   `pipx install --python python3.13 pre-commit`, or `brew install pre-commit`
   on macOS, and check it with `pre-commit --version`.
3. An SSH signing key. Create one with `ssh-keygen -t ed25519`. GPG signing is
   not supported. Setup reads only the public key, the file ending in `.pub`.
4. A public Git author name and email.
5. At most 10,000 files, in a standard repository root (no linked worktree or
   submodule).

## Install

First, compare the commit SHA this prints with the
[release page](https://github.com/amrendra18/first-commit/releases/tag/v0.6.0).
If they differ, do not install.

```sh
git ls-remote https://github.com/amrendra18/first-commit 'v0.6.0^{}'
```

Add the `export` line to your shell profile too (`~/.zshrc` on macOS,
`~/.profile` on Linux). Skip the `ln` line when the link exists.

```sh
python3 -m venv ~/.local/share/first-commit
~/.local/share/first-commit/bin/python -m pip install \
  'first-commit[setup] @ git+https://github.com/amrendra18/first-commit.git@v0.6.0'
mkdir -p ~/.local/bin
ln -s ~/.local/share/first-commit/bin/first-commit ~/.local/bin/first-commit
export PATH="$HOME/.local/bin:$PATH"
first-commit --version
```

The last command prints `0.6.0`.

Over SSH, with an SSH key on your GitHub account, use
`'first-commit[setup] @ git+ssh://git@github.com/amrendra18/first-commit.git@v0.6.0'`
in the `pip install` line.

Optional: write the agent skill for Claude Code and Codex.

```sh
mkdir -p ~/.claude/skills/first-commit ~/.codex/skills/first-commit
first-commit help --format markdown > ~/.claude/skills/first-commit/SKILL.md
first-commit help --format markdown > ~/.codex/skills/first-commit/SKILL.md
```

## What install writes

1. Install writes the tool folder `~/.local/share/first-commit` and the link
   `~/.local/bin/first-commit`. The skill lines write
   `~/.claude/skills/first-commit` and `~/.codex/skills/first-commit`.
2. Setup writes the project's files and local Git settings, and saves your
   identity in `~/.config/first-commit/identity.json`
   (`$XDG_CONFIG_HOME/first-commit/identity.json` when `XDG_CONFIG_HOME` is
   set). That state folder also holds your
   [private-values list](#project-settings). Set `XDG_CONFIG_HOME` to move it,
   or `FIRST_COMMIT_IDENTITY_FILE` to move the identity file alone.
   pre-commit keeps its hook environments in its own cache.

## Network use

Install and setup use GitHub, GitHub Releases (for Gitleaks), and a Python
package index. `check`, `doctor`, and the hooks are offline.

## Start a project

```sh
mkdir my-project && cd my-project
first-commit setup --dry-run
first-commit setup
first-commit doctor
```

1. The dry run prints the plan and changes nothing
   ([sample output](verify/features/first-run.md#proof)).
2. Setup asks for your name, email, and public-key path, then asks before
   applying the plan (`--yes` skips the question). It ends with
   `Verification: passed`. Other options are in
   [ARCHITECTURE.md](ARCHITECTURE.md#setup-options).
3. The first `doctor` prints `WARN doctor` with
   `git.signature-verification-trust` and exits 0, because this checkout does
   not trust your key yet. To trust it, run its `fix:` command:

```sh
FIRST_COMMIT_TRUST_SELF=1 pre-commit run first-commit-setup --hook-stage manual
```

### Make the first commit

Edit `README.md` and `AGENTS.md` for your project and delete their
`@no-commit` lines; the hooks block a commit while one remains. With
`--docs full` or `--license`, also stage `PRD.md`, `CONTRIBUTING.md`,
`SECURITY.md`, or `LICENSE`.

```sh
git add README.md AGENTS.md .gitignore .editorconfig .gitattributes .gitmessage .pre-commit-config.yaml .repo-policy.json
git commit
```

Git opens the template `.gitmessage`. Replace each `<...>` placeholder with
your own text, and write `Not run: <reason>` when no test applies.
Example message:

```text
docs: start the project

Why:
- The project needs its entry point and agent rules.

Changes:
- Add the starter files that first-commit setup created.

Test Plan:
- Not run: the commit holds documents and configuration only.

Risks:
- Low: no code yet.
```

The hooks print `Passed`, and Git signs the commit.

## Set up a clone

A clone needs pre-commit only. In the clone, run:

```sh
pre-commit install
pre-commit run first-commit-setup --hook-stage manual
```

The second command sets the clone's identity and signing from your saved
identity and installs Gitleaks; without one, it prints the command to run.
Prefix it with `FIRST_COMMIT_TRUST_SELF=1` to trust your key too.

With `--hooks installed`, a clone needs first-commit; run `first-commit setup`.

## Daily use

```sh
first-commit check   # working tree, staged files, and whole history
first-commit doctor  # identity, signing, hooks, and scanner
```

In a clone, run them through pre-commit:

```sh
pre-commit run first-commit-check --hook-stage manual --all-files
pre-commit run first-commit-doctor --hook-stage manual --all-files
```

Both are read-only ([two exceptions](ARCHITECTURE.md#security-rules)). Add
`--format json` for JSON.

## Project settings

1. **Private values.** Words never to commit, such as your employer, one per
   line in the ignored `.local/first-commit/private-values.txt`, or for every
   project in `~/.config/first-commit/private-values.txt`
   ([details](ARCHITECTURE.md#private-values)).
2. **Project facts.** `.repo-policy.json` holds approved public emails,
   forbidden paths, and reviewed exceptions. No field turns off a check.
   Stage an edit to it before the commit that needs it. Fields:
   [ARCHITECTURE.md](ARCHITECTURE.md#project-policy-file).
3. **False positives.** A reviewed Gitleaks false positive goes in
   `.gitleaksignore`; see
   [Gitleaks exceptions](ARCHITECTURE.md#gitleaks-exceptions).

## Stop and recover

A failed setup undoes its changes. Other failures:

1. **Install fails with `No matching distribution found`.** `python3` is
   older than 3.11. Delete `~/.local/share/first-commit`, then install again
   with `python3.13`.
2. **Clone setup or a commit fails with
   `No matching distribution found for setuptools`.** pre-commit runs on a
   Python older than 3.11. Run `python3 -m pip uninstall pre-commit`, then
   `pipx install --force --python python3.13 pre-commit`, then
   `pre-commit install` in the clone, and retry.
3. **Setup conflict.** The error names the file or setting and the fix.
   An existing `.gitignore` must ignore `.local/`. For an existing
   `.pre-commit-config.yaml`, see
   [Hook file rules](ARCHITECTURE.md#hook-file-rules).
4. **Wrong identity or key.** In the checkout, run the commands below,
   correct or delete the identity file from
   [What install writes](#what-install-writes), and run setup again
   (`--trust-self` trusts the new key).

   ```sh
   rm .local/first-commit/contributor.json
   rm -f .local/first-commit/allowed-signers
   git config --local --unset user.name
   git config --local --unset user.email
   git config --local --unset user.signingkey
   ```

5. **Scanner download failed.** Check access to GitHub Releases, or place a
   trusted Gitleaks 8.30.0 binary at `.local/bin/gitleaks`.
6. **Hook environment failed.** Read pre-commit's log before a new run
   replaces it: `~/.cache/pre-commit/pre-commit.log`, or
   `$PRE_COMMIT_HOME/pre-commit.log`, or
   `$XDG_CACHE_HOME/pre-commit/pre-commit.log` when only `XDG_CACHE_HOME` is
   set. Check the hook URL and network access, then rerun setup.
7. **Too many files.** `check` and the commit hook stop with exit 1 and
   `File count exceeds the limit of 10,000 paths.` Add generated folders such
   as `node_modules/` to `.gitignore`, untrack them with
   `git rm -r --cached <folder>`, and retry.
8. **A secret in a commit or tag message.** Revoke it with its provider
   first. Then reword it as
   [Messages already pushed](ARCHITECTURE.md#messages-already-pushed) says.

## Upgrade

1. Run the `pip install` line of [Install](#install) with the new tag, and
   any skill lines you use.
2. Run the `git ls-remote` line of [Install](#install) with the new tag.
   In `.pre-commit-config.yaml`, set the first-commit `rev:` to the printed SHA.
3. Review and commit `.pre-commit-config.yaml`. Each clone installs the new
   hooks on its next run. With `--hooks installed`, only step 1 applies.

## Remove

To undo setup in one checkout, run this block. Check
`git config --local --list` first; the loop also removes values you set
yourself.

```sh
pre-commit uninstall -t pre-commit -t commit-msg -t pre-push
for key in user.name user.email user.signingkey gpg.format commit.gpgsign \
  tag.gpgsign user.useConfigOnly commit.template gpg.ssh.allowedSignersFile; do
  git config --local --unset-all "$key"
done
rm -rf .local/first-commit .local/bin/gitleaks
```

To stop using the hooks, delete the first-commit entry from
`.pre-commit-config.yaml` and commit. When no setup runs, delete setup's
lock file: `rm .git/first-commit-setup.lock`.

To remove the tool, delete `~/.local/share/first-commit`,
`~/.local/bin/first-commit`, the skill folders, and the state folder from
[What install writes](#what-install-writes).

## Learn more

1. [ARCHITECTURE.md](ARCHITECTURE.md): design, security rules, limits,
   output, and policy fields.
2. [verify/features](verify/features/README.md): what the end-to-end tests
   prove.
3. [CONTRIBUTING.md](CONTRIBUTING.md): build, test, and propose a change.
4. [SECURITY.md](SECURITY.md): report a vulnerability.

## License and credits

Copyright 2026 Amrendra Kumar.

Apache-2.0, see [LICENSE](LICENSE). The software is provided as is, without
warranty; see sections 7 and 8 of the license.

first-commit stands on [pre-commit](https://pre-commit.com) and
[Gitleaks](https://github.com/gitleaks/gitleaks), both MIT licensed. pip
installs pre-commit with first-commit, and setup downloads Gitleaks. This
repository contains neither.
