# Architecture

How first-commit works, the rules it never breaks, and its limits. The code
holds the details; this file holds what the code cannot show. Each journey
that `scripts/verify` tests end to end is described in
[verify/features](verify/features/README.md).

## Principles

1. Generate once. The project owns generated files immediately; setup never
   rewrites or migrates them.
2. Stay small: repository hygiene only. Project tests and builds belong in
   project-owned hooks.
3. One obvious first-use path: preview, confirm, apply, with precise recovery
   steps.
4. Add no new mechanism when composition or an established dependency will do.
5. Secure fixed defaults. Guards cannot be turned off; exceptions are exact,
   bounded, and reasoned.
6. Separate setup from validation.

## Parts

All modules live in `src/first_commit/`.

| Part | Modules | Job |
| --- | --- | --- |
| Commands | `cli.py`, `arguments.py`, `models.py`, `fixes.py`, `reporting.py`, `json_values.py` | Grammar, help, exit codes, fix lines, output |
| Setup | `setup*.py` apart from `setup_trust.py`, `pre_commit_runner.py`, `scanner_install.py`, `starter.py`, `generated_files.py`, `git_settings.py` | Plan, preview, apply, and roll back |
| Identity | `contributor.py`, `machine_identity.py`, `setup_trust.py` | Contributor record, saved identity, opt-in trust |
| Validation | `validation.py`, `candidates.py`, `finding_collector.py`, `characters.py`, `checks/` | Read what to check and run the rules |
| Scanner | `gitleaks*.py` | Run the pinned Gitleaks and apply reviewed exceptions |
| Hooks and history | `hooks.py`, `push_hook_shape.py`, `setup_command.py`, `pushed.py`, `history_messages.py`, `message_scissors.py` | Hook file rules, push range, message and tag scans |
| Policy | `policy.py`, `policy_fields.py` | Read `.repo-policy.json` |
| Safety | `git.py`, `executables.py`, `paths.py`, `private_values.py` | Sanitized Git, program lookup, path confinement, masking |

## How a commit is checked

1. `git commit` runs the pre-commit hook, which calls
   `first-commit hook pre-commit`.
2. The hook reads each staged blob from the Git index and the policy from the
   staged `.repo-policy.json`.
3. It checks one file at a time, runs Gitleaks on the staged diff, and sends
   binary and allowlisted blobs through `gitleaks stdin`.
4. Git runs the commit-msg hook: message format, review sections, Gitleaks and
   privacy rules, identity, and signing settings.
5. `git push` runs the pre-push hook. It scans every local commit the remote
   lacks, their messages, and the annotated tags on them. This scan and the
   history scan of `check` skip the stash (`refs/stash`), because Git pushes
   it only when a push names it.
6. Each finding prints a rule, a path, a fixed summary, and a `fix:` line.

## Security rules

Every command keeps these rules. Changing one is a design change.

1. Only `setup` writes inside the repository or uses the network. `check`,
   `doctor`, and the hooks are read-only and offline; they never run project
   commands or load remote policy. The one exception is the scanner report: a
   private temporary folder outside the repository, removed on every exit path.
2. Commit decisions check the staged bytes from the Git index. The policy
   also comes from the index, so an unstaged edit approves nothing; without a
   staged or committed policy, the working copy's policy applies without its
   exemptions. A commit check also reads the working copy for the
   `@no-commit` marker in generated documents and their proposals, for
   dotenv files that are not ignored, and for local settings: the
   private-values list, the contributor record, and `.gitleaksignore`, which
   must equal its staged copy.
3. Output never holds matched content. `check` and the hooks print each
   private value as `<private value>` in paths, summaries, the repository
   path, and errors. Two exceptions: `doctor` loads no private values, so it
   prints the repository path as it is, and an error before the values load
   (such as Git or curl refused inside the repository) is not masked.
   Private-key contents are never read, and key comments are dropped.
4. Git, curl, and Gitleaks run by absolute path, found in absolute `PATH`
   folders outside the repository. The one copy accepted inside it is
   `.local/bin/gitleaks`: untracked, a regular file, and equal to the pinned
   SHA-256, checked before every scan. In a folder that is not yet a
   repository, setup runs the Git it finds, even one inside the folder, until
   `git init` makes `.git`. Git runs with fixed arguments, no shell, a
   timeout, and an environment without prompts, config injection, object
   replacement, or partial-clone fetches. Relative `PATH` entries are dropped.
5. Paths are normalized and confined before reading. Reads, file counts,
   findings, and messages are bounded; see [Limits](#limits).
6. Hooks are pinned to a 40-character commit SHA. Setup refuses a tag, because
   a tag can move, and names `pre-commit autoupdate --freeze`.
7. Gitleaks 8.30.0 is pinned by version; a downloaded or `.local/bin` copy
   also by SHA-256. It is calibrated before use and run with redaction.
   Repository files cannot weaken it. `gitleaks stdin` runs in an empty folder
   outside the repository, so no ignore file applies to a message.
8. Setup holds a repository lock. After a failure, Ctrl-C, SIGTERM, or SIGHUP
   it rolls back what it created, except caches and installer effects, and
   removes only a `.git` it created. The lock file
   `.git/first-commit-setup.lock` stays, so a setup that opened the old file
   cannot run beside a later one.
9. Trust is opt-in. Only `--trust-self` (`FIRST_COMMIT_TRUST_SELF=1` on the
   clone setup hook) writes `.local/first-commit/allowed-signers` with your own
   key. An existing file or setting is kept, never rewritten. An existing file
   must be untracked, and each line must hold your key with exact principals
   (no `*`, `?`, `!`, or `"`) and no `cert-authority`; otherwise setup stops.
   `doctor` and `check` report a tracked file as an error. No command verifies
   a signature.
10. The commit-msg hook compares the author and committer emails Git will
    record, including `--author`, `GIT_AUTHOR_*`, `git -c` settings, and the
    global or system configuration file that `GIT_CONFIG_GLOBAL` or
    `GIT_CONFIG_SYSTEM` names, with the contributor record.
11. The policy accepts version 1 only and refuses unknown fields. No field
    turns off a rule. The required documents are exactly `README.md` and
    `AGENTS.md`.
12. Setup's whole dependency tree is pinned to exact versions, in the `setup`
    extra and in the clone setup hook. A test keeps the two lists equal.

## Commands

| Command | What it does |
| --- | --- |
| `first-commit setup` | Plans and applies the one-time setup |
| `first-commit check` | Checks the working tree, the staged files, and the whole history |
| `first-commit doctor` | Checks the identity, signing, hooks, and scanner of this checkout |
| `first-commit version` | Prints the installed version; `--version` does the same |
| `first-commit hook <stage>` | Runs one Git hook stage; the installed Git hooks call it |

`setup`, `check`, and `doctor` take `--root <folder>` and `--format json`. In a
clone, pre-commit runs them from the pinned hooks: `first-commit-setup`,
`first-commit-check`, and `first-commit-doctor`, all at `--hook-stage manual`.
`--all-files` lets `check` see the working tree. A hook file without the check
and doctor hooks can add `- id: first-commit-check` and
`- id: first-commit-doctor` under the first-commit repository, with a `rev`
that has them.

## Setup

### Files setup creates

Setup creates whichever of these are missing: `README.md`, `AGENTS.md`,
`.gitignore`, `.editorconfig`, `.gitattributes`, `.gitmessage`,
`.pre-commit-config.yaml`, and `.repo-policy.json`. It creates documents only
while `.repo-policy.json` does not exist. An existing document gets a
`*.first-commit-proposal.md` to merge by hand. An existing `.editorconfig` or
`.gitattributes` is kept. Your identity stays in the ignored
`.local/first-commit/contributor.json`.

### Setup options

Give the same options to `setup --dry-run` and to `setup`.

| Option | Effect |
| --- | --- |
| `--dry-run` | Prints the plan and changes nothing. Runs no existing Gitleaks and checks no hook environment |
| `--yes` | Applies the plan without asking |
| `--docs full` | Also creates `PRD.md`, `CONTRIBUTING.md`, and `SECURITY.md` |
| `--license apache-2.0` | Also creates `LICENSE`, even on a later run |
| `--transport ssh` | New hooks use the SSH address instead of HTTPS |
| `--revision <sha>` | The hooks' commit, for an install without Git revision metadata; a project's own hook file supplies it otherwise |
| `--trust-self` | Trusts your own key, as security rule 9 says |

### Identity sources

Setup takes your identity from the checkout's contributor record, then the
saved identity file, then `FIRST_COMMIT_AUTHOR_NAME`,
`FIRST_COMMIT_AUTHOR_EMAIL`, and `FIRST_COMMIT_SIGNING_KEY`. It asks only when
none exists, and only in a terminal; the clone setup hook never asks.

1. The plan's `Identity:` line names the identity and where it came from.
2. Variables that name another identity than the record or the file stop
   setup, and the error names both.
3. The signing-key path must name a readable SSH public-key file ending in
   `.pub`.
4. Without a terminal, setup applies only with `--yes` or when the checkout
   already has its record; otherwise it prints the plan and exits 2.
5. After setup succeeds, it saves the identity to
   `~/.config/first-commit/identity.json`, or to
   `$XDG_CONFIG_HOME/first-commit/identity.json` when `XDG_CONFIG_HOME` is
   set. `FIRST_COMMIT_IDENTITY_FILE` chooses another file. The checkout's
   record still wins over any identity file.

## Output

Exit codes: `0` pass, `1` finding, `2` configuration or input (invalid
arguments, identity input, a cancelled setup), `3` dependency, `4` Git or file
access.

1. Ctrl-C exits 2 with `error: first-commit stopped on Ctrl-C.` When setup has
   already changed something, it undoes the change first and prints
   `error: Setup stopped on Ctrl-C; its changes were undone.`
2. Findings are sorted by path, line, and rule. Each is followed by a `fix:`
   line.
3. A fix line or `Next action:` line that names setup names the setup hook
   command when `.pre-commit-config.yaml` declares `first-commit-setup`, and
   `first-commit setup` otherwise.
4. When the repository root differs from the starting folder, human output
   starts with `Repository: <root>`.
5. `--format json` carries `schema_version`, `tool_version`, and each
   finding's `fix`. `check`, `doctor`, and the hooks also carry `repository`,
   the absolute root path.
6. When Gitleaks is missing or fails its check, `doctor` prints `FAIL doctor`
   with `secrets.scanner-unavailable` and exits 1; `check` and the hooks exit
   3.

## Commit messages

The header is `<type>(<scope>)!: <subject>`; the scope and `!` are optional.
`<type>` is one of `feat`, `fix`, `docs`, `style`, `refactor`, `test`,
`build`, `chore`, `perf`, `ci`, `deps`, `revert`, `security`, `infra`,
`release`. The body holds `Why:`, `Changes:`, `Test Plan:`, and `Risks:`, in
that order, unless the policy sets `commit_body_sections` to `false`.

Text below a scissors line (`# ------------------------ >8 ------------------------`)
only warns, because `git commit -v` puts the staged diff there and Git removes
it. A hand-written scissors line keeps that text unless `-v` is used, so the
pre-push hook blocks a finding there. With a `git -c` setting or a
configuration file named in the environment, the hook may also cut at a
scissors line Git keeps; the pre-push hook blocks a finding there too.

Git's comment lines also only warn: lines that start with `#`, or with
`core.commentChar` when set, or with `core.commentString` on Git 2.45 or
later. Git adds them, such as `# On branch <name>`, to a message it opens in
an editor, and removes them. The hook treats them as removed only when an
editor ran and `commit.cleanup` is unset, `default`, or `strip`. Git sets
`GIT_EDITOR` to `:` for the hook when no editor ran, as with `-m` or `-F`, so
then they block. They also block when `commit.cleanup` is `verbatim`,
`whitespace`, or `scissors`.
The hook cannot read configuration from `git -c` or from other files named in
the environment, because its Git calls drop `GIT_CONFIG_*` (security rule 4).
So when `GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_COUNT`, `GIT_CONFIG_GLOBAL`,
`GIT_CONFIG_SYSTEM`, `GIT_CONFIG_NOSYSTEM`, or `GIT_CONFIG` is set, it treats
comment lines as recorded and blocks them. `--cleanup` on the command line
stays invisible to the hook, and so does `-v`; when either keeps a finding, the
pre-push hook blocks it in the recorded message.
The hook may also block a line Git removes, which is the safe direction. That
happens when an editor ran but the user exported `GIT_EDITOR=:`, or when
`strip` cleanup (from `--cleanup` or the configuration) comes with `-m` or
`-F`.
With `core.commentChar=auto`, no line counts as a comment, so every line
blocks.

### Messages already pushed

1. `check` warns about a message finding in a commit a configured remote
   already has. If it is a secret, revoke it with its provider now. Rewording
   it needs a history rewrite and a force push, so agree on that with everyone
   who shares the branch.
2. A message finding in a commit no remote has blocks. The pre-push hook never
   warns; it blocks.
3. A tag message finding always blocks `check`. Delete the tag with
   `git tag -d`; if you pushed it, revoke any secret and run
   `git push --delete <remote> <tag>`. Then tag again.

## Project policy file

`.repo-policy.json` records project facts. The smallest one is
`{"schema_version": 1}`. Commit checks read the staged copy, so stage an edit
before you commit. See the [example policy](examples/repo-policy.json).

| Field | Meaning |
| --- | --- |
| `public_emails` | Up to 32 addresses allowed in content. `example.com`, `example.net`, `example.org`, `.invalid`, and `.test` always pass |
| `commit_body_sections` | `false` requires only the message header |
| `public_environment_files` | Public dotenv paths, with reasons |
| `forbidden_paths` | Paths to block: `match` (`exact`, `prefix`, `suffix`), `value`, `reason` |
| `private_literal_exceptions` | `path`, `line`, `sha256` of the exact line, `reason`. Allows one copy of that line anywhere in the file |
| `privacy_detector_exceptions` | The same plus one `privacy.*` `rule`. For `privacy.private-key`, `sha256` hashes the whole file |
| `public_github_owner_urls` | `true` allows a private value only as the owner in a GitHub URL; off by default |
| `immutable_vendor_files` | Up to 10,000 exact paths under `vendor/`, whole-file `sha256`, `reason`. Unchanged regular files skip email, home-path, trailing-whitespace, and final-newline checks only; symlinks are never exempt. A checksum does not verify the source, so review each file first, and stage the policy before the vendor files |

Each `reason` is one line of at most 500 characters. An error names the entry
it refuses, such as `forbidden_paths[2].reason`. No exception approves a file
name that holds a private value.

A line digest hashes the line's bytes without its newline, so `echo` piped to
`shasum` gives a different value. For line 12 of a file (on Linux,
`sha256sum` also works):

```sh
awk 'NR == 12 { printf "%s", $0 }' path/to/file | shasum -a 256
```

## Hook file rules

A project may keep its own `.pre-commit-config.yaml`. Setup and `doctor` then
require:

1. `first-commit-staged`, `first-commit-message`, and `first-commit-push`,
   each declared once, from the first-commit repository at the installed
   commit, unchanged apart from `stages`. `doctor` warns when one breaks this
   (`hooks.staged-check`, `hooks.message-check`, `hooks.push-check`).
2. When hooks are missing and setup knows the hook revision, it writes the
   block to `.pre-commit-config.first-commit-proposal.yaml` and changes
   nothing else. Merge it, delete the proposal, and run setup again. A dry run
   writes nothing, and without a revision the fix line says to rerun with
   `--revision`. A duplicate or changed
   hook stops setup with `The first-commit hook declaration conflicts.`, and a
   different `rev` stops it with an error that names both revisions.
3. In place of `first-commit-push`, a project hook may run the push checks. It
   needs `language: system`, `always_run: true`, `pass_filenames: false`, no
   `files`, `types`, `types_or`, or `exclude`, `pre-push` in `stages`, and
   exactly the entry `first-commit hook pre-push`, optionally followed by
   `--format human` or `--format json`. A wrapper script does not count, and
   neither does `first-commit check`.
4. A `repo: local` hook keeps the entry `first-commit hook <stage>`,
   `language: system`, `always_run: true`, and only its own stage, with
   `pass_filenames` true only for the message hook.
5. When the shipped push hook's `rev` is not the installed commit, `doctor`
   warns (`hooks.push-revision`). Set `rev` to the commit setup names.
6. Guidance names the setup hook only for a block-style item whose first key
   is its id (`- id: first-commit-setup`); any other layout makes it name
   `first-commit setup`.

pre-commit 3.8.0's old stage names `commit`, `merge-commit`, and `push` count
as their new names.

Each installed Git hook must be a regular file. `doctor` reports a symlinked
hook as `hooks.invalid` wherever it points, inside `.git` too, because Git
runs whatever the link names.

## Remotes

1. `doctor` warns (`hooks.nested-remote`) when one remote's name is another's
   plus `/`, such as `origin/x` next to `origin`. pre-commit then runs no
   pre-push hook for a new branch the nested remote already has. Rename it,
   for example `git remote rename origin/x origin-x`.
2. `doctor` warns (`hooks.remote-case`) for names that differ only in letter
   case, such as `origin` and `ORIGIN`. They share refs on a case-insensitive
   disk; rename one. The warning also appears on Linux, because the same
   configuration may move to macOS.

## Limits

The policy cannot change these limits.

| Limit | Value | Over the limit |
| --- | --- | --- |
| Bytes per file | 10 MiB | A `files.too-large` finding; the bytes are not checked. A file that grows past it during a run gives exit 4 |
| Paths per scope | 10,000 | Exit 4, `File count exceeds the limit of 10,000 paths.` |
| Findings per scope | 1,000 | Later findings are not shown |
| Commit message | 1 MiB | Exit 4. In history and pre-push scans, a commit or tag object over the limit also gives exit 4 |
| Policy file | 1 MiB | Exit 2 |
| One Git command, or one blob from `git cat-file --batch` | 120 seconds | Exit 4, `Git timed out.` |
| One Gitleaks scan | 120 seconds; 600 for a full history scan | Exit 3, `Gitleaks timed out after <N> seconds.` |

The 10,000-path limit is deliberate: first-commit targets new and small
projects.

## Gitleaks exceptions

A reviewed Gitleaks false positive goes in `.gitleaksignore` at the
repository root. Each fingerprint needs a `# reason:` line and a
`# file-sha256:` line directly above it, in either order:

```text
# reason: Synthetic token in a test fixture; it was never issued.
# file-sha256: 3f5a...64 hex digits...
tests/fixtures/token.txt:github-pat:3
```

1. Get the fingerprint:
   `.local/bin/gitleaks git --pre-commit --staged --redact --verbose` for
   staged content, or `.local/bin/gitleaks git --redact --verbose` for
   history. Staged content gives `<path>:<rule>:<line>`; a history commit
   gives `<commit>:<path>:<rule>:<line>`.
2. Get the whole file's digest: `git show :0:<path> | shasum -a 256`, or
   `git show <commit>:<path>` for a commit.
3. Stage it with `git add .gitleaksignore`.

The digest covers the whole file because some rules match across lines: a
digest of one line would fit any secret written below it. Any change to the
file needs a new review.

The file must be tracked and equal to its staged copy. A blank line ends a
comment block. An entry past the end of its file is refused, and so is a
line with a control character other than tab, or a space character other
than space and tab. History and pre-push
scans check each entry in every scanned commit that changes its file; a
different version stops the scan unless that commit has its own entry. A file
version over 10 MiB stops the check too, because its digest is not read. An
entry never applies to a commit message. The file holds at most 1,000
fingerprints and 1 MiB. The checks read at most 10,000 file versions and 256
MiB, and a bad file stops `check` and the hooks with exit 2.

## Threats and known gaps

| Threat | Control | Remaining risk |
| --- | --- | --- |
| Secret in a commit | Gitleaks on staged bytes, messages, history, and tags; privacy rules | Novel or obfuscated secrets |
| Working copy differs from index | Check index blobs | None known |
| Output leaks a match | Fixed summaries | Paths and line numbers stay visible |
| Hostile hook source | Fixed address, pinned commit | Trust in that commit |
| Bypassed hooks | None locally | Needs server rules |
| Forged authorship | Signing settings, checked author and committer emails, opt-in self-trust | No command verifies signatures |
| Resource exhaustion | Read, count, and finding limits; one file in memory (at most 256 MiB for a 10 MiB file) | Git's own memory and time |
| Hostile scanner or exceptions | Pinned digest, lookup outside the repository, whole-file digests | Trust in the reviewed file versions |
| Hostile setup dependency | Exact pins, each release at least 21 days old when pinned | No hashes: package metadata cannot hold them, and pip's hash mode refuses the `git+` install |

Known gaps:

1. History and pre-push scans read diffs, so they miss a secret in a binary
   or allowlisted file committed with `--no-verify`. Diffs use the working
   copy's `.gitattributes`, and a local `diff.<driver>.textconv` changes what
   Gitleaks reads unnoticed.
2. The pre-push hook reads only the tags of the commits a push adds. Run
   `first-commit check` before you push tags.
3. A commit pushed by raw id as a second ref, held by no branch, is not
   scanned by that push; `check` and the next branch push scan it.
4. A stale or hand-made ref of a configured remote is trusted: the pre-push
   scan leaves its commits out, and `check` only warns about their messages.
5. The hooks pre-commit installs run with your own `PATH`. An absolute `PATH`
   entry inside the repository still reaches programs other than Git, curl,
   and Gitleaks, such as `ssh`.
6. A Gitleaks found on `PATH` is trusted as installed; only its version and
   calibration are checked.
7. Gitleaks does not decode UTF-16. The privacy rules decode it only after a
   byte-order mark.
8. On macOS with Python 3.11 or 3.12, processes started by
   `git cat-file --batch` may outlive it.

## How it is tested

1. Unit tests and a coverage gate, run by `scripts/check`;
   [CONTRIBUTING.md](CONTRIBUTING.md) lists the commands and thresholds.
2. `scripts/verify` drives each journey in
   [verify/features](verify/features/README.md) with real setup, commits,
   hooks, and clones. `scripts/verify control` proves it catches planted
   defects.
3. CI runs both on Linux and macOS with Python 3.11 to 3.14.
4. Tested versions: pre-commit 3.8.0 and Git 2.39.5 on macOS. Newer
   pre-commit releases are accepted but not tested.
5. Not automated: fuzzing, mutation tests, reproducible builds, provenance,
   and a download from GitHub over HTTPS.
