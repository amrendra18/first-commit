---
name: first-commit
description: Use first-commit when a Git project, new or existing, needs its hooks, signing, and starter files, or when staged files, commit messages, or pushes need a check for secrets and private data before they leave the machine.
---

# first-commit

Sets up a project once, then checks staged bytes, commit messages, and pushes for secrets and private data. Only setup writes in a project.

Exit codes: 0 done; 1 a finding or not done (read the error); 2 bad call (unknown verb or flag, invalid or missing input); 5 held for a person's yes.

## Rules for agents

1. Preview first with `first-commit setup --dry-run`. Review each conflict and each `@no-commit` proposal by hand; never overwrite a project file to clear one.
2. Run setup only when the user allows Git initialization, local Git settings, dependency installation, and hooks.
3. Setup writes each starter file once; the project owns it from then on.
4. After setup, run `first-commit doctor` and `first-commit check`.
5. Never stage, commit, change remotes, or publish without the user's permission.
6. `first-commit doctor` and `first-commit check` are read-only, except that check and the hooks remove group and other access from the user's private-values list when the user owns it.
7. Keep the contributor identity in the ignored `.local/first-commit/contributor.json`.
8. Never read private-key contents or print matched private content.
9. Put the project's own tests and builds in the project's own hooks.
10. Never add a switch or setting that turns a check off.

## first-commit version

Print the installed first-commit version.

- Writes: nothing.
- Before: nothing.
- Effects: reads
- Exit codes: 0 done; 1 a finding or not done (read the error); 2 bad call (unknown verb or flag, invalid or missing input).

Options:

- `-h, --help`: show this help message and exit
- `--format {human,json}`: Output: human text, or one JSON object (default: human).

## first-commit check

Run the doctor, working-tree, staged, and history checks (read-only).

- Writes: nothing in the repository. It removes group and other access from ~/.config/first-commit/private-values.txt (or the same file under $XDG_CONFIG_HOME) when you own that file. The scanner writes its report to a private temporary folder, removed on exit.
- Before: run it inside a Git repository with a .repo-policy.json file, and Gitleaks 8.30.0 on PATH or at `<repository>/.local/bin/gitleaks`; setup prepares both.
- Effects: reads, writes own state
- Exit codes: 0 done; 1 a finding or not done (read the error); 2 bad call (unknown verb or flag, invalid or missing input).

Options:

- `-h, --help`: show this help message and exit
- `--root FOLDER`: A folder inside the Git repository (default: the current folder).
- `--format {human,json}`: Output: human text, or one JSON object (default: human).
- `--new-only`: Limit the history check to commits no configured remote holds, as its remote-tracking branches show (with no remote, the whole history).

## first-commit doctor

Check the local identity, signing, hooks, and scanner (read-only).

- Writes: nothing in the repository or ~/.config/first-commit/. Its Gitleaks check runs in a private temporary folder, removed on exit.
- Before: run it inside a Git repository that has a .repo-policy.json file.
- Effects: reads
- Exit codes: 0 done; 1 a finding or not done (read the error); 2 bad call (unknown verb or flag, invalid or missing input).

Options:

- `-h, --help`: show this help message and exit
- `--root FOLDER`: A folder inside the Git repository (default: the current folder).
- `--format {human,json}`: Output: human text, or one JSON object (default: human).

## first-commit setup

Preview or apply the one-time setup: files, Git settings, hooks, and Gitleaks.

- Writes: the missing files in `<repository>/`, the --root folder, such as README.md, AGENTS.md, .gitignore, .pre-commit-config.yaml, and .repo-policy.json, or a `*.first-commit-proposal.md` beside a document you already have; `<repository>/.git/` (git init when it has none, local Git settings, and hooks); `<repository>/.local/first-commit/`; `<repository>/.local/bin/gitleaks` when no Gitleaks is found; and ~/.config/first-commit/identity.json (or the same file under $XDG_CONFIG_HOME) when it does not exist. pre-commit fills its cache, ~/.cache/pre-commit/. A Gitleaks download and the scanner use private temporary folders, removed on exit. --dry-run writes nothing.
- Before: an identity (a public Git author name and email, and an SSH public key) from `<repository>/.local/first-commit/contributor.json`, the identity file, or the FIRST_COMMIT_AUTHOR_NAME, FIRST_COMMIT_AUTHOR_EMAIL, and FIRST_COMMIT_SIGNING_KEY variables, or typed in a terminal. Git and pre-commit 3.2.0 or newer on PATH, and network access. Without a terminal, --yes applies the plan.
- Effects: writes repository, writes own state, network github.com, network pypi.org
- Exit codes: 0 done; 1 a finding or not done (read the error); 2 bad call (unknown verb or flag, invalid or missing input); 5 held for a person's yes.

Options:

- `-h, --help`: show this help message and exit
- `--root FOLDER`: The project folder; setup creates a Git repository there when it has none (default: the current folder).
- `--format {human,json}`: Output: human text, or one JSON object (default: human).
- `--revision SHA`: The 40-character commit the hooks pin (default: the commit this install was built from, or the rev in an existing .pre-commit-config.yaml).
- `--transport {ssh,https}`: The address new hooks use (default: https). The SSH address needs a GitHub SSH key.
- `--hooks {pinned,installed}`: pinned: hooks from the first-commit repository at one commit, which pre-commit installs; installed: hooks that run the first-commit command on PATH, with no --revision or --transport (default: pinned).
- `--dry-run`: Print the plan only: write, fetch, and run nothing.
- `--license {none,apache-2.0}`: The license file to create (default: none).
- `--docs {core,full}`: core creates README.md and AGENTS.md; full adds PRD.md, CONTRIBUTING.md, and SECURITY.md (default: core).
- `--trust-self`: Trust your own signing key in this checkout: write .local/first-commit/allowed-signers and set gpg.ssh.allowedSignersFile.
- `--yes`: Apply the plan without asking first.

## first-commit hook

Entry points the installed Git hooks run; not for direct use.

- Writes: what the stage writes; first-commit hook STAGE --help names it.
- Before: Git and pre-commit run these stages from the hooks setup installed.
- Effects: reads, writes own state, writes repository, network github.com, network pypi.org
- Exit codes: 0 done; 1 a finding or not done (read the error); 2 bad call (unknown verb or flag, invalid or missing input).

Options:

- `-h, --help`: show this help message and exit

## first-commit hook pre-commit

Check the staged bytes.

- Writes: nothing in the repository. It removes group and other access from ~/.config/first-commit/private-values.txt (or the same file under $XDG_CONFIG_HOME) when you own that file. The scanner writes its report to a private temporary folder, removed on exit.
- Before: Git runs it from the pre-commit hook, inside a Git repository with a .repo-policy.json file, and Gitleaks 8.30.0 on PATH or at `<repository>/.local/bin/gitleaks`; setup prepares both.
- Effects: reads, writes own state
- Exit codes: 0 done; 1 a finding or not done (read the error); 2 bad call (unknown verb or flag, invalid or missing input).

Options:

- `-h, --help`: show this help message and exit
- `--root FOLDER`: A folder inside the Git repository (default: the current folder).
- `--format {human,json}`: Output: human text, or one JSON object (default: human).

## first-commit hook commit-msg

Check the commit message that MESSAGE_FILE holds.

- Writes: nothing in the repository. It removes group and other access from ~/.config/first-commit/private-values.txt (or the same file under $XDG_CONFIG_HOME) when you own that file. The scanner writes its report to a private temporary folder, removed on exit.
- Before: Git runs it from the commit-msg hook with MESSAGE_FILE, inside a Git repository with a .repo-policy.json file, and Gitleaks 8.30.0 on PATH or at `<repository>/.local/bin/gitleaks`; setup prepares both.
- Effects: reads, writes own state
- Exit codes: 0 done; 1 a finding or not done (read the error); 2 bad call (unknown verb or flag, invalid or missing input).

Options:

- `-h, --help`: show this help message and exit
- `MESSAGE_FILE`: The file Git passes to the commit-msg hook.
- `--root FOLDER`: A folder inside the Git repository (default: the current folder).
- `--format {human,json}`: Output: human text, or one JSON object (default: human).

## first-commit hook pre-push

Check readiness, the working tree, staged bytes, and the commits a push sends.

- Writes: nothing in the repository. It removes group and other access from ~/.config/first-commit/private-values.txt (or the same file under $XDG_CONFIG_HOME) when you own that file. The scanner writes its report to a private temporary folder, removed on exit.
- Before: pre-commit runs it from the pre-push hook and says what the push sends, inside a Git repository with a .repo-policy.json file, and Gitleaks 8.30.0 on PATH or at `<repository>/.local/bin/gitleaks`; setup prepares both.
- Effects: reads, writes own state
- Exit codes: 0 done; 1 a finding or not done (read the error); 2 bad call (unknown verb or flag, invalid or missing input).

Options:

- `-h, --help`: show this help message and exit
- `--root FOLDER`: A folder inside the Git repository (default: the current folder).
- `--format {human,json}`: Output: human text, or one JSON object (default: human).

## first-commit hook setup

Set up a clone from its pinned hooks; pre-commit runs it at the manual stage.

- Writes: the missing files in `<repository>/`, the --root folder, such as README.md, AGENTS.md, .gitignore, .pre-commit-config.yaml, and .repo-policy.json, or a `*.first-commit-proposal.md` beside a document you already have; `<repository>/.git/` (git init when it has none, local Git settings, and hooks); `<repository>/.local/first-commit/`; `<repository>/.local/bin/gitleaks` when no Gitleaks is found; and ~/.config/first-commit/identity.json (or the same file under $XDG_CONFIG_HOME) when it does not exist. pre-commit fills its cache, ~/.cache/pre-commit/. A Gitleaks download and the scanner use private temporary folders, removed on exit.
- Before: a clone whose .pre-commit-config.yaml pins the first-commit hooks; pre-commit runs it from the first-commit-setup hook at the manual stage. The identity comes from `<repository>/.local/first-commit/contributor.json`, the identity file, or the FIRST_COMMIT_AUTHOR_NAME, FIRST_COMMIT_AUTHOR_EMAIL, and FIRST_COMMIT_SIGNING_KEY variables; it never asks. Network access.
- Effects: writes repository, writes own state, network github.com, network pypi.org
- Exit codes: 0 done; 1 a finding or not done (read the error); 2 bad call (unknown verb or flag, invalid or missing input).

Options:

- `-h, --help`: show this help message and exit
- `--root FOLDER`: A folder inside the Git repository (default: the current folder).
- `--format {human,json}`: Output: human text, or one JSON object (default: human).

## first-commit help

Print the help, or all of it as JSON or Markdown.

- Writes: nothing.
- Before: nothing.
- Effects: reads
- Exit codes: 0 done; 1 a finding or not done (read the error); 2 bad call (unknown verb or flag, invalid or missing input).

Options:

- `-h, --help`: show this help message and exit
- `--format {human,json,markdown}`: Output: human text, one JSON object, or Markdown with front matter (default: human).
