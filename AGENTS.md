# Agent rules

## Read first

1. `README.md`: what the tool does and how a person uses it.
2. `ARCHITECTURE.md`: parts, security rules, contracts, and limits. Read it
   before you change a rule, a public interface, or the structure.
3. `verify/features/`: each journey `scripts/verify` drives, and how it proves it.
4. `CONTRIBUTING.md`: setup, checks, code rules, commit messages, release.
5. `skills/first-commit/SKILL.md`: adopting first-commit in another project.
   `bin/first-commit help --format markdown > skills/first-commit/SKILL.md`
   writes it from `src/first_commit/help_text.py`; never edit it by hand.

## Authority

1. Git configuration, hook or dependency installation, staging, commits,
   remotes, publication, and external services need explicit authorization.
2. Stage only approved paths, by name; never use broad staging commands.
3. Preserve unrelated work.
4. To prepare a release, run `scripts/release` and follow the release steps in
   `CONTRIBUTING.md`. Never tag or push; report the printed commands to the
   maintainer, who runs them.

## Engineering

1. Keep every security rule in `ARCHITECTURE.md`. Never weaken checks,
   fixtures, coverage, or signing requirements.
2. Never print matched private content or read private-key contents.
3. Prefer the smallest complete change. Add complexity only for a
   demonstrated need.
4. Use red-green-refactor for behavior changes.
5. Keep each fact in one file and link to it. The README stays short: what,
   why, how, recovery, license. Plain English; a light tone is fine in the
   README's opening, never in commands, warnings, or recovery steps.
6. A behavior change updates the `verify/features/` page that proves it, or
   adds one.

## Invariants

1. The command exits only with 0, 1, 2, or 5, and `ARCHITECTURE.md` lists the
   codes it uses; the checkout launcher too.
   Test: `tests.test_metadata.MetadataTest.test_reference_exit_codes_match_the_command`,
   `tests.test_contract.ToolContractTest.test_exit_codes_are_the_contract_table`,
   and `tests.test_cli_launchers.CliLauncherTest.test_checkout_launcher_refuses_python_older_than_3_11`.
2. `bin/first-commit` answers every probe a caller relies on: help, exit codes,
   JSON errors, and install documents. Test: `tests.test_contract`.
3. The README stays at most 1,500 words after its banner. Test:
   `tests.test_metadata.MetadataTest.test_readme_stays_a_short_entry_point`.

## Verification

1. Run `scripts/check full` before every commit.
2. Run `scripts/verify fast` before a pull request, and `full` when setup,
   identity, clone, or hook code changed. Name the evidence folder it prints.
3. After changing the help (`src/first_commit/arguments.py` or
   `src/first_commit/help_text.py`) or the agent rules, regenerate
   `skills/first-commit/SKILL.md` with the command in "Read first" item 5,
   then run `scripts/check full`; its tests fail when the file differs from
   the help.
4. Report missing dependencies, residual risks, and platform checks not run.
