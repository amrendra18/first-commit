# Agent rules

## Read first

1. `README.md`: what the tool does and how a person uses it.
2. `ARCHITECTURE.md`: parts, security rules, contracts, and limits. Read it
   before you change a rule, a public interface, or the structure.
3. `verify/features/`: each journey `scripts/verify` drives, and how it proves it.
4. `CONTRIBUTING.md`: setup, checks, code rules, commit messages, release.
5. `.agents/skills/first-commit/SKILL.md`: adopting first-commit in another
   project.

## Authority

1. Git configuration, hook or dependency installation, staging, commits,
   remotes, publication, and external services need explicit authorization.
2. Stage only approved paths, by name; never use broad staging commands.
3. Preserve unrelated work.

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

## Verification

1. Run `scripts/check full` before every commit.
2. Run `scripts/verify fast` before a pull request, and `full` when setup,
   identity, clone, or hook code changed. Name the evidence folder it prints.
3. After changing the skill, run `scripts/check full`; its tests check the
   skill's links and release steps.
4. Report missing dependencies, residual risks, and platform checks not run.
