# Feature map

The features `scripts/verify` drives, one file each. Every file says what the feature is, how
a person reaches it, how the harness drives it, and the end state that proves it works. Each
file links to the README or ARCHITECTURE section it proves, and a test keeps this table equal
to the harness's feature list in `scripts/verify_lib/cli.py`. The `github` feature is skipped
unless the product files match GitHub main.

The harness removes every folder that holds a `first-commit` command from the `PATH` it
inherits. A feature that runs `first-commit` puts the tool it tests on `PATH` itself or
starts it by its full path, so no other installed copy can answer. `summary.md` lists each
removed folder once, on the line `PATH folders removed for holding first-commit`. When a
removed folder also holds `git`, `ssh`, `ssh-add`, `ssh-agent`, or `ssh-keygen`, the harness
names the folder and exits 3 before any work.

| # | Feature | File | Level | Needs first |
| --- | --- | --- | --- | --- |
| 1 | Setup in an empty folder | [setup.md](setup.md) | fast | none |
| 2 | The first signed commit | [commit.md](commit.md) | fast | setup |
| 3 | A private value blocks a commit | [privacy.md](privacy.md) | fast | setup, commit |
| 4 | A bad message blocks a commit | [message.md](message.md) | fast | setup, commit |
| 5 | The pre-push hook | [push.md](push.md) | fast | setup, commit |
| 6 | A clone set up through pre-commit | [clone-guided.md](clone-guided.md) | fast | setup, commit |
| 7 | A control character blocks a commit | [control-character.md](control-character.md) | fast | setup, commit |
| 8 | Setup does what the dry run announced | [preview-matches-apply.md](preview-matches-apply.md) | fast | none |
| 9 | A setup fix line works without the setup hook | [fix-line-works.md](fix-line-works.md) | fast | setup |
| 10 | The README first run in a terminal | [first-run.md](first-run.md) | fast | none |
| 11 | The printed trust command works in a clone | [clone-trust.md](clone-trust.md) | fast | setup, commit |
| 12 | Commits that name their files | [commit-all.md](commit-all.md) | fast | setup, commit |
| 13 | A clone that reuses the saved identity | [clone-saved.md](clone-saved.md) | full | setup, commit, clone-guided |
| 14 | A clone with a chosen identity file | [clone-chosen-path.md](clone-chosen-path.md) | full | setup, commit |
| 15 | Remove first-commit from a checkout | [remove.md](remove.md) | full | setup, commit |
| 16 | Setup from the real GitHub repository | [github.md](github.md) | full | none |

`scripts/verify --feature NAME` runs NAME and the features it needs first. When setup or the
first commit fails, later features are reported as skipped ("not reached").

`scripts/verify control` runs once per planted defect, each planted in the snapshot, and
expects the feature it breaks to fail for that defect's reason:

1. `private-literal`: the private-literal check finds nothing. The privacy feature must fail
   because the commit with the private value exited 0.
2. `unsigned-commits`: setup leaves `commit.gpgsign` unset and the commit hook stops
   requiring it. The commit feature must fail because the commit carries no SSH signature.

It prints `control: caught` or `control: missed` per plant, and exits 0 when both are
caught.
