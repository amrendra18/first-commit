# Changelog

What changed in each release. Each GitHub release names its commit.

## 0.5.0

1. A user-level private-values list applies to every project:
   `~/.config/first-commit/private-values.txt`, or
   `$XDG_CONFIG_HOME/first-commit/private-values.txt` when that is an absolute
   path. It may be a link to a regular file. When its mode is wider than 600,
   first-commit removes group and other access if you own it (a 644 list
   becomes 600, a 744 list becomes 700), and otherwise warns; the check goes
   on either way. The project list keeps its rules. See
   [Private values](ARCHITECTURE.md#private-values).
2. A linked worktree applies the main worktree's project list as well as its
   own. Values only add.
3. `public_github_owner_urls` also allows a private value that is part of the
   owner name, such as `<value>-labs` in `https://github.com/<value>-labs/tool`.
   The whole owner name must be a name GitHub allows: 1 to 39 letters, digits,
   or hyphens. A value with a dot, a space, a slash, or a non-ASCII letter is
   never exempt.
4. `public_github_owner_urls` no longer exempts a value on the line after
   `https://github.com/`; the address and the owner must be on one line.
5. A relative `XDG_CONFIG_HOME` now counts as unset, as the XDG rules say. The
   user-level list and the machine identity file then live under
   `~/.config/first-commit/`.
6. Setup says when the user-level list also applies.
