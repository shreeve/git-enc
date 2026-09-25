# Changelog

## v0.2.0

### Upgrading from v0.1.x

- **Run `git enc init` again in every clone.** It installs new hooks and
  the merge driver; `git enc status` says when a clone still needs it.
- **`git enc update` exit codes:** 3 when it leaves a conflict for you
  (`git enc update && ./app` now stops there), 4 when a key is missing.
- **Two git-enc blocks may no longer share a key.** Merge them into one.
- **pre-push refuses commits that carry a secret's plaintext**, such as one
  committed with `--no-verify`.

### New

- `git enc rekey OLD NEW` rotates a key (when someone leaves), and
  `git enc rekey OLD NEW FILE…` re-encrypts a secret moved to another
  block. It re-encrypts what is committed, never your working copy.
- Secrets merge by their plaintext inside `git pull` and GitHub Desktop:
  edits to different lines merge by themselves. A merge that takes one
  side's `.enc` whole while both sides changed it is refused at commit.
- `git enc verify [RANGE]` checks a repository for CI with no key: no
  plaintext committed (also in RANGE's commits), every `.enc` encrypted,
  `.gitignore` sound. The README has a GitHub Actions workflow.
- `git config enc.skipKeys ops` quiets the blocks of a key you don't hold
  on purpose (another group's secrets, or a CI job's).
- `git enc update` warns when a secret would go back to an earlier value,
  which is how a rollback by someone without the key looks.

### Security

- `.gitignore`, which anyone who can push may edit, can no longer redirect
  a secret to another key: a block's key must match a key file by name and
  fingerprint, and ciphertext is only trusted when its block's key opens it.
- The pre-commit hook asks git which staged files the block lines match,
  refuses deleting a declared `.enc`, and refuses a plaintext copied over
  one.
- A plaintext that cannot be read is never overwritten; a deleted `.enc`
  is never shown as clean; Ctrl-C removes the lock and any temporary
  plaintext.
- `GIT_LITERAL_PATHSPECS` and similar variables no longer disable the
  pre-commit hook.

### Faster, clearer

- `git enc status` starts 7 git processes instead of 16, in about half the
  time; a branch switch that changes no secret costs one `git diff-tree`.
- A refused `add` changes nothing; every plaintext `update` replaces is
  backed up; `status` never waits for another git-enc.
- A `.env`-style pattern no longer claims files inside ignored directories
  such as `node_modules/`.
- git's own error is shown ("bad config line…") instead of "not in a git
  repository"; git older than 2.31 says so.
- Messages say what to run next; `--help` works after any command.
- Optional: `git log -p F.enc` can show secrets decrypted (see README).

## v0.1.1

- Accept a `.enc` re-included by a `!` rule after a broad one such as
  `.env*`, and suggest adding `!*.enc`.

## v0.1.0

- First release.
