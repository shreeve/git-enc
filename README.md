# git-enc

Keep secrets in git, encrypted, and declare them where you already
declare what git should not track: `.gitignore`.

```gitignore
.DS_Store
*.log

# git-enc: team 3f9a1c2e
.env
config/secrets.yml
# git-enc: end
```

Git ignores `.env`, so the plaintext can never be committed by accident,
whether or not anyone has git-enc installed. Beside it, git-enc keeps
`.env.enc`, an encrypted copy that is committed, pushed, and pulled like any
other file. Anyone with the key gets the plaintext; everyone else sees an
unreadable binary.

Nothing happens behind your back. You say when to encrypt your edits and
when to take your team's:

```console
$ git enc status
key team (3f9a1c2e): ok

Edited here (git enc add <file>):
  modified:  .env

Changed in git (git enc update):
  outdated:  config/secrets.yml

$ git enc add .env            # encrypt and stage .env.enc
$ git enc update              # bring config/secrets.yml up to date
$ git commit -m "Rotate the API key"
```

## Install

```sh
go install github.com/shreeve/git-enc/cmd/git-enc@latest
```

This puts `git-enc` on your PATH, so git runs it as `git enc`. It is one
self-contained binary for macOS, Linux and Windows. (A Homebrew formula is
coming.)

## Start using it in a repository

```sh
git enc key new team            # create a key named "team"
git enc add --key team .env     # declare .env in .gitignore, encrypt it, stage .env.enc
git enc init                    # install the hooks in this clone
git commit -m "Encrypt .env"
```

If `.env` was already committed in plain text, `git enc add` stops tracking
it and warns you: old commits still contain the old value, so change that
secret.

Share the key with your team **once**, through a password manager or another
private channel:

```sh
git enc key show team | pbcopy
```

## Join a repository that uses it

```sh
git clone …
git enc key add team            # paste the key, then Ctrl-D
git enc init                    # hooks, and decrypts every secret you have a key for
```

## Everyday use

| Command | What it does |
|---|---|
| `git enc status` | What you edited, what changed in git, what needs attention |
| `git enc add FILE…` / `--all` | Encrypt your edits and stage the `.enc` files |
| `git enc update [FILE…]` | Bring your copies up to date; never loses an edit |
| `git enc diff [FILE…]` | Your edits against the committed version |
| `git enc merge [FILE…]` | Resolve a git merge or rebase conflict on a secret |
| `git enc check` | Quiet, for scripts: exit 3 if anything needs doing |

Exit codes: 0 success, 1 error, 2 usage, 3 needs attention (a secret must be
added, updated or merged first), 4 a key is missing.

Put `git enc check` in the script that starts your app (`bin/dev`, a
`predev` script, a Makefile), and a forgotten `git enc update` or
`git enc add` shows up exactly when it matters.

### What each state means

| State | Meaning | Next step |
|---|---|---|
| `clean` | Your copy matches the committed version | — |
| `modified` / `new` | You edited it (or it isn't encrypted yet) | `git enc add` |
| `outdated` / `missing` | Someone committed a newer version | `git enc update` |
| `conflict` | You edited it *and* it changed in git | `git enc update` |
| `diverged` | It matches no committed version and git-enc has no record to tell why | `git enc update` |
| `merging` | Git has a merge or rebase conflict on the `.enc` | `git enc merge` |
| `no-key` | You don't have the key (or have a different key with that name) | `git enc key add` |

### It never loses your work

- **`update` never overwrites an edit.** It replaces a copy only when git's
  history already holds that exact version. Otherwise it merges the new
  version into your edits, or, if the same lines changed, keeps your copy and
  writes the committed version to `F.incoming`. The secret stays in
  `conflict` until you merge `F.incoming` into `F` and run `git enc add F`
  (`git enc add --all` skips it); `git enc update --discard F` takes the
  committed version instead.
- **`add` never overwrites someone else's change.** It refuses an
  `outdated`, `conflict` or `diverged` secret (or a file still holding
  conflict markers) unless you pass `--force`. Deleting a `.enc` file does not
  get around this: git-enc compares against git's copy.
- **Anything replaced is backed up first**, encrypted, under
  `.git/git-enc/backup/`. `git enc cat FILE` prints one.
- **Git merges and rebases are handled.** `git enc merge` decrypts both
  sides and merges the plaintext, so a teammate's change is never dropped
  in favor of yours.

git-enc remembers, per clone (in `.git/git-enc/`), which committed version
each of your copies came from. That is how it tells *your edit* from *an
outdated copy*, even after a stash, reset, rebase or branch switch. If the
record is lost, it falls back to searching git history, and when it cannot
tell, it says so (`diverged`) instead of guessing.

### Hooks

`git enc init` installs hooks that **never encrypt or decrypt anything**:

- **pre-commit** refuses to commit a secret's plaintext (for example after
  `git add -f .env`), and reminds you of edits you haven't added. Set
  `git config enc.requireAdded true` to make that reminder block the commit.
- **pre-push** gives the same reminder.
- **post-checkout, post-merge, post-rewrite** remind you when secrets
  changed in git (`run git enc update`).

Existing hooks are kept and run after git-enc's. If `core.hooksPath` is set
(a hook manager, or a global hooks directory), `init` leaves it alone and
tells you what to call from it. Hooks never wait for another `git enc`
command to finish, and if the pre-commit check cannot run at all, it stops
the commit and says why (`git commit --no-verify` skips it when you are sure).

Every plaintext git-enc has managed is also listed in `.git/info/exclude`, so
it stays out of commits even on a branch whose `.gitignore` lacks the block.

## GitHub Desktop

git-enc works with GitHub Desktop as it is. After `git enc add`, the `.enc`
file appears in Desktop's changes like any other file, and you commit it
there. Two things to know:

- Desktop cannot see the plaintext (it's ignored), so an edited secret does
  not show up in Desktop until you run `git enc add`.
- Desktop shows `.enc` changes as binary files.

A GitHub Desktop integration (a Secrets panel with Encrypt and Update
buttons) is planned.

## Declaring secrets

Inside a block, every line is an ordinary `.gitignore` pattern:

```gitignore
# git-enc: team 3f9a1c2e
# .env in any directory, one exact path, and every .pem in certs/
.env
/config/secrets.yml
/certs/*.pem
# git-enc: end
```

`.gitignore` has no end-of-line comments (`.env  # note` is a pattern for a
file literally named that), so git-enc refuses them; put comments on their
own lines.

- The header names the key and its fingerprint, so a different key that
  happens to have the same name is caught with a clear message.
- `git enc add FILE` writes these lines for you.
- To keep the rules exact, a block refuses directory patterns
  (`secrets/`), patterns ending in `*` (`secrets/*`, `.env*`), and patterns
  ending in `.enc`, because each would also hide the `.enc` files; name the
  extension (`secrets/*.yml`) or list the files. It also refuses `**` and
  negations (`!`). If some other rule still hides a `.enc` file, or a `!`
  rule un-ignores a plaintext, `git enc status` reports it and git-enc
  refuses to write that file.
- Secrets can never be `.gitignore`, `.gitattributes`, `.gitmodules`, or
  anything inside `.git`, and git-enc never reads or writes through a
  symlink.
- `git enc add` also adds `*.enc -text diff=git-enc merge=binary` to
  `.gitattributes`, so git never converts line endings in, or text-merges,
  ciphertext.

Several blocks may use different keys (`# git-enc: ops`) for different
groups of people.

## Keys

A key is one line of text, stored in `~/.config/git-enc/keys/NAME`
(readable only by you; git-enc refuses key files others can read). Keys are
[age](https://age-encryption.org) post-quantum keys. Import a key from
standard input, never from the command line, which would leave it in
your shell history.

For CI, put one or more keys in `GIT_ENC_KEY` and run `git enc update`.

## Security

A `.enc` file is a standard age file (`age -d -i ~/.config/git-enc/keys/team
.env.enc` opens it). Inside is a one-line header (format version, length and
path) followed by the secret and zero padding.

**git-enc protects the contents of your secrets from anyone who can read the
repository but does not have the key**: a leaked or public repository, a
fork, a CI cache, GitHub itself.

- Every save is encrypted with fresh randomness, so a secret changed back to
  an earlier value produces a new, unrelated file; nobody without the key can
  tell it was reverted.
- Secrets are padded (every secret up to about 200 bytes produces the same
  file size; larger ones round up by at most about 12%), so the exact length
  is hidden.
- Each `.enc` records its own path, so a `.enc` copied over another secret's
  name is detected.

**It does not protect:**

- **History from anyone who ever had the key.** Git keeps every version
  forever. When someone leaves, create a new key, re-encrypt, **and change
  the secrets themselves**.
- **Metadata**: file names, roughly how big each secret is, when it
  changed, who changed it, commit messages.
- **A compromised machine.** It holds both the key and the plaintext. Use
  disk encryption.
- **Who wrote a file.** Anyone with the key can write a valid `.enc`. Use
  branch protection and code review as you would for code.

**When not to use it**: production credentials, anything under an audit
regime (HIPAA, SOC 2), large teams, or teams with frequent turnover. Those
need per-person access, revocation and audit logs; use a secrets manager
(1Password, Doppler, Vault, a cloud KMS, SOPS). git-enc fits small, trusted
teams sharing development and staging secrets.

## Development

```sh
go test ./...                     # unit tests and end-to-end scenarios with real git
GIT_ENC_TEST_GIT=/path/to/git go test ./e2e/   # the same, with another git
python3 scripts/mutations.py      # re-introduce each guarded bug; every test must catch it
```

The end-to-end suite drives the real binary with a shared origin and
several clones, each with their own keys: everyday edits, stash/reset
after `add`, conflicts, git merges and rebases, lost state, autocrlf,
symlinks and path attacks, and missing or wrong keys. It runs in CI on
macOS, Linux and Windows.

## License

MIT
