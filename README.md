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

On macOS or Linux:

```sh
brew install shreeve/tap/git-enc
```

On Windows, download `git-enc.exe` from the
[latest release](https://github.com/shreeve/git-enc/releases/latest) and put
it on your PATH. With Go installed, `go install
github.com/shreeve/git-enc/cmd/git-enc@latest` works anywhere.

git-enc is one self-contained binary; git runs it as `git enc`. It needs
git 2.31 or later. Release
archives come with sha256 checksums and GitHub build attestations
(`gh attestation verify FILE --repo shreeve/git-enc`).

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
| `git enc rekey OLD NEW` | Move to a new key and re-encrypt (see [Changing keys](#changing-keys)) |

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
| `outdated` / `missing` | Someone committed a newer version (or your `.enc` was deleted) | `git enc update` |
| `conflict` | You edited it *and* it changed in git | `git enc update` |
| `diverged` | It matches no committed version and git-enc has no record to tell why | `git enc update` |
| `merging` | Git has a merge or rebase conflict on the `.enc` | `git enc merge` |
| `no-key` | You don't have the key (or have a different key with that name) | `git enc key add` |
| `no-key` (…`git enc rekey`) | Its `.enc` opens with another of your keys than its block names | `git enc rekey OLD NEW FILE` if you moved it; otherwise check `git log -p .gitignore` |
| `orphaned` | No block lists it any more, but the plaintext or `.enc` is still here | `git enc add` to declare it again, or delete it |
| `corrupt` | The `.enc` or the plaintext can't be read, or the `.enc` was encrypted for a different path | restore it from git, or fix the file's permissions |

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
- **Git merges and rebases are handled.** After `git enc init`, git merges
  secrets by their plaintext, like any text file: edits to different lines
  merge inside `git pull`. Edits to the same line stop as a conflict, and
  `git enc merge` writes both sides into your plaintext with the usual
  conflict markers. A merge that takes one side's `.enc` whole while both
  sides changed the secret (a "use mine" button) is refused at commit, so a
  teammate's change is never dropped in favor of yours.

git-enc remembers, per clone (in `.git/git-enc/`), which committed version
each of your copies came from. That is how it tells *your edit* from *an
outdated copy*, even after a stash, reset, rebase or branch switch. If the
record is lost, it falls back to searching git history, and when it cannot
tell, it says so (`diverged`) instead of guessing.

### Hooks

`git enc init` sets up git's merging of `.enc` files (in the clone's own
config: a repository cannot turn on a merge program for you) and installs
hooks that **never encrypt or decrypt anything**:

- **pre-commit** refuses to commit a secret's plaintext (for example after
  `git add -f .env`, or a plaintext copied over `.env.enc`), and reminds
  you of edits you haven't added. Set
  `git config enc.requireAdded true` to make that reminder block the commit.
- **pre-push** refuses to push commits that contain a secret's plaintext
  (committed with `--no-verify`, say), and gives the same reminder.
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
- Pulls merge secrets like other files. If both of you changed the same
  line, Desktop shows a conflict on the `.enc` and offers only "use mine"
  or "use theirs"; either would drop a change, so the commit is refused
  with the two commands that merge both sides instead.

A GitHub Desktop integration (a Secrets panel with Encrypt and Update
buttons) is planned.

## Declaring secrets

Inside a block, every line is an ordinary `.gitignore` pattern:

```gitignore
# git-enc: team 3f9a1c2e
# .env in any directory (except ones git already ignores, like
# node_modules/), one exact path, and every .pem in certs/
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
  extension (`secrets/*.yml`) or list the files. It also refuses `**`,
  character classes like `[[:digit:]]`, and negations (`!`). Git still
  ignores what a refused line matches, and the pre-commit hook still keeps
  those files out of commits. If some other rule still hides a `.enc` file, or a `!`
  rule un-ignores a plaintext, `git enc status` reports it and git-enc
  refuses to write that file.
- Secrets can never be `.gitignore`, `.gitattributes`, `.gitmodules`, or
  anything inside `.git`, and git-enc never reads or writes through a
  symlink.
- `git enc add` also adds `*.enc -text diff=git-enc merge=binary` to
  `.gitattributes`, so git never converts line endings in, or text-merges,
  ciphertext.

Several blocks may use different keys (`# git-enc: ops`) for different
groups of people; each block needs its own key. To move a secret to
another block, move its line there and run `git enc rekey OLD NEW FILE`
(for example `git enc rekey team ops config/prod.env`).

If an existing rule would also hide encrypted files (a common one is
`.env*`, which matches `.env.enc`), add `!*.enc` after it. Git applies the
last matching rule, so every `.enc` file becomes visible again, and a later
line can still hide a particular one:

```gitignore
.env*
!*.enc
something-else.foo.enc
```

A rule that ignores a whole directory (`config/`) cannot be undone this way,
because git never looks inside it; write `config/*` instead. Either way,
`git enc status` reports any encrypted file git would ignore.

## Keys

A key is one line of text, stored in `~/.config/git-enc/keys/NAME`
(readable only by you; git-enc refuses key files others can read). Keys are
[age](https://age-encryption.org) post-quantum keys. Import a key from
standard input, never from the command line, which would leave it in
your shell history.

For CI, put one or more keys in `GIT_ENC_KEY` and run `git enc update`.

### Changing keys

When someone leaves, or a key may have leaked:

```sh
git enc key new team2            # the new key
git enc rekey team team2         # every "team" block now uses team2; re-encrypts and stages
git commit -m "Move secrets to key team2"
```

Share `team2` with the people who stay. Until they import it
(`git enc key add team2`), their secrets show as `no-key`. `rekey`
re-encrypts what is committed, not your working copy, so edits you haven't
added stay edits. Then **change the secrets themselves**: anyone with the
old key can still read every old version in git history.

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
  forever. When someone leaves, [change keys](#changing-keys) **and change
  the secrets themselves**.
- **Metadata**: file names, roughly how big each secret is, when it
  changed, who changed it, commit messages.
- **A compromised machine.** It holds both the key and the plaintext. Use
  disk encryption.
- **Who wrote a file.** Anyone with the key can write a valid `.enc`. Use
  branch protection and code review as you would for code.
- **`.gitignore` from someone who can push.** git-enc only uses a key
  whose name *and* fingerprint match a block's header, refuses two blocks
  that share a key, and only re-encrypts under a new key when you run
  `git enc rekey` and name both keys. But review changes to git-enc blocks
  as you would code: a block pointed at a key someone else holds would
  encrypt the secrets you add next for them.

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
