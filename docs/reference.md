# git-enc reference

The details behind the [README](../README.md): what git-enc writes and
where, the settings and environment it reads, and the JSON other tools
can build on.

## What git-enc changes

### In the repository (committed)

| File | What git-enc puts there |
|---|---|
| `.gitignore` | the `# git-enc:` blocks: which files are secrets, and each block's key name and fingerprint. `git enc add` writes them; you can too. |
| `F.enc` beside each secret `F` | the encrypted secret: a standard [age](https://age-encryption.org) file |
| `.gitattributes` | one line, `*.enc -text diff=git-enc merge=binary`, so git never changes line endings in ciphertext or merges it as text |

### In each clone (never committed)

| Where | What |
|---|---|
| `.git/git-enc/state` | for each secret, which committed version your copy came from: how git-enc tells your edit from an outdated copy |
| `.git/git-enc/cache` | a hash of the plaintext in each `.enc` it has read, so it decrypts less. Safe to delete. |
| `.git/git-enc/backup/` | encrypted copies of every plaintext `update` replaced. Kept 90 days, and always the newest 20. |
| `.git/git-enc/desktop.json` | under GitHub Desktop: what the hooks after a pull did, for the next commit's list, and which notices were shown |
| `.git/git-enc/lock` | present while a git-enc command runs |
| `.git/info/exclude` | every plaintext git-enc has handled (and its `.incoming`), so it stays out of commits even on a branch whose `.gitignore` lacks the block |
| `.git/info/attributes` | `*.enc merge=git-enc`: turns on the merge driver in this clone only |
| `.git/config` | `merge.git-enc.name` and `merge.git-enc.driver`, the merge driver's definition |
| `.git/hooks/` | `pre-commit`, `pre-push`, `post-checkout`, `post-merge`, `post-rewrite`. A hook you already had is renamed `NAME.git-enc-chained` and runs after git-enc's. |

`git enc init` writes the last four. Linked worktrees (`git worktree add`)
each keep their own `state`, `lock`, `backup/` and `desktop.json`, and
share the rest.

### Beside a secret, in the worktree

| File | When |
|---|---|
| `F.incoming` | `update` found you edited `F` and the committed version changed on the same lines: the committed version, for you to merge into `F`. Removed when you `git enc add F`. |
| `.F.git-enc-tmp-*` | for a moment while git-enc writes a file; removed even when interrupted |

### In your home directory

| Where | What |
|---|---|
| `~/.config/git-enc/keys/NAME` | one key per file, readable only by you |

## Settings

Per clone, with `git config` (add `--global` for every repository):

| Setting | Default | What it does |
|---|---|---|
| `enc.autoUpdate` | off (on under Desktop) | pulls and checkouts update secrets that need no judgment |
| `enc.requireAdded` | off (on under Desktop) | a commit stops while a secret is edited but not encrypted |
| `enc.skipKeys` | none | key names, separated by spaces or commas, whose blocks you don't hold on purpose: they stay quiet |
| `enc.desktop` | on | `false`: under GitHub Desktop the hooks behave as in a terminal |
| `enc.notify` | on | `false`: no system notifications under GitHub Desktop |
| `diff.git-enc.textconv` | unset | `git-enc cat --textconv`: `git diff` and `git log -p` show secrets decrypted |

## Environment

| Variable | What it does |
|---|---|
| `GIT_ENC_KEY` | one or more keys, one per line, for CI; used as well as the key files |
| `GIT_ENC_KEYS_DIR` | where the key files are, instead of `~/.config/git-enc/keys` |
| `XDG_CONFIG_HOME` | if set, keys are in `$XDG_CONFIG_HOME/git-enc/keys` |
| `GITHUB_DESKTOP` | set by GitHub Desktop when it runs hooks; git-enc's hooks then work the Desktop way |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | done |
| 1 | an error |
| 2 | a mistake in the command (an unknown command or flag) |
| 3 | a secret needs you first: add, update or merge it (`check`, `status --exit-code`, `update` leaving a conflict, `verify` failing) |
| 4 | a key is missing |

## JSON

`git enc status --json` is for tools: an editor extension, a menu-bar app,
a script. While `version` is 1, fields are only added, never renamed or
removed. `git enc version --json` prints `{"protocol":1,"version":"…"}`.

```json
{
  "version": 1,
  "repo": {
    "root": "/home/you/app",
    "initialized": true,
    "uses_git_enc": true
  },
  "keys": [
    { "name": "team", "fingerprint": "5383c7d7", "available": true, "gitignore_line": 1 }
  ],
  "secrets": [
    {
      "path": ".env",
      "enc_path": ".env.enc",
      "state": "modified",
      "staged": false,
      "enc_unstaged": false,
      "key": "team",
      "fingerprint": "5383c7d7",
      "key_available": true,
      "gitignore_line": 2,
      "message": "edited",
      "action": "git enc add .env"
    }
  ],
  "problems": []
}
```

**`repo`**: `root` is the worktree's top directory; `initialized` means
`git enc init` has set up this clone; `uses_git_enc` means `.gitignore`
has a git-enc block.

**`keys`**, one per block: its key `name` and `fingerprint`, whether you
have it (`available`), `skipped` when you don't hold it on purpose
(`enc.skipKeys`), and the `.gitignore` line of the block's header.

**`secrets`**, one per secret:

| Field | Meaning |
|---|---|
| `path`, `enc_path` | the plaintext and its `.enc`, from the repository's top |
| `state` | one of `clean`, `modified`, `new`, `outdated`, `missing`, `conflict`, `diverged`, `merging`, `no-key`, `corrupt`, `orphaned` (see the README) |
| `staged` | the `.enc` in the index differs from the last commit |
| `enc_unstaged` | the `.enc` in the worktree differs from the index |
| `key`, `fingerprint`, `key_available` | the key of its block, and whether you have it |
| `gitignore_line` | the line that declares it |
| `incoming` | the path of `F.incoming`, if there is one |
| `skipped` | no key, on purpose (`enc.skipKeys`) |
| `message` | why it is in this state, in words |
| `action` | the command that moves it forward, if there is one |

**`problems`**: things wrong that are not one secret's state, each with a
`code`, a `message`, and where known a `path`, `line` and `action`:

| Code | Meaning |
|---|---|
| `gitignore` | a mistake in a git-enc block (an unended block, a pattern git-enc refuses) |
| `shared-key` | two blocks use the same key |
| `two-blocks` | two blocks declare the same file |
| `not-ignored` | git does not ignore a secret's plaintext (a `!` rule), so it could be committed |
| `enc-ignored` | git ignores a `.enc`, so it can't be committed |
| `tracked-plaintext` | git tracks a secret's plaintext |
| `unsafe-path` | a path git-enc refuses: through a symlink, inside `.git`, or unreadable |

## The `.enc` format

A `.enc` file is a standard age file: `age -d -i KEYFILE F.enc` opens it
without git-enc. Inside is one header line, `git-enc 1 LENGTH PATH`, then
the secret, then zero bytes padding it to a size bucket (every secret up to
about 200 bytes gives the same size; larger ones round up by at most about
12%). The path in the header is how git-enc notices a `.enc` copied over
another secret's name.
