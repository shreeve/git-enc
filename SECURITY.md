# Security

## Reporting a problem

Please report a security problem privately: on GitHub, open the
**Security** tab of this repository and choose **Report a vulnerability**.
Don't open a public issue for it.

You'll get an answer within a few days. Once a fix is released, the report
is published with credit to you, unless you'd rather not.

Only the latest release gets security fixes.

## What counts

git-enc's promises are in the README, under
[Security](README.md#security) and [It never loses your
work](README.md#it-never-loses-your-work). A way to break one of them is a
security problem, for example:

- plaintext of a declared secret getting committed or pushed while the
  hooks are installed, or passing `git enc verify`;
- someone without the key learning anything about a secret beyond what the
  README says leaks (names, rough size, when it changed);
- a repository's contents (`.gitignore`, `.gitattributes`, `.enc` files)
  making git-enc write outside the worktree, into `.git`, through a symlink,
  or encrypt a secret for a key its block does not name;
- `git enc update` or `git enc merge` losing an edit that neither git nor a
  backup holds.

These are known limits, not vulnerabilities: anyone with a key can read
every version in history and write valid `.enc` files; a hook can be
skipped with `--no-verify`; a compromised machine exposes its keys and
plaintext.
