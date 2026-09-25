#!/usr/bin/env python3
"""Mutation check: re-introduce each bug a safety rule exists to prevent,
one at a time, and confirm the test that guards it fails.

Every rule git-enc claims (docs, README) should have a line here. Run from
the repository root:  python3 scripts/mutations.py
Each mutation is an exact source substitution; if a line is refactored,
update its entry here in the same change. A mutation must still compile
(a build failure would fail the test for the wrong reason), so one that
does not is reported as BROKEN.
"""
import os, shutil, subprocess, sys

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
muts = [
 ("add advances base immediately (red-team critical 1)", "internal/engine/actions.go",
  "s.entry.Pending, s.entry.Seen, s.entry.Merge = blob, \"\", \"\"",
  "s.entry.Pending, s.entry.Seen, s.entry.Merge = blob, \"\", \"\"; s.entry.BaseBlob, s.entry.BaseHash = blob, s.PlainHash",
  "TestAddThenStashKeepsEdit"),
 ("ignore unmerged index stages (red-team critical 2)", "internal/engine/engine.go",
  "case len(s.Unmerged) > 0:", "case false && len(s.Unmerged) > 0:", "TestGitMergeConflict"),
 ("no pre-commit plaintext guard", "internal/engine/hooks.go",
  "if e.plaintextPath(p, byGit) {", "if false && e.plaintextPath(p, byGit) {", "TestPlaintextNeverCommittable"),
 ("no symlink check on write", "internal/fsx/fsx.go",
  "if fi.Mode()&os.ModeSymlink != 0 {", "if false {", "TestUnsafePaths"),
 ("no path binding", "internal/envelope/envelope.go",
  "if wantPath != \"\" && path != wantPath {", "if false {", "TestUnsafePaths"),
 ("diverged guessed as modified", "internal/engine/engine.go",
  "s.set(Diverged,", "s.set(Modified,", "TestLostState"),
 ("outdated copy treated as an edit", "internal/engine/engine.go",
  "case s.PlainHash == base:", "case false:", "TestEverydayLoop"),
 ("re-encrypt unchanged secrets", "internal/engine/actions.go",
  "\t\treturn []string{s.Path + \" is unchanged\"}, nil", "\t\ts.Kind = Modified; return e.addOne(s, force, explicit)", "TestNoChurnAndNoBlobReuse"),
 ("no padding", "internal/envelope/envelope.go",
  "payload := make([]byte, Padded(n))", "payload := make([]byte, n)", "TestSizeHidden"),
 ("conflict markers accepted", "internal/engine/actions.go",
  "if !force && hasMarkers(s.plain)", "if false && hasMarkers(s.plain)", "TestRebaseConflict"),
 ("deleted .enc treated as new (review H1)", "internal/engine/engine.go",
  "if s.EncBlob == \"\" && (s.IndexBlob != \"\" || s.HeadBlob != \"\") && len(s.Unmerged) == 0 {",
  "if false {", "TestReviewFindings/H1"),
 ("temp files not excluded (review H2)", "internal/engine/install.go",
  "entries[fsx.TempPattern] = true", "", "TestReviewFindings/H2"),
 ("hooks take the lock and fail open (review H3)", "cmd/git-enc/main.go",
  "e, err := engine.OpenReadOnly(\".\")\n\tif err != nil {\n\t\tfmt.Fprintln(os.Stderr, \"git-enc:\", err)",
  "e, err := engine.Open(\".\")\n\tif err != nil {\n\t\tfmt.Fprintln(os.Stderr, \"git-enc:\", err)", "TestReviewFindings/H3"),
 ("tracked plaintext kept tracked (review H4)", "internal/engine/actions.go",
  "\tif s.PlainTracked {\n\t\tif _, err := e.Repo.Git(\"rm\"", "\tif false {\n\t\tif _, err := e.Repo.Git(\"rm\"", "TestReviewFindings/H4"),
 ("re-add before commit refused (review M1)", "internal/engine/engine.go",
  "if s.entry.Pending != \"\" && s.entry.Pending == s.EncBlob {\n\t\t\t// Edited again", "if false {\n\t\t\t// Edited again", "TestReviewFindings/M1"),
 ("add --all takes an unmerged .incoming (review M2)", "internal/engine/actions.go",
  "\t\t\tcase s.Incoming != \"\":\n", "\t\t\tcase false:\n", "TestConflictIncoming"),
 ("end-of-line comments accepted (review C1)", "internal/spec/spec.go",
  "\tcase hasTrailingComment(pat):", "\tcase false:", "TestPatterns"),
 ("unignored plaintext written (review L1)", "internal/engine/actions.go",
  "\tif s.NotIgnored {\n\t\treturn \"\", refuse(", "\tif false {\n\t\treturn \"\", refuse(", "TestReviewFindings/L1"),
 ("negation read as ignored (v0.1.0 bug)", "internal/engine/engine.go",
  "\"check-ignore\", \"-z\", \"--no-index\", \"--stdin\"",
  "\"check-ignore\", \"-v\", \"-z\", \"--no-index\", \"--stdin\"", "TestNegationAfterBroadRule"),
 ("no .gitattributes -text", "internal/engine/install.go",
  "const AttrLine = \"*.enc -text diff=git-enc merge=binary\"", "const AttrLine = \"*.enc diff=git-enc merge=binary\"", "TestAutocrlfLeavesCiphertextAlone"),
 ("rekey seals the plaintext", "internal/engine/rekey.go",
  "sealed, err := envelope.Seal(s.Path, body, k.Recipient)", "sealed, err := envelope.Seal(s.Path, s.plain, k.Recipient)", "TestRekey"),
 ("rekey turns an outdated copy into an edit", "internal/engine/rekey.go",
  "\tif s.entry.Pending == old {", "\tif true {", "TestRekey"),
 ("block key chosen by fingerprint alone", "internal/engine/engine.go",
  "if k.Fingerprint == b.Fingerprint && (k.File == \"\" || k.Name == b.Key) {", "if k.Fingerprint == b.Fingerprint {", "TestKeyRedirect/fingerprint_of"),
 ("two blocks may share a key", "internal/engine/engine.go",
  "e.shared[o], e.shared[b] = msg, msg", "_ = o", "TestKeyRedirect/header"),
 ("ciphertext opened with any key", "internal/engine/engine.go",
  "_, body, err := envelope.Open(data, s.Path, s.Key.Identity)", "_, body, err := envelope.Open(data, s.Path, e.Keys.Identities()...)", "TestForeignKeyRejected"),
 ("add --key moves a declared secret silently", "internal/engine/actions.go",
  "if keyName != \"\" && b.Key != keyName {", "if false {", "TestRekeyMovedSecret"),
 ("files in ignored directories are secrets", "internal/engine/engine.go",
  "\t\tif !ignored[path.Dir(p)] {", "\t\tif !ignored[path.Dir(p)] || true {", "TestIgnoredDirectoryIsNotASecret"),
 ("plaintext committed under a .enc name", "internal/engine/hooks.go",
  "if s.Staged && !envelope.IsSealed(blobs[s.IndexBlob]) {", "if s.Staged && !envelope.IsSealed(blobs[s.IndexBlob]) && false {", "TestUnencryptedEncRefused"),
 ("interrupt leaves the lock", "internal/state/state.go",
  "return &Lock{path, fsx.Track(path)}, nil", "return &Lock{path, func() {}}, nil", "TestInterruptCleansUp"),
 ("interrupt leaves plaintext in a temp dir", "internal/fsx/fsx.go",
  "\tuntrack := Track(dir)", "\tuntrack := func() {}", "TestInterruptCleansUp"),
 ("backup path only works from the root", "internal/engine/actions.go",
  "return e.display(file), nil", "return filepath.ToSlash(strings.TrimPrefix(file, e.Repo.Root+string(filepath.Separator))), nil", "TestUsability/a_backup"),
 ("a file named twice is encrypted twice", "internal/engine/actions.go",
  "targets = appendNew(targets, s)", "targets = append(targets, s)", "TestUsability/a_file_named"),
 ("git's error replaced by a guess", "internal/gitx/gitx.go",
  "return nil, errors.New(strings.TrimPrefix(strings.TrimSpace(ge.Stderr), \"fatal: \"))", "return nil, errors.New(\"not in a git repository\")", "TestUsability/git's_own"),
 ("pathspec variables passed to git", "internal/gitx/gitx.go",
  "case \"GIT_LITERAL_PATHSPECS\", \"GIT_GLOB_PATHSPECS\", \"GIT_NOGLOB_PATHSPECS\", \"GIT_ICASE_PATHSPECS\":", "case \"none\":",
  "TestGitEnvironment/pathspec"),
 ("restoring a .enc runs the user's hook", "internal/engine/actions.go",
  "if err := fsx.WriteWorktree(e.Repo.Root, s.EncPath, data, 0o644); err != nil {",
  "if _, err := e.Repo.Git(\"restore\", \"--source=HEAD\", \"--staged\", \"--worktree\", \"--\", \":(literal)\"+s.EncPath); err != nil || data == nil {",
  "TestGitEnvironment/restoring"),
 ("post-checkout scans when no secret changed", "cmd/git-enc/main.go",
  "if args[0] == \"post-checkout\" && len(args) == 4", "if false && args[0] == \"post-checkout\" && len(args) == 4", "TestGitEnvironment/a_checkout"),
 ("unreadable plaintext treated as missing", "internal/engine/engine.go",
  "\t\tcase s.plainErr != nil:", "\t\tcase false:", "TestGuards/an_unreadable"),
 ("deleted .enc shown clean", "internal/engine/engine.go",
  "case s.PlainHash == s.EncHash && s.EncDeleted:", "case false:", "TestGuards/a_deleted"),
 ("deleting a declared .enc committed", "internal/engine/hooks.go",
  "if b, _, _ := e.Spec.Match(name); b != nil {", "if b, _, _ := e.Spec.Match(name); b != nil && false {", "TestGuards/a_deleted"),
 ("guard trusts git-enc's matcher alone", "internal/engine/hooks.go",
  "b != nil || err != nil || byGit[p] ||", "b != nil || err != nil || false && byGit[p] ||", "TestGuards/block_lines"),
 ("plaintext pushed", "internal/engine/hooks.go",
  "if e.plaintextPath(p, nil) {", "if false && e.plaintextPath(p, nil) {", "TestGuards/plaintext_is_not"),
 ("merge driver never merges", "internal/engine/driver.go",
  "if err != nil || conflicts > 0 {", "if err != nil || conflicts >= 0 {", "TestMergeDriver/different"),
 ("one-sided merge resolution committed", "internal/engine/driver.go",
  "bad = append(bad, s.Path)", "_ = s", "TestMergeDriver/taking"),
 ("base only advanced from the cache", "internal/engine/engine.go",
  "if _, ok := e.Cache.Hashes[b]; !ok {", "if _, ok := e.Cache.Hashes[b]; false && !ok {", "TestGuards/the_cache"),
 ("outdated copy replaced without a backup", "internal/engine/actions.go",
  "backup, err := e.backup(s)", "backup, err := \"\", error(nil)", "TestGuards/every_replaced"),
 ("add stops halfway on an ignored .enc", "internal/engine/actions.go",
  "\t\tif ignored[p] {", "\t\tif false && ignored[p] {", "TestGuards/a_refused_add"),
 ("status waits for the lock", "internal/engine/engine.go",
  "func OpenStatus(dir string) (*Engine, error) { return open(dir, false, true) }",
  "func OpenStatus(dir string) (*Engine, error) { return open(dir, true, false) }", "TestGuards/status_does"),
 ("add drops an unmerged .incoming", "internal/engine/actions.go",
  "if !force && s.Incoming != \"\" && s.PlainHash == s.entry.Kept {", "if false {", "TestLostState"),
 ("update exits 0 with a conflict left", "cmd/git-enc/main.go",
  "\t\t\tcode = exitAttention", "\t\t\tcode = exitOK", "TestConflictIncoming"),
 ("skipped keys still need attention", "internal/engine/report.go",
  "if s.Kind == Clean || s.Skipped {", "if s.Kind == Clean {", "TestSkipKeys"),
 ("verify misses committed plaintext", "internal/engine/verify.go",
  "if e.plaintextPath(p, byGit) && !reported[p] {", "if false && e.plaintextPath(p, byGit) && !reported[p] {", "TestVerify"),
 ("verify skips the range's commits", "internal/engine/verify.go",
  "if e.plaintextPath(p, nil) && !seen[p] {", "if false && e.plaintextPath(p, nil) && !seen[p] {", "TestVerify"),
 ("verify misses an unencrypted .enc", "internal/engine/verify.go",
  "out = append(out, s.EncPath+\": not an encrypted file\")", "_ = s", "TestVerify"),
 ("rollback not warned", "internal/engine/verify.go",
  "case eq && changed:", "case false && eq && changed:", "TestRollbackWarned"),
]
stale = [name for name, f, old, _, _ in muts if old not in open(f).read()]
if stale:
    sys.exit("stale mutations (source changed; update them): " + ", ".join(stale))
bad = 0
for name, f, old, new, test in muts:
    src = open(f).read()
    assert old in src, (name, old)
    shutil.copy(f, f + ".orig")
    open(f, "w").write(src.replace(old, new, 1))
    if subprocess.run(["go", "vet", "./..."], capture_output=True).returncode != 0:
        shutil.move(f + ".orig", f)
        bad += 1
        print("BROKEN " + name + "  (does not compile or vet; fix the substitution)")
        continue
    pattern = "/".join("^" + part + "$" if i == 0 else part for i, part in enumerate(test.split("/", 1)))
    r = subprocess.run(["go", "test", "-count=1", "./e2e/", "-run", pattern], capture_output=True, text=True)
    shutil.move(f + ".orig", f)
    caught = r.returncode != 0
    if not caught: bad += 1
    print(("CAUGHT " if caught else "MISSED ") + name + "  [" + test + "]")
sys.exit(1 if bad else 0)
