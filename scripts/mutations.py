#!/usr/bin/env python3
"""Mutation check: re-introduce each bug a safety rule exists to prevent,
one at a time, and confirm the test that guards it fails.

Every rule git-enc claims (docs, README) should have a line here. Run from
the repository root:  python3 scripts/mutations.py
Each mutation is an exact source substitution; if a line is refactored,
update its entry here in the same change.
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
  "if b != nil || err != nil || e.managed(p) || (name != p && e.managed(name)) || isTemp(p) {", "if false {", "TestPlaintextNeverCommittable"),
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
  "e, err := engine.OpenReadOnly(\".\")", "e, err := engine.Open(\".\")", "TestReviewFindings/H3"),
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
 ("negation read as ignored (v0.1.0 bug)", "internal/engine/actions.go",
  "\"check-ignore\", \"-q\", \"--no-index\", \"--\", s.EncPath); err == nil {",
  "\"check-ignore\", \"-v\", \"--no-index\", \"--\", s.EncPath); err == nil {", "TestNegationAfterBroadRule"),
 ("no .gitattributes -text", "internal/engine/install.go",
  "const AttrLine = \"*.enc -text diff=git-enc merge=binary\"", "const AttrLine = \"*.enc diff=git-enc merge=binary\"", "TestAutocrlfLeavesCiphertextAlone"),
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
    pattern = "/".join("^" + part + "$" if i == 0 else part for i, part in enumerate(test.split("/", 1)))
    r = subprocess.run(["go", "test", "-count=1", "./e2e/", "-run", pattern], capture_output=True, text=True)
    shutil.move(f + ".orig", f)
    caught = r.returncode != 0
    if not caught: bad += 1
    print(("CAUGHT " if caught else "MISSED ") + name + "  [" + test + "]")
sys.exit(1 if bad else 0)
