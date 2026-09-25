package engine

// Report is `git enc status --json`: the stable contract for tools such
// as a GitHub Desktop overlay. Fields are only ever added, never removed
// or renamed, while Version is 1.
type Report struct {
	Version  int            `json:"version"`
	Repo     ReportRepo     `json:"repo"`
	Keys     []ReportKey    `json:"keys"`
	Secrets  []ReportSecret `json:"secrets"`
	Problems []Problem      `json:"problems"`
}

// ReportRepo describes the repository.
type ReportRepo struct {
	Root        string `json:"root"`
	Initialized bool   `json:"initialized"` // git enc init has set up hooks and merging
	Uses        bool   `json:"uses_git_enc"`
}

// ReportKey is one block's key.
type ReportKey struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	Available   bool   `json:"available"`
	Line        int    `json:"gitignore_line"`
}

// ReportSecret is one secret.
type ReportSecret struct {
	Path         string `json:"path"`
	EncPath      string `json:"enc_path"`
	State        Kind   `json:"state"`
	Staged       bool   `json:"staged"`
	EncDirty     bool   `json:"enc_unstaged"`
	Key          string `json:"key"`
	Fingerprint  string `json:"fingerprint"`
	KeyAvailable bool   `json:"key_available"`
	Line         int    `json:"gitignore_line"`
	Incoming     string `json:"incoming,omitempty"`
	Message      string `json:"message,omitempty"`
	Action       string `json:"action,omitempty"`
}

// Report builds the status report.
func (e *Engine) Report() *Report {
	r := &Report{
		Version:  1,
		Repo:     ReportRepo{Root: e.Repo.Root, Initialized: !e.SetupNeeded(), Uses: len(e.Spec.Blocks) > 0},
		Keys:     []ReportKey{},
		Secrets:  []ReportSecret{},
		Problems: e.Problems,
	}
	if r.Problems == nil {
		r.Problems = []Problem{}
	}
	for _, b := range e.Spec.Blocks {
		k := e.blockKey(b)
		fp := b.Fingerprint
		if fp == "" && k != nil {
			fp = k.Fingerprint
		}
		r.Keys = append(r.Keys, ReportKey{Name: b.Key, Fingerprint: fp, Available: k != nil, Line: b.Start})
	}
	for _, s := range e.Secrets {
		rs := ReportSecret{
			Path: s.Path, EncPath: s.EncPath, State: s.Kind, Staged: s.Staged, EncDirty: s.EncDirty,
			KeyAvailable: s.Key != nil, Incoming: s.Incoming, Message: s.Message, Action: s.Action,
		}
		if s.Block != nil {
			rs.Key, rs.Fingerprint, rs.Line = s.Block.Key, s.Block.Fingerprint, s.Block.Start
			if _, p, _ := e.Spec.Match(s.Path); p != nil {
				rs.Line = p.Line
			}
		}
		r.Secrets = append(r.Secrets, rs)
	}
	return r
}

// NeedsAttention reports whether anything is not clean, and whether the
// only problem is missing keys.
func (e *Engine) NeedsAttention() (attention, onlyKeys bool) {
	keysOnly := true
	for _, s := range e.Secrets {
		if s.Kind == Clean {
			continue
		}
		attention = true
		if s.Kind != NoKey {
			keysOnly = false
		}
	}
	if len(e.Problems) > 0 {
		attention, keysOnly = true, false
	}
	return attention, attention && keysOnly
}
