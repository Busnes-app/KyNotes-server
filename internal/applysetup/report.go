package applysetup

import "net/url"

const (
	ExitOK       = 0
	ExitError    = 1
	ExitInvalid  = 2
	ExitConflict = 3
)

type Result struct {
	Section string `json:"section"`
	Status  Status `json:"status"`
	Detail  string `json:"detail,omitempty"`
}

// Handover carries only non-secret facts for the installer's handover record.
type Handover struct {
	URL                    string   `json:"url"`
	AdminUsernames         []string `json:"adminUsernames"`
	RecoveryKeyFingerprint string   `json:"recoveryKeyFingerprint"`
	BackupDir              string   `json:"backupDir"`
	Version                string   `json:"version"`
}

type Report struct {
	Version  int      `json:"version"`
	Results  []Result `json:"results"`
	Handover Handover `json:"handover"`
}

func NewReport(results []Result, h Handover) Report {
	if results == nil {
		results = []Result{}
	}
	if h.AdminUsernames == nil {
		h.AdminUsernames = []string{}
	}
	return Report{Version: Version, Results: results, Handover: h}
}

// ExitCode: invalid input first, then errors, then conflicts.
func (r Report) ExitCode() int {
	code := ExitOK
	for _, x := range r.Results {
		switch x.Status {
		case Invalid:
			return ExitInvalid
		case Failed:
			code = ExitError
		case Conflict:
			if code == ExitOK {
				code = ExitConflict
			}
		}
	}
	return code
}

func Origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
