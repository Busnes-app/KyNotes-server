package applysetup

import (
	"encoding/json"
	"testing"
)

func TestExitCodePrecedence(t *testing.T) {
	report := func(statuses ...Status) Report {
		var rs []Result
		for _, s := range statuses {
			rs = append(rs, Result{Section: "x", Status: s})
		}
		return NewReport(rs, Handover{})
	}
	for _, c := range []struct {
		r    Report
		want int
	}{
		{report(), ExitOK},
		{report(Created, Present), ExitOK},
		{report(Present, Conflict), ExitConflict},
		{report(Conflict, Failed), ExitError},
		{report(Failed, Invalid, Conflict), ExitInvalid},
	} {
		if got := c.r.ExitCode(); got != c.want {
			t.Errorf("%+v: got %d want %d", c.r.Results, got, c.want)
		}
	}
}

func TestReportJSONShape(t *testing.T) {
	b, err := json.Marshal(NewReport(nil, Handover{URL: "https://notes.example", Version: "v1"}))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":1,"results":[],"handover":{"url":"https://notes.example","adminUsernames":[],"recoveryKeyFingerprint":"","backupDir":"","version":"v1"}}`
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
	b, _ = json.Marshal(Result{Section: "sso", Status: Present})
	if string(b) != `{"section":"sso","status":"present"}` {
		t.Fatalf("got %s", b)
	}
}

func TestOrigin(t *testing.T) {
	if got := Origin("https://notes.example/api/v1/auth/oidc/callback"); got != "https://notes.example" {
		t.Fatal(got)
	}
	if got := Origin(""); got != "" {
		t.Fatal(got)
	}
}
