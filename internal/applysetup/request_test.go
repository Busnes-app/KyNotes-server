package applysetup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func validRequest() Request {
	return Request{
		Version: 1,
		SSO:     &SSO{IssuerURL: "https://id.example", ClientID: "kynotes", ClientSecret: "client-secret-value", RedirectURI: "https://notes.example/api/v1/auth/oidc/callback", HMACSecret: "hmac-secret-value"},
		Admins:  []Admin{{Issuer: "https://id.example", Subject: "sub-owner", Username: "owner-admin"}},
		Backup:  &Backup{Dir: "/backups", Keep: 7, DepositInterval: "24h", Recovery: &Recovery{URL: "https://kyrecovery.example", PairingCode: "123456"}},
	}
}

func TestValidateAcceptsSpecExample(t *testing.T) {
	if err := validRequest().Validate(false); err != nil {
		t.Fatal(err)
	}
	if err := (Request{Version: 1}).Validate(false); err != nil {
		t.Fatal("every section is optional:", err)
	}
}

func TestValidateRefusesHostileInput(t *testing.T) {
	cases := map[string]func(*Request){
		"version":           func(r *Request) { r.Version = 2 },
		"http issuer":       func(r *Request) { r.SSO.IssuerURL = "http://id.example" },
		"loopback issuer":   func(r *Request) { r.SSO.IssuerURL = "https://127.0.0.1" },
		"credential in url": func(r *Request) { r.SSO.IssuerURL = "https://u:p@id.example" },
		"padded url":        func(r *Request) { r.SSO.IssuerURL = " https://id.example" },
		"private recovery":  func(r *Request) { r.Backup.Recovery.URL = "https://10.0.0.5" },
		"redirect path":     func(r *Request) { r.SSO.RedirectURI = "https://notes.example/callback" },
		"empty client id":   func(r *Request) { r.SSO.ClientID = "" },
		"empty secret":      func(r *Request) { r.SSO.ClientSecret = "" },
		"control in secret": func(r *Request) { r.SSO.ClientSecret = "a\x00b" },
		"oversize secret":   func(r *Request) { r.SSO.HMACSecret = strings.Repeat("h", MaxSecretBytes+1) },
		"admin issuer":      func(r *Request) { r.Admins[0].Issuer = "https://other.example" },
		"blank username":    func(r *Request) { r.Admins[0].Username = " " },
		"control username":  func(r *Request) { r.Admins[0].Username = "a\nb" },
		"duplicate subject": func(r *Request) {
			r.Admins = append(r.Admins, Admin{Issuer: "https://id.example", Subject: "sub-owner", Username: "other"})
		},
		"duplicate username": func(r *Request) {
			r.Admins = append(r.Admins, Admin{Issuer: "https://id.example", Subject: "sub-2", Username: "OWNER-ADMIN"})
		},
		"relative dir":        func(r *Request) { r.Backup.Dir = "backups" },
		"negative keep":       func(r *Request) { r.Backup.Keep = -1 },
		"short interval":      func(r *Request) { r.Backup.DepositInterval = "5m" },
		"fractional interval": func(r *Request) { r.Backup.DepositInterval = "15m0.5s" },
		"pairing code":        func(r *Request) { r.Backup.Recovery.PairingCode = "12345a" },
		"too many admins": func(r *Request) {
			for i := 0; i < MaxAdmins; i++ {
				r.Admins = append(r.Admins, Admin{Issuer: "https://id.example", Subject: fmt.Sprint("s", i), Username: fmt.Sprint("u", i)})
			}
		},
	}
	for name, mutate := range cases {
		r := validRequest()
		mutate(&r)
		if err := r.Validate(false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidatePrivateRecoveryNeedsOptIn(t *testing.T) {
	r := validRequest()
	r.Backup.Recovery.URL = "https://10.0.0.5"
	if err := r.Validate(true); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeRequestIsStrict(t *testing.T) {
	good, err := json.Marshal(validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRequest(bytes.NewReader(good), false); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"unknown field": `{"version":1,"extra":true}`,
		"trailing data": `{"version":1}{"version":1}`,
		"not an object": `[1]`,
		"bad version":   `{"version":2}`,
	} {
		if _, err := DecodeRequest(strings.NewReader(body), false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
