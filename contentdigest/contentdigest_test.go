// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package contentdigest

import (
	"errors"
	"testing"
)

// RFC 9530 Section 2: digest of the body {"hello": "world"}.
const (
	rfcBody   = `{"hello": "world"}`
	rfcSHA256 = `sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:`
	rfcSHA512 = `sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:`
)

func TestValueRFCVectors(t *testing.T) {
	for alg, want := range map[string]string{"sha-256": rfcSHA256, "sha-512": rfcSHA512} {
		got, err := Value(alg, []byte(rfcBody))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("Value(%s):\n got  %s\n want %s", alg, got, want)
		}
	}
	if _, err := Value("md5", []byte(rfcBody)); err == nil {
		t.Error("Value accepted md5")
	}
}

func TestVerify(t *testing.T) {
	body := []byte(rfcBody)
	both := []string{"sha-256", "sha-512"}
	tests := []struct {
		name     string
		values   []string
		body     []byte
		accepted []string
		wantErr  error // nil means accept; non-nil is matched with errors.Is when set
		reject   bool
	}{
		{name: "sha-256 ok", values: []string{rfcSHA256}, body: body, accepted: both},
		{name: "sha-512 ok", values: []string{rfcSHA512}, body: body, accepted: both},
		{name: "both entries ok", values: []string{rfcSHA256 + ", " + rfcSHA512}, body: body, accepted: both},
		{name: "split across field lines", values: []string{rfcSHA256, rfcSHA512}, body: body, accepted: both},
		{name: "wrong body", values: []string{rfcSHA256}, body: []byte("tampered"), accepted: both, reject: true, wantErr: ErrDigestMismatch},
		{name: "supported alg outside accepted set must still match", values: []string{rfcSHA256 + `, sha-512=:AAAA:`}, body: body, accepted: []string{"sha-256"}, reject: true, wantErr: ErrDigestMismatch},
		{name: "accepted set excludes provided", values: []string{rfcSHA256}, body: body, accepted: []string{"sha-512"}, reject: true, wantErr: ErrNoAcceptedDigest},
		{name: "only unknown algorithms", values: []string{`unixsum=:AAAA:`}, body: body, accepted: both, reject: true, wantErr: ErrNoAcceptedDigest},
		{name: "unknown alongside valid accepted", values: []string{rfcSHA256 + `, unixsum=:AAAA:`}, body: body, accepted: both},
		{name: "empty dictionary", values: []string{""}, body: body, accepted: both, reject: true},
		{name: "not a dictionary", values: []string{`::bogus`}, body: body, accepted: both, reject: true},
		{name: "entry not a byte sequence", values: []string{`sha-256="text"`}, body: body, accepted: both, reject: true},
		{name: "inner list entry", values: []string{`sha-256=(:AAAA: :BBBB:)`}, body: body, accepted: both, reject: true},
		// An empty accepted set is the verifier's own misconfiguration, so
		// it must not be reported as a rejected message.
		{name: "no accepted algorithms", values: []string{rfcSHA256}, body: body, accepted: nil, reject: true},
	}
	for _, tt := range tests {
		err := Verify(tt.values, tt.body, tt.accepted)
		if tt.reject {
			if err == nil {
				t.Errorf("%s: accepted", tt.name)
			} else if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("%s: got %v, want %v", tt.name, err, tt.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
		}
	}
	// The empty-accepted-set error is distinct from a message that carries
	// no accepted entry: a caller matching ErrNoAcceptedDigest to blame the
	// sender must not match its own missing configuration.
	if err := Verify([]string{rfcSHA256}, body, nil); errors.Is(err, ErrNoAcceptedDigest) {
		t.Error("empty accepted set reported as ErrNoAcceptedDigest")
	}
}

func TestSupported(t *testing.T) {
	got := Supported()
	if len(got) != 2 || got[0] != SHA256 || got[1] != SHA512 {
		t.Fatalf("Supported() = %v", got)
	}
	// Every name Supported returns must be computable, and the returned
	// slice must not alias state a caller can mutate.
	for _, alg := range got {
		if _, err := Value(alg, nil); err != nil {
			t.Errorf("Value(%s): %v", alg, err)
		}
	}
	got[0] = "md5"
	if Supported()[0] != SHA256 {
		t.Error("Supported returns aliased state")
	}
}

func TestVerifyEmptyBody(t *testing.T) {
	v, err := Value("sha-256", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify([]string{v}, nil, []string{"sha-256"}); err != nil {
		t.Errorf("empty body digest: %v", err)
	}
}
