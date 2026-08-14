// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package keyscope

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/micahhausler/httpsig"
)

// The AWS documentation's worked SigV4 example: the Amazon Glacier signing
// walkthrough publishes the secret key, the credential scope, the exact
// string to sign, and the resulting signature, which exercises every rung
// of the ladder.
// https://docs.aws.amazon.com/amazonglacier/latest/dev/amazon-glacier-signing-requests.html
const (
	awsSecret       = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	awsAccessKeyID  = "AKIAIOSFODNN7EXAMPLE"
	awsStringToSign = "AWS4-HMAC-SHA256\n" +
		"20120525T002453Z\n" +
		"20120525/us-east-1/glacier/aws4_request\n" +
		"5f1da1a2d0feb614dd03d71e87928b8e449ac87614479332aced3a701f916743"
	awsSignature = "3ce5b2f2fffac9262b4da9256f8d086b4aaf42eba5f111c21681a65a127b7c2a"
)

var awsCreated = time.Date(2012, 5, 25, 0, 24, 53, 0, time.UTC)

func awsScope() map[string]string {
	return map[string]string{"date": "20120525", "region": "us-east-1", "service": "glacier"}
}

func rootKey(t *testing.T) *Key {
	t.Helper()
	k, err := New(SigV4(), Stage{
		Name:  awsAccessKeyID,
		Scope: map[string]string{"region": "us-east-1", "service": "glacier"},
	}, []byte(awsSecret))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestSigV4Vector reproduces the AWS-published signature: derive the signing
// key from the documented secret and scope, HMAC the documented string to
// sign, and compare against the documented signature hex. The signing key is
// reached through Signer, whose hmac-sha256 over the string to sign is
// exactly SigV4's final signing step.
func TestSigV4Vector(t *testing.T) {
	signer, err := rootKey(t).Signer(awsCreated)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign([]byte(awsStringToSign))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(sig); got != awsSignature {
		t.Fatalf("signature over AWS string to sign:\n got  %s\n want %s", got, awsSignature)
	}
}

func TestKeyID(t *testing.T) {
	got, err := rootKey(t).KeyID(awsCreated)
	if err != nil {
		t.Fatal(err)
	}
	want := "AKIAIOSFODNN7EXAMPLE/20120525/us-east-1/glacier/aws4_request"
	if got != want {
		t.Fatalf("KeyID = %q, want %q", got, want)
	}
}

// TestStageEquivalence checks that every hand-off point yields the same
// signatures as the root: a stage key must be exactly the ladder's
// intermediate output, with the remaining steps applied at use.
func TestStageEquivalence(t *testing.T) {
	root := rootKey(t)
	base := []byte("test signature base")
	rootSigner, err := root.Signer(awsCreated)
	if err != nil {
		t.Fatal(err)
	}
	want, err := rootSigner.Sign(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, through := range []string{"date", "region", "service", "terminator"} {
		material, stage, err := root.Derive(through, awsCreated)
		if err != nil {
			t.Fatalf("Derive(%s): %v", through, err)
		}
		staged, err := New(SigV4(), stage, material)
		if err != nil {
			t.Fatalf("New from %s stage: %v", through, err)
		}
		signer, err := staged.Signer(awsCreated)
		if err != nil {
			t.Fatalf("Signer from %s stage: %v", through, err)
		}
		got, err := signer.Sign(base)
		if err != nil {
			t.Fatal(err)
		}
		if !hmac.Equal(got, want) {
			t.Errorf("stage %s signs differently from root", through)
		}
		keyid, err := staged.KeyID(awsCreated)
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := staged.Verifier(keyid, awsCreated)
		if err != nil {
			t.Fatalf("Verifier from %s stage: %v", through, err)
		}
		if err := verifier.Verify(base, want); err != nil {
			t.Errorf("stage %s does not verify the root's signature: %v", through, err)
		}
	}
}

// TestVerifierScopeMismatch checks that every scope disagreement is
// ErrScopeMismatch, distinct from signature math, and that the error names
// the disagreeing step.
func TestVerifierScopeMismatch(t *testing.T) {
	root := rootKey(t)
	material, stage, err := root.Derive("service", awsCreated)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := New(SigV4(), stage, material)
	if err != nil {
		t.Fatal(err)
	}
	good, err := staged.KeyID(awsCreated)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		keyid   string
		created time.Time
		detail  string // substring the error must carry
	}{
		{name: "wrong service", keyid: strings.Replace(good, "/glacier/", "/s3/", 1), created: awsCreated, detail: "service"},
		{name: "wrong region", keyid: strings.Replace(good, "/us-east-1/", "/us-west-2/", 1), created: awsCreated, detail: "region"},
		{name: "wrong key name", keyid: strings.Replace(good, awsAccessKeyID, "AKIAOTHER", 1), created: awsCreated, detail: "name"},
		{name: "keyid date disagrees with created", keyid: strings.Replace(good, "/20120525/", "/20120526/", 1), created: awsCreated, detail: "date"},
		{name: "created outside key's date scope", keyid: good, created: awsCreated.Add(24 * time.Hour), detail: "date"},
	}
	for _, tt := range tests {
		_, err := staged.Verifier(tt.keyid, tt.created)
		if !errors.Is(err, ErrScopeMismatch) {
			t.Errorf("%s: got %v, want ErrScopeMismatch", tt.name, err)
			continue
		}
		var se *ScopeError
		if !errors.As(err, &se) {
			t.Errorf("%s: not a *ScopeError", tt.name)
			continue
		}
		if !strings.Contains(se.Step, tt.detail) && !strings.Contains(se.Claimed, tt.detail) {
			t.Errorf("%s: ScopeError{Step: %q, Claimed: %q} does not carry %q", tt.name, se.Step, se.Claimed, tt.detail)
		}
		// Error text renders only peer-known values; the key's own
		// expected value is opt-in via Expected, so a server that
		// echoes error text to clients does not disclose its scope.
		if want := se.Expected(); want != "" && strings.Contains(err.Error(), want) {
			t.Errorf("%s: error text %q discloses the key's expected value %q", tt.name, err, want)
		}
	}
	// Malformed keyids are rejected but are not scope mismatches.
	for _, keyid := range []string{"", "no-slashes", good + "/extra", strings.Repeat("x", 4096)} {
		_, err := staged.Verifier(keyid, awsCreated)
		if err == nil {
			t.Errorf("Verifier accepted keyid %q", keyid)
		} else if errors.Is(err, ErrScopeMismatch) {
			t.Errorf("malformed keyid %q reported as scope mismatch", keyid)
		}
	}
	// Comparison is byte-exact: case is never normalized.
	if _, err := staged.Verifier(strings.Replace(good, "/us-east-1/", "/US-EAST-1/", 1), awsCreated); !errors.Is(err, ErrScopeMismatch) {
		t.Errorf("case-folded region: got %v, want ErrScopeMismatch", err)
	}
	// A root key has no baked date, so any created is in scope.
	if _, err := root.Verifier("AKIAIOSFODNN7EXAMPLE/20120526/us-east-1/glacier/aws4_request", awsCreated.Add(24*time.Hour)); err != nil {
		t.Errorf("root key rejected the next day: %v", err)
	}
}

// TestDateScopeChecked_RegressionOrdering pins that a stage key's baked
// date rejects other days on its own, with no freshness policy in play: the
// scope check must not be reordered behind a MaxAge bound, or a stage key
// from an arbitrary past date becomes usable within that day's requests.
func TestDateScopeChecked_RegressionOrdering(t *testing.T) {
	root := rootKey(t)
	material, stage, err := root.Derive("service", awsCreated)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := New(SigV4(), stage, material)
	if err != nil {
		t.Fatal(err)
	}
	// Same instant claimed everywhere and internally consistent, only the
	// key's baked date disagrees. Nothing here consults a clock: the
	// rejection can only come from the scope comparison.
	nextDay := awsCreated.Add(24 * time.Hour)
	keyid := strings.Replace(mustKeyID(t, root, awsCreated), "/20120525/", "/20120526/", 1)
	var se *ScopeError
	if _, err := staged.Verifier(keyid, nextDay); !errors.As(err, &se) || se.Step != "date" {
		t.Fatalf("got %v, want ScopeError on the date step", err)
	}
	if se.Claimed != "20120526" || se.Expected() != "20120525" {
		t.Errorf("ScopeError = {Claimed: %q, Expected: %q}", se.Claimed, se.Expected())
	}
}

func mustKeyID(t *testing.T, k *Key, created time.Time) string {
	t.Helper()
	keyid, err := k.KeyID(created)
	if err != nil {
		t.Fatal(err)
	}
	return keyid
}

// TestEndToEnd signs a base with the root secret and verifies it with a
// service-scoped stage key, the broker hand-off this package exists for.
func TestEndToEnd(t *testing.T) {
	root := rootKey(t)
	keyid, err := root.KeyID(awsCreated)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := root.Signer(awsCreated)
	if err != nil {
		t.Fatal(err)
	}
	base := []byte("\"@method\": POST\n\"@signature-params\": ...")
	sig, err := signer.Sign(base)
	if err != nil {
		t.Fatal(err)
	}

	material, stage, err := root.Derive("service", awsCreated)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(SigV4(), stage, material)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := service.Verifier(keyid, awsCreated)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(base, sig); err != nil {
		t.Fatalf("service stage does not verify root signature: %v", err)
	}
	if verifier.Algorithm() != httpsig.HMACSHA256 {
		t.Errorf("Algorithm = %q, want hmac-sha256", verifier.Algorithm())
	}
	// Tampered base fails as a signature mismatch, not a scope error.
	if err := verifier.Verify([]byte("tampered"), sig); !errors.Is(err, httpsig.ErrSignatureMismatch) {
		t.Errorf("tampered base: got %v, want ErrSignatureMismatch", err)
	}
}

func TestZeroCreated(t *testing.T) {
	root := rootKey(t)
	if _, err := root.Signer(time.Time{}); err == nil {
		t.Error("Signer accepted a zero created time on a dated chain")
	}
	if _, err := root.KeyID(time.Time{}); err == nil {
		t.Error("KeyID accepted a zero created time on a dated chain")
	}
	// A chain without a date step needs no created time.
	undated := Derivation{Kind: KindHMACLadder, Steps: []Step{{Name: "service", Scope: true}}}
	k, err := New(undated, Stage{Name: "k1", Scope: map[string]string{"service": "iam"}}, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Signer(time.Time{}); err != nil {
		t.Errorf("undated chain rejected zero created: %v", err)
	}
}

func TestParseKeyID(t *testing.T) {
	claim, err := ParseKeyID(SigV4(), "AKIAIOSFODNN7EXAMPLE/20120525/us-east-1/glacier/aws4_request")
	if err != nil {
		t.Fatal(err)
	}
	if claim.Name() != awsAccessKeyID {
		t.Errorf("Name = %q", claim.Name())
	}
	for k, want := range awsScope() {
		if got := claim.Claimed(k); got != want {
			t.Errorf("Claimed(%s) = %q, want %q", k, got, want)
		}
	}
	if got := claim.Claimed("terminator"); got != "" {
		t.Errorf("Claimed(terminator) = %q, want empty: literals are fixed by the derivation", got)
	}
	for _, bad := range []string{
		"AKIA/20120525/us-east-1/glacier/wrong-literal",
		"AKIA/20120525/us-east-1/glacier",
		"/20120525/us-east-1/glacier/aws4_request",
		"AKIA/20120525//glacier/aws4_request",
		strings.Repeat("x", 4096),
	} {
		if _, err := ParseKeyID(SigV4(), bad); err == nil {
			t.Errorf("ParseKeyID accepted %q", bad)
		}
	}
}

func TestValidation(t *testing.T) {
	valid := SigV4()
	secret := []byte("secret")
	okStage := Stage{Name: "k1", Scope: map[string]string{"region": "us-east-1", "service": "iam"}}
	if _, err := New(valid, okStage, secret); err != nil {
		t.Fatalf("valid inputs rejected: %v", err)
	}

	tests := []struct {
		name   string
		d      func(Derivation) Derivation
		s      func(Stage) Stage
		secret []byte
	}{
		{name: "unknown kind", d: func(d Derivation) Derivation { d.Kind = "hkdf"; return d }},
		{name: "unknown hash", d: func(d Derivation) Derivation { d.Hash = "md5"; return d }},
		{name: "no steps", d: func(d Derivation) Derivation { d.Steps = nil; return d }},
		{name: "duplicate step names", d: func(d Derivation) Derivation {
			d.Steps[1].Name = d.Steps[2].Name
			return d
		}},
		{name: "step with no input", d: func(d Derivation) Derivation {
			d.Steps[1].Scope = false
			return d
		}},
		{name: "step with two inputs", d: func(d Derivation) Derivation {
			d.Steps[1].Literal = "x"
			return d
		}},
		{name: "literal with separator", d: func(d Derivation) Derivation {
			d.Steps[3].Literal = "aws4/request"
			return d
		}},
		{name: "date format outside the closed set", d: func(d Derivation) Derivation {
			d.Steps[0].Date = "2006/01/02"
			return d
		}},
		{name: "go layout is not a format token", d: func(d Derivation) Derivation {
			// The serialized form is language-neutral; a Go layout
			// that would work here must not silently validate.
			d.Steps[0].Date = "20060102"
			return d
		}},
		{name: "strftime is not a format token", d: func(d Derivation) Derivation {
			d.Steps[0].Date = "%Y%m%d"
			return d
		}},
		{name: "empty stage name", s: func(s Stage) Stage { s.Name = ""; return s }},
		{name: "stage name with separator", s: func(s Stage) Stage { s.Name = "a/b"; return s }},
		{name: "unknown from step", s: func(s Stage) Stage { s.From = "nope"; return s }},
		{name: "missing scope value", s: func(s Stage) Stage {
			s.Scope = map[string]string{"region": "us-east-1"}
			return s
		}},
		{name: "scope value with separator", s: func(s Stage) Stage {
			s.Scope["service"] = "a/b"
			return s
		}},
		{name: "extra scope key", s: func(s Stage) Stage {
			s.Scope["extra"] = "x"
			return s
		}},
		{name: "date assertion missing for staged key", s: func(s Stage) Stage {
			s.From = "date"
			return s
		}},
		{name: "date assertion not a date", s: func(s Stage) Stage {
			s.From = "date"
			s.Scope["date"] = "May 25 2012"
			return s
		}},
		{name: "empty key", secret: []byte{}},
	}
	for _, tt := range tests {
		d, s, key := valid, okStage, secret
		s.Scope = map[string]string{"region": "us-east-1", "service": "iam"}
		if tt.d != nil {
			d = tt.d(SigV4())
		}
		if tt.s != nil {
			s = tt.s(s)
		}
		if tt.secret != nil {
			key = tt.secret
		}
		if _, err := New(d, s, key); err == nil {
			t.Errorf("%s: accepted", tt.name)
		}
	}
}

// TestSerialization round-trips the derivation and a stage through JSON and
// confirms the deserialized forms verify a signature made by the originals.
func TestSerialization(t *testing.T) {
	root := rootKey(t)
	material, stage, err := root.Derive("service", awsCreated)
	if err != nil {
		t.Fatal(err)
	}
	dJSON, err := json.Marshal(SigV4())
	if err != nil {
		t.Fatal(err)
	}
	sJSON, err := json.Marshal(stage)
	if err != nil {
		t.Fatal(err)
	}
	var d2 Derivation
	var s2 Stage
	if err := json.Unmarshal(dJSON, &d2); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(sJSON, &s2); err != nil {
		t.Fatal(err)
	}
	restored, err := New(d2, s2, material)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := root.Signer(awsCreated)
	if err != nil {
		t.Fatal(err)
	}
	base := []byte("base")
	sig, err := signer.Sign(base)
	if err != nil {
		t.Fatal(err)
	}
	keyid, err := root.KeyID(awsCreated)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := restored.Verifier(keyid, awsCreated)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(base, sig); err != nil {
		t.Errorf("round-tripped config does not verify: %v", err)
	}
}

// TestUnmarshalRejectsInvalid checks that an invalid derivation fails where
// it is decoded: a broker or config loader that never calls New must not be
// able to store and forward a ladder that fails at some other party's New.
func TestUnmarshalRejectsInvalid(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown kind":    `{"kind":"hkdf","steps":[{"name":"d","date":"YYYYMMDD"}]}`,
		"unknown hash":    `{"kind":"hmac-ladder","hash":"md5","steps":[{"name":"d","date":"YYYYMMDD"}]}`,
		"no steps":        `{"kind":"hmac-ladder"}`,
		"two inputs":      `{"kind":"hmac-ladder","steps":[{"name":"d","date":"YYYYMMDD","literal":"x"}]}`,
		"no input":        `{"kind":"hmac-ladder","steps":[{"name":"d"}]}`,
		"duplicate names": `{"kind":"hmac-ladder","steps":[{"name":"d","date":"YYYYMMDD"},{"name":"d","scope":true}]}`,
	} {
		var d Derivation
		if err := json.Unmarshal([]byte(doc), &d); err == nil {
			t.Errorf("%s: unmarshal accepted %s", name, doc)
		}
	}
	// The SigV4 chain round-trips through its own UnmarshalJSON with
	// nothing lost: the JSON fully determines the ladder, secret prefix
	// included.
	data, err := json.Marshal(SigV4())
	if err != nil {
		t.Fatal(err)
	}
	var d Derivation
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, SigV4()) {
		t.Fatalf("round trip changed the derivation:\n got  %+v\n want %+v", d, SigV4())
	}
}

// TestDeriveMemo checks the single-entry memo: repeated derivation for the
// same date reuses the result, a different date recomputes correctly, and
// returning to the first date recomputes correctly again (the memo holds
// only the most recent entry). Correctness under memo churn is what matters;
// signatures must be identical with and without hits.
func TestDeriveMemo(t *testing.T) {
	root := rootKey(t)
	base := []byte("base")
	sigFor := func(created time.Time) []byte {
		t.Helper()
		signer, err := root.Signer(created)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := signer.Sign(base)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	day1a := sigFor(awsCreated)
	day1b := sigFor(awsCreated)                    // memo hit
	day2 := sigFor(awsCreated.Add(24 * time.Hour)) // memo replaced
	day1c := sigFor(awsCreated)                    // recomputed after eviction
	if !hmac.Equal(day1a, day1b) || !hmac.Equal(day1a, day1c) {
		t.Error("same-date signatures differ across memo states")
	}
	if hmac.Equal(day1a, day2) {
		t.Error("different dates produced the same signature")
	}
	// Concurrent use with mixed dates stays consistent.
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 100 {
				created := awsCreated.Add(time.Duration(i%2) * 24 * time.Hour)
				signer, err := root.Signer(created)
				if err != nil {
					t.Error(err)
					return
				}
				got, err := signer.Sign(base)
				if err != nil {
					t.Error(err)
					return
				}
				want := day1a
				if i%2 == 1 {
					want = day2
				}
				if !hmac.Equal(got, want) {
					t.Errorf("concurrent derive for day %d produced a wrong signature", i%2)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestSupportedHashes(t *testing.T) {
	base := []byte("base")
	sigFor := func(h string) []byte {
		t.Helper()
		d := SigV4()
		d.Hash = h
		k, err := New(d, Stage{
			Name:  awsAccessKeyID,
			Scope: map[string]string{"region": "us-east-1", "service": "glacier"},
		}, []byte(awsSecret))
		if err != nil {
			t.Fatalf("hash %q: %v", h, err)
		}
		signer, err := k.Signer(awsCreated)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := signer.Sign(base)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	// An empty Hash defaults to SHA-256, and SHA-512 must actually change
	// the ladder rather than being accepted and ignored.
	if !hmac.Equal(sigFor(""), sigFor(HashSHA256)) {
		t.Error("empty Hash does not default to HashSHA256")
	}
	if hmac.Equal(sigFor(HashSHA256), sigFor(HashSHA512)) {
		t.Error("HashSHA512 derives the same key as HashSHA256")
	}
	// The signature stays hmac-sha256 regardless; the hash governs only
	// key derivation.
	for _, h := range []string{HashSHA256, HashSHA512} {
		if got := len(sigFor(h)); got != 32 {
			t.Errorf("hash %q: signature is %d bytes, want 32 (hmac-sha256)", h, got)
		}
	}
}

// foldScopePath is an independent reimplementation of the derivation that
// uses none of this package's types: it takes a secret and a credential
// scope path string, skips the leading key name, and folds HMAC over the
// remaining segments. A client in another language has exactly this much to
// work from, so it stands in for one here.
func foldScopePath(hashFn func() hash.Hash, prefix, secret, scopePath string, from int) []byte {
	segments := strings.Split(scopePath, "/")[1:] // drop the key name
	key := []byte(prefix + secret)
	for _, seg := range segments[from:] {
		m := hmac.New(hashFn, key)
		m.Write([]byte(seg))
		key = m.Sum(nil)
	}
	return key
}

// TestScopePathFoldInterop pins the interoperability contract for an
// independent implementation: the derived key is a function of the secret
// and the credential scope path alone. A foreign client needs no Derivation
// config, only the scope path this package puts in the keyid, and folding
// HMAC over that path's segments reproduces the same signatures.
//
// The contract must hold for chains other than SigV4 and for keys handed
// off partway down the ladder, since those are the cases where a foreign
// implementation could silently disagree.
func TestScopePathFoldInterop(t *testing.T) {
	base := []byte("\"@method\": POST\n\"@signature-params\": (\"@method\")")

	// A chain with different steps, a different secret prefix, a different
	// terminator, and a different date format from SigV4's.
	generic := Derivation{
		Kind:         KindHMACLadder,
		Hash:         HashSHA512,
		SecretPrefix: "KUBERNETES",
		Steps: []Step{
			{Name: "date", Date: "YYYY-MM-DD"},
			{Name: "region", Scope: true},
			{Name: "cluster", Scope: true},
			{Name: "terminator", Literal: "k8s_request"},
		},
	}
	genericScope := map[string]string{"region": "us-east-1", "cluster": "prod01"}
	sigv4Scope := map[string]string{"region": "us-east-1", "service": "glacier"}

	tests := []struct {
		name    string
		chain   Derivation
		scope   map[string]string
		secret  string
		hashFn  func() hash.Hash
		from    string // stage hand-off point, empty for root
		fromIdx int    // segments already folded into the stage key
	}{
		{name: "sigv4 root", chain: SigV4(), scope: sigv4Scope, secret: awsSecret, hashFn: sha256.New},
		{name: "generic chain root", chain: generic, scope: genericScope, secret: "s3cret", hashFn: sha512.New},
		{name: "sigv4 from date", chain: SigV4(), scope: sigv4Scope, secret: awsSecret, hashFn: sha256.New, from: "date", fromIdx: 1},
		{name: "sigv4 from service", chain: SigV4(), scope: sigv4Scope, secret: awsSecret, hashFn: sha256.New, from: "service", fromIdx: 3},
		{name: "generic from cluster", chain: generic, scope: genericScope, secret: "s3cret", hashFn: sha512.New, from: "cluster", fromIdx: 3},
	}
	for _, tt := range tests {
		// The party holding the root secret, which is what an
		// independent implementation reproduces from the scope path.
		root, err := New(tt.chain, Stage{Name: awsAccessKeyID, Scope: tt.scope}, []byte(tt.secret))
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		scopePath, err := root.KeyID(awsCreated)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}

		// This package's signature, from whichever rung the test holds.
		holder := root
		if tt.from != "" {
			material, stage, err := root.Derive(tt.from, awsCreated)
			if err != nil {
				t.Fatalf("%s: %v", tt.name, err)
			}
			if holder, err = New(tt.chain, stage, material); err != nil {
				t.Fatalf("%s: %v", tt.name, err)
			}
		}
		signer, err := holder.Signer(awsCreated)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		got, err := signer.Sign(base)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}

		// The independent implementation's signature: fold the whole
		// path from the root secret, then HMAC-SHA256 the base, which
		// is what RFC 9421's hmac-sha256 does.
		derived := foldScopePath(tt.hashFn, tt.chain.SecretPrefix, tt.secret, scopePath, 0)
		m := hmac.New(sha256.New, derived)
		m.Write(base)
		if want := m.Sum(nil); !hmac.Equal(got, want) {
			t.Errorf("%s: signature differs from an independent scope-path fold", tt.name)
		}

		// A stage key must equal the fold up to its hand-off point, so
		// a foreign broker can vend the same intermediate.
		if tt.from != "" {
			material, _, err := root.Derive(tt.from, awsCreated)
			if err != nil {
				t.Fatal(err)
			}
			segments := strings.Split(scopePath, "/")
			truncated := strings.Join(segments[:1+tt.fromIdx], "/")
			if want := foldScopePath(tt.hashFn, tt.chain.SecretPrefix, tt.secret, truncated, 0); !hmac.Equal(material, want) {
				t.Errorf("%s: stage key differs from an independent partial fold", tt.name)
			}
		}
	}
}

func TestDeriveErrors(t *testing.T) {
	root := rootKey(t)
	if _, _, err := root.Derive("nope", awsCreated); err == nil {
		t.Error("Derive accepted an unknown step")
	}
	material, stage, err := root.Derive("service", awsCreated)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := New(SigV4(), stage, material)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := staged.Derive("date", awsCreated); err == nil {
		t.Error("Derive re-applied an already-applied step")
	}
	// Deriving further from a stage works and stays consistent.
	m2, s2, err := staged.Derive("terminator", awsCreated)
	if err != nil {
		t.Fatal(err)
	}
	m3, _, err := root.Derive("terminator", awsCreated)
	if err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(m2, m3) {
		t.Error("stage-derived terminator key differs from root-derived")
	}
	if s2.From != "terminator" {
		t.Errorf("stage From = %q", s2.From)
	}
}
