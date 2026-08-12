// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig/sigconfig"
)

// captureTransport records the outgoing request instead of sending it.
type captureTransport struct {
	req *http.Request
}

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.req = req
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: req}, nil
}

func testKeys(t testing.TB) (httpsig.Signer, httpsig.Verifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := httpsig.NewSigner(httpsig.Ed25519, priv)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := httpsig.NewVerifier(httpsig.Ed25519, pub)
	if err != nil {
		t.Fatal(err)
	}
	return signer, verifier
}

// send signs req through a Transport built from profile and returns the
// request as it would hit the wire.
func send(t *testing.T, profile sigconfig.SigningProfile, req *http.Request) (*http.Request, httpsig.Verifier) {
	t.Helper()
	signer, verifier := testKeys(t)
	capture := &captureTransport{}
	rt, err := NewTransport(capture, signer, profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	return capture.req, verifier
}

// parseOne parses exactly one signature off a captured request.
func parseOne(t *testing.T, req *http.Request) *httpsig.Signature {
	t.Helper()
	// The captured request is client-shaped; verification is
	// server-shaped. Rebuild it as an inbound request.
	inbound := httptest.NewRequest(req.Method, req.URL.String(), req.Body)
	inbound.Header = req.Header
	inbound.Host = req.URL.Host
	sigs, err := httpsig.ParseSignatures(inbound, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 {
		t.Fatalf("got %d signatures, want 1", len(sigs))
	}
	return sigs[0]
}

func covered(sig *httpsig.Signature) map[string]bool {
	m := map[string]bool{}
	for _, c := range sig.Components() {
		m[c.Name] = true
	}
	return m
}

func TestPostBodyGetsDigest(t *testing.T) {
	profile := sigconfig.SigningProfile{
		Coverage: sigconfig.Coverage{Components: []string{`"@method"`, `"@authority"`, `"@path"`}},
		KeyID:    "k1",
	}
	req, _ := http.NewRequest("POST", "http://example.com/upload", strings.NewReader(`{"a":1}`))
	wire, verifier := send(t, profile, req)

	if wire.Header.Get("Content-Digest") == "" {
		t.Fatal("no Content-Digest on request with body")
	}
	sig := parseOne(t, wire)
	if !covered(sig)["content-digest"] {
		t.Error("content-digest not covered")
	}
	if sig.KeyID() != "k1" {
		t.Errorf("keyid = %q", sig.KeyID())
	}
	if err := sig.Verify(verifier, httpsig.Policy{}); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestGetOmitsDigestWhenBodyMode(t *testing.T) {
	profile := sigconfig.SigningProfile{
		Coverage: sigconfig.Coverage{Components: []string{`"@method"`, `"@authority"`, `"@path"`}},
	}
	req, _ := http.NewRequest("GET", "http://example.com/data", nil)
	wire, verifier := send(t, profile, req)

	if got := wire.Header.Get("Content-Digest"); got != "" {
		t.Fatalf("Content-Digest %q on bodiless GET in when-body mode", got)
	}
	sig := parseOne(t, wire)
	if covered(sig)["content-digest"] {
		t.Error("content-digest covered on bodiless GET")
	}
	if err := sig.Verify(verifier, httpsig.Policy{}); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestGetAlwaysModeSignsEmptyDigest(t *testing.T) {
	profile := sigconfig.SigningProfile{
		Coverage: sigconfig.Coverage{
			Components:    []string{`"@method"`},
			ContentDigest: sigconfig.DigestAlways,
		},
	}
	req, _ := http.NewRequest("GET", "http://example.com/data", nil)
	wire, verifier := send(t, profile, req)

	// SHA-256 of the empty string.
	const emptyDigest = `sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:`
	if got := wire.Header.Get("Content-Digest"); got != emptyDigest {
		t.Errorf("Content-Digest = %q, want %q", got, emptyDigest)
	}
	sig := parseOne(t, wire)
	if !covered(sig)["content-digest"] {
		t.Error("content-digest not covered in always mode")
	}
	if err := sig.Verify(verifier, httpsig.Policy{}); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestNeverModeLeavesBodyStreaming(t *testing.T) {
	profile := sigconfig.SigningProfile{
		Coverage: sigconfig.Coverage{
			Components:    []string{`"@method"`},
			ContentDigest: sigconfig.DigestNever,
		},
	}
	req, _ := http.NewRequest("POST", "http://example.com/", strings.NewReader("data"))
	wire, _ := send(t, profile, req)
	if wire.Header.Get("Content-Digest") != "" {
		t.Error("Content-Digest set in never mode")
	}
}

func TestEmptyProfileSignsWireDefaults(t *testing.T) {
	req, _ := http.NewRequest("POST", "http://example.com/x", strings.NewReader("body"))
	wire, verifier := send(t, sigconfig.SigningProfile{}, req)
	sig := parseOne(t, wire)
	got := covered(sig)
	for _, want := range []string{"@method", "@target-uri", "content-digest"} {
		if !got[want] {
			t.Errorf("%s not covered; got %v", want, sig.Components())
		}
	}
	if err := sig.Verify(verifier, httpsig.Policy{}); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestCallerRequestNotMutated(t *testing.T) {
	req, _ := http.NewRequest("POST", "http://example.com/", strings.NewReader("body"))
	send(t, sigconfig.SigningProfile{}, req)
	if req.Header.Get("Signature") != "" || req.Header.Get("Signature-Input") != "" || req.Header.Get("Content-Digest") != "" {
		t.Error("caller's request was mutated")
	}
}

func TestParametersFromProfile(t *testing.T) {
	profile := sigconfig.SigningProfile{
		Label:      "app",
		KeyID:      "k9",
		Tag:        "svc",
		TTL:        sigconfig.Duration(5 * time.Minute),
		Nonce:      true,
		IncludeAlg: true,
	}
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	wire, _ := send(t, profile, req)
	sig := parseOne(t, wire)

	if sig.Label() != "app" {
		t.Errorf("label = %q", sig.Label())
	}
	if sig.Tag() != "svc" {
		t.Errorf("tag = %q", sig.Tag())
	}
	if sig.Alg() != httpsig.Ed25519 {
		t.Errorf("alg = %q", sig.Alg())
	}
	if sig.Nonce() == "" {
		t.Error("no nonce")
	}
	if sig.Created().IsZero() {
		t.Error("no created")
	}
	if want := sig.Created().Add(5 * time.Minute); !sig.Expires().Equal(want) {
		t.Errorf("expires = %v, want %v", sig.Expires(), want)
	}

	// A second request gets a different nonce.
	req2, _ := http.NewRequest("GET", "http://example.com/", nil)
	wire2, _ := send(t, profile, req2)
	if parseOne(t, wire2).Nonce() == sig.Nonce() {
		t.Error("nonce repeated across requests")
	}
}

func TestGetBodySetForRetries(t *testing.T) {
	req, _ := http.NewRequest("POST", "http://example.com/", strings.NewReader("body"))
	wire, _ := send(t, sigconfig.SigningProfile{}, req)
	if wire.GetBody == nil {
		t.Fatal("GetBody not set")
	}
	if wire.ContentLength != 4 {
		t.Errorf("ContentLength = %d", wire.ContentLength)
	}
}

func TestConstructorRejections(t *testing.T) {
	signer, _ := testKeys(t)
	if _, err := NewTransport(nil, nil, sigconfig.SigningProfile{}); err == nil {
		t.Error("nil signer accepted")
	}
	bad := sigconfig.SigningProfile{Coverage: sigconfig.Coverage{Components: []string{`@method`}}}
	if _, err := NewTransport(nil, signer, bad); err == nil {
		t.Error("bare component form accepted")
	}
}

func TestAuthorityAllowlist(t *testing.T) {
	profile := sigconfig.SigningProfile{Authorities: []string{"API.Example.com"}}
	signer, _ := testKeys(t)
	rt, err := NewTransport(&captureTransport{}, signer, profile)
	if err != nil {
		t.Fatal(err)
	}
	ok, _ := http.NewRequest("GET", "http://api.example.com/x", nil)
	if _, err := rt.RoundTrip(ok); err != nil {
		t.Errorf("allowed authority refused: %v", err)
	}
	// The redirect-harvest shape: same transport, different host.
	other, _ := http.NewRequest("GET", "http://evil.example.net/x", nil)
	if _, err := rt.RoundTrip(other); err == nil {
		t.Error("signed for a host outside the authorities list")
	}
}

func TestBodyOverProfileCapRefused(t *testing.T) {
	profile := sigconfig.SigningProfile{MaxBodyBytes: 8}
	signer, _ := testKeys(t)
	rt, err := NewTransport(&captureTransport{}, signer, profile)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", "http://example.com/", strings.NewReader("well over eight bytes"))
	if _, err := rt.RoundTrip(req); err == nil {
		t.Error("body over MaxBodyBytes was signed")
	}
	small, _ := http.NewRequest("POST", "http://example.com/", strings.NewReader("tiny"))
	if _, err := rt.RoundTrip(small); err != nil {
		t.Errorf("body under cap refused: %v", err)
	}
}
