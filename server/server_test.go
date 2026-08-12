// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig/sigconfig"
)

type user struct{ Name string }

type env struct {
	signer   httpsig.Signer
	verifier httpsig.Verifier
	dir      KeyDirectory[user]
}

func newEnv(t testing.TB) *env {
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
	e := &env{signer: signer, verifier: verifier}
	e.dir = KeyDirectoryFunc[user](func(r *http.Request, sig *httpsig.Signature) (httpsig.Verifier, user, error) {
		if sig.KeyID() != "k1" {
			return nil, user{}, fmt.Errorf("unknown key %q", sig.KeyID())
		}
		return e.verifier, user{Name: "alice"}, nil
	})
	return e
}

func digestOf(body string) string {
	d := sha256.Sum256([]byte(body))
	return "sha-256=:" + base64.StdEncoding.EncodeToString(d[:]) + ":"
}

// signedRequest builds an inbound request signed over the given components,
// attaching a correct Content-Digest when body is non-empty.
func (e *env) signedRequest(t testing.TB, method, url, body string, opts httpsig.SignOptions) *http.Request {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, url, r)
	if body != "" {
		req.Header.Set("Content-Digest", digestOf(body))
	}
	if opts.KeyID == "" {
		opts.KeyID = "k1"
	}
	if err := httpsig.Sign(req, e.signer, opts); err != nil {
		t.Fatal(err)
	}
	return req
}

var defaultComponents = []httpsig.Component{{Name: "@method"}, {Name: "@path"}, {Name: "content-digest"}}

func serve(t *testing.T, m *Middleware[user], req *http.Request) (*httptest.ResponseRecorder, *Verified[user]) {
	t.Helper()
	var got *Verified[user]
	rec := httptest.NewRecorder()
	m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = FromRequest[user](r)
	})).ServeHTTP(rec, req)
	return rec, got
}

func TestAcceptWithIdentity(t *testing.T) {
	e := newEnv(t)
	m, err := New(e.dir, sigconfig.VerifyPolicy{
		Coverage: sigconfig.Coverage{Components: []string{`"@method"`, `"@path"`}},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := e.signedRequest(t, "POST", "http://svc.test/act", `{"x":1}`,
		httpsig.SignOptions{Components: defaultComponents})
	rec, v := serve(t, m, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if v == nil || v.Identity.Name != "alice" {
		t.Fatalf("identity = %+v", v)
	}
	if v.Signature.KeyID() != "k1" {
		t.Errorf("signature keyid = %q", v.Signature.KeyID())
	}
}

func TestFromRequestTypeMismatch(t *testing.T) {
	e := newEnv(t)
	m, _ := New(e.dir, sigconfig.VerifyPolicy{})
	req := e.signedRequest(t, "GET", "http://svc.test/", "",
		httpsig.SignOptions{})
	rec := httptest.NewRecorder()
	m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := FromRequest[user](r); !ok {
			t.Error("FromRequest[user] did not match")
		}
		defer func() {
			if recover() == nil {
				t.Error("FromRequest[string] on a Middleware[user] request did not panic")
			}
		}()
		FromRequest[string](r)
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	// A request that never passed through the middleware reports false,
	// no panic.
	if _, ok := FromRequest[user](httptest.NewRequest("GET", "http://svc.test/", nil)); ok {
		t.Error("FromRequest matched an unwrapped request")
	}
}

func TestUnsignedRejected(t *testing.T) {
	e := newEnv(t)
	m, _ := New(e.dir, sigconfig.VerifyPolicy{})
	rec, _ := serve(t, m, httptest.NewRequest("GET", "http://svc.test/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", rec.Code)
	}
}

func TestBodyAddedToSignedGetRejected(t *testing.T) {
	// The hole when-body closes: take a valid bodiless signature, then
	// attach a body. The signature still verifies; the digest rule must
	// be what rejects it.
	e := newEnv(t)
	m, _ := New(e.dir, sigconfig.VerifyPolicy{})
	req := e.signedRequest(t, "GET", "http://svc.test/", "",
		httpsig.SignOptions{})
	req.Body = io.NopCloser(strings.NewReader("attacker body"))
	rec, _ := serve(t, m, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401 for unsigned body on signed GET", rec.Code)
	}
}

func TestTamperedBodyRejected(t *testing.T) {
	e := newEnv(t)
	m, _ := New(e.dir, sigconfig.VerifyPolicy{})
	req := e.signedRequest(t, "POST", "http://svc.test/", "original",
		httpsig.SignOptions{Components: defaultComponents})
	req.Body = io.NopCloser(strings.NewReader("tampered!"))
	rec, _ := serve(t, m, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", rec.Code)
	}
}

func TestUncoveredDigestRejected(t *testing.T) {
	// Correct digest header, but the signature does not cover it: an
	// intermediary could swap body and header together.
	e := newEnv(t)
	m, _ := New(e.dir, sigconfig.VerifyPolicy{})
	req := e.signedRequest(t, "POST", "http://svc.test/", "body",
		httpsig.SignOptions{Components: []httpsig.Component{{Name: "@method"}}})
	rec, _ := serve(t, m, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401 for uncovered content-digest", rec.Code)
	}
}

func TestGarbageSignatureAlongsideValidAccepted(t *testing.T) {
	e := newEnv(t)
	m, _ := New(e.dir, sigconfig.VerifyPolicy{})
	req := e.signedRequest(t, "GET", "http://svc.test/", "",
		httpsig.SignOptions{})
	req.Header.Add("Signature-Input", `garbage=("@method");keyid="who"`)
	req.Header.Add("Signature", `garbage=:AAAA:`)
	rec, v := serve(t, m, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: appended garbage broke acceptance", rec.Code)
	}
	if v == nil || v.Signature.Label() == "garbage" {
		t.Errorf("accepted wrong signature: %+v", v)
	}
}

func TestRequiredComponentsEnforced(t *testing.T) {
	e := newEnv(t)
	m, _ := New(e.dir, sigconfig.VerifyPolicy{
		Coverage: sigconfig.Coverage{Components: []string{`"@method"`, `"@authority"`}},
	})
	req := e.signedRequest(t, "GET", "http://svc.test/", "",
		httpsig.SignOptions{Components: []httpsig.Component{{Name: "@method"}}})
	rec, _ := serve(t, m, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401 for missing @authority coverage", rec.Code)
	}
}

func TestTagSelection(t *testing.T) {
	e := newEnv(t)
	m, _ := New(e.dir, sigconfig.VerifyPolicy{Tag: "svc"})
	wrong := e.signedRequest(t, "GET", "http://svc.test/", "",
		httpsig.SignOptions{Tag: "other"})
	rec, _ := serve(t, m, wrong)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401 for tag mismatch", rec.Code)
	}
	right := e.signedRequest(t, "GET", "http://svc.test/", "",
		httpsig.SignOptions{Tag: "svc"})
	rec, _ = serve(t, m, right)
	if rec.Code != http.StatusOK {
		t.Errorf("status %d, want 200", rec.Code)
	}
}

func TestAlgorithmRestriction(t *testing.T) {
	e := newEnv(t)
	m, _ := New(e.dir, sigconfig.VerifyPolicy{Algorithms: []string{"ecdsa-p256-sha256"}})
	req := e.signedRequest(t, "GET", "http://svc.test/", "",
		httpsig.SignOptions{})
	rec, _ := serve(t, m, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401: ed25519 key against ecdsa-only policy", rec.Code)
	}
}

func TestBodyTooLarge(t *testing.T) {
	e := newEnv(t)
	m, _ := New(e.dir, sigconfig.VerifyPolicy{MaxBodyBytes: 8})
	req := e.signedRequest(t, "POST", "http://svc.test/", "well over eight bytes",
		httpsig.SignOptions{Components: defaultComponents})
	rec, _ := serve(t, m, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d, want 413", rec.Code)
	}
}

func TestHandlerReadsReplayedBody(t *testing.T) {
	e := newEnv(t)
	m, _ := New(e.dir, sigconfig.VerifyPolicy{})
	req := e.signedRequest(t, "POST", "http://svc.test/", "payload",
		httpsig.SignOptions{Components: defaultComponents})
	rec := httptest.NewRecorder()
	m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil || string(got) != "payload" {
			t.Errorf("handler body = %q, %v", got, err)
		}
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestErrorHandlerOverride(t *testing.T) {
	e := newEnv(t)
	var seen error
	m, err := New(e.dir, sigconfig.VerifyPolicy{},
		WithErrorHandler[user](func(w http.ResponseWriter, r *http.Request, err error) {
			seen = err
			w.WriteHeader(http.StatusTeapot)
		}))
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := serve(t, m, httptest.NewRequest("GET", "http://svc.test/", nil))
	if rec.Code != http.StatusTeapot {
		t.Errorf("status %d", rec.Code)
	}
	if !errors.Is(seen, ErrUnsigned) {
		t.Errorf("err = %v, want ErrUnsigned", seen)
	}
}

func TestDefaultMaxAgeRejectsStaleSignature(t *testing.T) {
	// A policy that says nothing about age still bounds it: zero-value
	// MaxAge means the sigconfig default, not "no check".
	e := newEnv(t)
	m, _ := New(e.dir, sigconfig.VerifyPolicy{})
	stale := e.signedRequest(t, "GET", "http://svc.test/", "",
		httpsig.SignOptions{Created: time.Now().Add(-time.Duration(sigconfig.DefaultMaxAge) - time.Minute)})
	rec, _ := serve(t, m, stale)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401 for stale signature under default MaxAge", rec.Code)
	}
	// Negative MaxAge is the explicit opt-out.
	off, _ := New(e.dir, sigconfig.VerifyPolicy{MaxAge: sigconfig.Duration(-time.Second)})
	rec, _ = serve(t, off, e.signedRequest(t, "GET", "http://svc.test/", "",
		httpsig.SignOptions{Created: time.Now().Add(-24 * time.Hour)}))
	if rec.Code != http.StatusOK {
		t.Errorf("status %d, want 200 with age bound disabled", rec.Code)
	}
}

func TestConstructorRejections(t *testing.T) {
	e := newEnv(t)
	if _, err := New[user](nil, sigconfig.VerifyPolicy{}); err == nil {
		t.Error("nil directory accepted")
	}
	bad := sigconfig.VerifyPolicy{Coverage: sigconfig.Coverage{Components: []string{`@method`}}}
	if _, err := New(e.dir, bad); err == nil {
		t.Error("bare component form accepted")
	}
	never := sigconfig.VerifyPolicy{Coverage: sigconfig.Coverage{ContentDigest: sigconfig.DigestNever}}
	if _, err := New(e.dir, never); err == nil {
		t.Error("contentDigest never accepted in a verify policy")
	}
}
