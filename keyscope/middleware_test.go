// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package keyscope_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig/keyscope"
	"github.com/micahhausler/httpsig/server"
	"github.com/micahhausler/httpsig/sigconfig"
)

// TestMiddleware proves the integration the package documentation promises:
// a client signs with the root secret via httpsig.Sign, and the server
// middleware verifies with a service-scoped stage key through a
// KeyDirectoryFunc, never holding the root secret.
func TestMiddleware(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	root, err := keyscope.New(keyscope.SigV4(), keyscope.Stage{
		Name:  "AKIAIOSFODNN7EXAMPLE",
		Scope: map[string]string{"region": "us-east-1", "service": "glacier"},
	}, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}

	// The middleware checks MaxAge against the real clock, so signatures
	// carry a fresh timestamp and the broker hand-off is for today: the
	// service receives only today's service-scoped key.
	now := time.Now().UTC()
	material, stage, err := root.Derive("service", now)
	if err != nil {
		t.Fatal(err)
	}
	serviceKey, err := keyscope.New(keyscope.SigV4(), stage, material)
	if err != nil {
		t.Fatal(err)
	}

	dir := server.KeyDirectoryFunc[string](
		func(r *http.Request, sig *httpsig.Signature) (httpsig.Verifier, string, error) {
			v, err := serviceKey.Verifier(sig.KeyID(), sig.Created())
			return v, sig.KeyID(), err
		})
	policy := sigconfig.VerifyPolicy{
		Coverage:   sigconfig.Coverage{Components: []string{`"@method"`, `"@target-uri"`}},
		Algorithms: []string{string(httpsig.HMACSHA256)},
		MaxAge:     sigconfig.Duration(time.Hour),
	}
	mw, err := server.New(dir, policy)
	if err != nil {
		t.Fatal(err)
	}
	var sawIdentity string
	handler := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, ok := server.FromRequest[string](r); ok {
			sawIdentity = v.Identity
		}
		w.WriteHeader(http.StatusOK)
	}))

	// rejecting wraps the same directory and policy with an error
	// handler that captures the rejection for assertions.
	rejecting := func(t *testing.T, gotErr *error) http.Handler {
		t.Helper()
		mw, err := server.New(dir, policy,
			server.WithErrorHandler[string](func(w http.ResponseWriter, r *http.Request, err error) {
				*gotErr = err
				w.WriteHeader(http.StatusUnauthorized)
			}))
		if err != nil {
			t.Fatal(err)
		}
		return mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	}

	sign := func(created time.Time, mutate func(*http.Request)) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "https://api.example.test/v1/thing", nil)
		keyid, err := root.KeyID(created)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := root.Signer(created)
		if err != nil {
			t.Fatal(err)
		}
		err = httpsig.Sign(req, signer, httpsig.SignOptions{
			Components: []httpsig.Component{{Name: "@method"}, {Name: "@target-uri"}},
			// One timestamp feeds both derivation and the created
			// parameter; a divergence across midnight derives for
			// one date and claims another.
			Created: created,
			KeyID:   keyid,
		})
		if err != nil {
			t.Fatal(err)
		}
		if mutate != nil {
			mutate(req)
		}
		return req
	}

	t.Run("verifies", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, sign(now, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		want, _ := root.KeyID(now)
		if sawIdentity != want {
			t.Errorf("identity = %q, want %q", sawIdentity, want)
		}
	})

	t.Run("wrong scope in keyid is rejected", func(t *testing.T) {
		var gotErr error
		h := rejecting(t, &gotErr)
		req := sign(now, func(r *http.Request) {
			// Re-sign for another service; the stage key must name
			// the scope error rather than report bad signature math.
			other, err := keyscope.New(keyscope.SigV4(), keyscope.Stage{
				Name:  "AKIAIOSFODNN7EXAMPLE",
				Scope: map[string]string{"region": "us-east-1", "service": "s3"},
			}, []byte(secret))
			if err != nil {
				t.Fatal(err)
			}
			keyid, _ := other.KeyID(now)
			signer, _ := other.Signer(now)
			r.Header.Del("Signature")
			r.Header.Del("Signature-Input")
			err = httpsig.Sign(r, signer, httpsig.SignOptions{
				Components: []httpsig.Component{{Name: "@method"}, {Name: "@target-uri"}},
				Created:    now,
				KeyID:      keyid,
			})
			if err != nil {
				t.Fatal(err)
			}
		})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", rec.Code)
		}
		if !errors.Is(gotErr, keyscope.ErrScopeMismatch) {
			t.Errorf("got %v, want ErrScopeMismatch", gotErr)
		}
		if !strings.Contains(gotErr.Error(), "service") {
			t.Errorf("error %q does not name the service step", gotErr)
		}
	})

	t.Run("tampered request is a signature mismatch", func(t *testing.T) {
		var gotErr error
		h := rejecting(t, &gotErr)
		req := sign(now, func(r *http.Request) {
			r.URL.Path = "/v1/other"
		})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", rec.Code)
		}
		if !errors.Is(gotErr, httpsig.ErrSignatureMismatch) {
			t.Errorf("got %v, want ErrSignatureMismatch", gotErr)
		}
	})
}
