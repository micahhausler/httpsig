// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig/client"
	"github.com/micahhausler/httpsig/server"
	"github.com/micahhausler/httpsig/sigconfig"
)

// TestEndToEnd runs a client Transport against a Middleware-wrapped server
// over a real HTTP connection, with one signing profile serving both a
// bodiless GET and a POST with a body.
func TestEndToEnd(t *testing.T) {
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

	type account struct{ ID string }
	dir := server.KeyDirectoryFunc[account](func(r *http.Request, sig *httpsig.Signature) (httpsig.Verifier, account, error) {
		if sig.KeyID() != "acct-42" {
			return nil, account{}, fmt.Errorf("unknown key %q", sig.KeyID())
		}
		return verifier, account{ID: "42"}, nil
	})

	// The dual documents: profile covers what the policy requires.
	coverage := []string{`"@method"`, `"@authority"`, `"@path"`}
	mw, err := server.New(dir, sigconfig.VerifyPolicy{
		Coverage:   sigconfig.Coverage{Components: coverage},
		MaxAge:     sigconfig.Duration(time.Minute),
		Algorithms: []string{"ed25519"},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := server.FromRequest[account](r)
		if !ok {
			t.Error("no verified identity in handler")
		}
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "account=%s body=%d", v.Identity.ID, len(body))
	})))
	defer srv.Close()

	rt, err := client.NewTransport(nil, signer, sigconfig.SigningProfile{
		Coverage: sigconfig.Coverage{Components: coverage},
		KeyID:    "acct-42",
		TTL:      sigconfig.Duration(30 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: rt}

	get, err := c.Get(srv.URL + "/data")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(get.Body)
	get.Body.Close()
	if get.StatusCode != http.StatusOK || string(body) != "account=42 body=0" {
		t.Errorf("GET: %d %q", get.StatusCode, body)
	}

	post, err := c.Post(srv.URL+"/data", "application/json", strings.NewReader(`{"n":7}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(post.Body)
	post.Body.Close()
	if post.StatusCode != http.StatusOK || string(body) != "account=42 body=7" {
		t.Errorf("POST: %d %q", post.StatusCode, body)
	}

	// An unsigned client is turned away.
	plain, err := http.Get(srv.URL + "/data")
	if err != nil {
		t.Fatal(err)
	}
	plain.Body.Close()
	if plain.StatusCode != http.StatusUnauthorized {
		t.Errorf("unsigned GET: %d, want 401", plain.StatusCode)
	}
}
