// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig/sigconfig"
)

func BenchmarkMiddlewareAccept(b *testing.B) {
	e := newEnv(b)
	m, err := New(e.dir, sigconfig.VerifyPolicy{
		Coverage: sigconfig.Coverage{Components: []string{`"@method"`, `"@path"`}},
	})
	if err != nil {
		b.Fatal(err)
	}
	body := strings.Repeat("x", 1024)
	signed := e.signedRequest(b, "POST", "http://svc.test/act", body,
		httpsig.SignOptions{Components: defaultComponents})
	raw, _ := io.ReadAll(signed.Body)
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	b.ReportAllocs()
	for b.Loop() {
		req := signed.Clone(signed.Context())
		req.Body = io.NopCloser(bytes.NewReader(raw))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("status %d", rec.Code)
		}
	}
}
