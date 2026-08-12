// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"net/http"
	"strings"
	"testing"

	"github.com/micahhausler/httpsig/sigconfig"
)

func BenchmarkRoundTripSign(b *testing.B) {
	signer, _ := testKeys(b)
	rt, err := NewTransport(&captureTransport{}, signer, sigconfig.SigningProfile{
		Coverage: sigconfig.Coverage{Components: []string{`"@method"`, `"@authority"`, `"@path"`}},
		KeyID:    "k1",
	})
	if err != nil {
		b.Fatal(err)
	}
	body := strings.Repeat("x", 1024)
	b.ReportAllocs()
	for b.Loop() {
		req, _ := http.NewRequest("POST", "http://example.com/data", strings.NewReader(body))
		if _, err := rt.RoundTrip(req); err != nil {
			b.Fatal(err)
		}
	}
}
