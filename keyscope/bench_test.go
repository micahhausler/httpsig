// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package keyscope

import (
	"testing"
	"time"
)

func benchKey(b *testing.B, from string) *Key {
	b.Helper()
	created := time.Date(2012, 5, 25, 0, 24, 53, 0, time.UTC)
	root, err := New(SigV4(), Stage{
		Name:  "AKIAIOSFODNN7EXAMPLE",
		Scope: map[string]string{"region": "us-east-1", "service": "glacier"},
	}, []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))
	if err != nil {
		b.Fatal(err)
	}
	if from == "" {
		return root
	}
	material, stage, err := root.Derive(from, created)
	if err != nil {
		b.Fatal(err)
	}
	k, err := New(SigV4(), stage, material)
	if err != nil {
		b.Fatal(err)
	}
	return k
}

// BenchmarkVerifierStaged measures the per-request cost a verifying service
// actually pays: keyid parsing, scope comparison, and a memo hit on the
// single-entry derivation memo (the steady state: same scope, same date,
// every request). This is the work a KeyDirectory adds to every request.
func BenchmarkVerifierStaged(b *testing.B) {
	key := benchKey(b, "service")
	created := time.Date(2012, 5, 25, 0, 24, 53, 0, time.UTC)
	keyid, err := key.KeyID(created)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := key.Verifier(keyid, created); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifierRoot measures the worst case: a verifier holding the
// root secret walks the whole ladder. Holding the root on the verifier
// forfeits the containment this package exists for; the benchmark exists to
// bound the cost, not to suggest the deployment.
func BenchmarkVerifierRoot(b *testing.B) {
	key := benchKey(b, "")
	created := time.Date(2012, 5, 25, 0, 24, 53, 0, time.UTC)
	keyid, err := key.KeyID(created)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := key.Verifier(keyid, created); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSignerMemoMiss measures full-ladder derivation from the root
// secret on every call, the cost paid at date rollover or under
// date-thrashing input: the memo is a single entry, so alternating dates
// defeat it by design rather than growing memory.
func BenchmarkSignerMemoMiss(b *testing.B) {
	key := benchKey(b, "")
	days := []time.Time{
		time.Date(2012, 5, 25, 0, 24, 53, 0, time.UTC),
		time.Date(2012, 5, 26, 0, 24, 53, 0, time.UTC),
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		if _, err := key.Signer(days[i%2]); err != nil {
			b.Fatal(err)
		}
		i++
	}
}

// BenchmarkSigner measures per-request signing in the steady state: the
// derivation memo hits, so the cost is claims computation plus signer
// construction.
func BenchmarkSigner(b *testing.B) {
	key := benchKey(b, "")
	created := time.Date(2012, 5, 25, 0, 24, 53, 0, time.UTC)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := key.Signer(created); err != nil {
			b.Fatal(err)
		}
	}
}
