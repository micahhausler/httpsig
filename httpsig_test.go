// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// parseOneOpts is parseOne with explicit parse options.
func parseOneOpts(t *testing.T, req *http.Request, label string, opts *ParseOptions) *Signature {
	t.Helper()
	sigs, err := ParseSignatures(req, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sigs {
		if s.Label() == label {
			return s
		}
	}
	t.Fatalf("no signature labeled %q", label)
	return nil
}

// testKeys returns a signing and verification key pair for each supported
// algorithm. The RSA keys come from RFC 9421 Appendix B.1 to avoid slow key
// generation.
func testKeys(t *testing.T, alg Algorithm) (crypto.PrivateKey, crypto.PublicKey) {
	t.Helper()
	switch alg {
	case RSAPSSSHA512:
		priv, pub := rsaPSSTestKeys(t)
		return priv, pub
	case RSAV15SHA256:
		priv, pub := rsaTestKeys(t)
		return priv, pub
	case HMACSHA256:
		secret := sharedSecret(t)
		return secret, secret
	case ECDSAP256SHA256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return priv, &priv.PublicKey
	case ECDSAP384SHA384:
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return priv, &priv.PublicKey
	case Ed25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return priv, pub
	}
	t.Fatalf("unknown algorithm %q", alg)
	return nil, nil
}

var allAlgorithms = []Algorithm{
	RSAPSSSHA512, RSAV15SHA256, HMACSHA256,
	ECDSAP256SHA256, ECDSAP384SHA384, Ed25519,
}

func TestRoundTrip(t *testing.T) {
	for _, alg := range allAlgorithms {
		t.Run(string(alg), func(t *testing.T) {
			priv, pub := testKeys(t, alg)
			req := testRequest(t)
			err := Sign(req, signer(t, alg, priv), SignOptions{
				Components: []Component{
					{Name: "@method"}, {Name: "@target-uri"}, {Name: "content-digest"},
				},
				KeyID:      "test-key",
				IncludeAlg: true,
				Scheme:     "https",
			})
			if err != nil {
				t.Fatal(err)
			}
			sig := parseOneOpts(t, req, "sig1", &ParseOptions{Scheme: "https"})
			if sig.KeyID() != "test-key" {
				t.Errorf("KeyID = %q", sig.KeyID())
			}
			if sig.Alg() != alg {
				t.Errorf("Alg = %q, want %q", sig.Alg(), alg)
			}
			err = sig.Verify(verifier(t, alg, pub), Policy{
				RequiredComponents: []Component{{Name: "@method"}, {Name: "content-digest"}},
				MaxAge:             time.Minute,
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func TestVerifyWrongKey(t *testing.T) {
	priv, _ := testKeys(t, Ed25519)
	_, otherPub := testKeys(t, Ed25519)
	req := testRequest(t)
	if err := Sign(req, signer(t, Ed25519, priv), SignOptions{}); err != nil {
		t.Fatal(err)
	}
	err := parseOne(t, req, "sig1").Verify(verifier(t, Ed25519, otherPub), Policy{})
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("Verify = %v, want ErrSignatureMismatch", err)
	}
	var verr *VerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("Verify = %T, want *VerificationError", err)
	}
	if len(verr.SignatureBase) == 0 {
		t.Error("VerificationError has no signature base")
	}
}

func TestVerifyMutatedRequest(t *testing.T) {
	priv, pub := testKeys(t, HMACSHA256)
	req := testRequest(t)
	err := Sign(req, signer(t, HMACSHA256, priv), SignOptions{
		Components: []Component{{Name: "content-type"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain")
	err = parseOne(t, req, "sig1").Verify(verifier(t, HMACSHA256, pub), Policy{})
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("Verify = %v, want ErrSignatureMismatch", err)
	}
}

func TestAlgorithmMismatch(t *testing.T) {
	priv, _ := testKeys(t, Ed25519)
	req := testRequest(t)
	err := Sign(req, signer(t, Ed25519, priv), SignOptions{IncludeAlg: true})
	if err != nil {
		t.Fatal(err)
	}
	// The signature claims ed25519; the verifier is HMAC.
	err = parseOne(t, req, "sig1").Verify(verifier(t, HMACSHA256, sharedSecret(t)), Policy{})
	if !errors.Is(err, ErrAlgorithmMismatch) {
		t.Errorf("Verify = %v, want ErrAlgorithmMismatch", err)
	}
}

func TestExpiry(t *testing.T) {
	priv, pub := testKeys(t, HMACSHA256)
	key := verifier(t, HMACSHA256, pub)
	now := time.Now()

	req := testRequest(t)
	err := Sign(req, signer(t, HMACSHA256, priv), SignOptions{
		Created: now.Add(-10 * time.Minute),
		Expires: now.Add(-5 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	sig := parseOne(t, req, "sig1")
	if err := sig.Verify(key, Policy{}); !errors.Is(err, ErrExpired) {
		t.Errorf("expired: Verify = %v, want ErrExpired", err)
	}
	// A large enough tolerance admits it.
	if err := sig.Verify(key, Policy{Tolerance: 10 * time.Minute}); err != nil {
		t.Errorf("expired with tolerance: %v", err)
	}

	req = testRequest(t)
	err = Sign(req, signer(t, HMACSHA256, priv), SignOptions{Created: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	sig = parseOne(t, req, "sig1")
	if err := sig.Verify(key, Policy{MaxAge: time.Minute}); !errors.Is(err, ErrExpired) {
		t.Errorf("max age: Verify = %v, want ErrExpired", err)
	}
	if err := sig.Verify(key, Policy{MaxAge: 2 * time.Hour}); err != nil {
		t.Errorf("within max age: %v", err)
	}

	req = testRequest(t)
	err = Sign(req, signer(t, HMACSHA256, priv), SignOptions{Created: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	sig = parseOne(t, req, "sig1")
	if err := sig.Verify(key, Policy{}); !errors.Is(err, ErrCreatedInFuture) {
		t.Errorf("future created: Verify = %v, want ErrCreatedInFuture", err)
	}
}

func TestMissingCreated(t *testing.T) {
	// A signature with no created parameter fails a MaxAge policy. The
	// signature bytes are irrelevant: policy runs before crypto.
	req := testRequest(t)
	req.Header.Set("Signature-Input", `sig1=();keyid="k"`)
	req.Header.Set("Signature", "sig1=:AAAA:")
	err := parseOne(t, req, "sig1").Verify(verifier(t, HMACSHA256, sharedSecret(t)), Policy{MaxAge: time.Minute})
	if !errors.Is(err, ErrMissingCreated) {
		t.Errorf("Verify = %v, want ErrMissingCreated", err)
	}
}

func TestRequiredComponents(t *testing.T) {
	priv, pub := testKeys(t, HMACSHA256)
	req := testRequest(t)
	err := Sign(req, signer(t, HMACSHA256, priv), SignOptions{
		Components: []Component{{Name: "@method"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	sig := parseOne(t, req, "sig1")
	err = sig.Verify(verifier(t, HMACSHA256, pub), Policy{
		RequiredComponents: []Component{{Name: "@method"}, {Name: "content-digest"}},
	})
	if !errors.Is(err, ErrMissingComponent) {
		t.Errorf("Verify = %v, want ErrMissingComponent", err)
	}
}

func TestMultipleSignatures(t *testing.T) {
	// Section 4.3: a second signer merges into the existing dictionaries.
	edPriv, edPub := testKeys(t, Ed25519)
	req := testRequest(t)
	err := Sign(req, signer(t, Ed25519, edPriv), SignOptions{
		Components: []Component{{Name: "@method"}},
		Label:      "sig1",
		KeyID:      "client-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = Sign(req, signer(t, HMACSHA256, sharedSecret(t)), SignOptions{
		Components: []Component{{Name: "@method"}, {Name: "@authority"}},
		Label:      "proxy_sig",
		KeyID:      "proxy-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(req.Header.Values("Signature-Input")); n != 1 {
		t.Errorf("Signature-Input header count = %d, want 1", n)
	}
	sigs, err := ParseSignatures(req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 2 {
		t.Fatalf("got %d signatures, want 2", len(sigs))
	}
	if err := parseOne(t, req, "sig1").Verify(verifier(t, Ed25519, edPub), Policy{}); err != nil {
		t.Errorf("sig1: %v", err)
	}
	if err := parseOne(t, req, "proxy_sig").Verify(verifier(t, HMACSHA256, sharedSecret(t)), Policy{}); err != nil {
		t.Errorf("proxy_sig: %v", err)
	}
}

func TestSignLabelCollision(t *testing.T) {
	priv, _ := testKeys(t, HMACSHA256)
	req := testRequest(t)
	if err := Sign(req, signer(t, HMACSHA256, priv), SignOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := Sign(req, signer(t, HMACSHA256, priv), SignOptions{}); err == nil {
		t.Error("duplicate label: no error")
	}
}

func TestGarbageSignatureIsolation(t *testing.T) {
	// A malformed signature added to the message must not invalidate a
	// good one.
	priv, pub := testKeys(t, Ed25519)
	req := testRequest(t)
	if err := Sign(req, signer(t, Ed25519, priv), SignOptions{}); err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Signature-Input", `bogus=("x-not-present");created=99`)
	req.Header.Add("Signature", "bogus=:AAAA:")

	sigs, err := ParseSignatures(req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 2 {
		t.Fatalf("got %d signatures, want 2", len(sigs))
	}
	if err := parseOne(t, req, "sig1").Verify(verifier(t, Ed25519, pub), Policy{}); err != nil {
		t.Errorf("good signature: %v", err)
	}
	var serr *SyntaxError
	err = parseOne(t, req, "bogus").Verify(verifier(t, Ed25519, pub), Policy{})
	if !errors.As(err, &serr) {
		t.Errorf("bogus signature: Verify = %v, want *SyntaxError", err)
	}
}

func TestMultipleSignatureInputFields(t *testing.T) {
	// Signature-Input and Signature split across separate header fields
	// must combine per RFC 9651 dictionary parsing.
	edPriv, edPub := testKeys(t, Ed25519)
	req := testRequest(t)
	if err := Sign(req, signer(t, Ed25519, edPriv), SignOptions{Label: "a"}); err != nil {
		t.Fatal(err)
	}
	inputA := req.Header.Get("Signature-Input")
	sigA := req.Header.Get("Signature")

	req2 := testRequest(t)
	if err := Sign(req2, signer(t, HMACSHA256, sharedSecret(t)), SignOptions{Label: "b"}); err != nil {
		t.Fatal(err)
	}
	req2.Header.Add("Signature-Input", inputA)
	req2.Header.Add("Signature", sigA)

	if err := parseOne(t, req2, "a").Verify(verifier(t, Ed25519, edPub), Policy{}); err != nil {
		t.Errorf("a: %v", err)
	}
	if err := parseOne(t, req2, "b").Verify(verifier(t, HMACSHA256, sharedSecret(t)), Policy{}); err != nil {
		t.Errorf("b: %v", err)
	}
}

func TestDuplicateLabelLastWins(t *testing.T) {
	// Duplicate dictionary keys resolve deterministically to the last
	// value, per RFC 9651. An attacker appending a duplicate label
	// replaces the original, whose signature then fails.
	priv, pub := testKeys(t, Ed25519)
	req := testRequest(t)
	if err := Sign(req, signer(t, Ed25519, priv), SignOptions{}); err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Signature", "sig1=:AAAA:")
	err := parseOne(t, req, "sig1").Verify(verifier(t, Ed25519, pub), Policy{})
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("Verify = %v, want ErrSignatureMismatch", err)
	}
}

func TestNonCanonicalSignatureInput(t *testing.T) {
	// The signature base uses the strict reserialization of the
	// Signature-Input value, not its wire bytes, so legal whitespace
	// variations do not break verification.
	priv, pub := testKeys(t, HMACSHA256)
	req := testRequest(t)
	err := Sign(req, signer(t, HMACSHA256, priv), SignOptions{
		Components: []Component{{Name: "date"}, {Name: "@authority"}},
		KeyID:      "k",
	})
	if err != nil {
		t.Fatal(err)
	}
	input := req.Header.Get("Signature-Input")
	loose := strings.Replace(input, `"date" "@authority"`, `"date"   "@authority"`, 1)
	loose = strings.Replace(loose, ";created", ";  created", 1)
	if loose == input {
		t.Fatal("test did not alter the field")
	}
	req.Header.Set("Signature-Input", loose)
	if err := parseOne(t, req, "sig1").Verify(verifier(t, HMACSHA256, pub), Policy{}); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestMalformedSignatureFields(t *testing.T) {
	// Document-level breakage fails ParseSignatures outright.
	tests := []struct {
		name, input, sig string
	}{
		{"unclosed quote", `sig1=("@method;created=1`, "sig1=:AAAA:"},
		{"not a dictionary", "\x7f", "sig1=:AAAA:"},
		{"bad signature dict", `sig1=("@method");created=1`, ":::"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := testRequest(t)
			req.Header.Set("Signature-Input", tt.input)
			req.Header.Set("Signature", tt.sig)
			_, err := ParseSignatures(req, nil)
			var serr *SyntaxError
			if !errors.As(err, &serr) {
				t.Errorf("ParseSignatures = %v, want *SyntaxError", err)
			}
		})
	}
}

func TestPerSignatureDefects(t *testing.T) {
	// Defects confined to one signature surface from Verify, not
	// ParseSignatures.
	tests := []struct {
		name, input, sig string
	}{
		{"status component", `sig1=("@status");created=1`, "sig1=:AAAA:"},
		{"req parameter", `sig1=("@method";req);created=1`, "sig1=:AAAA:"},
		{"tr parameter", `sig1=("expires";tr);created=1`, "sig1=:AAAA:"},
		{"unknown parameter", `sig1=("@method";wat);created=1`, "sig1=:AAAA:"},
		{"unknown derived", `sig1=("@nope");created=1`, "sig1=:AAAA:"},
		{"missing field", `sig1=("x-not-present");created=1`, "sig1=:AAAA:"},
		{"no signature member", `sig1=("@method");created=1`, `other=:AAAA:`},
		{"signature not bytes", `sig1=("@method");created=1`, `sig1="nope"`},
		{"input not inner list", `sig1="nope"`, "sig1=:AAAA:"},
		{"created not integer", `sig1=("@method");created="x"`, "sig1=:AAAA:"},
		{"keyid not string", `sig1=("@method");created=1;keyid=1`, "sig1=:AAAA:"},
		{"duplicate component", `sig1=("@method" "@method");created=1`, "sig1=:AAAA:"},
		{"component not string", `sig1=(1);created=1`, "sig1=:AAAA:"},
	}
	key := verifier(t, HMACSHA256, sharedSecret(t))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := testRequest(t)
			req.Header.Set("Signature-Input", tt.input)
			req.Header.Set("Signature", tt.sig)
			sigs, err := ParseSignatures(req, nil)
			if err != nil {
				t.Fatalf("ParseSignatures: %v", err)
			}
			if len(sigs) == 0 {
				t.Fatal("no signatures")
			}
			var serr *SyntaxError
			if err := sigs[0].Verify(key, Policy{}); !errors.As(err, &serr) {
				t.Errorf("Verify = %v, want *SyntaxError", err)
			}
		})
	}
}

func TestOrphanSignatureMember(t *testing.T) {
	// A Signature member with no Signature-Input counterpart appears as a
	// defective signature.
	req := testRequest(t)
	req.Header.Set("Signature", "lonely=:AAAA:")
	sigs, err := ParseSignatures(req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 || sigs[0].Label() != "lonely" {
		t.Fatalf("sigs = %v", sigs)
	}
	var serr *SyntaxError
	if err := sigs[0].Verify(verifier(t, HMACSHA256, sharedSecret(t)), Policy{}); !errors.As(err, &serr) {
		t.Errorf("Verify = %v, want *SyntaxError", err)
	}
}

func TestNoSignatures(t *testing.T) {
	sigs, err := ParseSignatures(testRequest(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 0 {
		t.Errorf("got %d signatures, want 0", len(sigs))
	}
}

func TestHostFieldFallback(t *testing.T) {
	// net/http moves the Host header into Request.Host; covering "host"
	// still works.
	priv, pub := testKeys(t, HMACSHA256)
	req := testRequest(t)
	err := Sign(req, signer(t, HMACSHA256, priv), SignOptions{
		Components: []Component{{Name: "host"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := parseOne(t, req, "sig1").Verify(verifier(t, HMACSHA256, pub), Policy{}); err != nil {
		t.Error(err)
	}
}

func TestSignDefaultComponents(t *testing.T) {
	priv, pub := testKeys(t, HMACSHA256)
	req := testRequest(t)
	if err := Sign(req, signer(t, HMACSHA256, priv), SignOptions{Scheme: "https"}); err != nil {
		t.Fatal(err)
	}
	sig := parseOneOpts(t, req, "sig1", &ParseOptions{Scheme: "https"})
	want := []Component{{Name: "@method"}, {Name: "@target-uri"}}
	if got := sig.Components(); !slices.Equal(got, want) {
		t.Errorf("Components = %v, want %v", got, want)
	}
	if err := sig.Verify(verifier(t, HMACSHA256, pub), Policy{}); err != nil {
		t.Error(err)
	}
}

func TestNewSignerKeyValidation(t *testing.T) {
	edPriv, _ := testKeys(t, Ed25519)
	p256, _ := testKeys(t, ECDSAP256SHA256)
	tests := []struct {
		alg Algorithm
		key crypto.PrivateKey
	}{
		{RSAPSSSHA512, edPriv},
		{HMACSHA256, "not bytes"},
		{ECDSAP256SHA256, edPriv},
		{ECDSAP384SHA384, p256}, // wrong curve
		{Ed25519, sharedSecret(t)},
		{Algorithm("rsa-pss-sha384"), edPriv}, // unregistered
	}
	for _, tt := range tests {
		if _, err := NewSigner(tt.alg, tt.key); err == nil {
			t.Errorf("NewSigner(%q, %T): no error", tt.alg, tt.key)
		}
		if _, err := NewVerifier(tt.alg, tt.key); err == nil {
			t.Errorf("NewVerifier(%q, %T): no error", tt.alg, tt.key)
		}
	}
}

func BenchmarkSign(b *testing.B) {
	secret := make([]byte, 64)
	key, err := NewSigner(HMACSHA256, secret)
	if err != nil {
		b.Fatal(err)
	}
	req, err := http.NewRequest("POST", "https://example.com/foo?param=Value", nil)
	if err != nil {
		b.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	opts := SignOptions{
		Components: []Component{{Name: "@method"}, {Name: "@target-uri"}, {Name: "content-type"}},
		KeyID:      "bench",
	}
	for b.Loop() {
		req.Header.Del("Signature-Input")
		req.Header.Del("Signature")
		if err := Sign(req, key, opts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseAndVerify(b *testing.B) {
	secret := make([]byte, 64)
	key, err := NewSigner(HMACSHA256, secret)
	if err != nil {
		b.Fatal(err)
	}
	req, err := http.NewRequest("POST", "https://example.com/foo?param=Value", nil)
	if err != nil {
		b.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	err = Sign(req, key, SignOptions{
		Components: []Component{{Name: "@method"}, {Name: "@target-uri"}, {Name: "content-type"}},
		KeyID:      "bench",
	})
	if err != nil {
		b.Fatal(err)
	}
	vkey, err := NewVerifier(HMACSHA256, secret)
	if err != nil {
		b.Fatal(err)
	}
	opts := &ParseOptions{Scheme: "https"}
	policy := Policy{RequiredComponents: []Component{{Name: "@method"}}}
	for b.Loop() {
		sigs, err := ParseSignatures(req, opts)
		if err != nil {
			b.Fatal(err)
		}
		if err := sigs[0].Verify(vkey, policy); err != nil {
			b.Fatal(err)
		}
	}
}
