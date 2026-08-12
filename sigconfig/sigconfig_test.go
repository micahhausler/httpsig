// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package sigconfig

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/micahhausler/httpsig"
)

func TestSigningProfileRoundTrip(t *testing.T) {
	in := SigningProfile{
		Coverage: Coverage{
			Components:       []string{`"@method"`, `"@authority"`, `"@path"`, `"@query-param";name="q"`, `"example-dict";sf`},
			ContentDigest:    DigestAlways,
			StructuredFields: map[string]string{"example-dict": "dictionary"},
		},
		Label:           "app",
		KeyID:           "my-key",
		Tag:             "svc",
		TTL:             Duration(5 * time.Minute),
		Nonce:           true,
		IncludeAlg:      true,
		DigestAlgorithm: SHA512,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out SigningProfile
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip:\n in  %+v\n out %+v", in, out)
	}
	if err := out.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestVerifyPolicyRoundTrip(t *testing.T) {
	in := VerifyPolicy{
		Coverage: Coverage{
			Components:    []string{`"@method"`, `"@authority"`},
			ContentDigest: DigestWhenBody,
		},
		MaxAge:           Duration(5 * time.Minute),
		Tolerance:        Duration(30 * time.Second),
		Algorithms:       []string{"ed25519"},
		DigestAlgorithms: []string{SHA256},
		Tag:              "svc",
		Scheme:           "https",
		Authority:        "api.example.com",
		MaxBodyBytes:     1 << 16,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out VerifyPolicy
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip:\n in  %+v\n out %+v", in, out)
	}
	if err := out.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestEmbeddedCoverageMarshalsFlat(t *testing.T) {
	b, err := json.Marshal(SigningProfile{
		Coverage: Coverage{Components: []string{`"@method"`}},
		KeyID:    "k",
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["components"]; !ok {
		t.Errorf("components not at top level: %s", b)
	}
	if _, ok := m["Coverage"]; ok {
		t.Errorf("Coverage nested instead of inlined: %s", b)
	}
}

func TestValidateRejections(t *testing.T) {
	tests := []struct {
		name string
		p    SigningProfile
	}{
		{"bare component form", SigningProfile{Coverage: Coverage{Components: []string{`@method`}}}},
		{"content-digest in list", SigningProfile{Coverage: Coverage{Components: []string{`"content-digest"`}}}},
		{"duplicate component", SigningProfile{Coverage: Coverage{Components: []string{`"@method"`, `"@method"`}}}},
		{"unknown digest mode", SigningProfile{Coverage: Coverage{ContentDigest: "sometimes"}}},
		{"sf without type", SigningProfile{Coverage: Coverage{Components: []string{`"example-dict";sf`}}}},
		{"unreferenced structured field", SigningProfile{Coverage: Coverage{Components: []string{`"@method"`}, StructuredFields: map[string]string{"example-dict": "dictionary"}}}},
		{"bad field type", SigningProfile{Coverage: Coverage{StructuredFields: map[string]string{"x": "map"}}}},
		{"bad digest algorithm", SigningProfile{DigestAlgorithm: "md5"}},
		{"negative ttl", SigningProfile{TTL: Duration(-time.Second)}},
	}
	for _, tt := range tests {
		if err := tt.p.Validate(); err == nil {
			t.Errorf("%s: Validate accepted %+v", tt.name, tt.p)
		}
	}
	if err := (SigningProfile{}).Validate(); err != nil {
		t.Errorf("zero profile: %v", err)
	}
	if err := (VerifyPolicy{}).Validate(); err != nil {
		t.Errorf("zero policy: %v", err)
	}
	if err := (VerifyPolicy{DigestAlgorithms: []string{"unixsum"}}).Validate(); err == nil {
		t.Error("Validate accepted deprecated digest algorithm")
	}
	if err := (VerifyPolicy{Coverage: Coverage{ContentDigest: DigestNever}}).Validate(); err == nil {
		t.Error("Validate accepted contentDigest never in a verify policy")
	}
	if err := (SigningProfile{Coverage: Coverage{ContentDigest: DigestNever}}).Validate(); err != nil {
		t.Errorf("contentDigest never in a signing profile: %v", err)
	}
	if err := (VerifyPolicy{MaxAge: Duration(-time.Second)}).Validate(); err != nil {
		t.Errorf("negative maxAge is the explicit opt-out, got: %v", err)
	}
}

func TestDurationForms(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`"1h30m"`), &d); err != nil {
		t.Fatal(err)
	}
	if time.Duration(d) != 90*time.Minute {
		t.Errorf("got %v", time.Duration(d))
	}
	if err := json.Unmarshal([]byte(`300`), &d); err == nil {
		t.Error("bare number accepted; only the string form is valid")
	}
	if err := json.Unmarshal([]byte(`"5 minutes"`), &d); err == nil {
		t.Error("prose duration accepted")
	}
}

func TestDefaults(t *testing.T) {
	var p VerifyPolicy
	if got := p.BodyLimit(); got != DefaultMaxBodyBytes {
		t.Errorf("BodyLimit() = %d", got)
	}
	p.MaxBodyBytes = -1
	if got := p.BodyLimit(); got != -1 {
		t.Errorf("BodyLimit() = %d, want -1", got)
	}
	if got := (SigningProfile{}).BodyLimit(); got != DefaultMaxBodyBytes {
		t.Errorf("profile BodyLimit() = %d", got)
	}
	if got := (VerifyPolicy{}).AgeLimit(); got != time.Duration(DefaultMaxAge) {
		t.Errorf("AgeLimit() = %v", got)
	}
	if got := (VerifyPolicy{MaxAge: Duration(-time.Second)}).AgeLimit(); got != 0 {
		t.Errorf("AgeLimit() = %v, want 0 (disabled)", got)
	}
	if got := (VerifyPolicy{MaxAge: Duration(time.Hour)}).AgeLimit(); got != time.Hour {
		t.Errorf("AgeLimit() = %v", got)
	}
	if got := (Coverage{}).Digest(); got != DigestWhenBody {
		t.Errorf("Digest() = %q, want when-body", got)
	}
	if got := (VerifyPolicy{}).AcceptedDigests(); !reflect.DeepEqual(got, []string{SHA256, SHA512}) {
		t.Errorf("AcceptedDigests() = %v", got)
	}
}

func TestFieldTypes(t *testing.T) {
	c := Coverage{StructuredFields: map[string]string{"example-dict": "dictionary", "x-item": "item", "x-list": "list"}}
	m, err := c.FieldTypes()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]httpsig.FieldType{
		"example-dict": httpsig.FieldTypeDictionary,
		"x-item":       httpsig.FieldTypeItem,
		"x-list":       httpsig.FieldTypeList,
	}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("FieldTypes() = %v, want %v", m, want)
	}
}

// The two documents must not blur: a consumer decoding strictly gets an
// error when a field from the other document appears.
func TestStrictDecodeSeparatesDocuments(t *testing.T) {
	dec := json.NewDecoder(strings.NewReader(`{"keyId": "nope"}`))
	dec.DisallowUnknownFields()
	var p VerifyPolicy
	if err := dec.Decode(&p); err == nil {
		t.Error("strict decode accepted a SigningProfile field in a VerifyPolicy")
	}
	dec = json.NewDecoder(strings.NewReader(`{"maxAge": "5m"}`))
	dec.DisallowUnknownFields()
	var sp SigningProfile
	if err := dec.Decode(&sp); err == nil {
		t.Error("strict decode accepted a VerifyPolicy field in a SigningProfile")
	}
}
