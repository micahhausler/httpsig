// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package sigconfig

import (
	"fmt"

	"github.com/micahhausler/httpsig"
)

// A DigestMode states when a signature must cover the request body via the
// Content-Digest field (RFC 9530).
//
// The body itself is never a signature component; only the Content-Digest
// field binds it to the signature. A mode is therefore load-bearing: without
// one, an intermediary can attach a body to a signed bodiless request and
// the signature still verifies.
type DigestMode string

const (
	// DigestWhenBody covers Content-Digest exactly when the message has a
	// body. "Has a body" means the body read yields at least one byte;
	// framing headers such as Content-Length are never consulted. This is
	// the default and the interoperable setting.
	DigestWhenBody DigestMode = "when-body"

	// DigestAlways covers Content-Digest on every message, using the
	// digest of the empty body when there is none. This removes the
	// conditional entirely; prefer it when the same party controls both
	// client and server.
	DigestAlways DigestMode = "always"

	// DigestNever leaves the body out of the signature. It is valid only
	// in a [SigningProfile], for talking to servers outside your
	// control that reject the field; [VerifyPolicy.Validate] rejects it,
	// since a verifier with this mode accepts unsigned bodies on signed
	// requests.
	DigestNever DigestMode = "never"
)

// Digest algorithms this module computes and verifies, from the IANA "Hash
// Algorithms for HTTP Digest Fields" registry. The deprecated and insecure
// registry entries are deliberately absent.
const (
	SHA256 = "sha-256"
	SHA512 = "sha-512"
)

// Coverage is the component set a signature covers. It is the shared
// vocabulary of a [SigningProfile] and a [VerifyPolicy]: the client signs at
// least this, the server requires at least this.
type Coverage struct {
	// Components are component identifiers in RFC 9421 wire syntax, such
	// as `"@method"` or `"@query-param";name="q"`. Order is preserved
	// and semantic: signatures cover components in this order.
	//
	// Every listed component must be present on every request the
	// profile signs; there is no "cover if present" rule. The one
	// message-shape-dependent component, content-digest, is controlled
	// by ContentDigest and must not be listed here.
	Components []string `json:"components"`

	// ContentDigest states when the body is bound to the signature. An
	// empty value means DigestWhenBody.
	ContentDigest DigestMode `json:"contentDigest,omitempty"`

	// StructuredFields maps lowercase field names to their structured
	// field type: "item", "list", or "dictionary". An entry is required
	// for each component using the sf parameter, and every entry must be
	// referenced by such a component; an unreferenced entry is treated
	// as a typo and rejected.
	//
	// This map is local canonicalization knowledge, not coverage: it has
	// no place in an Accept-Signature value, so it is the one part of a
	// Coverage that could not travel to the peer. A registry of
	// well-known field types could replace it.
	StructuredFields map[string]string `json:"structuredFields,omitempty"`
}

var fieldTypes = map[string]httpsig.FieldType{
	"item":       httpsig.FieldTypeItem,
	"list":       httpsig.FieldTypeList,
	"dictionary": httpsig.FieldTypeDictionary,
}

// Digest returns the content-digest mode with the default applied.
func (c Coverage) Digest() DigestMode {
	if c.ContentDigest == "" {
		return DigestWhenBody
	}
	return c.ContentDigest
}

// HTTPComponents parses the component list into wire-library components.
func (c Coverage) HTTPComponents() ([]httpsig.Component, error) {
	parsed := make([]httpsig.Component, len(c.Components))
	for i, s := range c.Components {
		comp, err := httpsig.ParseComponent(s)
		if err != nil {
			return nil, err
		}
		if comp.Name == "content-digest" {
			return nil, fmt.Errorf("sigconfig: content-digest is controlled by the contentDigest setting, not the component list")
		}
		if comp.SF {
			if _, ok := c.StructuredFields[comp.Name]; !ok {
				return nil, fmt.Errorf("sigconfig: component %s uses sf but structuredFields has no entry for %q", s, comp.Name)
			}
		}
		for _, prev := range parsed[:i] {
			if prev == comp {
				return nil, fmt.Errorf("sigconfig: duplicate component %s", s)
			}
		}
		parsed[i] = comp
	}
	return parsed, nil
}

// FieldTypes converts the StructuredFields map to wire-library field types.
func (c Coverage) FieldTypes() (map[string]httpsig.FieldType, error) {
	if len(c.StructuredFields) == 0 {
		return nil, nil
	}
	m := make(map[string]httpsig.FieldType, len(c.StructuredFields))
	for name, t := range c.StructuredFields {
		ft, ok := fieldTypes[t]
		if !ok {
			return nil, fmt.Errorf("sigconfig: structured field %q has unknown type %q (want item, list, or dictionary)", name, t)
		}
		m[name] = ft
	}
	return m, nil
}

// validate checks the coverage in isolation.
func (c Coverage) validate() error {
	switch c.ContentDigest {
	case "", DigestWhenBody, DigestAlways, DigestNever:
	default:
		return fmt.Errorf("sigconfig: unknown contentDigest mode %q", c.ContentDigest)
	}
	if _, err := c.FieldTypes(); err != nil {
		return err
	}
	comps, err := c.HTTPComponents()
	if err != nil {
		return err
	}
	// Every structured field entry must be referenced; an unreferenced
	// entry is a typo'd field name that would otherwise fail silently.
	for name := range c.StructuredFields {
		referenced := false
		for _, comp := range comps {
			if comp.SF && comp.Name == name {
				referenced = true
				break
			}
		}
		if !referenced {
			return fmt.Errorf("sigconfig: structuredFields entry %q is not referenced by any component with the sf parameter", name)
		}
	}
	return nil
}

func validDigestAlgorithm(alg string) bool {
	return alg == SHA256 || alg == SHA512
}
