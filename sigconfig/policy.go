// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package sigconfig

import (
	"fmt"
	"time"
)

// A VerifyPolicy is a server's minimum signature requirements. A request is
// accepted when at least one of its signatures satisfies the whole policy;
// requiring every signature to verify is trivially defeated by appending a
// garbage signature, so the policy is expressed positively.
//
// The zero value requires a valid signature no older than five minutes with
// any coverage and any algorithm, and Content-Digest whenever a body is
// present.
type VerifyPolicy struct {
	// Coverage is the minimum a signature must cover. Signatures may
	// cover more. The DigestNever mode is invalid in a policy: a server
	// that ignores request bodies pays nothing for DigestWhenBody, and
	// any other server would be accepting unsigned bodies.
	Coverage

	// MaxAge is the maximum accepted signature age, measured from the
	// created parameter; signatures without created are rejected. Zero
	// means five minutes. A negative value, such as "-1s", removes the
	// age bound entirely, which also admits signatures without created;
	// replay of a captured signature is then bounded by nothing.
	MaxAge Duration `json:"maxAge,omitempty"`

	// Tolerance is added to time comparisons to allow for clock skew
	// between signer and verifier.
	Tolerance Duration `json:"tolerance,omitempty"`

	// Algorithms restricts the verification key algorithms accepted,
	// by IANA registry name such as "ed25519". Empty accepts any
	// algorithm the key directory returns.
	Algorithms []string `json:"algorithms,omitempty"`

	// DigestAlgorithms are the Content-Digest hashes accepted:
	// "sha-256", "sha-512", or both. Empty accepts both. A digest
	// field whose entries are all outside this set is rejected, not
	// ignored.
	DigestAlgorithms []string `json:"digestAlgorithms,omitempty"`

	// Tag, when set, selects signatures by their tag parameter;
	// signatures with any other tag are not considered. Use it when
	// multiple signers annotate the same requests.
	Tag string `json:"tag,omitempty"`

	// Scheme and Authority are the external values clients sign, for
	// servers behind a TLS-terminating proxy or load balancer. When
	// empty, they are derived from the connection, and valid signatures
	// covering @scheme, @authority, or @target-uri fail as if the
	// signature bytes were wrong. Forwarded and X-Forwarded-* are
	// unsigned input and are never consulted; state the deployment fact
	// here instead.
	Scheme    string `json:"scheme,omitempty"`
	Authority string `json:"authority,omitempty"`

	// MaxBodyBytes caps the body buffering that digest verification
	// requires. Zero means 1 MiB; -1 removes the cap, making memory use
	// per concurrent request unbounded unless something upstream limits
	// body size. Requests with larger bodies are rejected outright, so
	// size this to the largest body the application accepts.
	MaxBodyBytes int64 `json:"maxBodyBytes,omitempty"`
}

// DefaultMaxBodyBytes is the body buffering cap applied when
// [VerifyPolicy.MaxBodyBytes] is zero.
const DefaultMaxBodyBytes = 1 << 20

// DefaultMaxAge is the signature age bound applied when
// [VerifyPolicy.MaxAge] is zero.
const DefaultMaxAge = Duration(5 * time.Minute)

// AgeLimit returns the age bound with the default applied, or zero when the
// policy disables the bound.
func (p VerifyPolicy) AgeLimit() time.Duration {
	switch {
	case p.MaxAge == 0:
		return time.Duration(DefaultMaxAge)
	case p.MaxAge < 0:
		return 0
	}
	return time.Duration(p.MaxAge)
}

// BodyLimit returns the body buffering cap with the default applied, or -1
// for no cap.
func (p VerifyPolicy) BodyLimit() int64 { return bodyLimit(p.MaxBodyBytes) }

// bodyLimit applies the MaxBodyBytes convention: zero is the default cap,
// negative is uncapped.
func bodyLimit(v int64) int64 {
	switch {
	case v == 0:
		return DefaultMaxBodyBytes
	case v < 0:
		return -1
	}
	return v
}

// AcceptedDigests returns the accepted digest algorithms with the default
// applied.
func (p VerifyPolicy) AcceptedDigests() []string {
	if len(p.DigestAlgorithms) == 0 {
		return []string{SHA256, SHA512}
	}
	return p.DigestAlgorithms
}

// Validate reports whether the policy is well-formed: components parse,
// referenced structured field types exist, and enumerated fields hold known
// values.
func (p VerifyPolicy) Validate() error {
	if err := p.Coverage.validate(); err != nil {
		return err
	}
	if p.ContentDigest == DigestNever {
		return fmt.Errorf("sigconfig: contentDigest never is not valid in a verify policy: it accepts unsigned bodies on signed requests")
	}
	for _, alg := range p.DigestAlgorithms {
		if !validDigestAlgorithm(alg) {
			return fmt.Errorf("sigconfig: unknown digest algorithm %q (want sha-256 or sha-512)", alg)
		}
	}
	if p.Tolerance < 0 {
		return fmt.Errorf("sigconfig: tolerance must not be negative")
	}
	return nil
}
