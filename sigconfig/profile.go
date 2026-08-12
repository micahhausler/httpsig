// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package sigconfig

import "fmt"

// A SigningProfile is a client's instruction sheet for signing requests to
// one server: the coverage plus the signature parameters. It is the
// serializable projection of the wire library's SignOptions.
//
// The zero value is usable: it signs @method and @target-uri per the wire
// library default, covers Content-Digest when a body is present, and sets no
// optional parameters.
type SigningProfile struct {
	Coverage

	// Label identifies the signature within the message. It defaults to
	// "sig1". A label is local bookkeeping; servers select signatures by
	// tag or key, never by label.
	Label string `json:"label,omitempty"`

	// KeyID sets the keyid parameter, the client's name for its key in
	// whatever key directory the server consults. Empty omits it.
	KeyID string `json:"keyId,omitempty"`

	// Tag sets the application-specific tag parameter. Empty omits it.
	Tag string `json:"tag,omitempty"`

	// TTL sets the expires parameter to the signing time plus this
	// duration. Zero omits expires; the created parameter is always set.
	TTL Duration `json:"ttl,omitempty"`

	// Nonce attaches a fresh random nonce to each signature. This
	// module does no replay detection on either side; the nonce only
	// gives a server that tracks nonces something to track, and a
	// verifier's MaxAge is the only replay bound this module enforces.
	Nonce bool `json:"nonce,omitempty"`

	// IncludeAlg includes the signing algorithm as the alg parameter.
	IncludeAlg bool `json:"includeAlg,omitempty"`

	// DigestAlgorithm is the Content-Digest hash: "sha-256" (the
	// default) or "sha-512".
	DigestAlgorithm string `json:"digestAlgorithm,omitempty"`

	// Authorities, when non-empty, are the only hosts requests may be
	// signed for, compared case-insensitively against the request URL's
	// host. An HTTP redirect re-enters the transport, so without this
	// list a server can redirect the client and harvest a signature
	// over a request, body included, to a host of its choosing.
	Authorities []string `json:"authorities,omitempty"`

	// MaxBodyBytes caps the body buffering that digest computation
	// requires. Zero means 1 MiB; -1 removes the cap. Requests with
	// larger bodies fail rather than sign, so size this to the largest
	// body the client sends.
	MaxBodyBytes int64 `json:"maxBodyBytes,omitempty"`
}

// BodyLimit returns the body buffering cap with the default applied, or -1
// for no cap.
func (p SigningProfile) BodyLimit() int64 { return bodyLimit(p.MaxBodyBytes) }

// Validate reports whether the profile is well-formed: components parse,
// referenced structured field types exist, and enumerated fields hold known
// values. Load-time validation is the contract; a valid profile does not
// fail at signing time except for message-shape errors, such as a covered
// field missing from a request.
func (p SigningProfile) Validate() error {
	if err := p.Coverage.validate(); err != nil {
		return err
	}
	if p.DigestAlgorithm != "" && !validDigestAlgorithm(p.DigestAlgorithm) {
		return fmt.Errorf("sigconfig: unknown digestAlgorithm %q (want sha-256 or sha-512)", p.DigestAlgorithm)
	}
	if p.TTL < 0 {
		return fmt.Errorf("sigconfig: ttl must not be negative")
	}
	return nil
}
