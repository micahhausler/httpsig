// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

// Package sigconfig defines the serializable configuration for HTTP message
// signature clients and servers: what a client covers when it signs, and
// what a server requires when it verifies.
//
// The two documents are duals, not copies. A [SigningProfile] is a client's
// instruction sheet for one server. A [VerifyPolicy] is a server's minimum
// requirements. Their shared vocabulary is [Coverage]: the ordered component
// list and the content-digest rule. Coverage is the only part that would
// ever need to travel between the two sides; RFC 9421 has no deployed
// mechanism for a server to publish it, so today it is coordinated
// out-of-band by shipping these documents.
//
// All types marshal with encoding/json. For YAML, use a converter that
// honors json tags, such as sigs.k8s.io/yaml. Components are written in the
// wire syntax of RFC 9421 itself, so a config file diffs directly against
// the Signature-Input header a signed request carries:
//
//	components:
//	  - '"@method"'
//	  - '"@authority"'
//	  - '"@path"'
//	  - '"@query-param";name="q"'
//	contentDigest: when-body
//	keyId: my-key
//	ttl: 5m
//
// Only the wire form is accepted; a bare @method is rejected.
package sigconfig
