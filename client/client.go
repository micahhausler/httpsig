// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

// Package client signs outgoing HTTP requests per a [sigconfig.SigningProfile].
//
// A Transport wraps an http.RoundTripper. Each request is signed with the
// profile's coverage, and the body is bound to the signature with a
// Content-Digest field (RFC 9530) per the profile's digest mode, so one
// profile serves both bodiless GETs and POSTs with bodies:
//
//	profile := sigconfig.SigningProfile{
//		Coverage: sigconfig.Coverage{
//			Components: []string{`"@method"`, `"@authority"`, `"@path"`},
//		},
//		KeyID: "my-key",
//		TTL:   sigconfig.Duration(5 * time.Minute),
//	}
//	rt, err := client.NewTransport(nil, signer, profile)
//	if err != nil {
//		// Malformed profile; nothing was sent.
//	}
//	httpClient := &http.Client{Transport: rt}
//
// The profile is validated once at construction. A request can still fail to
// sign if its shape does not match the profile, such as a covered field
// missing from the request.
//
// Computing a digest requires the whole body, so requests are buffered in
// memory when the digest mode calls for one. Callers own the choice of which
// profile a request gets: one Transport signs for one server relationship.
package client

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig/contentdigest"
	"github.com/micahhausler/httpsig/sigconfig"
)

// A Transport is an http.RoundTripper that signs each request before
// delegating to a base transport. It is safe for concurrent use.
type Transport struct {
	base        http.RoundTripper
	signer      httpsig.Signer
	profile     sigconfig.SigningProfile
	comps       []httpsig.Component
	fields      map[string]httpsig.FieldType
	digestAlg   string
	authorities map[string]bool
}

// NewTransport returns a Transport that signs with signer per profile. A nil
// base means http.DefaultTransport. The profile is validated here; a
// Transport that constructs will not fail later on account of its
// configuration.
func NewTransport(base http.RoundTripper, signer httpsig.Signer, profile sigconfig.SigningProfile) (*Transport, error) {
	if signer == nil {
		return nil, fmt.Errorf("httpsig/client: signer is nil")
	}
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	comps, err := profile.HTTPComponents()
	if err != nil {
		return nil, err
	}
	if len(comps) == 0 {
		// Materialize the wire library's default so appending
		// content-digest does not silently replace it.
		comps = []httpsig.Component{{Name: "@method"}, {Name: "@target-uri"}}
	}
	fields, err := profile.FieldTypes()
	if err != nil {
		return nil, err
	}
	alg := profile.DigestAlgorithm
	if alg == "" {
		alg = sigconfig.SHA256
	}
	t := &Transport{
		base:      base,
		signer:    signer,
		profile:   profile,
		comps:     comps,
		fields:    fields,
		digestAlg: alg,
	}
	if len(profile.Authorities) > 0 {
		t.authorities = make(map[string]bool, len(profile.Authorities))
		for _, a := range profile.Authorities {
			t.authorities[strings.ToLower(a)] = true
		}
	}
	return t, nil
}

// RoundTrip signs the request and sends it. The caller's request is not
// modified beyond consuming its body; headers are set on a clone.
//
// RoundTrip is re-entered on HTTP redirects, so every hop of a redirect
// chain is signed. The profile's Authorities list is what keeps a server
// from redirecting the client into signing for a host of the server's
// choosing.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.authorities != nil && !t.authorities[strings.ToLower(req.URL.Host)] {
		return nil, fmt.Errorf("httpsig/client: refusing to sign for %q: not in the profile's authorities", req.URL.Host)
	}
	clone := req.Clone(req.Context())
	comps := t.comps

	if t.profile.Digest() != sigconfig.DigestNever {
		body, err := t.readBody(req)
		if err != nil {
			return nil, err
		}
		setBody(clone, body)
		if len(body) > 0 || t.profile.Digest() == sigconfig.DigestAlways {
			value, err := contentdigest.Value(t.digestAlg, body)
			if err != nil {
				return nil, err
			}
			clone.Header.Set("Content-Digest", value)
			comps = append(comps[:len(comps):len(comps)], httpsig.Component{Name: "content-digest"})
		}
	}

	opts := httpsig.SignOptions{
		Components:       comps,
		Label:            t.profile.Label,
		KeyID:            t.profile.KeyID,
		Tag:              t.profile.Tag,
		IncludeAlg:       t.profile.IncludeAlg,
		StructuredFields: t.fields,
	}
	if t.profile.TTL > 0 {
		now := time.Now()
		opts.Created = now
		opts.Expires = now.Add(time.Duration(t.profile.TTL))
	}
	if t.profile.Nonce {
		nonce, err := newNonce()
		if err != nil {
			return nil, err
		}
		opts.Nonce = nonce
	}
	if err := httpsig.Sign(clone, t.signer, opts); err != nil {
		return nil, err
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(clone)
}

// readBody consumes and returns the request body, up to the profile's cap.
// A nil body reads as empty. Digest computation needs the whole body, so
// the cap is what bounds this buffer; a body over the cap is an error, not
// a truncation.
func (t *Transport) readBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	defer req.Body.Close()
	reader := io.Reader(req.Body)
	limit := t.profile.BodyLimit()
	if limit >= 0 {
		reader = io.LimitReader(reader, limit+1)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("httpsig/client: reading body: %w", err)
	}
	if limit >= 0 && int64(len(body)) > limit {
		return nil, fmt.Errorf("httpsig/client: body exceeds the profile's MaxBodyBytes (%d)", limit)
	}
	return body, nil
}

// setBody installs body on the clone with correct framing, replacing the
// consumed original. GetBody is set so the transport can replay the request
// on redirects and retries.
func setBody(clone *http.Request, body []byte) {
	if len(body) == 0 {
		clone.Body = http.NoBody
		clone.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
	} else {
		clone.Body = io.NopCloser(bytes.NewReader(body))
		clone.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}
	clone.ContentLength = int64(len(body))
	clone.TransferEncoding = nil
}

func newNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("httpsig/client: generating nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
