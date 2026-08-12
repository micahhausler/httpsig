// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

// Package server verifies HTTP message signatures on incoming requests per a
// [sigconfig.VerifyPolicy].
//
// A Middleware wraps an http.Handler. The application supplies a
// [KeyDirectory], which resolves an unverified signature to a verification
// key plus an application identity value of any type T; the middleware
// carries that identity to the handler, typed:
//
//	type user struct{ Name string }
//
//	dir := server.KeyDirectoryFunc[user](func(r *http.Request, sig *httpsig.Signature) (httpsig.Verifier, user, error) {
//		// Look up by sig.KeyID(), or by a credential the request
//		// carries, such as an encrypted session token header.
//		return verifier, user{Name: "alice"}, nil
//	})
//	mw, err := server.New(dir, policy)
//	if err != nil {
//		// Malformed policy; nothing was served.
//	}
//	mux.Handle("/", mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		v, _ := server.FromRequest[user](r)
//		fmt.Fprintf(w, "hello, %s", v.Identity.Name)
//	})))
//
// The KeyDirectory receives the whole request precisely so that key material
// carried in a covered header needs no side channel: resolution, not a
// second middleware, is where a session token gets decrypted.
//
// A request is accepted when at least one signature satisfies the whole
// policy. The handler only runs on acceptance; on rejection the middleware
// responds 401 (413 when the body exceeds the policy's buffering cap),
// or delegates to a [WithErrorHandler] option.
//
// Verifying a Content-Digest requires the whole body, so requests are
// buffered in memory up to the policy's MaxBodyBytes when the digest mode
// calls for it. The handler reads the replayed body as usual.
package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig/internal/contentdigest"
	"github.com/micahhausler/httpsig/sigconfig"
)

var (
	// ErrUnsigned reports a request with no signatures at all.
	ErrUnsigned = errors.New("httpsig/server: request is not signed")

	// ErrBodyTooLarge reports a body over the policy's MaxBodyBytes. The
	// default error response for it is 413 rather than 401.
	ErrBodyTooLarge = errors.New("httpsig/server: body exceeds the policy's MaxBodyBytes")
)

// A KeyDirectory resolves an unverified signature to its verification key
// and the application's identity value for the signer. Returning an error
// rejects that one signature; other signatures on the request are still
// considered.
//
// Everything the resolver sees is unverified: sig's accessors are claims
// from the wire, and req is the raw request. In particular sig.KeyID is a
// peer-chosen string; do not use it as a file path, query fragment, or any
// other interpreted input. The request is read-only here; its body is not
// available. Implementations must be safe for concurrent use.
type KeyDirectory[T any] interface {
	Key(req *http.Request, sig *httpsig.Signature) (httpsig.Verifier, T, error)
}

// KeyDirectoryFunc adapts a function to a [KeyDirectory].
type KeyDirectoryFunc[T any] func(req *http.Request, sig *httpsig.Signature) (httpsig.Verifier, T, error)

func (f KeyDirectoryFunc[T]) Key(req *http.Request, sig *httpsig.Signature) (httpsig.Verifier, T, error) {
	return f(req, sig)
}

// A Verified reports the accepted signature and the identity the
// [KeyDirectory] resolved for it. When a request carries several policy-
// satisfying signatures, which one is accepted follows header order, which
// the peer controls; an application distinguishing multiple signers must
// select by the signature's tag or key, never by which one happened to
// verify first.
type Verified[T any] struct {
	Identity  T
	Signature *httpsig.Signature
}

// A Middleware verifies request signatures before a wrapped handler runs.
type Middleware[T any] struct {
	errorHandler func(w http.ResponseWriter, r *http.Request, err error)

	keys      KeyDirectory[T]
	policy    sigconfig.VerifyPolicy
	required  []httpsig.Component
	parseOpts httpsig.ParseOptions
	verify    httpsig.Policy
	accepted  []string
	algs      map[httpsig.Algorithm]bool
}

// An Option configures a [Middleware] at construction.
type Option[T any] func(*Middleware[T])

// WithErrorHandler responds to rejected requests in place of the default,
// which writes a plain 401, or 413 for [ErrBodyTooLarge]. The err carries
// the per-signature failures for logging; the default never writes it to
// the response, and replacements should not either.
func WithErrorHandler[T any](h func(w http.ResponseWriter, r *http.Request, err error)) Option[T] {
	return func(m *Middleware[T]) { m.errorHandler = h }
}

// New returns a Middleware enforcing policy with keys resolved by dir. The
// policy is validated here; a Middleware that constructs will not fail later
// on account of its configuration.
func New[T any](dir KeyDirectory[T], policy sigconfig.VerifyPolicy, opts ...Option[T]) (*Middleware[T], error) {
	if dir == nil {
		return nil, fmt.Errorf("httpsig/server: key directory is nil")
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	required, err := policy.HTTPComponents()
	if err != nil {
		return nil, err
	}
	fields, err := policy.FieldTypes()
	if err != nil {
		return nil, err
	}
	m := &Middleware[T]{
		keys:     dir,
		policy:   policy,
		required: required,
		parseOpts: httpsig.ParseOptions{
			Scheme:           policy.Scheme,
			Authority:        policy.Authority,
			StructuredFields: fields,
		},
		verify: httpsig.Policy{
			MaxAge:    policy.AgeLimit(),
			Tolerance: time.Duration(policy.Tolerance),
		},
		accepted: policy.AcceptedDigests(),
	}
	if len(policy.Algorithms) > 0 {
		m.algs = make(map[httpsig.Algorithm]bool, len(policy.Algorithms))
		for _, a := range policy.Algorithms {
			m.algs[httpsig.Algorithm(a)] = true
		}
	}
	for _, opt := range opts {
		opt(m)
	}
	return m, nil
}

// Wrap returns a handler that runs next only for accepted requests.
func (m *Middleware[T]) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, err := m.check(r)
		if err != nil {
			m.reject(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(withVerified(r.Context(), v)))
	})
}

// check verifies the request against the policy. On success it returns the
// accepted signature's Verified value; the request body has been replayed
// for the handler when buffering occurred.
func (m *Middleware[T]) check(r *http.Request) (*Verified[T], error) {
	digestRequired := false
	if mode := m.policy.Digest(); mode != sigconfig.DigestNever {
		body, err := m.readBody(r)
		if err != nil {
			return nil, err
		}
		// Body presence is decided by what was read, never by
		// framing headers, which are unsigned input.
		digestRequired = len(body) > 0 || mode == sigconfig.DigestAlways
		if values := r.Header.Values("Content-Digest"); digestRequired || len(values) > 0 {
			if len(values) == 0 {
				return nil, errors.New("httpsig/server: request has a body but no Content-Digest field")
			}
			if err := contentdigest.Verify(values, body, m.accepted); err != nil {
				return nil, err
			}
		}
	}

	sigs, err := httpsig.ParseSignatures(r, &m.parseOpts)
	if err != nil {
		return nil, err
	}
	if len(sigs) == 0 {
		return nil, ErrUnsigned
	}

	verify := m.verify
	verify.RequiredComponents = m.required
	if digestRequired {
		verify.RequiredComponents = append(m.required[:len(m.required):len(m.required)],
			httpsig.Component{Name: "content-digest"})
	}

	var failures []error
	for _, sig := range sigs {
		label := sig.Label()
		if m.policy.Tag != "" && sig.Tag() != m.policy.Tag {
			failures = append(failures, fmt.Errorf("%s: tag %q is not policy tag %q", label, sig.Tag(), m.policy.Tag))
			continue
		}
		verifier, identity, err := m.keys.Key(r, sig)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: resolving key: %w", label, err))
			continue
		}
		if m.algs != nil && !m.algs[verifier.Algorithm()] {
			failures = append(failures, fmt.Errorf("%s: algorithm %q is not allowed by policy", label, verifier.Algorithm()))
			continue
		}
		if err := sig.Verify(verifier, verify); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", label, err))
			continue
		}
		return &Verified[T]{Identity: identity, Signature: sig}, nil
	}
	return nil, errors.Join(failures...)
}

// readBody buffers the body up to the policy cap and replays it on the
// request for the handler.
func (m *Middleware[T]) readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	reader := io.Reader(r.Body)
	limit := m.policy.BodyLimit()
	if limit >= 0 {
		reader = io.LimitReader(reader, limit+1)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("httpsig/server: reading body: %w", err)
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	if limit >= 0 && int64(len(body)) > limit {
		return nil, ErrBodyTooLarge
	}
	return body, nil
}

func (m *Middleware[T]) reject(w http.ResponseWriter, r *http.Request, err error) {
	if m.errorHandler != nil {
		m.errorHandler(w, r, err)
		return
	}
	if errors.Is(err, ErrBodyTooLarge) {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	// The failure detail names covered components and key ids; it is for
	// the server's logs, not the peer.
	http.Error(w, "signature verification failed", http.StatusUnauthorized)
}

type ctxKey struct{}

func withVerified[T any](ctx context.Context, v *Verified[T]) context.Context {
	return context.WithValue(ctx, ctxKey{}, v)
}

// FromRequest returns the accepted signature and resolved identity for a
// request inside a handler wrapped by a [Middleware]. It reports false for
// a request that did not pass through the middleware. The type parameter
// must match the middleware's; a mismatch is a programming error and
// panics rather than masquerading as an unverified request.
func FromRequest[T any](r *http.Request) (*Verified[T], bool) {
	raw := r.Context().Value(ctxKey{})
	if raw == nil {
		return nil, false
	}
	v, ok := raw.(*Verified[T])
	if !ok {
		panic(fmt.Sprintf("httpsig/server: FromRequest[%T] on a request verified by a middleware of a different identity type %T", *new(T), raw))
	}
	return v, true
}
