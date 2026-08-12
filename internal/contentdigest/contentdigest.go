// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

// Package contentdigest computes and verifies the Content-Digest field of
// RFC 9530. Only sha-256 and sha-512 are supported; the registry's
// deprecated and insecure entries are deliberately absent.
package contentdigest

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/micahhausler/sfv"
)

// ErrNoAcceptedDigest reports a Content-Digest field with no entry in the
// verifier's accepted algorithm set.
var ErrNoAcceptedDigest = errors.New("httpsig: no Content-Digest entry uses an accepted algorithm")

// ErrDigestMismatch reports a Content-Digest entry that does not match the
// message body.
var ErrDigestMismatch = errors.New("httpsig: Content-Digest does not match the body")

func digest(alg string, body []byte) ([]byte, bool) {
	switch alg {
	case "sha-256":
		d := sha256.Sum256(body)
		return d[:], true
	case "sha-512":
		d := sha512.Sum512(body)
		return d[:], true
	}
	return nil, false
}

// Value computes a Content-Digest field value for the body, such as
// `sha-256=:...:`.
func Value(alg string, body []byte) (string, error) {
	d, ok := digest(alg, body)
	if !ok {
		return "", fmt.Errorf("httpsig: unsupported digest algorithm %q", alg)
	}
	b, err := sfv.Dictionary{{Key: alg, Value: sfv.Item{Value: sfv.Bytes(d)}}}.MarshalText()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Verify checks the Content-Digest field values against the body. Every
// entry with a supported algorithm must match the body, and at least one
// matching entry must use an algorithm in accepted. Entries with unsupported
// algorithms are ignored, but cannot satisfy the requirement on their own:
// a field carrying only unknown algorithms is rejected.
func Verify(values []string, body []byte, accepted []string) error {
	dict, err := sfv.ParseDictionary(values...)
	if err != nil {
		return fmt.Errorf("httpsig: Content-Digest is not a dictionary: %w", err)
	}
	if len(dict) == 0 {
		return errors.New("httpsig: Content-Digest is empty")
	}
	sawAccepted := false
	for _, m := range dict {
		item, ok := m.Value.(sfv.Item)
		if !ok {
			return fmt.Errorf("httpsig: Content-Digest entry %q is not an item", m.Key)
		}
		want, supported := digest(m.Key, body)
		if !supported {
			continue
		}
		got, ok := item.Value.(sfv.Bytes)
		if !ok {
			return fmt.Errorf("httpsig: Content-Digest entry %q is not a byte sequence", m.Key)
		}
		if !equalDigests([]byte(got), want) {
			return fmt.Errorf("%w: %s", ErrDigestMismatch, m.Key)
		}
		for _, a := range accepted {
			if m.Key == a {
				sawAccepted = true
			}
		}
	}
	if !sawAccepted {
		return ErrNoAcceptedDigest
	}
	return nil
}

// equalDigests compares digests without early exit. Digests are not secrets,
// but the comparison is on an attacker-reachable path and constant time
// costs nothing here.
func equalDigests(got, want []byte) bool {
	if len(got) != len(want) {
		return false
	}
	var v byte
	for i := range got {
		v |= got[i] ^ want[i]
	}
	return v == 0
}
