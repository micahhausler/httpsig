# httpsig

A Go implementation of HTTP Message Signatures ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)).

The package provides the wire-level primitives: sign a request with a key,
parse the signatures on a request, and verify one against a key and policy.
Key distribution, signature selection, and nonce replay tracking belong to
the application. Higher-level client and server packages can build on these
primitives.

```
go get github.com/micahhausler/httpsig
```

## Signing

```go
signer, err := httpsig.NewSigner(httpsig.Ed25519, privateKey)
if err != nil {
	return err
}
err = httpsig.Sign(req, signer, httpsig.SignOptions{
	Components: []httpsig.Component{
		{Name: "@method"}, {Name: "@target-uri"}, {Name: "content-digest"},
	},
	KeyID: "my-key",
})
```

`Sign` adds the `Signature-Input` and `Signature` fields to the request,
merging with any signatures already present. Algorithms are always explicit;
nothing is inferred from the key type.

## Verifying

Verification is two-phase. `ParseSignatures` parses the signatures and builds
each signature base from the message as received. The caller then looks up
the key, by `KeyID` or however it likes, and checks each signature against a
policy:

```go
sigs, err := httpsig.ParseSignatures(req, nil)
if err != nil {
	// Malformed message.
}
for _, sig := range sigs {
	key, err := lookupKey(sig.KeyID()) // application-defined
	if err != nil {
		continue
	}
	err = sig.Verify(key, httpsig.Policy{
		RequiredComponents: []httpsig.Component{
			{Name: "@method"}, {Name: "@target-uri"}, {Name: "content-digest"},
		},
		MaxAge: 5 * time.Minute,
	})
	if err == nil {
		// Verified.
	}
}
```

Accessors such as `KeyID` report unverified claims from the wire until
`Verify` succeeds. Express requirements positively: accept a request when at
least one signature with the expected tag or key verifies. Anyone can attach
a signature to a request, so a policy that requires every signature to verify
is trivially broken by appending a garbage one. For the same reason, a defect
confined to one signature is reported by that signature's `Verify`, not by
`ParseSignatures`.

Verification errors come in two classes. A `*SyntaxError` means the message
or signature could not be parsed; servers usually answer 400. A
`*VerificationError` means the signature parsed but is not valid for the
message, key, or policy; servers usually answer 401. The wrapped sentinel
errors (`ErrSignatureMismatch`, `ErrExpired`, and so on) are testable with
`errors.Is`.

Servers behind a TLS-terminating proxy must set `ParseOptions.Scheme` and
`ParseOptions.Authority` to the external values the client signed. The
`X-Forwarded-*` fields are untrusted input and are never consulted.

## Algorithms

| Registry name       | Key types                            |
|---------------------|--------------------------------------|
| `rsa-pss-sha512`    | `*rsa.PrivateKey`, `*rsa.PublicKey`  |
| `rsa-v1_5-sha256`   | `*rsa.PrivateKey`, `*rsa.PublicKey`  |
| `hmac-sha256`       | `[]byte`                             |
| `ecdsa-p256-sha256` | `*ecdsa.PrivateKey`, `*ecdsa.PublicKey` |
| `ecdsa-p384-sha384` | `*ecdsa.PrivateKey`, `*ecdsa.PublicKey` |
| `ed25519`           | `ed25519.PrivateKey`, `ed25519.PublicKey` |

If a signature carries an `alg` parameter that disagrees with the verifier's
algorithm, verification fails. This closes the algorithm-confusion class of
attack in the primitive rather than in documentation.

## Scope

Request messages only. Not supported: response signing, the `req` and `tr`
component parameters, `@status`, JSON Web Signature algorithms, and the
`Accept-Signature` field. Unsupported components and parameters are rejected
with specific errors rather than skipped.

## Testing

The test suite includes the RFC 9421 [Appendix B](https://datatracker.ietf.org/doc/html/rfc9421#appendix-B) vectors: signature bases are
compared byte for byte against the strings printed in the RFC, the RFC's
signature values are verified against the RFC's keys, and the deterministic
`hmac-sha256` and `ed25519` vectors reproduce the exact `Signature-Input`
and `Signature` fields. Benchmarks for signing and verification run with
`go test -bench .`.

## License

Apache-2.0
