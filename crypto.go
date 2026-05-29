package sdjwt

import (
	"context"
	"crypto"
)

// Signer abstracts any asymmetric signing key capable of producing a JWT
// signature. Implementations are provided by callers or by the adapters
// sub-packages.
//
// The payload passed to Sign is the base64url(header).base64url(claims)
// string — the standard JWT signing input. The returned bytes are the raw
// signature, which the library base64url-encodes to form the third JWT
// component.
type Signer interface {
	// Sign produces a signature over payload using the underlying key.
	Sign(payload []byte) (signature []byte, err error)

	// Algorithm returns the JWA algorithm identifier (e.g. "ES256", "EdDSA").
	// This value is written into the JWT header's alg field.
	Algorithm() string

	// KeyID returns the key identifier placed in the JWT header's kid field.
	// An empty string omits the kid header.
	KeyID() string
}

// KeyResolver retrieves the public key needed to verify an issuer JWT.
// Implementations may fetch from a remote JWKS URI, a local key store,
// or a test fixture.
//
// The issuer parameter is the iss claim from the JWT. The keyID parameter
// is the kid header value; it may be empty if the JWT omits kid, in which
// case the resolver should return the sole key for that issuer or an error.
type KeyResolver interface {
	ResolveKey(ctx context.Context, issuer, keyID string) (crypto.PublicKey, error)
}

// KeyResolverFunc is a function that implements [KeyResolver]. It allows
// simple one-off resolvers to be written inline without defining a new type.
//
//	resolver := sdjwt.KeyResolverFunc(func(ctx context.Context, issuer, kid string) (crypto.PublicKey, error) {
//	    return myKeyStore.Lookup(issuer, kid)
//	})
type KeyResolverFunc func(ctx context.Context, issuer, keyID string) (crypto.PublicKey, error)

func (f KeyResolverFunc) ResolveKey(ctx context.Context, issuer, keyID string) (crypto.PublicKey, error) {
	return f(ctx, issuer, keyID)
}
