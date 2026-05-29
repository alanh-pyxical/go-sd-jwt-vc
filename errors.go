// Package sdjwt implements SD-JWT-VC (Selective Disclosure for JWTs as
// Verifiable Credentials) as defined in draft-ietf-oauth-sd-jwt-vc.
//
// The library is structured around three roles:
//
//   - [Issuer] creates and signs SD-JWT-VC tokens
//   - [Holder] selects disclosures and constructs presentations with key binding
//   - [Verifier] validates presentations end-to-end
//
// Cryptographic operations are delegated to caller-supplied implementations of
// [Signer] and [KeyResolver], keeping the core library free of mandatory
// dependencies. Ready-made adapters for lestrrat-go/jwx are in the adapters/jwx
// sub-package.
package sdjwt

import (
	"errors"
	"fmt"
)

// Sentinel errors returned by this package. Callers should use [errors.Is] to
// test for these values rather than comparing strings.
var (
	// ErrInvalidFormat is returned when a token string cannot be parsed as a
	// valid SD-JWT (e.g. missing tildes, malformed base64).
	ErrInvalidFormat = errors.New("sdjwt: invalid token format")

	// ErrSignatureInvalid is returned when the issuer JWT signature does not
	// verify against the resolved public key.
	ErrSignatureInvalid = errors.New("sdjwt: issuer signature invalid")

	// ErrKeyResolutionFailed is returned when the issuer's public key cannot
	// be retrieved from the configured KeyResolver.
	ErrKeyResolutionFailed = errors.New("sdjwt: key resolution failed")

	// ErrDisclosureMismatch is returned when a disclosure's digest does not
	// appear in the _sd array of the issuer JWT.
	ErrDisclosureMismatch = errors.New("sdjwt: disclosure digest not found in token")

	// ErrDisclosureDuplicate is returned when the same claim key appears in
	// more than one disclosure within a single presentation.
	ErrDisclosureDuplicate = errors.New("sdjwt: duplicate disclosure key")

	// ErrDisclosureInvalid is returned when a disclosure cannot be decoded or
	// does not conform to the expected [salt, key, value] structure.
	ErrDisclosureInvalid = errors.New("sdjwt: disclosure encoding invalid")

	// ErrKBJWTRequired is returned when the verifier requires key binding but
	// the presentation contains no KB-JWT.
	ErrKBJWTRequired = errors.New("sdjwt: key binding required but KB-JWT absent")

	// ErrKBJWTInvalid is returned when the KB-JWT cannot be parsed or its
	// signature does not verify against the cnf key in the issuer JWT.
	ErrKBJWTInvalid = errors.New("sdjwt: KB-JWT signature invalid")

	// ErrKBJWTNonceMismatch is returned when the nonce in the KB-JWT does not
	// match the nonce supplied to the verifier.
	ErrKBJWTNonceMismatch = errors.New("sdjwt: KB-JWT nonce mismatch")

	// ErrKBJWTAudMismatch is returned when the aud claim in the KB-JWT does
	// not match the verifier's expected audience.
	ErrKBJWTAudMismatch = errors.New("sdjwt: KB-JWT audience mismatch")

	// ErrKBJWTHashMismatch is returned when the sd_hash in the KB-JWT does not
	// match the digest of the presentation prefix.
	ErrKBJWTHashMismatch = errors.New("sdjwt: KB-JWT sd_hash mismatch")

	// ErrHolderKeyMissing is returned when key binding is requested during
	// issuance but no holder public key is provided.
	ErrHolderKeyMissing = errors.New("sdjwt: holder key required for key binding but not provided")

	// ErrCnfMissing is returned when a KB-JWT is present but the issuer JWT
	// contains no cnf claim to validate the holder key against.
	ErrCnfMissing = errors.New("sdjwt: cnf claim absent from issuer JWT")

	// ErrTokenExpired is returned when the exp claim in the issuer JWT
	// indicates the token is no longer valid.
	ErrTokenExpired = errors.New("sdjwt: token has expired")

	// ErrTokenNotYetValid is returned when the nbf claim in the issuer JWT
	// is in the future.
	ErrTokenNotYetValid = errors.New("sdjwt: token not yet valid")

	// ErrVCTMismatch is returned when the vct claim does not match the
	// type expected by the verifier.
	ErrVCTMismatch = errors.New("sdjwt: vct mismatch")

	// ErrUnsupportedHashAlgorithm is returned when the _sd_alg value in the
	// issuer JWT names an algorithm this library does not support.
	ErrUnsupportedHashAlgorithm = errors.New("sdjwt: unsupported hash algorithm")

	// ErrSelectiveFieldNotFound is returned when Issue is called with a
	// selective field name that does not exist in the provided payload.
	ErrSelectiveFieldNotFound = errors.New("sdjwt: selective field not found in payload")

	// ErrNestingTooDeep is returned when a structured claim map exceeds the
	// maximum supported nesting depth (currently 16 levels). This guards
	// against accidentally recursive or maliciously crafted payloads.
	ErrNestingTooDeep = errors.New("sdjwt: structured claims exceed maximum nesting depth")
)

// DisclosureError records a failure that can be attributed to a specific
// disclosure key, providing better diagnostics than a bare sentinel.
type DisclosureError struct {
	// Key is the claim name from the failing disclosure. Empty for
	// array-element disclosures.
	Key string
	// Err is the underlying sentinel error (e.g. ErrDisclosureMismatch).
	Err error
}

func (e *DisclosureError) Error() string {
	if e.Key != "" {
		return fmt.Sprintf("sdjwt: disclosure %q: %v", e.Key, e.Err)
	}
	return fmt.Sprintf("sdjwt: disclosure: %v", e.Err)
}

func (e *DisclosureError) Unwrap() error { return e.Err }

// VerificationError records a complete verification failure with enough
// context to produce a useful audit log entry.
type VerificationError struct {
	// Stage names the verification step that failed
	// (e.g. "signature", "kbjwt_nonce", "disclosure_hash").
	Stage string
	// Err is the underlying cause.
	Err error
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("sdjwt: verification failed at %s: %v", e.Stage, e.Err)
}

func (e *VerificationError) Unwrap() error { return e.Err }
