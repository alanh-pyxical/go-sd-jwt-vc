package sdjwt

import (
	"strings"
)

const tilde = "~"

// Token is a parsed SD-JWT-VC. It holds the raw issuer JWT string, the set of
// disclosure strings included in this presentation, and the optional KB-JWT.
//
// A Token is obtained by parsing a presentation string with [Parse], or as the
// output of [Issuer.Issue]. It is the input to [Verifier.Verify] and
// [Holder.Present].
type Token struct {
	// IssuerJWT is the base64url(header).base64url(payload).base64url(sig)
	// string produced and signed by the credential issuer.
	IssuerJWT string

	// Disclosures holds the base64url-encoded disclosure strings that were
	// included in this presentation. An issued token (before the holder
	// selects disclosures) contains all disclosures. A presented token
	// contains only the subset the holder chose to reveal.
	Disclosures []string

	// KBJWT is the Key Binding JWT appended by the holder to bind the
	// presentation to a specific verifier and nonce. It is empty for tokens
	// that have not yet been presented (e.g. as stored in a wallet).
	KBJWT string
}

// String serialises the token back to its tilde-separated wire format:
//
//	<issuerJWT>~[disc1~disc2~...]~[kbJWT]
//
// This is the value sent over the wire to a verifier.
func (t *Token) String() string {
	parts := make([]string, 0, 2+len(t.Disclosures))
	parts = append(parts, t.IssuerJWT)
	parts = append(parts, t.Disclosures...)
	parts = append(parts, t.KBJWT) // empty string → trailing tilde, which is correct
	return strings.Join(parts, tilde)
}

// Prefix returns the presentation prefix used when computing the sd_hash for
// key binding: issuerJWT~disc1~disc2~
// Note the trailing tilde and absence of the KB-JWT.
func (t *Token) Prefix() string {
	parts := make([]string, 0, 1+len(t.Disclosures))
	parts = append(parts, t.IssuerJWT)
	parts = append(parts, t.Disclosures...)
	// Join gives us issuerJWT~disc1~disc2, then we append ~ manually.
	return strings.Join(parts, tilde) + tilde
}

// HasKeyBinding reports whether this token includes a KB-JWT.
func (t *Token) HasKeyBinding() bool { return t.KBJWT != "" }

// Parse splits a tilde-separated SD-JWT presentation string into its
// constituent parts. It performs structural validation only; signature
// verification is done by [Verifier.Verify].
//
// A valid SD-JWT string has at least one tilde, starts with the issuer JWT,
// and optionally ends with a KB-JWT. An empty final segment (trailing tilde,
// no KB-JWT) is accepted — this represents a stored credential awaiting
// holder presentation.
func Parse(raw string) (*Token, error) {
	if raw == "" {
		return nil, ErrInvalidFormat
	}

	parts := strings.Split(raw, tilde)
	if len(parts) < 2 {
		return nil, ErrInvalidFormat
	}

	issuerJWT := parts[0]
	if issuerJWT == "" {
		return nil, ErrInvalidFormat
	}

	// The last segment is either a KB-JWT or an empty string (trailing ~).
	last := parts[len(parts)-1]
	middle := parts[1 : len(parts)-1]

	t := &Token{
		IssuerJWT:   issuerJWT,
		Disclosures: make([]string, 0, len(middle)),
		KBJWT:       last,
	}

	for _, d := range middle {
		if d == "" {
			// Empty disclosure segment is not allowed between issuer JWT and KB-JWT.
			return nil, ErrInvalidFormat
		}
		t.Disclosures = append(t.Disclosures, d)
	}

	return t, nil
}
