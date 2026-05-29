package sdjwt

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/alanh-pyxical/go-sd-jwt-vc/internal/hashutil"
)

const (
	// DefaultSaltBytes is the number of random bytes used when generating a
	// disclosure salt. The spec requires at least 128 bits (16 bytes).
	DefaultSaltBytes = 16

	// minDisclosureElements is the minimum number of elements in the decoded
	// disclosure array (salt + key + value = 3 for object properties;
	// salt + value = 2 for array elements).
	minDisclosureElements = 2
)

// Disclosure represents a single selectively-disclosable claim. For object
// properties (the common case) it holds a Salt, Key, and Value. For array
// elements the Key is empty.
//
// Callers should construct Disclosures via [NewDisclosure] or
// [NewArrayDisclosure] rather than filling the struct directly, so that a
// cryptographically random salt is always generated.
type Disclosure struct {
	// Salt is the base64url-encoded random value that ensures each disclosure
	// encodes to a unique string even when the claim value is the same.
	Salt string

	// Key is the claim name. Empty for array-element disclosures.
	Key string

	// Value is the claim value. Any JSON-serialisable type is accepted.
	Value any
}

// NewDisclosure creates a Disclosure for an object property with a fresh
// cryptographically random salt.
func NewDisclosure(key string, value any) (*Disclosure, error) {
	salt, err := randomSalt(DefaultSaltBytes)
	if err != nil {
		return nil, fmt.Errorf("sdjwt: generating disclosure salt: %w", err)
	}
	return &Disclosure{Salt: salt, Key: key, Value: value}, nil
}

// NewArrayDisclosure creates a Disclosure for an array element. Array-element
// disclosures omit the key field per the spec.
func NewArrayDisclosure(value any) (*Disclosure, error) {
	salt, err := randomSalt(DefaultSaltBytes)
	if err != nil {
		return nil, fmt.Errorf("sdjwt: generating disclosure salt: %w", err)
	}
	return &Disclosure{Salt: salt, Value: value}, nil
}

// Encode returns the base64url-encoded JSON array that forms the disclosure
// string appended to an SD-JWT presentation.
//
// For object properties the array is [salt, key, value].
// For array elements the array is [salt, value].
func (d *Disclosure) Encode() (string, error) {
	var arr []any
	if d.Key != "" {
		arr = []any{d.Salt, d.Key, d.Value}
	} else {
		arr = []any{d.Salt, d.Value}
	}

	b, err := json.Marshal(arr)
	if err != nil {
		return "", fmt.Errorf("sdjwt: encoding disclosure: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Digest encodes the disclosure and returns its base64url-encoded digest using
// the supplied hash algorithm. The digest is what gets embedded in the _sd
// array of the issuer JWT.
func (d *Disclosure) Digest(h crypto.Hash) (encoded string, digest string, err error) {
	encoded, err = d.Encode()
	if err != nil {
		return "", "", err
	}
	digest, err = hashutil.Digest(h, []byte(encoded))
	if err != nil {
		return "", "", fmt.Errorf("sdjwt: digesting disclosure: %w", err)
	}
	return encoded, digest, nil
}

// ParseDisclosure decodes a base64url-encoded disclosure string back into a
// [Disclosure]. It returns [ErrDisclosureInvalid] if the string cannot be
// decoded or does not match the expected array structure.
func ParseDisclosure(encoded string) (*Disclosure, error) {
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, &DisclosureError{Err: fmt.Errorf("%w: base64 decode: %v", ErrDisclosureInvalid, err)}
	}

	var arr []json.RawMessage
	if err := json.Unmarshal(b, &arr); err != nil {
		return nil, &DisclosureError{Err: fmt.Errorf("%w: JSON parse: %v", ErrDisclosureInvalid, err)}
	}

	if len(arr) < minDisclosureElements {
		return nil, &DisclosureError{
			Err: fmt.Errorf("%w: expected at least %d elements, got %d",
				ErrDisclosureInvalid, minDisclosureElements, len(arr)),
		}
	}

	var salt string
	if err := json.Unmarshal(arr[0], &salt); err != nil {
		return nil, &DisclosureError{Err: fmt.Errorf("%w: salt is not a string", ErrDisclosureInvalid)}
	}

	// Three-element form: [salt, key, value] — object property.
	if len(arr) == 3 {
		var key string
		if err := json.Unmarshal(arr[1], &key); err != nil {
			return nil, &DisclosureError{Err: fmt.Errorf("%w: key is not a string", ErrDisclosureInvalid)}
		}
		var value any
		if err := json.Unmarshal(arr[2], &value); err != nil {
			return nil, &DisclosureError{Key: key, Err: fmt.Errorf("%w: value not parseable", ErrDisclosureInvalid)}
		}
		return &Disclosure{Salt: salt, Key: key, Value: value}, nil
	}

	// Two-element form: [salt, value] — array element.
	var value any
	if err := json.Unmarshal(arr[1], &value); err != nil {
		return nil, &DisclosureError{Err: fmt.Errorf("%w: value not parseable", ErrDisclosureInvalid)}
	}
	return &Disclosure{Salt: salt, Value: value}, nil
}

// randomSalt returns n cryptographically random bytes encoded as base64url.
func randomSalt(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
