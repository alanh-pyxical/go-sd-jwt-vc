// Package hashutil provides the digest helpers used internally by go-sd-jwt-vc.
// It is not part of the public API.
package hashutil

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
)

// HashForAlg is a named wrapper around crypto.Hash used by signature
// verification functions in the verifier.
type HashForAlg crypto.Hash

// CryptoHash returns the underlying crypto.Hash value.
func (h HashForAlg) CryptoHash() crypto.Hash { return crypto.Hash(h) }

// Pre-declared algorithm values used by verifier.go.
const (
	SHA256Alg HashForAlg = HashForAlg(crypto.SHA256)
	SHA384Alg HashForAlg = HashForAlg(crypto.SHA384)
	SHA512Alg HashForAlg = HashForAlg(crypto.SHA512)
)

// AlgorithmFromSDAlg maps the _sd_alg string from an SD-JWT to a
// [crypto.Hash]. Only the algorithms mandated by the spec are supported.
func AlgorithmFromSDAlg(alg string) (crypto.Hash, error) {
	switch alg {
	case "sha-256":
		return crypto.SHA256, nil
	case "sha-384":
		return crypto.SHA384, nil
	case "sha-512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported _sd_alg value %q", alg)
	}
}

// SDAlgFromHash returns the _sd_alg string for a given [crypto.Hash].
func SDAlgFromHash(h crypto.Hash) (string, error) {
	switch h {
	case crypto.SHA256:
		return "sha-256", nil
	case crypto.SHA384:
		return "sha-384", nil
	case crypto.SHA512:
		return "sha-512", nil
	default:
		return "", fmt.Errorf("no _sd_alg string for hash %v", h)
	}
}

// Digest computes a base64url-encoded (no padding) digest of data using h.
func Digest(h crypto.Hash, data []byte) (string, error) {
	hh, err := newHash(h)
	if err != nil {
		return "", err
	}
	hh.Write(data)
	return base64.RawURLEncoding.EncodeToString(hh.Sum(nil)), nil
}

// DigestSHA256 is a convenience wrapper for the common SHA-256 case.
func DigestSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newHash(h crypto.Hash) (hash.Hash, error) {
	switch h {
	case crypto.SHA256:
		return sha256.New(), nil
	case crypto.SHA384:
		return sha512.New384(), nil
	case crypto.SHA512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported hash %v", h)
	}
}
