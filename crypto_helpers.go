package sdjwt

import (
	"crypto"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

// curveForName maps a JWK crv string to the Go elliptic.Curve.
func curveForName(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported EC curve %q", crv)
	}
}

// HashForAlg is a thin wrapper that lets verifier.go reference hash functions
// without importing crypto/sha* directly. It bridges the alg string world
// (from JWT headers) to Go's crypto.Hash.
type HashForAlg int

const (
	SHA256Alg HashForAlg = iota + 1
	SHA384Alg
	SHA512Alg
)

func (h HashForAlg) CryptoHash() crypto.Hash {
	switch h {
	case SHA256Alg:
		return crypto.SHA256
	case SHA384Alg:
		return crypto.SHA384
	default:
		return crypto.SHA512
	}
}

// sha256Sum, sha384Sum, sha512Sum are local wrappers so verifier.go can use
// them without importing the hash packages directly.

func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func sha384Sum(data []byte) [48]byte {
	return sha512.Sum384(data)
}

func sha512Sum(data []byte) [64]byte {
	return sha512.Sum512(data)
}
