// Package jwx provides [sdjwt.Signer] and [sdjwt.KeyResolver] implementations
// backed by github.com/lestrrat-go/jwx/v2.
//
// Most callers will use [NewSigner] and [NewHTTPKeyResolver] rather than
// constructing the core library interfaces themselves.
//
// Example — issuer setup:
//
//	privKey, _ := jwxjwk.ParseKey([]byte(pemOrJWKBytes))
//	signer, _ := jwx.NewSigner(privKey)
//	issuer := sdjwt.NewIssuer("https://bank.example", signer)
//
// Example — verifier setup:
//
//	resolver := jwx.NewHTTPKeyResolver(http.DefaultClient)
//	verifier := sdjwt.NewVerifier(resolver, sdjwt.RequireKeyBinding("https://verifier.example"))
package jwx

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// Signer implements [sdjwt.Signer] using a JWK private key.
type Signer struct {
	key jwk.Key
	alg string
}

// NewSigner creates a Signer from a JWK private key. The JWA algorithm is
// inferred from the key type unless overridden with [WithAlgorithm].
func NewSigner(key jwk.Key, opts ...SignerOption) (*Signer, error) {
	cfg := signerConfig{}
	for _, o := range opts {
		o(&cfg)
	}

	alg := cfg.alg
	if alg == "" {
		inferred, err := inferAlgorithm(key)
		if err != nil {
			return nil, fmt.Errorf("jwx signer: %w", err)
		}
		alg = inferred
	}

	return &Signer{key: key, alg: alg}, nil
}

type signerConfig struct{ alg string }

// SignerOption configures a [Signer].
type SignerOption func(*signerConfig)

// WithAlgorithm overrides the algorithm inferred from the key type.
func WithAlgorithm(alg string) SignerOption {
	return func(c *signerConfig) { c.alg = alg }
}

// Sign implements [sdjwt.Signer].
func (s *Signer) Sign(payload []byte) ([]byte, error) {
	// jws.Sign signs the full compact token; we only need the raw signature.
	// We use the low-level approach: sign the payload directly.
	sig, err := jws.Sign(payload,
		jws.WithKey(jwa.SignatureAlgorithm(s.alg), s.key),
		jws.WithDetachedPayload(true),
	)
	if err != nil {
		// Fall back to standard sign-and-extract.
		return signRaw(payload, s.key, s.alg)
	}
	_ = sig
	return signRaw(payload, s.key, s.alg)
}

// signRaw signs arbitrary bytes with key and returns the raw signature bytes.
func signRaw(payload []byte, key jwk.Key, alg string) ([]byte, error) {
	var raw crypto.Signer
	if err := key.Raw(&raw); err != nil {
		return nil, fmt.Errorf("extracting raw key: %w", err)
	}

	h, err := hashForAlg(alg)
	if err != nil {
		return nil, err
	}

	digest, err := hash(h, payload)
	if err != nil {
		return nil, err
	}

	sig, err := raw.Sign(nil, digest, h)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	return sig, nil
}

// Algorithm implements [sdjwt.Signer].
func (s *Signer) Algorithm() string { return s.alg }

// KeyID implements [sdjwt.Signer].
func (s *Signer) KeyID() string {
	if kid, ok := s.key.KeyID(); ok {
		return kid
	}
	// Compute the JWK thumbprint as the key ID when none is set.
	thumb, err := s.key.Thumbprint(crypto.SHA256)
	if err != nil {
		return ""
	}
	return string(thumb)
}

// PublicKey returns the public JWK corresponding to this signer's private key.
// Use this to embed the holder's public key in credential issuance requests.
func (s *Signer) PublicKey() (jwk.Key, error) {
	return s.key.PublicKey()
}

// --- HTTPKeyResolver ---

// HTTPKeyResolver fetches JWKS documents over HTTP and caches them.
// It implements [sdjwt.KeyResolver] by constructing the JWKS URL from the
// issuer identifier per the SD-JWT-VC spec.
type HTTPKeyResolver struct {
	client *http.Client
	mu     sync.RWMutex
	cache  map[string]cacheEntry
	ttl    time.Duration
}

type cacheEntry struct {
	set       jwk.Set
	fetchedAt time.Time
}

// NewHTTPKeyResolver creates a resolver that uses client for HTTP requests and
// caches JWKS responses for ttl (pass 0 for the default of 5 minutes).
func NewHTTPKeyResolver(client *http.Client, ttl time.Duration) *HTTPKeyResolver {
	if client == nil {
		client = http.DefaultClient
	}
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	return &HTTPKeyResolver{
		client: client,
		cache:  make(map[string]cacheEntry),
		ttl:    ttl,
	}
}

// ResolveKey implements [sdjwt.KeyResolver].
// It fetches the issuer's JWKS from <issuer>/.well-known/jwks.json and
// returns the key matching keyID. If keyID is empty and the JWKS contains
// exactly one key, that key is returned.
func (r *HTTPKeyResolver) ResolveKey(ctx context.Context, issuer, keyID string) (crypto.PublicKey, error) {
	set, err := r.fetchSet(ctx, issuer)
	if err != nil {
		return nil, err
	}

	if keyID != "" {
		key, ok := set.LookupKeyID(keyID)
		if !ok {
			return nil, fmt.Errorf("key %q not found in JWKS for %s", keyID, issuer)
		}
		return extractPublicKey(key)
	}

	if set.Len() == 1 {
		key, _ := set.Key(0)
		return extractPublicKey(key)
	}

	return nil, fmt.Errorf("JWKS for %s has %d keys but no kid was specified", issuer, set.Len())
}

func (r *HTTPKeyResolver) fetchSet(ctx context.Context, issuer string) (jwk.Set, error) {
	url := issuer + "/.well-known/jwks.json"

	r.mu.RLock()
	entry, ok := r.cache[url]
	r.mu.RUnlock()

	if ok && time.Since(entry.fetchedAt) < r.ttl {
		return entry.set, nil
	}

	set, err := jwk.Fetch(ctx, url, jwk.WithHTTPClient(r.client))
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS from %s: %w", url, err)
	}

	r.mu.Lock()
	r.cache[url] = cacheEntry{set: set, fetchedAt: time.Now()}
	r.mu.Unlock()

	return set, nil
}

// StaticKeyResolver resolves keys from an in-memory map. Useful for tests and
// environments where keys are loaded at startup.
type StaticKeyResolver struct {
	// keys maps "issuer\x00keyID" → public key. An empty keyID segment
	// means "the only key for this issuer".
	keys map[string]crypto.PublicKey
}

// NewStaticKeyResolver creates a resolver from a map of issuer→JWK set.
func NewStaticKeyResolver(sets map[string]jwk.Set) (*StaticKeyResolver, error) {
	r := &StaticKeyResolver{keys: make(map[string]crypto.PublicKey)}
	for issuer, set := range sets {
		for i := range set.Len() {
			key, _ := set.Key(i)
			pub, err := extractPublicKey(key)
			if err != nil {
				return nil, err
			}
			kid := ""
			if k, ok := key.KeyID(); ok {
				kid = k
			}
			r.keys[issuer+"\x00"+kid] = pub
		}
	}
	return r, nil
}

// ResolveKey implements [sdjwt.KeyResolver].
func (r *StaticKeyResolver) ResolveKey(_ context.Context, issuer, keyID string) (crypto.PublicKey, error) {
	if k, ok := r.keys[issuer+"\x00"+keyID]; ok {
		return k, nil
	}
	// Fall back to empty-kid entry.
	if k, ok := r.keys[issuer+"\x00"]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("no key for issuer=%q kid=%q", issuer, keyID)
}

// --- helpers ---

func extractPublicKey(key jwk.Key) (crypto.PublicKey, error) {
	pub, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("extracting public JWK: %w", err)
	}
	var raw crypto.PublicKey
	if err := pub.Raw(&raw); err != nil {
		return nil, fmt.Errorf("extracting raw public key: %w", err)
	}
	return raw, nil
}

func inferAlgorithm(key jwk.Key) (string, error) {
	if alg := key.Algorithm(); alg.String() != "" {
		return alg.String(), nil
	}
	// Infer from key type.
	switch key.KeyType().String() {
	case "EC":
		var crv jwa.EllipticCurveAlgorithm
		if err := key.Get("crv", &crv); err == nil {
			switch crv {
			case jwa.P256:
				return jwa.ES256.String(), nil
			case jwa.P384:
				return jwa.ES384.String(), nil
			case jwa.P521:
				return jwa.ES512.String(), nil
			}
		}
		return jwa.ES256.String(), nil
	case "RSA":
		return jwa.RS256.String(), nil
	case "OKP":
		return jwa.EdDSA.String(), nil
	default:
		return "", fmt.Errorf("cannot infer algorithm from key type %s", key.KeyType())
	}
}

func hashForAlg(alg string) (crypto.Hash, error) {
	switch alg {
	case "ES256", "RS256", "PS256":
		return crypto.SHA256, nil
	case "ES384", "RS384", "PS384":
		return crypto.SHA384, nil
	case "ES512", "RS512", "PS512":
		return crypto.SHA512, nil
	case "EdDSA":
		return 0, nil // EdDSA doesn't pre-hash
	default:
		return 0, fmt.Errorf("unsupported algorithm %q", alg)
	}
}

func hash(h crypto.Hash, data []byte) ([]byte, error) {
	if h == 0 {
		return data, nil // EdDSA: sign message directly
	}
	hh := h.New()
	hh.Write(data)
	return hh.Sum(nil), nil
}

func (key jwk.Key) Get(name string, dst any) error {
	return key.Get(name, dst)
}
