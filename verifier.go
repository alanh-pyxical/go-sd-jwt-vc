package sdjwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/alanh-pyxical/go-sd-jwt-vc/internal/hashutil"
)

// maxVerifyDepth is the maximum nesting depth the verifier will recurse into
// when collecting _sd digests. Mirrors [maxNestingDepth] in the issuer.
const maxVerifyDepth = 16

// Verifier validates SD-JWT-VC presentations. Construct one with [NewVerifier].
//
// A Verifier is safe for concurrent use.
type Verifier struct {
	resolver KeyResolver
	opts     verifierConfig
}

type verifierConfig struct {
	// expectedVCT, if set, is checked against the vct claim.
	expectedVCT string
	// requireKeyBinding controls whether a KB-JWT must be present.
	requireKeyBinding bool
	// audience is the verifier's own identifier, checked against KB-JWT aud.
	audience string
	// clockSkew permits small clock differences between issuer and verifier.
	clockSkew time.Duration
}

// VerifierOption configures a [Verifier].
type VerifierOption func(*verifierConfig)

// RequireKeyBinding configures the verifier to reject presentations that do
// not include a valid KB-JWT. audience is the verifier's own identifier (its
// HTTPS URI) and will be checked against the KB-JWT's aud claim.
func RequireKeyBinding(audience string) VerifierOption {
	return func(c *verifierConfig) {
		c.requireKeyBinding = true
		c.audience = audience
	}
}

// ExpectVCT configures the verifier to reject presentations whose vct claim
// does not equal vct.
func ExpectVCT(vct string) VerifierOption {
	return func(c *verifierConfig) { c.expectedVCT = vct }
}

// WithClockSkew permits up to d of clock skew when evaluating iat/exp/nbf.
// Defaults to zero (strict).
func WithClockSkew(d time.Duration) VerifierOption {
	return func(c *verifierConfig) { c.clockSkew = d }
}

// NewVerifier creates a Verifier that resolves issuer keys via resolver.
func NewVerifier(resolver KeyResolver, opts ...VerifierOption) *Verifier {
	cfg := verifierConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	return &Verifier{resolver: resolver, opts: cfg}
}

// VerifyOptions carries per-call options that cannot be set globally on the
// Verifier — typically the nonce from the current transaction.
type VerifyOptions struct {
	// Nonce is the challenge previously issued to the holder. Required when
	// the Verifier was configured with RequireKeyBinding.
	Nonce string
}

// VerificationResult is returned by a successful [Verifier.Verify] call.
// It exposes the verified claims, never raw JWT strings.
type VerificationResult struct {
	// IssuerClaims holds all claims from the issuer JWT, including those
	// that were selectively disclosed.
	IssuerClaims map[string]any

	// DisclosedClaims holds only the claims that were revealed by the
	// holder in this presentation (i.e. those with matching disclosures).
	DisclosedClaims map[string]any

	// Issuer is the iss claim from the issuer JWT.
	Issuer string

	// VCT is the Verifiable Credential Type from the issuer JWT.
	VCT string

	// Subject is the sub claim, if present.
	Subject string

	// KeyBound is true if a valid KB-JWT was verified.
	KeyBound bool
}

// Verify performs the full SD-JWT-VC verification chain on raw, a
// tilde-separated presentation string:
//
//  1. Parse the presentation into issuer JWT, disclosures, and optional KB-JWT.
//  2. Decode and validate the issuer JWT header and payload.
//  3. Resolve the issuer's public key and verify the JWT signature.
//  4. Check iat/nbf/exp timing claims.
//  5. Verify each disclosure's digest appears exactly once in the _sd array.
//  6. Check for duplicate disclosure keys.
//  7. If a KB-JWT is present (or required): verify its signature against the
//     cnf key, check aud and nonce, verify sd_hash covers the prefix.
//  8. Optionally check the vct claim.
//
// Verify returns a [VerificationResult] only when all checks pass. On failure
// it returns a [VerificationError] wrapping the appropriate sentinel.
func (v *Verifier) Verify(ctx context.Context, raw string, vopts VerifyOptions) (*VerificationResult, error) {
	t, err := Parse(raw)
	if err != nil {
		return nil, &VerificationError{Stage: "parse", Err: err}
	}

	// --- Step 1: decode the issuer JWT (no sig verification yet) ---
	issuerHeader, issuerPayload, err := decodeJWT(t.IssuerJWT)
	if err != nil {
		return nil, &VerificationError{Stage: "issuer_jwt_decode", Err: ErrInvalidFormat}
	}

	// --- Step 2: resolve issuer key ---
	issuer, _ := issuerPayload["iss"].(string)
	if issuer == "" {
		return nil, &VerificationError{Stage: "issuer_jwt_decode", Err: fmt.Errorf("%w: missing iss", ErrInvalidFormat)}
	}
	keyID, _ := issuerHeader["kid"].(string)
	alg, _ := issuerHeader["alg"].(string)

	pubKey, err := v.resolver.ResolveKey(ctx, issuer, keyID)
	if err != nil {
		return nil, &VerificationError{Stage: "key_resolution", Err: fmt.Errorf("%w: %v", ErrKeyResolutionFailed, err)}
	}

	// --- Step 3: verify issuer JWT signature ---
	if err := verifyJWTSignature(t.IssuerJWT, pubKey, alg); err != nil {
		return nil, &VerificationError{Stage: "signature", Err: ErrSignatureInvalid}
	}

	// --- Step 4: timing claims ---
	now := time.Now().UTC()
	skew := v.opts.clockSkew

	if exp, ok := issuerPayload["exp"].(float64); ok {
		if now.After(time.Unix(int64(exp), 0).Add(skew)) {
			return nil, &VerificationError{Stage: "exp", Err: ErrTokenExpired}
		}
	}
	if nbf, ok := issuerPayload["nbf"].(float64); ok {
		if now.Before(time.Unix(int64(nbf), 0).Add(-skew)) {
			return nil, &VerificationError{Stage: "nbf", Err: ErrTokenNotYetValid}
		}
	}

	// --- Step 5: resolve _sd_alg ---
	sdAlgStr, _ := issuerPayload["_sd_alg"].(string)
	if sdAlgStr == "" {
		sdAlgStr = "sha-256" // default per spec
	}
	hashAlg, err := hashutil.AlgorithmFromSDAlg(sdAlgStr)
	if err != nil {
		return nil, &VerificationError{Stage: "sd_alg", Err: ErrUnsupportedHashAlgorithm}
	}

	// --- Step 6: verify disclosures ---
	//
	// Structured SD-JWTs embed _sd arrays at multiple levels of nesting, not
	// just at the top level. We perform a two-pass approach:
	//
	//   Pass 1: walk the entire issuer JWT payload and collect every digest
	//           found in any _sd array, recording which object in the tree it
	//           belongs to so we can write the revealed value back in place.
	//
	//   Pass 2: for each disclosure in the presentation, compute its digest,
	//           look it up in the collected set, verify it was expected, and
	//           record the revealed claim.

	// digestLocation records where in the payload tree a digest lives.
	type digestLocation struct {
		container map[string]any // the object that holds the _sd array
	}

	// collectDigests walks obj recursively and returns a map of
	// digest string → digestLocation.
	var collectDigests func(obj map[string]any, depth int) (map[string]digestLocation, error)
	collectDigests = func(obj map[string]any, depth int) (map[string]digestLocation, error) {
		if depth > maxVerifyDepth {
			return nil, ErrNestingTooDeep
		}
		out := make(map[string]digestLocation)

		// Collect digests at this level.
		if sdRaw, ok := obj["_sd"].([]any); ok {
			for _, h := range sdRaw {
				if s, ok := h.(string); ok {
					out[s] = digestLocation{container: obj}
				}
			}
		}

		// Recurse into any nested objects.
		for _, v := range obj {
			if nested, ok := v.(map[string]any); ok {
				sub, err := collectDigests(nested, depth+1)
				if err != nil {
					return nil, err
				}
				for k, loc := range sub {
					out[k] = loc
				}
			}
		}
		return out, nil
	}

	digestMap, err := collectDigests(issuerPayload, 0)
	if err != nil {
		return nil, &VerificationError{Stage: "disclosure_collect", Err: err}
	}

	// disclosedClaims is a flat view of every revealed claim (key → value),
	// regardless of nesting depth. This is what VerificationResult exposes.
	disclosedClaims := map[string]any{}
	seenKeys := map[string]bool{}

	for _, enc := range t.Disclosures {
		d, err := ParseDisclosure(enc)
		if err != nil {
			return nil, &VerificationError{Stage: "disclosure_parse", Err: err}
		}

		// Recompute the digest and look it up across all nesting levels.
		digest, err := hashutil.Digest(hashAlg, []byte(enc))
		if err != nil {
			return nil, &VerificationError{Stage: "disclosure_hash", Err: err}
		}

		loc, found := digestMap[digest]
		if !found {
			return nil, &VerificationError{
				Stage: "disclosure_hash",
				Err:   &DisclosureError{Key: d.Key, Err: ErrDisclosureMismatch},
			}
		}

		if d.Key != "" {
			// Duplicate key check — scoped globally across all nesting levels,
			// which is the conservative safe choice.
			if seenKeys[d.Key] {
				return nil, &VerificationError{
					Stage: "disclosure_duplicate",
					Err:   &DisclosureError{Key: d.Key, Err: ErrDisclosureDuplicate},
				}
			}
			seenKeys[d.Key] = true

			// Write the revealed value back into the container object so that
			// IssuerClaims reflects the fully-reconstructed payload tree.
			loc.container[d.Key] = d.Value

			// Also record in the flat disclosed map.
			disclosedClaims[d.Key] = d.Value
		}
	}

	// --- Step 7: KB-JWT verification ---
	keyBound := false

	if v.opts.requireKeyBinding && !t.HasKeyBinding() {
		return nil, &VerificationError{Stage: "kbjwt", Err: ErrKBJWTRequired}
	}

	if t.HasKeyBinding() {
		cnf, err := extractCnf(issuerPayload)
		if err != nil {
			return nil, &VerificationError{Stage: "cnf", Err: ErrCnfMissing}
		}

		if err := v.verifyKBJWT(t, cnf, vopts.Nonce, v.opts.audience); err != nil {
			return nil, err
		}
		keyBound = true
	}

	// --- Step 8: vct check ---
	vct, _ := issuerPayload["vct"].(string)
	if v.opts.expectedVCT != "" && vct != v.opts.expectedVCT {
		return nil, &VerificationError{Stage: "vct", Err: ErrVCTMismatch}
	}

	sub, _ := issuerPayload["sub"].(string)

	return &VerificationResult{
		IssuerClaims:    issuerPayload,
		DisclosedClaims: disclosedClaims,
		Issuer:          issuer,
		VCT:             vct,
		Subject:         sub,
		KeyBound:        keyBound,
	}, nil
}

// verifyKBJWT validates the KB-JWT against the holder's cnf key.
func (v *Verifier) verifyKBJWT(t *Token, holderKey any, expectedNonce, expectedAud string) error {
	_, kbPayload, err := decodeJWT(t.KBJWT)
	if err != nil {
		return &VerificationError{Stage: "kbjwt_decode", Err: ErrKBJWTInvalid}
	}

	// Verify KB-JWT signature against holder key from cnf.
	pubKey, err := jwkToPublicKey(holderKey)
	if err != nil {
		return &VerificationError{Stage: "kbjwt_key", Err: fmt.Errorf("%w: cnf key: %v", ErrKBJWTInvalid, err)}
	}

	kbHeader, _, _ := decodeJWT(t.KBJWT)
	alg, _ := kbHeader["alg"].(string)
	if err := verifyJWTSignature(t.KBJWT, pubKey, alg); err != nil {
		return &VerificationError{Stage: "kbjwt_sig", Err: ErrKBJWTInvalid}
	}

	// Nonce check.
	if expectedNonce != "" {
		nonce, _ := kbPayload["nonce"].(string)
		if nonce != expectedNonce {
			return &VerificationError{Stage: "kbjwt_nonce", Err: ErrKBJWTNonceMismatch}
		}
	}

	// Audience check.
	if expectedAud != "" {
		switch aud := kbPayload["aud"].(type) {
		case string:
			if aud != expectedAud {
				return &VerificationError{Stage: "kbjwt_aud", Err: ErrKBJWTAudMismatch}
			}
		case []any:
			found := false
			for _, a := range aud {
				if s, ok := a.(string); ok && s == expectedAud {
					found = true
					break
				}
			}
			if !found {
				return &VerificationError{Stage: "kbjwt_aud", Err: ErrKBJWTAudMismatch}
			}
		default:
			return &VerificationError{Stage: "kbjwt_aud", Err: ErrKBJWTAudMismatch}
		}
	}

	// sd_hash check — recompute over the presentation prefix.
	expectedHash := hashutil.DigestSHA256([]byte(t.Prefix()))
	sdHash, _ := kbPayload["sd_hash"].(string)
	if sdHash != expectedHash {
		return &VerificationError{Stage: "kbjwt_sd_hash", Err: ErrKBJWTHashMismatch}
	}

	return nil
}

// --- JWT helpers (stdlib-only, no external JWT library) ---

// decodeJWT decodes a compact-serialised JWT into its header and payload maps.
// It does NOT verify the signature.
func decodeJWT(token string) (header, payload map[string]any, err error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("not a three-part JWT")
	}

	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("header decode: %w", err)
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("payload decode: %w", err)
	}

	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, nil, fmt.Errorf("header json: %w", err)
	}
	if err := json.Unmarshal(pb, &payload); err != nil {
		return nil, nil, fmt.Errorf("payload json: %w", err)
	}
	return header, payload, nil
}

// verifyJWTSignature verifies the signature of a compact-serialised JWT using
// the supplied public key and algorithm name. Supports ES256, ES384, ES512,
// RS256, RS384, RS512, PS256, PS384, PS512.
func verifyJWTSignature(token string, pub any, alg string) error {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("signature decode: %w", err)
	}

	digest, hashFunc, err := algToDigest(alg, signingInput)
	if err != nil {
		return err
	}

	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return verifyECDSA(key, digest, sig, hashFunc)
	case *rsa.PublicKey:
		return verifyRSA(key, digest, sig, alg, hashFunc)
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
}

func algToDigest(alg string, data []byte) (digest []byte, h hashutil.HashForAlg, err error) {
	switch alg {
	case "ES256", "RS256", "PS256":
		h = hashutil.SHA256Alg
		sum := sha256Sum(data)
		return sum[:], h, nil
	case "ES384", "RS384", "PS384":
		h = hashutil.SHA384Alg
		sum := sha384Sum(data)
		return sum[:], h, nil
	case "ES512", "RS512", "PS512":
		h = hashutil.SHA512Alg
		sum := sha512Sum(data)
		return sum[:], h, nil
	default:
		return nil, 0, fmt.Errorf("unsupported algorithm %q", alg)
	}
}

func verifyECDSA(key *ecdsa.PublicKey, digest, sig []byte, _ hashutil.HashForAlg) error {
	// ECDSA signature is two big-endian integers of length = key curve byte size.
	l := len(sig) / 2
	if len(sig) != 2*l {
		return fmt.Errorf("invalid ECDSA signature length %d", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:l])
	s := new(big.Int).SetBytes(sig[l:])
	if !ecdsa.Verify(key, digest, r, s) {
		return ErrSignatureInvalid
	}
	return nil
}

func verifyRSA(key *rsa.PublicKey, digest, sig []byte, alg string, h hashutil.HashForAlg) error {
	hash := h.CryptoHash()
	switch {
	case strings.HasPrefix(alg, "PS"):
		return rsa.VerifyPSS(key, hash, digest, sig, nil)
	default:
		return rsa.VerifyPKCS1v15(key, hash, digest, sig)
	}
}

// extractCnf pulls the JWK from the cnf.jwk path in an issuer JWT payload.
func extractCnf(payload map[string]any) (map[string]any, error) {
	cnf, ok := payload["cnf"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("cnf claim absent or wrong type")
	}
	jwk, ok := cnf["jwk"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("cnf.jwk absent or wrong type")
	}
	return jwk, nil
}

// jwkToPublicKey reconstructs a crypto.PublicKey from a JWK map.
// Supports EC (P-256, P-384, P-521) and RSA keys.
func jwkToPublicKey(jwk any) (any, error) {
	m, ok := jwk.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("cnf is not a JWK map")
	}

	kty, _ := m["kty"].(string)
	switch kty {
	case "EC":
		return ecPublicKeyFromJWK(m)
	case "RSA":
		return rsaPublicKeyFromJWK(m)
	default:
		return nil, fmt.Errorf("unsupported JWK kty %q", kty)
	}
}

func ecPublicKeyFromJWK(m map[string]any) (*ecdsa.PublicKey, error) {
	crv, _ := m["crv"].(string)
	xStr, _ := m["x"].(string)
	yStr, _ := m["y"].(string)

	xb, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("ec jwk x: %w", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("ec jwk y: %w", err)
	}

	curve, err := curveForName(crv)
	if err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}, nil
}

func rsaPublicKeyFromJWK(m map[string]any) (*rsa.PublicKey, error) {
	nStr, _ := m["n"].(string)
	eStr, _ := m["e"].(string)

	nb, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("rsa jwk n: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("rsa jwk e: %w", err)
	}

	eInt := int(new(big.Int).SetBytes(eb).Int64())
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: eInt,
	}, nil
}
