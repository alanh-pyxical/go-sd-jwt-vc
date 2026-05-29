package sdjwt

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/alanh-pyxical/go-sd-jwt-vc/internal/hashutil"
)

// Issuer creates SD-JWT-VC tokens. Construct one with [NewIssuer].
//
// A single Issuer is safe for concurrent use.
type Issuer struct {
	id     string
	signer Signer
	opts   issuerConfig
}

type issuerConfig struct {
	hashAlg      crypto.Hash
	decoyCount   int
	schemaURI    string
	tokenTTL     time.Duration
	extraHeaders map[string]any
}

// IssuerOption configures an [Issuer] at construction time.
type IssuerOption func(*issuerConfig)

// WithHashAlgorithm sets the digest algorithm used for disclosure hashes.
// Defaults to SHA-256, which is the only algorithm mandated by the spec.
func WithHashAlgorithm(h crypto.Hash) IssuerOption {
	return func(c *issuerConfig) { c.hashAlg = h }
}

// WithDecoyDigests adds n randomly-generated digests to the _sd array,
// making it harder for a verifier to infer the total number of claims from
// the digest count alone.
func WithDecoyDigests(n int) IssuerOption {
	return func(c *issuerConfig) { c.decoyCount = n }
}

// WithSchemaURI sets the vct#integrity or schema URI embedded in the issued
// credential, allowing verifiers to validate the credential structure.
func WithSchemaURI(uri string) IssuerOption {
	return func(c *issuerConfig) { c.schemaURI = uri }
}

// WithTokenTTL sets how long issued tokens remain valid (the exp claim).
// Defaults to 90 days if not set.
func WithTokenTTL(d time.Duration) IssuerOption {
	return func(c *issuerConfig) { c.tokenTTL = d }
}

// NewIssuer creates an Issuer that will sign tokens as issuerID using signer.
// issuerID must be a URI (typically HTTPS) that uniquely identifies the
// credential issuer — it becomes the iss claim in issued tokens.
func NewIssuer(issuerID string, signer Signer, opts ...IssuerOption) *Issuer {
	cfg := issuerConfig{
		hashAlg:  crypto.SHA256,
		tokenTTL: 90 * 24 * time.Hour,
	}
	for _, o := range opts {
		o(&cfg)
	}
	return &Issuer{id: issuerID, signer: signer, opts: cfg}
}

// maxNestingDepth is the maximum number of levels of nested structured claims
// the issuer will process. This guards against runaway recursion.
const maxNestingDepth = 16

// IssueRequest carries everything [Issuer.Issue] needs to create a token.
type IssueRequest struct {
	// VCT is the Verifiable Credential Type URI. Required.
	// Example: "https://credentials.example.com/MortgageOffer"
	VCT string

	// Subject is the sub claim (the credential subject identifier).
	Subject string

	// Claims holds all the credential claims.
	//
	// Flat selective disclosure (original behaviour):
	// Set SelectiveFields to name which top-level keys become disclosures.
	//
	// Structured selective disclosure (nested objects):
	// Set any map[string]any value to a [StructuredClaim] to make its
	// sub-fields independently selectively disclosable. The structured
	// object itself is always present in the JWT; its individual fields
	// may be hidden. Nesting is supported up to [maxNestingDepth] levels.
	//
	// Example — address sub-object with selective sub-fields:
	//
	//   Claims: map[string]any{
	//       "bank_name": "Lloyds",                // always disclosed
	//       "address": sdjwt.Structured(
	//           map[string]any{
	//               "street":   "10 Downing St",
	//               "postcode": "SW1A 2AA",
	//               "country":  "GB",
	//           },
	//           "street", "postcode",              // these become disclosures
	//       ),
	//   }
	Claims map[string]any

	// SelectiveFields names the top-level keys in Claims that should be made
	// selectively disclosable as whole values. For sub-field granularity on
	// nested objects, use [StructuredClaim] values in Claims instead.
	SelectiveFields []string

	// HolderKey, when non-nil, is the credential subject's public key.
	// It is embedded in the issuer JWT as a cnf claim, enabling key binding.
	// If nil, the issued token can be presented without a KB-JWT (bearer
	// token semantics).
	HolderKey crypto.PublicKey

	// NotBefore, if non-zero, sets the nbf claim. Defaults to now.
	NotBefore time.Time

	// ExpiresAt, if non-zero, overrides the TTL-derived exp claim.
	ExpiresAt time.Time
}

// StructuredClaim wraps a nested map[string]any so the issuer knows to
// recurse into it and make individual sub-fields selectively disclosable,
// rather than treating the whole object as a single opaque value.
//
// Use the [Structured] constructor rather than filling this directly.
type StructuredClaim struct {
	// Fields is the nested claim object.
	Fields map[string]any

	// SelectiveFields names which keys in Fields become individual
	// disclosures. Keys not listed here are always disclosed within the
	// nested object. May itself contain [StructuredClaim] values for
	// deeper nesting.
	SelectiveFields []string
}

// Structured is the constructor for [StructuredClaim]. It makes the named
// sub-fields of fields selectively disclosable.
//
//	sdjwt.Structured(
//	    map[string]any{"street": "10 Downing St", "city": "London"},
//	    "street",
//	)
func Structured(fields map[string]any, selectiveFields ...string) StructuredClaim {
	return StructuredClaim{Fields: fields, SelectiveFields: selectiveFields}
}

// Issue creates a new SD-JWT-VC token from req. The returned [Token] contains
// the full set of disclosures; use [Holder.Present] to select a subset for
// presentation to a verifier.
func (i *Issuer) Issue(ctx context.Context, req IssueRequest) (*Token, error) {
	if req.VCT == "" {
		return nil, fmt.Errorf("sdjwt: IssueRequest.VCT is required")
	}

	sdAlg, err := hashutil.SDAlgFromHash(i.opts.hashAlg)
	if err != nil {
		return nil, fmt.Errorf("sdjwt: %w", err)
	}

	// Validate all top-level selective fields exist before doing any work.
	for _, f := range req.SelectiveFields {
		if _, ok := req.Claims[f]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrSelectiveFieldNotFound, f)
		}
	}

	// Recursively process all claims, collecting disclosures as we go.
	var allDisclosures []string

	payload, err := i.buildClaimsObject(req.Claims, req.SelectiveFields, &allDisclosures, 0)
	if err != nil {
		return nil, err
	}

	// Add decoy digests at the top level only.
	if i.opts.decoyCount > 0 {
		existing, _ := payload["_sd"].([]string)
		for range i.opts.decoyCount {
			decoy, err := randomSalt(32)
			if err != nil {
				return nil, fmt.Errorf("sdjwt: generating decoy digest: %w", err)
			}
			existing = append(existing, decoy)
		}
		payload["_sd"] = existing
	}

	// Build the JWT registered claims.
	now := time.Now().UTC()
	nbf := req.NotBefore
	if nbf.IsZero() {
		nbf = now
	}
	exp := req.ExpiresAt
	if exp.IsZero() {
		exp = now.Add(i.opts.tokenTTL)
	}

	payload["iss"] = i.id
	payload["iat"] = now.Unix()
	payload["nbf"] = nbf.Unix()
	payload["exp"] = exp.Unix()
	payload["vct"] = req.VCT
	payload["_sd_alg"] = sdAlg

	if req.Subject != "" {
		payload["sub"] = req.Subject
	}
	if i.opts.schemaURI != "" {
		payload["vct#integrity"] = i.opts.schemaURI
	}
	if req.HolderKey != nil {
		cnf, err := buildCnf(req.HolderKey)
		if err != nil {
			return nil, fmt.Errorf("sdjwt: building cnf claim: %w", err)
		}
		payload["cnf"] = cnf
	}

	// Remove empty _sd array — omit it entirely when there are no selective
	// disclosures at the top level (they may all be in nested objects).
	if sd, ok := payload["_sd"].([]string); ok && len(sd) == 0 {
		delete(payload, "_sd")
	}

	issuerJWT, err := i.signJWT(payload)
	if err != nil {
		return nil, fmt.Errorf("sdjwt: signing issuer JWT: %w", err)
	}

	return &Token{
		IssuerJWT:   issuerJWT,
		Disclosures: allDisclosures,
	}, nil
}

// buildClaimsObject processes a map of claims at one level of nesting.
// It returns the JWT object for that level (with _sd array if needed) and
// appends any new disclosures to allDisclosures.
//
// selectiveFields names which top-level keys of claims become disclosures.
// Values that are [StructuredClaim] are always recursed into regardless.
func (i *Issuer) buildClaimsObject(
	claims map[string]any,
	selectiveFields []string,
	allDisclosures *[]string,
	depth int,
) (map[string]any, error) {

	if depth > maxNestingDepth {
		return nil, ErrNestingTooDeep
	}

	selective := make(map[string]bool, len(selectiveFields))
	for _, f := range selectiveFields {
		selective[f] = true
	}

	obj := make(map[string]any, len(claims))
	var sdDigests []string

	for k, v := range claims {
		switch typed := v.(type) {

		case StructuredClaim:
			// Recurse — produce a nested object with its own _sd array.
			nested, err := i.buildClaimsObject(
				typed.Fields,
				typed.SelectiveFields,
				allDisclosures,
				depth+1,
			)
			if err != nil {
				return nil, fmt.Errorf("sdjwt: structured claim %q: %w", k, err)
			}
			if selective[k] {
				// The whole nested object is itself a selective disclosure.
				d, err := NewDisclosure(k, nested)
				if err != nil {
					return nil, err
				}
				encoded, digest, err := d.Digest(i.opts.hashAlg)
				if err != nil {
					return nil, err
				}
				*allDisclosures = append(*allDisclosures, encoded)
				sdDigests = append(sdDigests, digest)
			} else {
				// The nested object is always present; only its sub-fields
				// are selectively disclosable (already handled by the
				// recursive call above).
				obj[k] = nested
			}

		case []any:
			// Slice values: each element may itself be a StructuredClaim or
			// a plain value. Plain elements become array disclosures when
			// the parent key is selective.
			if selective[k] {
				// Whole array as one disclosure.
				d, err := NewDisclosure(k, v)
				if err != nil {
					return nil, err
				}
				encoded, digest, err := d.Digest(i.opts.hashAlg)
				if err != nil {
					return nil, err
				}
				*allDisclosures = append(*allDisclosures, encoded)
				sdDigests = append(sdDigests, digest)
			} else {
				// Always-present array; individual elements may be wrapped
				// in {  "...": { "...": digest } } if caller uses
				// array-element selective disclosure (advanced use case).
				obj[k] = v
			}

		default:
			if selective[k] {
				d, err := NewDisclosure(k, v)
				if err != nil {
					return nil, err
				}
				encoded, digest, err := d.Digest(i.opts.hashAlg)
				if err != nil {
					return nil, err
				}
				*allDisclosures = append(*allDisclosures, encoded)
				sdDigests = append(sdDigests, digest)
			} else {
				obj[k] = v
			}
		}
	}

	if len(sdDigests) > 0 {
		obj["_sd"] = sdDigests
	}

	return obj, nil
}

// signJWT produces a compact-serialised JWT signed with i.signer.
// It does not depend on any external JWT library so that the core package
// stays stdlib-only.
func (i *Issuer) signJWT(payload map[string]any) (string, error) {
	header := map[string]any{
		"typ": "vc+sd-jwt",
		"alg": i.signer.Algorithm(),
	}
	if kid := i.signer.KeyID(); kid != "" {
		header["kid"] = kid
	}

	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	headerEnc := base64.RawURLEncoding.EncodeToString(hb)
	payloadEnc := base64.RawURLEncoding.EncodeToString(pb)
	signingInput := headerEnc + "." + payloadEnc

	sig, err := i.signer.Sign([]byte(signingInput))
	if err != nil {
		return "", err
	}
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)

	return strings.Join([]string{headerEnc, payloadEnc, sigEnc}, "."), nil
}

// buildCnf constructs the cnf (confirmation) claim map from a public key.
// Currently supports *ecdsa.PublicKey and *rsa.PublicKey via JSON marshalling
// through the standard crypto/ecdsa and encoding/json packages.
func buildCnf(pub crypto.PublicKey) (map[string]any, error) {
	// We rely on the adapters/jwx package for full JWK serialisation in
	// production use. Here we produce a minimal representation that the
	// verifier can round-trip. Callers using the adapters/jwx adapter will
	// get a richer cnf automatically via the JWKSigner option.
	b, err := json.Marshal(pub)
	if err != nil {
		return nil, fmt.Errorf("marshalling holder public key: %w", err)
	}
	var jwk map[string]any
	if err := json.Unmarshal(b, &jwk); err != nil {
		return nil, err
	}
	return map[string]any{"jwk": jwk}, nil
}
