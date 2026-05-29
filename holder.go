package sdjwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/alanh-pyxical/go-sd-jwt-vc/internal/hashutil"
)

// Holder constructs presentations from stored tokens, selecting which claims
// to disclose and optionally appending a Key Binding JWT.
//
// A custodial wallet creates one Holder per managed credential subject key.
// A self-custodied wallet typically has one Holder for the wallet's own key.
//
// A Holder is safe for concurrent use.
type Holder struct {
	signer Signer // the holder/subject key — signs KB-JWTs
}

// NewHolder creates a Holder that will sign KB-JWTs with signer.
// Pass nil if you only need [Holder.FilterDisclosures] without key binding.
func NewHolder(signer Signer) *Holder {
	return &Holder{signer: signer}
}

// PresentOptions controls how [Holder.Present] builds a presentation.
type PresentOptions struct {
	// RevealClaims lists the claim keys to include in the presentation.
	// Claims not listed here are withheld (their disclosures are dropped).
	// If empty, all disclosures from the token are included.
	RevealClaims []string

	// Nonce is the challenge issued by the verifier. Required when
	// KeyBinding is true.
	Nonce string

	// Audience is the verifier's identifier (typically its HTTPS URI).
	// Required when KeyBinding is true.
	Audience string

	// KeyBinding controls whether a KB-JWT is appended to the presentation.
	// Requires that the token was issued with a cnf claim and that this
	// Holder was constructed with a non-nil Signer.
	KeyBinding bool
}

// Present builds a presentation token from t, filtered to the claims named
// in opts.RevealClaims. If opts.KeyBinding is true, a KB-JWT is appended.
//
// The returned [Token] is ready to serialise with [Token.String] and send to
// a verifier.
func (h *Holder) Present(ctx context.Context, t *Token, opts PresentOptions) (*Token, error) {
	// Select the disclosures to include.
	selected, err := h.selectDisclosures(t, opts.RevealClaims)
	if err != nil {
		return nil, err
	}

	presented := &Token{
		IssuerJWT:   t.IssuerJWT,
		Disclosures: selected,
	}

	if !opts.KeyBinding {
		return presented, nil
	}

	if h.signer == nil {
		return nil, fmt.Errorf("sdjwt: Holder has no Signer; cannot produce KB-JWT")
	}
	if opts.Nonce == "" {
		return nil, fmt.Errorf("sdjwt: Nonce is required for key binding")
	}
	if opts.Audience == "" {
		return nil, fmt.Errorf("sdjwt: Audience is required for key binding")
	}

	kbJWT, err := h.buildKBJWT(presented, opts.Nonce, opts.Audience)
	if err != nil {
		return nil, fmt.Errorf("sdjwt: building KB-JWT: %w", err)
	}

	presented.KBJWT = kbJWT
	return presented, nil
}

// selectDisclosures filters t.Disclosures to only those whose decoded key
// appears in reveal. If reveal is empty, all disclosures are returned.
func (h *Holder) selectDisclosures(t *Token, reveal []string) ([]string, error) {
	if len(reveal) == 0 {
		// Caller wants everything — return a copy.
		out := make([]string, len(t.Disclosures))
		copy(out, t.Disclosures)
		return out, nil
	}

	wanted := make(map[string]bool, len(reveal))
	for _, k := range reveal {
		wanted[k] = true
	}

	var selected []string
	for _, enc := range t.Disclosures {
		d, err := ParseDisclosure(enc)
		if err != nil {
			return nil, err
		}
		// Array-element disclosures have no Key; include them only if the
		// caller explicitly passes an empty key in RevealClaims or always
		// (since they cannot be individually identified by name).
		if d.Key == "" || wanted[d.Key] {
			selected = append(selected, enc)
		}
	}

	return selected, nil
}

// buildKBJWT constructs and signs the Key Binding JWT for presented.
// The KB-JWT binds the presentation to a specific verifier+nonce pair and
// commits to the exact set of disclosed claims via sd_hash.
func (h *Holder) buildKBJWT(presented *Token, nonce, audience string) (string, error) {
	// sd_hash is the SHA-256 digest of the presentation prefix
	// (issuerJWT~disc1~disc2~), not including the KB-JWT itself.
	prefix := presented.Prefix()
	sdHash := hashutil.DigestSHA256([]byte(prefix))

	header := map[string]any{
		"typ": "kb+jwt",
		"alg": h.signer.Algorithm(),
	}
	if kid := h.signer.KeyID(); kid != "" {
		header["kid"] = kid
	}

	payload := map[string]any{
		"iat":     time.Now().UTC().Unix(),
		"nonce":   nonce,
		"aud":     audience,
		"sd_hash": sdHash,
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

	sig, err := h.signer.Sign([]byte(signingInput))
	if err != nil {
		return "", err
	}
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)

	return strings.Join([]string{headerEnc, payloadEnc, sigEnc}, "."), nil
}
