package sdjwt_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	sdjwt "github.com/alanh-pyxical/go-sd-jwt-vc"
)

// --- test helpers ---

// testKeyPair holds a key pair and implements sdjwt.Signer for use in tests.
type testKeyPair struct {
	priv *ecdsa.PrivateKey
	pub  *ecdsa.PublicKey
	kid  string
}

func newTestKeyPair(t *testing.T, kid string) *testKeyPair {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	return &testKeyPair{priv: priv, pub: &priv.PublicKey, kid: kid}
}

func (k *testKeyPair) Sign(payload []byte) ([]byte, error) {
	h := crypto.SHA256.New()
	h.Write(payload)
	return ecdsa.SignASN1(rand.Reader, k.priv, h.Sum(nil))
}

func (k *testKeyPair) Algorithm() string { return "ES256" }
func (k *testKeyPair) KeyID() string     { return k.kid }

// testResolver implements sdjwt.KeyResolver using an in-memory map.
type testResolver map[string]*ecdsa.PublicKey

func (r testResolver) ResolveKey(_ context.Context, issuer, _ string) (crypto.PublicKey, error) {
	if k, ok := r[issuer]; ok {
		return k, nil
	}
	return nil, sdjwt.ErrKeyResolutionFailed
}

// --- Disclosure tests ---

func TestDisclosure_RoundTrip(t *testing.T) {
	d, err := sdjwt.NewDisclosure("max_amount", 450000.0)
	if err != nil {
		t.Fatalf("NewDisclosure: %v", err)
	}

	encoded, err := d.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	got, err := sdjwt.ParseDisclosure(encoded)
	if err != nil {
		t.Fatalf("ParseDisclosure: %v", err)
	}

	if got.Key != d.Key {
		t.Errorf("Key: got %q, want %q", got.Key, d.Key)
	}
	if got.Value.(float64) != d.Value.(float64) {
		t.Errorf("Value: got %v, want %v", got.Value, d.Value)
	}
}

func TestDisclosure_ArrayElement(t *testing.T) {
	d, err := sdjwt.NewArrayDisclosure("item-one")
	if err != nil {
		t.Fatalf("NewArrayDisclosure: %v", err)
	}
	if d.Key != "" {
		t.Errorf("array disclosure should have empty key, got %q", d.Key)
	}
	encoded, _ := d.Encode()
	got, err := sdjwt.ParseDisclosure(encoded)
	if err != nil {
		t.Fatalf("ParseDisclosure: %v", err)
	}
	if got.Key != "" {
		t.Errorf("parsed array disclosure has non-empty key %q", got.Key)
	}
}

func TestDisclosure_InvalidBase64(t *testing.T) {
	_, err := sdjwt.ParseDisclosure("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDisclosure_UniqueSalts(t *testing.T) {
	d1, _ := sdjwt.NewDisclosure("k", "v")
	d2, _ := sdjwt.NewDisclosure("k", "v")
	if d1.Salt == d2.Salt {
		t.Error("two disclosures for the same claim should have different salts")
	}
}

// --- Token parse tests ---

func TestParse_Valid(t *testing.T) {
	raw := "issuerJWT~disc1~disc2~"
	tok, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if tok.IssuerJWT != "issuerJWT" {
		t.Errorf("IssuerJWT: got %q", tok.IssuerJWT)
	}
	if len(tok.Disclosures) != 2 {
		t.Errorf("Disclosures: got %d, want 2", len(tok.Disclosures))
	}
	if tok.KBJWT != "" {
		t.Errorf("expected empty KBJWT, got %q", tok.KBJWT)
	}
}

func TestParse_WithKBJWT(t *testing.T) {
	raw := "issuerJWT~disc1~kbJWT"
	tok, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if tok.KBJWT != "kbJWT" {
		t.Errorf("KBJWT: got %q", tok.KBJWT)
	}
}

func TestParse_Empty(t *testing.T) {
	_, err := sdjwt.Parse("")
	if err != sdjwt.ErrInvalidFormat {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestParse_NoTilde(t *testing.T) {
	_, err := sdjwt.Parse("justajwtwithouttilde")
	if err != sdjwt.ErrInvalidFormat {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestToken_RoundTrip(t *testing.T) {
	raw := "issuerJWT~disc1~disc2~"
	tok, _ := sdjwt.Parse(raw)
	if got := tok.String(); got != raw {
		t.Errorf("String(): got %q, want %q", got, raw)
	}
}

// --- Full issuance + holder + verifier integration test ---

func TestIssueHoldVerify_NoKeyBinding(t *testing.T) {
	issuerKey := newTestKeyPair(t, "issuer-key-1")
	resolver := testResolver{"https://bank.example": issuerKey.pub}

	issuer := sdjwt.NewIssuer("https://bank.example", issuerKey)
	verifier := sdjwt.NewVerifier(resolver,
		sdjwt.ExpectVCT("MortgageOffer"),
	)
	holder := sdjwt.NewHolder(nil) // no key binding

	tok, err := issuer.Issue(context.Background(), sdjwt.IssueRequest{
		VCT:     "MortgageOffer",
		Subject: "cust-123",
		Claims: map[string]any{
			"bank_name":    "Lloyds Bank",
			"offer_expiry": time.Now().Add(90 * 24 * time.Hour).Format(time.DateOnly),
			"max_amount":   450000.0,
			"currency":     "GBP",
		},
		SelectiveFields: []string{"max_amount", "currency"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Holder presents, revealing only bank_name and offer_expiry (not amount).
	presented, err := holder.Present(context.Background(), tok, sdjwt.PresentOptions{
		RevealClaims: []string{"bank_name", "offer_expiry"},
	})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	result, err := verifier.Verify(context.Background(), presented.String(), sdjwt.VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if result.VCT != "MortgageOffer" {
		t.Errorf("VCT: got %q", result.VCT)
	}
	if result.Subject != "cust-123" {
		t.Errorf("Subject: got %q", result.Subject)
	}
	if _, ok := result.DisclosedClaims["max_amount"]; ok {
		t.Error("max_amount should not be in disclosed claims")
	}
	if result.KeyBound {
		t.Error("expected KeyBound=false for no-KB presentation")
	}
}

func TestIssueHoldVerify_WithKeyBinding(t *testing.T) {
	issuerKey := newTestKeyPair(t, "issuer-key-1")
	holderKey := newTestKeyPair(t, "holder-key-1")
	resolver := testResolver{"https://bank.example": issuerKey.pub}

	issuer := sdjwt.NewIssuer("https://bank.example", issuerKey)
	holder := sdjwt.NewHolder(holderKey)
	verifier := sdjwt.NewVerifier(resolver,
		sdjwt.RequireKeyBinding("https://conveyancer.example"),
		sdjwt.ExpectVCT("MortgageOffer"),
	)

	tok, err := issuer.Issue(context.Background(), sdjwt.IssueRequest{
		VCT:       "MortgageOffer",
		Subject:   "cust-456",
		HolderKey: holderKey.pub,
		Claims: map[string]any{
			"bank_name":    "NatWest",
			"offer_expiry": time.Now().Add(60 * 24 * time.Hour).Format(time.DateOnly),
			"max_amount":   375000.0,
		},
		SelectiveFields: []string{"max_amount"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	presented, err := holder.Present(context.Background(), tok, sdjwt.PresentOptions{
		KeyBinding:   true,
		Nonce:        "verifier-nonce-xyz",
		Audience:     "https://conveyancer.example",
		RevealClaims: []string{"bank_name", "offer_expiry"},
	})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	result, err := verifier.Verify(context.Background(), presented.String(), sdjwt.VerifyOptions{
		Nonce: "verifier-nonce-xyz",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if !result.KeyBound {
		t.Error("expected KeyBound=true")
	}
}

func TestVerify_WrongNonce(t *testing.T) {
	issuerKey := newTestKeyPair(t, "k1")
	holderKey := newTestKeyPair(t, "k2")
	resolver := testResolver{"https://bank.example": issuerKey.pub}

	issuer := sdjwt.NewIssuer("https://bank.example", issuerKey)
	holder := sdjwt.NewHolder(holderKey)
	verifier := sdjwt.NewVerifier(resolver,
		sdjwt.RequireKeyBinding("https://verifier.example"),
	)

	tok, _ := issuer.Issue(context.Background(), sdjwt.IssueRequest{
		VCT:       "TestVC",
		HolderKey: holderKey.pub,
		Claims:    map[string]any{"claim": "value"},
	})

	presented, _ := holder.Present(context.Background(), tok, sdjwt.PresentOptions{
		KeyBinding: true,
		Nonce:      "correct-nonce",
		Audience:   "https://verifier.example",
	})

	_, err := verifier.Verify(context.Background(), presented.String(), sdjwt.VerifyOptions{
		Nonce: "wrong-nonce",
	})
	if err == nil {
		t.Fatal("expected error for wrong nonce")
	}
	if !isVerificationErr(err, sdjwt.ErrKBJWTNonceMismatch) {
		t.Errorf("expected ErrKBJWTNonceMismatch, got %v", err)
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	issuerKey := newTestKeyPair(t, "k1")
	resolver := testResolver{"https://bank.example": issuerKey.pub}

	issuer := sdjwt.NewIssuer("https://bank.example", issuerKey,
		sdjwt.WithTokenTTL(-1*time.Hour), // already expired
	)
	verifier := sdjwt.NewVerifier(resolver)

	tok, _ := issuer.Issue(context.Background(), sdjwt.IssueRequest{
		VCT:    "TestVC",
		Claims: map[string]any{"claim": "value"},
	})

	_, err := verifier.Verify(context.Background(), tok.String()+"~", sdjwt.VerifyOptions{})
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if !isVerificationErr(err, sdjwt.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestIssue_SelectiveFieldNotFound(t *testing.T) {
	issuerKey := newTestKeyPair(t, "k1")
	issuer := sdjwt.NewIssuer("https://bank.example", issuerKey)

	_, err := issuer.Issue(context.Background(), sdjwt.IssueRequest{
		VCT:             "TestVC",
		Claims:          map[string]any{"present": "value"},
		SelectiveFields: []string{"missing_field"},
	})
	if err == nil {
		t.Fatal("expected error when selective field not in claims")
	}
}

func TestHolder_RevealAll(t *testing.T) {
	issuerKey := newTestKeyPair(t, "k1")
	issuer := sdjwt.NewIssuer("https://bank.example", issuerKey)
	holder := sdjwt.NewHolder(nil)

	tok, _ := issuer.Issue(context.Background(), sdjwt.IssueRequest{
		VCT: "TestVC",
		Claims: map[string]any{
			"a": 1, "b": 2, "c": 3,
		},
		SelectiveFields: []string{"a", "b", "c"},
	})

	// No RevealClaims = reveal all
	presented, err := holder.Present(context.Background(), tok, sdjwt.PresentOptions{})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if len(presented.Disclosures) != 3 {
		t.Errorf("expected 3 disclosures, got %d", len(presented.Disclosures))
	}
}

// --- Structured (nested) SD-JWT tests ---

func TestIssue_StructuredClaims_BasicNesting(t *testing.T) {
	issuerKey := newTestKeyPair(t, "k1")
	resolver := testResolver{"https://bank.example": issuerKey.pub}

	issuer := sdjwt.NewIssuer("https://bank.example", issuerKey)
	verifier := sdjwt.NewVerifier(resolver)
	holder := sdjwt.NewHolder(nil)

	tok, err := issuer.Issue(context.Background(), sdjwt.IssueRequest{
		VCT: "TestVC",
		Claims: map[string]any{
			"bank_name": "Lloyds Bank",
			"address": sdjwt.Structured(
				map[string]any{
					"street":   "10 Downing St",
					"city":     "London",
					"postcode": "SW1A 2AA",
				},
				"street", "postcode", // selectively disclosable sub-fields
				// "city" is always disclosed within the address object
			),
		},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Should have 2 disclosures (street + postcode); city is always disclosed.
	if len(tok.Disclosures) != 2 {
		t.Errorf("expected 2 disclosures, got %d", len(tok.Disclosures))
	}

	// Present revealing street only (withhold postcode).
	presented, err := holder.Present(context.Background(), tok, sdjwt.PresentOptions{
		RevealClaims: []string{"street"},
	})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if len(presented.Disclosures) != 1 {
		t.Errorf("expected 1 disclosure, got %d", len(presented.Disclosures))
	}

	result, err := verifier.Verify(context.Background(), presented.String()+"~", sdjwt.VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if _, ok := result.DisclosedClaims["street"]; !ok {
		t.Error("street should be in disclosed claims")
	}
	if _, ok := result.DisclosedClaims["postcode"]; ok {
		t.Error("postcode should NOT be in disclosed claims")
	}
}

func TestIssue_StructuredClaims_DeepNesting(t *testing.T) {
	issuerKey := newTestKeyPair(t, "k1")
	resolver := testResolver{"https://bank.example": issuerKey.pub}

	issuer := sdjwt.NewIssuer("https://bank.example", issuerKey)
	verifier := sdjwt.NewVerifier(resolver)
	holder := sdjwt.NewHolder(nil)

	// Three levels deep: credential → address → geo
	tok, err := issuer.Issue(context.Background(), sdjwt.IssueRequest{
		VCT: "TestVC",
		Claims: map[string]any{
			"name": "Jane Smith",
			"address": sdjwt.Structured(
				map[string]any{
					"city": "London",
					"geo": sdjwt.Structured(
						map[string]any{
							"lat": 51.5074,
							"lng": -0.1278,
						},
						"lat", "lng", // both selective at the geo level
					),
				},
				// city is always disclosed within address; only geo sub-fields are selective
			),
		},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// 2 disclosures: lat and lng
	if len(tok.Disclosures) != 2 {
		t.Errorf("expected 2 disclosures, got %d", len(tok.Disclosures))
	}

	// Reveal lat but withhold lng.
	presented, err := holder.Present(context.Background(), tok, sdjwt.PresentOptions{
		RevealClaims: []string{"lat"},
	})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	result, err := verifier.Verify(context.Background(), presented.String()+"~", sdjwt.VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if _, ok := result.DisclosedClaims["lat"]; !ok {
		t.Error("lat should be disclosed")
	}
	if _, ok := result.DisclosedClaims["lng"]; ok {
		t.Error("lng should not be disclosed")
	}
}

func TestIssue_StructuredClaims_WholeObjectSelective(t *testing.T) {
	issuerKey := newTestKeyPair(t, "k1")
	resolver := testResolver{"https://bank.example": issuerKey.pub}

	issuer := sdjwt.NewIssuer("https://bank.example", issuerKey)
	verifier := sdjwt.NewVerifier(resolver)
	holder := sdjwt.NewHolder(nil)

	// The entire address object is selectively disclosable as a unit.
	tok, err := issuer.Issue(context.Background(), sdjwt.IssueRequest{
		VCT: "TestVC",
		Claims: map[string]any{
			"name": "Jane Smith",
			"address": sdjwt.Structured(
				map[string]any{
					"street": "10 Downing St",
					"city":   "London",
				},
				// No sub-fields selective — whole object disclosed or not
			),
		},
		SelectiveFields: []string{"address"}, // whole address is one disclosure
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// 1 disclosure: the entire address object.
	if len(tok.Disclosures) != 1 {
		t.Errorf("expected 1 disclosure, got %d", len(tok.Disclosures))
	}

	// Present without address — only name is revealed.
	presented, err := holder.Present(context.Background(), tok, sdjwt.PresentOptions{
		RevealClaims: []string{},
	})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if len(presented.Disclosures) != 0 {
		t.Errorf("expected 0 disclosures when address is withheld, got %d", len(presented.Disclosures))
	}

	result, err := verifier.Verify(context.Background(), presented.String()+"~", sdjwt.VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if _, ok := result.DisclosedClaims["address"]; ok {
		t.Error("address should not be in disclosed claims when withheld")
	}

	// Now present with address revealed.
	presentedWithAddr, err := holder.Present(context.Background(), tok, sdjwt.PresentOptions{
		RevealClaims: []string{"address"},
	})
	if err != nil {
		t.Fatalf("Present with address: %v", err)
	}

	result2, err := verifier.Verify(context.Background(), presentedWithAddr.String()+"~", sdjwt.VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify with address: %v", err)
	}
	if _, ok := result2.DisclosedClaims["address"]; !ok {
		t.Error("address should be in disclosed claims when revealed")
	}
}

func TestIssue_StructuredClaims_MixedFlatAndNested(t *testing.T) {
	issuerKey := newTestKeyPair(t, "k1")
	resolver := testResolver{"https://bank.example": issuerKey.pub}

	issuer := sdjwt.NewIssuer("https://bank.example", issuerKey)
	verifier := sdjwt.NewVerifier(resolver)
	holder := sdjwt.NewHolder(nil)

	tok, err := issuer.Issue(context.Background(), sdjwt.IssueRequest{
		VCT: "MortgageOffer",
		Claims: map[string]any{
			// Always disclosed
			"bank_name":    "Lloyds Bank plc",
			"offer_expiry": "2025-10-01",
			// Top-level selective (flat)
			"max_amount": 450000,
			"currency":   "GBP",
			// Nested with selective sub-fields
			"applicant": sdjwt.Structured(
				map[string]any{
					"name": "Jane Smith",
					"dob":  "1985-06-15",
					"ref":  "APP-2025-78291",
				},
				"name", "dob", // selective; ref is always disclosed within applicant
			),
		},
		SelectiveFields: []string{"max_amount", "currency"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// 4 disclosures: max_amount, currency, name, dob
	if len(tok.Disclosures) != 4 {
		t.Errorf("expected 4 disclosures, got %d", len(tok.Disclosures))
	}

	// Present as a conveyancer would: bank details + ref only, no amounts, no PII.
	presented, err := holder.Present(context.Background(), tok, sdjwt.PresentOptions{
		RevealClaims: []string{"ref"}, // only applicant ref needed
	})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	result, err := verifier.Verify(context.Background(), presented.String()+"~", sdjwt.VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// bank_name and offer_expiry always present
	if _, ok := result.IssuerClaims["bank_name"]; !ok {
		t.Error("bank_name should be in issuer claims")
	}
	// max_amount and currency not revealed
	if _, ok := result.DisclosedClaims["max_amount"]; ok {
		t.Error("max_amount should not be disclosed")
	}
	// name and dob not revealed
	if _, ok := result.DisclosedClaims["name"]; ok {
		t.Error("name should not be disclosed")
	}
	// ref is always-disclosed within the applicant object
	// It appears in issuer claims (it was never selective), not disclosedClaims.
	if result.VCT != "MortgageOffer" {
		t.Errorf("VCT: got %q", result.VCT)
	}
}

func TestIssue_StructuredClaims_NestingTooDeep(t *testing.T) {
	issuerKey := newTestKeyPair(t, "k1")
	issuer := sdjwt.NewIssuer("https://bank.example", issuerKey)

	// Build a pathologically deep nesting (beyond maxNestingDepth).
	var buildDeep func(depth int) map[string]any
	buildDeep = func(depth int) map[string]any {
		if depth == 0 {
			return map[string]any{"leaf": "value"}
		}
		return map[string]any{
			"nested": sdjwt.Structured(buildDeep(depth - 1)),
		}
	}

	_, err := issuer.Issue(context.Background(), sdjwt.IssueRequest{
		VCT:    "TestVC",
		Claims: buildDeep(20), // 20 > maxNestingDepth (16)
	})
	if err == nil {
		t.Fatal("expected error for excessive nesting depth")
	}
	if !errors.Is(err, sdjwt.ErrNestingTooDeep) {
		t.Errorf("expected ErrNestingTooDeep, got %v", err)
	}
}

// isVerificationErr checks whether err wraps target via errors.Is.
func isVerificationErr(err error, target error) bool {
	ve, ok := err.(*sdjwt.VerificationError)
	if !ok {
		return false
	}
	return ve.Unwrap() == target
}
