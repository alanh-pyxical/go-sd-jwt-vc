// Command mortgage demonstrates go-sd-jwt-vc using a mortgage offer credential.
//
// It runs all three roles — issuer, holder, and verifier — in a single process
// so you can see the full flow without standing up any HTTP servers.
//
// Run with: go run ./example/mortgage
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	sdjwt "github.com/alanh-pyxical/go-sd-jwt-vc"
)

func main() {
	ctx := context.Background()

	// -----------------------------------------------------------------------
	// 1. Setup: generate keys for the bank issuer and the aggregator wallet.
	// -----------------------------------------------------------------------

	bankKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err, "generating bank key")

	walletKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err, "generating wallet key")

	bankSigner := &ecSigner{priv: bankKey, kid: "bank-signing-key-1"}
	walletSigner := &ecSigner{priv: walletKey, kid: "wallet-key-1"}

	// The verifier resolves keys via an in-memory resolver (in production
	// this would fetch from bank's /.well-known/jwks.json).
	resolver := sdjwt.KeyResolverFunc(func(_ context.Context, issuer, _ string) (crypto.PublicKey, error) {
		if issuer == "https://lloyds.example" {
			return &bankKey.PublicKey, nil
		}
		return nil, fmt.Errorf("unknown issuer %q", issuer)
	})

	// -----------------------------------------------------------------------
	// 2. Bank issues a mortgage offer credential to the aggregator wallet.
	// -----------------------------------------------------------------------

	issuer := sdjwt.NewIssuer(
		"https://lloyds.example",
		bankSigner,
		sdjwt.WithSchemaURI("https://schema.pyxical.com/mortgage-offer/v1"),
		sdjwt.WithTokenTTL(90*24*time.Hour),
	)

	tok, err := issuer.Issue(ctx, sdjwt.IssueRequest{
		VCT:       "https://schema.pyxical.com/MortgageOffer",
		Subject:   "customer-ref-7829",
		HolderKey: &walletKey.PublicKey, // key binding to the wallet
		Claims: map[string]any{
			// Always disclosed — the conveyancer always needs these.
			"bank_name":    "Lloyds Bank plc",
			"bank_lei":     "H7FNTJ4851HG0EXQ1Z70",
			"offer_expiry": time.Now().Add(90 * 24 * time.Hour).Format(time.DateOnly),

			// Selectively disclosable flat claims.
			"max_amount": 450000,
			"currency":   "GBP",

			// Structured claim — applicant sub-fields are individually selective.
			// The conveyancer only needs the ref; name and DOB are withheld.
			"applicant": sdjwt.Structured(
				map[string]any{
					"name": "Jane Smith",
					"dob":  "1985-06-15",
					"ref":  "APP-2025-78291", // always disclosed within applicant
				},
				"name", "dob", // these become individual disclosures
			),
		},
		SelectiveFields: []string{"max_amount", "currency"},
	})
	must(err, "issuing credential")

	fmt.Println("=== Bank issued credential ===")
	fmt.Printf("Issuer JWT prefix: %s...\n", tok.IssuerJWT[:40])
	fmt.Printf("Disclosures: %d (all stored in wallet)\n\n", len(tok.Disclosures))

	// -----------------------------------------------------------------------
	// 3. Wallet holder presents to conveyancer — revealing only what's needed.
	//    The conveyancer needs proof of offer and expiry but NOT the amount.
	// -----------------------------------------------------------------------

	holder := sdjwt.NewHolder(walletSigner)

	// Conveyancer issued a nonce as a challenge.
	nonce := "conveyancer-challenge-9f3ab"
	conveyancerURI := "https://smiths-conveyancers.example"

	presented, err := holder.Present(ctx, tok, sdjwt.PresentOptions{
		RevealClaims: []string{
			// max_amount, currency, name, dob are all withheld.
			// bank_name, bank_lei, offer_expiry are always disclosed.
			// applicant.ref is always disclosed within the applicant object.
		},
		KeyBinding: true,
		Nonce:      nonce,
		Audience:   conveyancerURI,
	})
	must(err, "constructing presentation")

	fmt.Println("=== Wallet presentation ===")
	fmt.Printf("Disclosures included: %d (of %d available)\n", len(presented.Disclosures), len(tok.Disclosures))
	fmt.Printf("KB-JWT present: %v\n\n", presented.HasKeyBinding())

	// -----------------------------------------------------------------------
	// 4. Conveyancer verifies the presentation.
	// -----------------------------------------------------------------------

	verifier := sdjwt.NewVerifier(
		resolver,
		sdjwt.RequireKeyBinding(conveyancerURI),
		sdjwt.ExpectVCT("https://schema.pyxical.com/MortgageOffer"),
		sdjwt.WithClockSkew(30*time.Second),
	)

	result, err := verifier.Verify(ctx, presented.String(), sdjwt.VerifyOptions{
		Nonce: nonce,
	})
	must(err, "verifying presentation")

	fmt.Println("=== Conveyancer verification result ===")
	fmt.Printf("✓ Issuer:     %s\n", result.Issuer)
	fmt.Printf("✓ VCT:        %s\n", result.VCT)
	fmt.Printf("✓ Key bound:  %v\n", result.KeyBound)
	fmt.Printf("✓ Disclosed claims:\n")
	printJSON(result.DisclosedClaims)

	// Confirm max_amount was NOT disclosed.
	if _, revealed := result.DisclosedClaims["max_amount"]; revealed {
		log.Fatal("max_amount should not have been disclosed")
	}
	fmt.Println("\n✓ max_amount correctly withheld from conveyancer")

	// -----------------------------------------------------------------------
	// 5. Demonstrate replay protection — reusing the presentation fails.
	// -----------------------------------------------------------------------

	fmt.Println("\n=== Replay attack simulation ===")
	_, err = verifier.Verify(ctx, presented.String(), sdjwt.VerifyOptions{
		Nonce: "different-nonce", // verifier would use a fresh nonce
	})
	if err != nil {
		var ve *sdjwt.VerificationError
		if errors.As(err, &ve) {
			fmt.Printf("✓ Replay rejected: %v\n", err)
		}
	}
}

// --- minimal stdlib-only Signer for the example (no external deps) ---

type ecSigner struct {
	priv *ecdsa.PrivateKey
	kid  string
}

func (s *ecSigner) Sign(payload []byte) ([]byte, error) {
	h := crypto.SHA256.New()
	h.Write(payload)
	return ecdsa.SignASN1(rand.Reader, s.priv, h.Sum(nil))
}

func (s *ecSigner) Algorithm() string { return "ES256" }
func (s *ecSigner) KeyID() string     { return s.kid }

func must(err error, context string) {
	if err != nil {
		log.Fatalf("%s: %v", context, err)
	}
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "  ", "  ")
	fmt.Printf("  %s\n", b)
}
