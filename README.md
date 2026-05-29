# go-sd-jwt-vc

[![Go Reference](https://pkg.go.dev/badge/github.com/alanh-pyxical/go-sd-jwt-vc.svg)](https://pkg.go.dev/github.com/alanh-pyxical/go-sd-jwt-vc)
[![Go Report Card](https://goreportcard.com/badge/github.com/alanh-pyxical/go-sd-jwt-vc)](https://goreportcard.com/report/github.com/alanh-pyxical/go-sd-jwt-vc)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An idiomatic Go implementation of [SD-JWT-VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) — Selective Disclosure for JWTs as Verifiable Credentials.

## Overview

SD-JWT-VC allows credential issuers to create verifiable credentials where the **holder controls which claims are revealed** to each verifier, while the verifier can still cryptographically confirm those claims came from the issuer.

This library implements all three roles:

| Role | Type | Responsibility |
|---|---|---|
| **Issuer** | `sdjwt.Issuer` | Signs and issues SD-JWT-VC tokens |
| **Holder** | `sdjwt.Holder` | Selects disclosures, builds presentations with key binding |
| **Verifier** | `sdjwt.Verifier` | Validates presentations end-to-end |

## Installation

```sh
go get github.com/alanh-pyxical/go-sd-jwt-vc
```

The core package has **no mandatory dependencies** — it uses only the Go standard library. An optional adapter for [lestrrat-go/jwx](https://github.com/lestrrat-go/jwx) is provided in `adapters/jwx`.

## Quick Start

```go
package main

import (
    "context"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "fmt"
    "time"

    sdjwt "github.com/alanh-pyxical/go-sd-jwt-vc"
)

func main() {
    ctx := context.Background()

    // 1. Issuer creates a credential.
    //    Implement sdjwt.Signer with your key management solution,
    //    or use the adapters/jwx adapter.
    issuer := sdjwt.NewIssuer("https://bank.example", mySigner)

    tok, err := issuer.Issue(ctx, sdjwt.IssueRequest{
        VCT:       "MortgageOffer",
        Subject:   "customer-123",
        HolderKey: holderPublicKey, // binds the credential to the holder's key
        Claims: map[string]any{
            "bank_name":    "Example Bank",
            "offer_expiry": time.Now().Add(90 * 24 * time.Hour).Format(time.DateOnly),
            "max_amount":   450000,
            "currency":     "GBP",
        },
        SelectiveFields: []string{"max_amount", "currency"},
    })

    // 2. Holder presents to a verifier — revealing only what's needed.
    holder := sdjwt.NewHolder(holderSigner)

    presented, err := holder.Present(ctx, tok, sdjwt.PresentOptions{
        RevealClaims: []string{"bank_name", "offer_expiry"}, // withhold amount
        KeyBinding:   true,
        Nonce:        "verifier-issued-nonce",
        Audience:     "https://verifier.example",
    })

    // 3. Verifier checks the presentation.
    verifier := sdjwt.NewVerifier(
        myKeyResolver,
        sdjwt.RequireKeyBinding("https://verifier.example"),
        sdjwt.ExpectVCT("MortgageOffer"),
    )

    result, err := verifier.Verify(ctx, presented.String(), sdjwt.VerifyOptions{
        Nonce: "verifier-issued-nonce",
    })

    fmt.Println(result.DisclosedClaims) // max_amount is absent
}
```

See [example/mortgage](./example/mortgage/main.go) for a complete runnable example.

## Key Concepts

### Selective Disclosure

Claims listed in `IssueRequest.SelectiveFields` are individually hashed and their values withheld from the token body. The holder reveals them by including the corresponding disclosure strings in the presentation. Claims not in `SelectiveFields` are always visible to any verifier.

```
Issued token:   issuerJWT ~ disc(max_amount) ~ disc(currency) ~
Presented:      issuerJWT ~ disc(max_amount) ~                    (currency withheld)
```

### Key Binding

When `HolderKey` is provided at issuance, the issuer embeds it as a `cnf` claim. At presentation, the holder signs a **KB-JWT** that commits to:

- The specific verifier (`aud`)  
- The verifier's challenge (`nonce`)  
- A hash of the exact disclosures being presented (`sd_hash`)

This prevents replay and ensures the presenter is the legitimate holder.

### Implementing `Signer`

```go
type Signer interface {
    Sign(payload []byte) ([]byte, error)
    Algorithm() string // JWA name: "ES256", "EdDSA", etc.
    KeyID() string     // kid header value, or "" to omit
}
```

The `adapters/jwx` package provides a ready-made implementation:

```go
import jwxadapter "github.com/alanh-pyxical/go-sd-jwt-vc/adapters/jwx"

signer, err := jwxadapter.NewSigner(myJWKPrivateKey)
```

### Implementing `KeyResolver`

```go
type KeyResolver interface {
    ResolveKey(ctx context.Context, issuer, keyID string) (crypto.PublicKey, error)
}
```

For HTTP-based key resolution (fetches `<issuer>/.well-known/jwks.json`):

```go
resolver := jwxadapter.NewHTTPKeyResolver(http.DefaultClient, 5*time.Minute)
```

For tests and local development:

```go
resolver := sdjwt.KeyResolverFunc(func(ctx context.Context, issuer, kid string) (crypto.PublicKey, error) {
    return myKeyStore[issuer], nil
})
```

## Verifier Options

| Option | Effect |
|---|---|
| `RequireKeyBinding(audience)` | Rejects presentations without a valid KB-JWT; checks `aud` |
| `ExpectVCT(vct)` | Rejects tokens whose `vct` doesn't match |
| `WithClockSkew(d)` | Permits clock skew when checking `exp`/`nbf` |

## Issuer Options

| Option | Effect |
|---|---|
| `WithHashAlgorithm(h)` | Digest algorithm for `_sd` hashes (default: SHA-256) |
| `WithDecoyDigests(n)` | Adds n random digests to obscure the claim count |
| `WithSchemaURI(uri)` | Sets `vct#integrity` in the issued token |
| `WithTokenTTL(d)` | Sets the `exp` claim (default: 90 days) |

## Error Handling

All errors are typed values. Use `errors.Is` and `errors.As`:

```go
result, err := verifier.Verify(ctx, raw, opts)
if err != nil {
    var ve *sdjwt.VerificationError
    if errors.As(err, &ve) {
        log.Printf("verification failed at stage %s: %v", ve.Stage, ve.Err)
    }
    if errors.Is(err, sdjwt.ErrTokenExpired) {
        // handle specifically
    }
}
```

## Specification Compliance

This library implements:

- [draft-ietf-oauth-sd-jwt-vc](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) — SD-JWT-based Verifiable Credentials
- [draft-ietf-oauth-selective-disclosure-jwt](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) — Selective Disclosure for JWTs

Supported algorithms: ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512, EdDSA.

## Related Libraries

- [`go-oid4vci`](https://github.com/alanh-pyxical/go-oid4vci) — OpenID for Verifiable Credential Issuance
- [`go-oid4vp`](https://github.com/alanh-pyxical/go-oid4vp) — OpenID for Verifiable Presentations

## Things to fix before publishing

1. The adapters/jwx/jwx.go has a self-referential key.Get() method call that needs tidying — the jwx API uses a slightly different call pattern
1. The verifier.go algToDigest returns a HashForAlg that's defined in crypto_helpers.go — these two files need their imports aligned
1. Add go.sum by running go mod tidy after cloning

## Other libraries

Relationship to go-sd-jwt: This library implements the SD-JWT-VC credential profile (draft-ietf-oauth-sd-jwt-vc) rather than the base SD-JWT specification. If you need only the low-level SD-JWT primitive, https://github.com/MichaelFraser99/go-sd-jwt is an excellent choice. This library adds the Verifiable Credential layer — vct, cnf, holder key binding at issuance, a KeyResolver for verifier-side JWKS lookup, and the Issuer/Holder/Verifier role separation required by OID4VCI and OID4VP.

| Concern | Michael Fraser99 go-sd-jwt | go-sd-jwt-vc|
|---|---|---|
| Spec |draft-ietf-oauth-selective-disclosure-jwt | draft-ietf-oauth-sd-jwt-vc |
| vct claim | Not present | First-class — required, validated |
| cnf / holder binding | AddKeyBindingJwt exists | Embedded at issuance via HolderKey; cnf written into issuer JWT |
| Key resolution | Not present — no verifier role | KeyResolver interface; HTTP JWKS fetch in adapter |
| Three roles | Partial — no distinct Issuer/Holder/Verifier types | Explicit Issuer, Holder, Verifier types 
| VerificationResult | GetDisclosedClaims() returns a map | Structured result with DisclosedClaims, AllClaims, Issuer, VCT, KeyBound |
| Issuer signing | Not present — you bring your own JWT | Issuer.Issue() builds and signs the full token |
| Decoy digests | Not present | WithDecoyDigests(n) option |
| Schema URI| Not present | WithSchemaURI() → vct#integrity |
| Typed errors | Not present | VerificationError{Stage, Err}, DisclosureError{Key, Err} |
| context.Context | Not present | All I/O methods accept a context |
| Zero mandatory deps | Has dependencies | Stdlib-only core; jwx adapter optional |
| OID4VCI/OID4VP integration | Not designed for it | Signer interface shared with go-oid4vci; CredentialValidator/Presenter plug directly into go-oid4vp |

## Functional Gaps to close

Where MichaelFraser99 is ahead

### To be fair about it:

* Battle-tested — it has been used in production, has a playground at sdjwt.org, and has real-world adoption. Yours is new.
* Structured SD-JWTs — nested/recursive selective disclosure. 
* NewFromComponents — lets you construct an SdJwt from already-split parts, useful when the transport layer has already parsed the token. A useful low-level escape hatch.
* Salt injection — the salt *string parameter on NewFromObject lets callers supply their own salt Go Packages, which is useful for deterministic test vectors.

### Where this project is ahead

* The VC profile — vct, cnf, schema integrity, the full issuer JWT construction. This is the gap that matters for the OID4VCI/OID4VP suite.
* Role separation — having distinct Issuer, Holder, and Verifier types makes the library self-documenting for implementors building wallet or relying-party services.
* KeyResolver with JWKS caching — production-ready key resolution against live issuers.
* Integration seam — the Signer / CredentialValidator / Presenter interfaces are designed to snap into go-oid4vci and go-oid4vp.
* VerificationError{Stage} — machine-readable failure stages for audit logging.

The nested structured SD-JWT support is the main functional gap. Worth adding a WithStructuredClaims option to Issuer.Issue that recurses into nested maps and makes sub-objects selectively disclosable. That closes the last real feature gap between the two.


## License

MIT — see [LICENSE](LICENSE).