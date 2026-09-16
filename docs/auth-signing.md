# Auth signing

`AuthServiceSigner::create(token, url)` and the `SignerType::AuthService`
configuration remain legacy: fetch `did-doc`, SHA-256 hash each input once,
POST the hexadecimal digest to `sign`, and decode the 64-byte IEEE P1363
signature. Existing three-field configurations (`api_key`, `url`, `did_doc`)
and Rust struct literals continue to work. Legacy mode does not solve rotation
between metadata and signing.

## Explicit version binding

Enable the `signer-auth-service` feature, then select the new type explicitly:

```rust,no_run
use integrity::signer::{AuthSigningPurpose, BoundAuthServiceSigner, SignerType};
# async fn example() -> anyhow::Result<()> {
let signer = BoundAuthServiceSigner::create(
    "bearer-token".into(),
    "https://auth.example.test".into(),
    AuthSigningPurpose::Did,
).await?;
let signer = SignerType::BoundAuthService(signer);
// Pass this same signer to statement/VC proof construction and signing.
# Ok(())
# }
```

Use `Did` for the actual authenticated user or service-account principal; use
`Platform` for the shared platform key. The URL is Auth's base URL, without
`/platform`. Metadata/sign routes are `/api/v1/protected/signing-key` and
`/api/v1/protected/sign`, or their `/api/v1/protected/platform/` equivalents.
Auth still enforces bearer authentication, ownership and platform roles.
Consumers receive no OpenBao credentials.

The bound signer requires Guardian F3 (Guardian PR #212) or a later compatible
Auth deployment. It validates metadata's purpose, SHA-256/P1363 profile and
P-256/ES256 or secp256k1/ES256K JWK. It stores the opaque `signingKeyReference`
unchanged, sends it on every signing request, and requires an identical echoed
reference before returning a signature. Missing metadata, unsupported profiles,
missing/mismatched echoes and HTTP errors fail closed. No legacy fallback,
metadata refresh, signing retry, redirect or latest-version lookup occurs.
No proof-suite or digest/64-byte signature representation changes.

Requests, including response bodies, have a ten-second deadline.
`create_with_timeout` accepts another nonzero deadline. Dropping a signing
future cancels client-side work; Auth may have already signed. An error does
not authorize a retry with a different key or imply no remote operation occurred.

`SignerType::BoundAuthService` supports the existing signer save/load helpers.
Its required metadata fields and reference survive serialization; removing them
is an error, not a request for legacy mode. Saved configurations contain the
bearer credential and must be kept private. Debug output redacts credentials.
Adding this enum variant requires downstream exhaustive matches to handle it;
the existing `AuthServiceSigner` struct and serialized variant are unchanged.

## Deployment and recovery

Deploy a compatible Auth producer before opting consumers into bound mode.
OpenBao remains Auth-only, opt-in, development-gated and P-256; choosing this
signer does not activate or reconfigure any custody backend. Old clients can
continue using new Auth servers. Bound clients reject incompatible old servers.

Keep the same signer snapshot for public issuer selection and signing. A stale,
wrong-owner or wrong-purpose reference is rejected by Auth. Stop that issuance
operation and investigate; only start a new issuance with newly selected metadata
after authorizing any identity/trust change. Restore backend access or retained
key/association state for outages. Never clear associations, reset keys or switch
to legacy mode as an automatic recovery step.

The library must be merged and published as an immutable S1 release before final
Guardian release qualification. Draft consumers may pin the exact S1 Git commit
for coordinated preview tests. Such evidence is preview validation, not released
artifact qualification. No release is published by this change.

## Validation

`cargo test -p integrity-signer --features signer-auth-service,signer-p256 --test auth_bound`
runs mock HTTP compatibility, cryptographic digest verification, purpose routes,
conflict/failure, timeout/cancellation, concurrent clone and saved-config tests.
Mock bearer labels do not establish real Auth service-account authentication.
Real Auth/OpenBao/PostgreSQL and consumer artifact validation belong to the
coordinated Guardian S2 preview, with exact heads recorded separately.
