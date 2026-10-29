# Changelog

Notable changes to Integrity are recorded here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
See [CONTRIBUTING.md](CONTRIBUTING.md) for PR and release instructions.

One release section covers the Rust workspace and native FFI artifacts using
the repository's Git tag version. The FFI ABI version is independent.
Only plain `vX.Y.Z` tags receive versioned sections; candidate and unofficial
tag changes stay under `Unreleased`.

History covers tags from `v0.0.0` onward and was backfilled through 2026-09-10 from
Git commit messages and diffs. Historical dates are the tagged commits' committer
dates, not verified GitHub publication dates. Early Cargo package versions did
not always match the Git tags; section versions follow the tags.

## [Unreleased]

### Changed

- `integrity-lineage-models`: `utoipa` from 3.5.0 to 6.0.0. **Breaking:** the models'
  `ToSchema` implementations are now utoipa 6's, so an OpenAPI document that embeds
  them has to be built with utoipa 6. Serialization and the Rust API are unchanged.
  The schemas describe the same JSON, now in OpenAPI 3.1 form: a nullable field's
  `type` includes `"null"`, references carry their doc comments, and maps declare
  string keys. The internally tagged `anchor::Location` enum no longer has a
  `discriminator`; each variant still requires its `type` value.

## [0.0.20] - 2026-10-28

### Changed

- `integrity-blob`: the `blob-azure` backend moves from the legacy `azure_storage` /
  `azure_storage_blobs` 0.21.0 crates to `object_store` 0.14.2 (Apache Arrow).
  `AzureBlob::new` and the FFI's `ig_blob_store_azure_blob_new` keep the same
  arguments and still authenticate with the storage account key. A missing blob
  still reads as `None`, and puts still store a block blob with content type
  `text/plain`. Requests are now retried on server errors and timeouts, connecting
  times out after 5 seconds, and a key that isn't valid base64 fails at `init`
  rather than on the first request.
  ([#55](https://github.com/eqtylab/integrity/pull/55))

### Security

- `blob-azure` no longer depends on `azure_core` 0.21, which logs each request's
  `authorization` header (the Shared Key signature) at debug and trace level
  (RUSTSEC-2026-0275). The legacy Azure SDK is unsupported and won't be fixed
  upstream. If you ran the Azure backend with debug or trace logging enabled for the
  Azure crates, treat those logs as holding credentials and rotate the storage
  account key. `signer-akv` still depends on `azure_core` 0.21.
  ([#55](https://github.com/eqtylab/integrity/pull/55))

## [0.0.19] - 2026-10-16

### Added

- `integrity-vc`: `verify_vc_at`, which verifies a credential as of a given time
  instead of now. `verify_vc` validates `validFrom` / `validUntil` before the proof,
  so a credential that has since expired fails without its signature being checked;
  `verify_vc_at` at a time inside its validity period checks the signature for real.
  `verify_vc` is unchanged. A legacy (pre-ssi-0.16) credential is judged at the
  current time, because the legacy verifier takes no other; its result, accepted or
  not, says that `at` was not applied, and `is_legacy_vc` (now public) tells a
  caller beforehand. `at_applied` says, for a result, whether the dates were judged
  at `at`. `verify_vc_with_date_time` takes an optional time for callers
  that may have none.
  ([#50](https://github.com/eqtylab/integrity/pull/50))
- `integrity-vc`: `VcVerificationError`, the reason `verify_vc` or `verify_vc_at`
  did not accept a credential: `Expired`, `NotYetValid`, `InvalidClaims`,
  `InvalidSignature`, `MissingProof`, `InvalidProof`, `Malformed` (the input is
  not a well-formed credential, or its JSON-LD does not expand), `UnsupportedSuite`,
  `UnresolvedContext`, `UnresolvedKey` (the proof could not be completed: its suite
  is not supported, a context did not load, or its key did not resolve),
  `Unverifiable` (could not be completed, for another reason) or `Legacy`, with a
  stable `code()`. Every reason is a rejection, `Malformed` included: a credential
  altered in its suite, contexts, key or shape reads the same as one that could not
  be checked, so none of them means "not checked". It is `#[non_exhaustive]`,
  carried inside the returned `anyhow::Error` and recovered with `downcast_ref`.
  ([#50](https://github.com/eqtylab/integrity/pull/50))
- FFI: `ig_vc_verify_at`: like `ig_vc_verify`, with a check time (`at_rfc3339`),
  a failure reason code (`out_reason`) and `out_at_applied`, which is `false` when a
  legacy credential could only be judged at the current time, or when the call fails
  before the credential is checked. Advance the FFI ABI from `0.4.0` to `0.5.0`.
  ([#50](https://github.com/eqtylab/integrity/pull/50))

### Changed

- `integrity-vc`: a claim or proof failure's error message keeps its prefix, but
  what follows is no longer ssi's Debug output: `invalid VC proof: Claims(Expired
  { .. })` now reads `invalid VC proof: expired: valid until …, judged at …`.
  Match on `VcVerificationError` rather than the message.
  ([#50](https://github.com/eqtylab/integrity/pull/50))
- FFI: `ig_vc_verify`'s status for a credential that does not verify comes from
  its `VcVerificationError`: `IG_STATUS_VERIFICATION_FAILED` for every reason,
  including a proof that could not be completed (before, a bad signature or an
  expired credential could read `IG_STATUS_INVALID_INPUT`, and an unsupported
  suite `IG_STATUS_NOT_SUPPORTED`). Input that is not a well-formed credential
  keeps reading `IG_STATUS_JSON_ERROR`, now with the reason `malformed`.
  `*out_valid` is now `false` whenever the call fails; before, a failure left it
  unchanged.
  ([#50](https://github.com/eqtylab/integrity/pull/50))
- **Breaking:** the `blob-s3` feature (and `blob-all`, which includes it) now needs
  Rust 1.94.1, because the fixed aws crates require it. Without `blob-s3` the crates
  still build on Rust 1.89.
- `integrity-cid` encodes and reads iroh collections (`CollectionV0`) itself instead
  of through `iroh-blobs`. The encoding is unchanged: the pinned collection CIDs in
  its tests still match, and a new test reads a collection back.
- The pinned Rust toolchain moves from 1.89.0 to 1.94.1, and the `rust-overlay` input
  in `flake.lock` is updated so the Nix shell provides it. The Nix shell no longer
  adds nixpkgs' own `cargo` and `clippy`, so `cargo` and `cargo clippy` come from the
  pinned toolchain, and `RUST_SRC_PATH` points at that toolchain's `rust-src`. The
  shell is now the flake's `devShells.<system>.default` output, replacing the legacy
  `devShell`; `nix develop` works as before. The vendored `cacaos` allows
  `dependency_on_unit_never_type_fallback`, which Rust 1.92 and later deny in its
  `DagCbor` derive output.

### Removed

- The flake's `defaultPackage` and its `naersk` input. It had not evaluated since
  0.0.12, because naersk can't read `version.workspace = true`. Even when it builds,
  it installs nothing: naersk copies only executables, and the root crate builds none.
  The native library is `integrity-ffi`, which the release workflow builds.

### Fixed

- Reading an iroh collection fails if its meta blob lacks the `CollectionV0.` header
  or lists a name twice. Before, a repeated name silently kept only the last file's
  hash, so a model-signing manifest built from the collection could leave a file out.
- Exporting a manifest logs an error when an iroh collection it references can't be
  read. Before, the collection's file blobs were left out without a message. Export
  also reads each collection from the blobs it has already fetched, instead of
  fetching the collection and meta blobs a second time, so a missing meta blob is
  reported once. `integrity_cid::collection::hashmap_from_iroh_collection_blobs` is
  now public for callers that already hold both blobs.
- Exporting a manifest no longer panics on a hash-sequence blob shorter than 32
  bytes. Before, one truncated or corrupt collection blob failed the whole export;
  now it is exported as is, with an error logged and its file blobs left out.

### Security

- Clears the open Trivy findings on `aws-smithy-json` (CVE-2026-18140, now 0.62.7)
  and `hickory-resolver` (GHSA-5j98-2g5x-46v6, GHSA-6w6g-hm98-mhgm). `integrity-cid`
  no longer depends on `iroh-blobs`, which brought in iroh's networking stack and
  its pinned `hickory-resolver` beta; the aws crates move to releases that include
  the fix.

## [0.0.18] - 2026-09-22

### Added

- `VcStatement::create_with_contexts` and `compute_cid_with_contexts`, which take
  caller-supplied JSON-LD context documents so a statement can embed a credential
  whose `@context` is not in the static bundle (such as the vc-schema
  `https://ns.eqtylab.io/vc/...` contexts). `create` and `compute_cid` are unchanged.
- A changelog and contributor instructions for documenting PRs and releases.
- A release CI check requiring a matching changelog heading for stable tags
  before native FFI builds begin.

## [0.0.17] - 2026-09-10

### Fixed

- Recursively discover `urn:cid:` blob references throughout VC statements,
  including nested objects and arrays in `credentialSubject.identity`, so blobs
  referenced by newer attestation schemas are included during resolution.
  ([#46](https://github.com/eqtylab/integrity/pull/46))

## [0.0.16] - 2026-09-06

### Fixed

- Restore downstream Nix/Crane packaging by renaming vendored reference manifests
  from Cargo's reserved `Cargo.toml.orig` filename to `Cargo.toml.upstream`.
  ([#44](https://github.com/eqtylab/integrity/pull/44))

## [0.0.15] - 2026-09-02

### Fixed

- Vendor the complete legacy VC verification dependency path so downstream Git
  consumers also avoid the yanked `core2` dependency without root-level patches.
  ([#42](https://github.com/eqtylab/integrity/pull/42))

## [0.0.14] - 2026-09-02

### Fixed

- Remove the yanked `core2` dependency from the workspace dependency tree by
  patching legacy CID/IPLD crates to use `no_std_io2`. Downstream dependency
  resolution receives a further fix in 0.0.15.
  ([#40](https://github.com/eqtylab/integrity/pull/40))

## [0.0.13] - 2026-08-27

### Changed

- **Breaking:** VC signing and verification now accept caller-supplied JSON-LD
  contexts. Pass a context URL-to-document map (for EQTY credentials, use
  `vc-schema`'s `contexts()` output), or `None` when no additional contexts are
  needed. Unknown contexts produce errors; legacy VC verification remains supported.
  ([#39](https://github.com/eqtylab/integrity/pull/39))
- **Breaking:** Advance the FFI ABI from `0.3.0` to `0.4.0`: `ig_vc_sign` and
  `ig_vc_verify` gain a `contexts_json` argument. Rebuild bindings against the
  updated header and pass a JSON context map or `NULL`.
  ([#39](https://github.com/eqtylab/integrity/pull/39))

### Removed

- Remove automatic credential-context synchronization; new credential contexts
  can now be supplied by callers without an Integrity release.
  ([#39](https://github.com/eqtylab/integrity/pull/39))

## [0.0.12] - 2026-08-13

### Changed

- Align workspace package versions from `0.0.1` to `0.0.12` and centralize the
  version in the root Cargo manifest. Upgrade the direct `cid` dependency from
  `0.10` to `0.11`.
  ([#38](https://github.com/eqtylab/integrity/pull/38))

### Fixed

- Return errors instead of panicking when `vcomp-notary` refuses to sign or
  returns an HTTP error, invalid JSON, or a missing or malformed signature.
  ([#37](https://github.com/eqtylab/integrity/pull/37))

## [0.0.11] - 2026-07-27

### Removed

- **Breaking:** Remove YubiHSM signer support and its LGPL dependency. Remove
  `signer-yubihsm` from feature selections and migrate affected integrations to
  a supported signer. The separate YubiKey PIV backend remains available.
  ([#35](https://github.com/eqtylab/integrity/pull/35))

## [0.0.10] - 2026-07-22

### Added

- Automatically embed credential schema contexts during builds and add a workflow
  to synchronize them from the credentials repository.
  ([#31](https://github.com/eqtylab/integrity/pull/31))

### Changed

- **Breaking:** Rename `VCompNotarySigner`'s `did_statements` field to `credentials`
  in the signer API. Update callers accessing the field.
  ([#32](https://github.com/eqtylab/integrity/pull/32))

### Removed

- **Breaking:** Remove legacy VComp DID statement variants and their FFI
  constructors; deserialization rejects legacy `vcomp` payloads. Migrate those
  integrations to verifiable credentials and update bindings to the current header.
  ([#33](https://github.com/eqtylab/integrity/pull/33))

## [0.0.9] - 2026-07-13

### Fixed

- Log missing static contexts during manifest generation as warnings instead of errors.
  ([#30](https://github.com/eqtylab/integrity/pull/30))

## [0.0.8] - 2026-07-08

### Added

- Add batch blob-store reads and writes with bounded concurrency, including C FFI
  bindings. Advance the FFI ABI from `0.2.0` to `0.3.0`.
  ([#28](https://github.com/eqtylab/integrity/pull/28))

### Changed

- Add configurable batch concurrency; batch reads filter duplicate CIDs and
  common non-CID identifiers.
  ([#29](https://github.com/eqtylab/integrity/pull/29))

### Fixed

- Return Azure blob download errors for HTTP failures other than 404 instead of
  treating all client errors as missing blobs.
  ([#29](https://github.com/eqtylab/integrity/pull/29))
- Upgrade `reqwest` in the vendored legacy VC verifier (`ssi-vc`) from `0.11`
  to `0.13`, removing its older HTTP dependency path.
  ([#28](https://github.com/eqtylab/integrity/pull/28))

## [0.0.7] - 2026-06-10

### Changed

- Upgrade `serde_jcs` from `0.1.0` to `0.2.0` in CID and lineage canonicalization.
  ([#27](https://github.com/eqtylab/integrity/pull/27))

## [0.0.6] - 2026-06-05

### Changed

- **Breaking:** Add an optional `credential_type` argument to
  `build_unsigned_with_eqty_contexts`. Pass `None` to retain the default type or
  `Some(...)` to append a custom credential type.
  ([#26](https://github.com/eqtylab/integrity/pull/26))

## [0.0.5] - 2026-06-03

### Added

- Add credential status allocation and update functions, plus helpers to revoke,
  suspend, and unsuspend credentials through a VC status server.
  ([#24](https://github.com/eqtylab/integrity/pull/24))

### Changed

- Use an inline EQTY `@vocab` in unsigned credential construction so arbitrary
  EQTY evidence fields survive JSON-LD processing.
  ([#24](https://github.com/eqtylab/integrity/pull/24))

## [0.0.4] - 2026-06-01

### Added

- Add `check_credential_status` for checking VC 2.0 bitstring status lists.
  ([#23](https://github.com/eqtylab/integrity/pull/23))

## [0.0.3] - 2026-05-21

### Added

- Add `build_unsigned_with_eqty_contexts` to construct unsigned credentials with
  EQTY contexts, structured subjects, validity dates, and evidence.
  ([#22](https://github.com/eqtylab/integrity/pull/22))

## [0.0.2] - 2026-05-19

### Added

- Add YubiKey PIV signing through the `signer-yubikey` feature and a usage example.
  ([#15](https://github.com/eqtylab/integrity/pull/15))
- Compute Iroh hashes in memory.
  ([#14](https://github.com/eqtylab/integrity/pull/14))
- Add `issue_revocable_vc` for issuing credentials backed by a status server.
  ([#18](https://github.com/eqtylab/integrity/pull/18))

### Changed

- **Breaking:** Migrate credential issuance to VC 2.0 and upgrade the primary
  `ssi` dependency from `0.7` to `0.16`. Update Rust integrations to the new
  credential types and VC 2.0 fields; legacy credentials remain verifiable.
  ([#18](https://github.com/eqtylab/integrity/pull/18))
- Update the bundled EQTY common JSON-LD context.
  ([#21](https://github.com/eqtylab/integrity/pull/21))

### Fixed

- Retain legacy proof suites for downstream compatibility and add legacy VC verification.
  ([#19](https://github.com/eqtylab/integrity/pull/19))
- Validate CID-addressed contexts used in credentials.
  ([#20](https://github.com/eqtylab/integrity/pull/20))

## [0.0.1] - 2026-03-11

### Added

- Split functionality into workspace crates with feature-gated blob and signer
  backends, and package the C ABI in the dedicated `integrity-ffi` crate.
  ([#6](https://github.com/eqtylab/integrity/pull/6))
- Bundle common and historical JSON-LD contexts for local resolution.
  ([#11](https://github.com/eqtylab/integrity/pull/11),
  [#12](https://github.com/eqtylab/integrity/pull/12))

### Changed

- **Breaking:** Restrict default backends to local blob stores and software signers.
  Enable the required `blob-*` and `signer-*` features explicitly for cloud or
  hardware backends, and build `integrity-ffi` for native SDK bindings.
  ([#6](https://github.com/eqtylab/integrity/pull/6))
- **Breaking:** Remove manifest attributes and the database-oriented `Graph` model,
  and revise the association registration schema. Remove attribute arguments from
  manifest calls and update association payloads to the revised model.
  ([#10](https://github.com/eqtylab/integrity/pull/10))

### Fixed

- Correct P-256 DID JWK coordinates and public-key decoding for software and
  `vcomp-notary` signers to prevent key mismatches.
  ([#9](https://github.com/eqtylab/integrity/pull/9),
  [#13](https://github.com/eqtylab/integrity/pull/13))

## [0.0.0] - 2026-02-11

### Added

- Initial tagged Integrity library with content addressing, JSON-LD processing,
  digital signing, verifiable credentials, blob storage, DSSE, in-toto attestations,
  lineage models, and model signing.
  ([#1](https://github.com/eqtylab/integrity/pull/1))
- Add C ABI bindings and a native artifact release workflow for Linux and macOS.
  ([#3](https://github.com/eqtylab/integrity/pull/3))

### Fixed

- Correct shell commands used to stage native release artifacts.
  ([#4](https://github.com/eqtylab/integrity/pull/4))

[Unreleased]: https://github.com/eqtylab/integrity/compare/v0.0.20...main
[0.0.20]: https://github.com/eqtylab/integrity/compare/v0.0.19...v0.0.20
[0.0.19]: https://github.com/eqtylab/integrity/compare/v0.0.18...v0.0.19
[0.0.18]: https://github.com/eqtylab/integrity/compare/v0.0.17...v0.0.18
[0.0.17]: https://github.com/eqtylab/integrity/compare/v0.0.16...v0.0.17
[0.0.16]: https://github.com/eqtylab/integrity/compare/v0.0.15...v0.0.16
[0.0.15]: https://github.com/eqtylab/integrity/compare/v0.0.14...v0.0.15
[0.0.14]: https://github.com/eqtylab/integrity/compare/v0.0.13...v0.0.14
[0.0.13]: https://github.com/eqtylab/integrity/compare/v0.0.12...v0.0.13
[0.0.12]: https://github.com/eqtylab/integrity/compare/v0.0.11...v0.0.12
[0.0.11]: https://github.com/eqtylab/integrity/compare/v0.0.10...v0.0.11
[0.0.10]: https://github.com/eqtylab/integrity/compare/v0.0.9...v0.0.10
[0.0.9]: https://github.com/eqtylab/integrity/compare/v0.0.8...v0.0.9
[0.0.8]: https://github.com/eqtylab/integrity/compare/v0.0.7...v0.0.8
[0.0.7]: https://github.com/eqtylab/integrity/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/eqtylab/integrity/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/eqtylab/integrity/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/eqtylab/integrity/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/eqtylab/integrity/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/eqtylab/integrity/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/eqtylab/integrity/compare/v0.0.0...v0.0.1
[0.0.0]: https://github.com/eqtylab/integrity/releases/tag/v0.0.0
