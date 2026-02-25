#ifndef INTEGRITY_FFI_H
#define INTEGRITY_FFI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct IgRuntimeHandle IgRuntimeHandle;
typedef struct IgSignerHandle IgSignerHandle;
typedef struct IgBlobStoreHandle IgBlobStoreHandle;

typedef enum IgStatus {
    IG_STATUS_OK = 0,
    IG_STATUS_INVALID_INPUT = 1,
    IG_STATUS_NULL_POINTER = 2,
    IG_STATUS_UTF8_ERROR = 3,
    IG_STATUS_JSON_ERROR = 4,
    IG_STATUS_VERIFICATION_FAILED = 5,
    IG_STATUS_NOT_SUPPORTED = 6,
    IG_STATUS_RUNTIME_ERROR = 7,
    IG_STATUS_INTERNAL_ERROR = 255,
} IgStatus;

typedef struct IgBytes {
    uint8_t *ptr;
    size_t len;
} IgBytes;

void ig_string_free(char *s);
void ig_error_free(char *err);
void ig_bytes_free(IgBytes bytes);

IgStatus ig_runtime_new(IgRuntimeHandle **out_runtime, char **err_out);
void ig_runtime_free(IgRuntimeHandle *runtime);

IgStatus ig_abi_version_string(char **out_version, char **err_out);
uint32_t ig_abi_version_major(void);
uint32_t ig_abi_version_minor(void);
uint32_t ig_abi_version_patch(void);
IgStatus ig_core_crate_version(char **out_version, char **err_out);

void ig_signer_free(IgSignerHandle *signer);
IgStatus ig_signer_get_did(const IgSignerHandle *signer, char **out_did, char **err_out);
IgStatus ig_signer_ed25519_create(IgSignerHandle **out_signer, char **out_did, char **err_out);
IgStatus ig_signer_ed25519_import(
    const uint8_t *secret_key_ptr,
    size_t secret_key_len,
    IgSignerHandle **out_signer,
    char **out_did,
    char **err_out
);
IgStatus ig_signer_p256_create(IgSignerHandle **out_signer, char **out_did, char **err_out);
IgStatus ig_signer_p256_import(
    const uint8_t *secret_key_ptr,
    size_t secret_key_len,
    IgSignerHandle **out_signer,
    char **out_did,
    char **err_out
);
IgStatus ig_signer_secp256k1_create(IgSignerHandle **out_signer, char **out_did, char **err_out);
IgStatus ig_signer_secp256k1_import(
    const uint8_t *secret_key_ptr,
    size_t secret_key_len,
    IgSignerHandle **out_signer,
    char **out_did,
    char **err_out
);
IgStatus ig_signer_auth_service_create(
    const IgRuntimeHandle *runtime,
    const char *api_key,
    const char *url,
    IgSignerHandle **out_signer,
    char **out_did,
    char **err_out
);
IgStatus ig_signer_vcomp_notary_create(
    const IgRuntimeHandle *runtime,
    const char *url,
    const char *pub_key_hex_or_null,
    IgSignerHandle **out_signer,
    char **out_did,
    char **err_out
);
IgStatus ig_signer_akv_create(
    const IgRuntimeHandle *runtime,
    const char *config_json,
    const char *key_name,
    IgSignerHandle **out_signer,
    char **out_did,
    char **err_out
);
IgStatus ig_signer_yubihsm_create(
    uint16_t auth_key_id,
    uint16_t signing_key_id,
    const char *password,
    IgSignerHandle **out_signer,
    char **out_did,
    char **err_out
);
IgStatus ig_signer_save(
    const IgSignerHandle *signer,
    const char *folder,
    const char *name,
    char **err_out
);
IgStatus ig_signer_load(
    const char *signer_file,
    IgSignerHandle **out_signer,
    char **out_did,
    char **err_out
);

IgStatus ig_dsse_sign(
    const IgRuntimeHandle *runtime,
    const IgSignerHandle *signer,
    const uint8_t *payload_ptr,
    size_t payload_len,
    const char *payload_type,
    char **out_envelope_json,
    char **err_out
);
IgStatus ig_dsse_sign_integrity_statement(
    const IgRuntimeHandle *runtime,
    const IgSignerHandle *signer,
    const char *statement_cid,
    char **out_envelope_json,
    char **err_out
);
IgStatus ig_dsse_verify(
    const IgRuntimeHandle *runtime,
    const char *envelope_json,
    bool *out_valid,
    char **err_out
);

IgStatus ig_vc_issue(
    const IgRuntimeHandle *runtime,
    const IgSignerHandle *signer,
    const char *subject,
    char **out_credential_json,
    char **err_out
);
IgStatus ig_vc_sign(
    const IgRuntimeHandle *runtime,
    const IgSignerHandle *signer,
    const char *unsigned_credential_json,
    char **out_signed_credential_json,
    char **err_out
);
IgStatus ig_vc_verify(
    const IgRuntimeHandle *runtime,
    const char *credential_json,
    char **out_verify_result_json,
    bool *out_valid,
    char **err_out
);

IgStatus ig_intoto_sign_statement(
    const IgRuntimeHandle *runtime,
    const IgSignerHandle *signer,
    const char *statement_json,
    char **out_dsse_envelope_json,
    char **err_out
);
IgStatus ig_intoto_verify_envelope(
    const IgRuntimeHandle *runtime,
    const char *dsse_envelope_json,
    bool *out_valid,
    char **err_out
);
IgStatus ig_intoto_digest_from_cid(const char *cid, char **out_digest_json, char **err_out);

IgStatus ig_model_signing_create_intoto_statement_from_hashes(
    const IgRuntimeHandle *runtime,
    const char *model_name,
    const char *path_hashes_json,
    bool allow_symlinks,
    const char *ignore_paths_json_or_null,
    char **out_statement_json,
    char **err_out
);
IgStatus ig_model_signing_create_sigstore_bundle(
    const char *dsse_json,
    const char *signer_did_key,
    char **out_sigstore_bundle_json,
    char **err_out
);

IgStatus ig_lineage_statement_create_association(
    const IgRuntimeHandle *runtime,
    const char *request_json,
    char **out_statement_json,
    char **err_out
);
IgStatus ig_lineage_statement_create_computation(
    const IgRuntimeHandle *runtime,
    const char *request_json,
    char **out_statement_json,
    char **err_out
);
IgStatus ig_lineage_statement_create_data(
    const IgRuntimeHandle *runtime,
    const char *request_json,
    char **out_statement_json,
    char **err_out
);
IgStatus ig_lineage_statement_create_dsse(
    const IgRuntimeHandle *runtime,
    const char *request_json,
    char **out_statement_json,
    char **err_out
);
IgStatus ig_lineage_statement_create_entity(
    const IgRuntimeHandle *runtime,
    const char *request_json,
    char **out_statement_json,
    char **err_out
);
IgStatus ig_lineage_statement_create_governance(
    const IgRuntimeHandle *runtime,
    const char *request_json,
    char **out_statement_json,
    char **err_out
);
IgStatus ig_lineage_statement_create_metadata(
    const IgRuntimeHandle *runtime,
    const char *request_json,
    char **out_statement_json,
    char **err_out
);
IgStatus ig_lineage_statement_create_metadata_from_json(
    const IgRuntimeHandle *runtime,
    const char *request_json,
    char **out_statement_json,
    char **err_out
);
IgStatus ig_lineage_statement_create_sigstore_bundle(
    const IgRuntimeHandle *runtime,
    const char *request_json,
    char **out_statement_json,
    char **err_out
);
IgStatus ig_lineage_statement_create_storage(
    const IgRuntimeHandle *runtime,
    const char *request_json,
    char **out_statement_json,
    char **err_out
);
IgStatus ig_lineage_statement_create_vc(
    const IgRuntimeHandle *runtime,
    const char *request_json,
    char **out_statement_json,
    char **err_out
);
IgStatus ig_lineage_statement_create_did_regular(
    const IgRuntimeHandle *runtime,
    const char *request_json,
    char **out_statement_json,
    char **err_out
);
IgStatus ig_lineage_statement_create_did_amdsev_v1(
    const IgRuntimeHandle *runtime,
    const char *request_json,
    char **out_statement_json,
    char **err_out
);
IgStatus ig_lineage_statement_create_did_azure_v1(
    const IgRuntimeHandle *runtime,
    const char *request_json,
    char **out_statement_json,
    char **err_out
);
IgStatus ig_lineage_statement_create_did_custom_v1(
    const IgRuntimeHandle *runtime,
    const char *request_json,
    char **out_statement_json,
    char **err_out
);
IgStatus ig_lineage_statement_create_did_docker_v1(
    const IgRuntimeHandle *runtime,
    const char *request_json,
    char **out_statement_json,
    char **err_out
);
IgStatus ig_lineage_statement_create_did_inteltdx_v0(
    const IgRuntimeHandle *runtime,
    const char *request_json,
    char **out_statement_json,
    char **err_out
);
IgStatus ig_lineage_statement_compute_cid(
    const IgRuntimeHandle *runtime,
    const char *statement_json,
    char **out_cid,
    char **err_out
);
IgStatus ig_lineage_statement_extract_id(
    const char *statement_json,
    char **out_id,
    char **err_out
);
IgStatus ig_lineage_statement_extract_type(
    const char *statement_json,
    char **out_type,
    char **err_out
);
IgStatus ig_lineage_statement_jsonld_filename(
    const char *statement_json,
    char **out_filename,
    char **err_out
);
IgStatus ig_lineage_statement_referenced_cids_json(
    const char *statement_json,
    char **out_referenced_cids_json,
    char **err_out
);
IgStatus ig_lineage_statement_registered_by(
    const char *statement_json,
    char **out_registered_by,
    char **err_out
);

void ig_blob_store_free(IgBlobStoreHandle *store);
IgStatus ig_blob_store_local_fs_new(
    const IgRuntimeHandle *runtime,
    const char *path,
    IgBlobStoreHandle **out_store,
    char **err_out
);
IgStatus ig_blob_store_s3_new(
    const IgRuntimeHandle *runtime,
    const char *region,
    const char *bucket,
    const char *folder,
    IgBlobStoreHandle **out_store,
    char **err_out
);
IgStatus ig_blob_store_gcs_new(
    const IgRuntimeHandle *runtime,
    const char *bucket,
    const char *folder,
    IgBlobStoreHandle **out_store,
    char **err_out
);
IgStatus ig_blob_store_azure_blob_new(
    const IgRuntimeHandle *runtime,
    const char *account,
    const char *key,
    const char *container,
    IgBlobStoreHandle **out_store,
    char **err_out
);
IgStatus ig_blob_store_exists(
    const IgRuntimeHandle *runtime,
    const IgBlobStoreHandle *store,
    const char *cid,
    bool *out_exists,
    char **err_out
);
IgStatus ig_blob_store_get(
    const IgRuntimeHandle *runtime,
    const IgBlobStoreHandle *store,
    const char *cid,
    IgBytes *out_blob,
    bool *out_found,
    char **err_out
);
IgStatus ig_blob_store_put(
    const IgRuntimeHandle *runtime,
    const IgBlobStoreHandle *store,
    const uint8_t *blob_ptr,
    size_t blob_len,
    uint64_t multicodec_code,
    const char *expected_cid_or_null,
    char **out_cid,
    char **err_out
);

IgStatus ig_lineage_manifest_generate(
    const IgRuntimeHandle *runtime,
    bool include_context,
    const char *statements_json,
    const char *attributes_json_or_null,
    const char *blobs_json,
    char **out_manifest_json,
    char **err_out
);
IgStatus ig_lineage_manifest_merge(
    const IgRuntimeHandle *runtime,
    const char *manifest_a_json,
    const char *manifest_b_json,
    char **out_manifest_json,
    char **err_out
);
IgStatus ig_lineage_manifest_resolve_blobs(
    const IgRuntimeHandle *runtime,
    const char *statements_json,
    const IgBlobStoreHandle *store,
    uint32_t concurrency_limit,
    char **out_blobs_json,
    char **err_out
);

#ifdef __cplusplus
}
#endif

#endif
