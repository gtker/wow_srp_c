#include <cstdint>

constexpr static const uint8_t WOW_SRP_TBC_SERVER_HEADER_LENGTH = 4;


/// Header crypto for TBC.
///
/// Created through `wow_srp_tbc_proof_seed_into_*_header_crypto`.
///
/// This object must manually be freed.
struct WowSrpTBCHeaderCrypto;


/// First step of header decryption for TBC.
///
/// Created through `wow_srp_tbc_proof_seed_new`.
struct WowSrpTBCProofSeed;


extern "C" {
/// Creates a proof seed.
///
/// Can not be null.
WowSrpTBCProofSeed *wow_srp_tbc_proof_seed_new();


/// Returns the randomized seed value.
///
/// Used in `CMD_AUTH_RECONNECT_CHALLENGE_Server`.
uint32_t wow_srp_tbc_proof_seed(const WowSrpTBCProofSeed *seed, char *out_error);


/// Converts the seed into a `WowSrpTBCHeaderCrypto` for the client.
///
/// * `username` is a null terminated string no longer than 16 characters.
/// * `session_key` is a `WOW_SRP_SESSION_KEY_LENGTH` array.
/// * `out_client_proof` is a `WOW_SRP_PROOF_LENGTH` array that will be written to.
/// * `out_error` is a pointer to a single `uint8_t` that will be written to.
///
/// This function can return a null pointer, in which case errors will be in `out_error`.
/// It can return:
/// * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
/// * `WOW_SRP_ERROR_UTF8` if the username/password contains disallowed characters.
/// * `WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME` if the username/password contains disallowed characters.
WowSrpTBCHeaderCrypto *wow_srp_tbc_proof_seed_into_client_header_crypto(WowSrpTBCProofSeed *seed,
                                                                        const char *username,
                                                                        const uint8_t *session_key,
                                                                        uint32_t server_seed,
                                                                        uint8_t *out_client_proof,
                                                                        char *out_error);


/// Converts the seed into a `WowSrpTBCHeaderCrypto` for the server.
///
/// * `username` is a null terminated string no longer than 16 characters.
/// * `session_key` is a `WOW_SRP_SESSION_KEY_LENGTH` array.
/// * `client_proof` is a `WOW_SRP_PROOF_LENGTH` array.
/// * `out_error` is a pointer to a single `uint8_t` that will be written to.
///
/// This function can return a null pointer, in which case errors will be in `out_error`.
/// It can return:
/// * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
/// * `WOW_SRP_ERROR_UTF8` if the username/password contains disallowed characters.
/// * `WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME` if the username/password contains disallowed characters.
WowSrpTBCHeaderCrypto *wow_srp_tbc_proof_seed_into_server_header_crypto(WowSrpTBCProofSeed *seed,
                                                                        const char *username,
                                                                        const uint8_t *session_key,
                                                                        const uint8_t *client_proof,
                                                                        uint32_t client_seed,
                                                                        char *out_error);


/// Frees the `WowSrpTBCProofSeed`.
///
/// This should not normally be called since `wow_srp_tbc_proof_seed_into_tbc_*` functions
/// free this object.
void wow_srp_tbc_proof_seed_free(WowSrpTBCProofSeed *seed);


/// Encrypts the `data`.
///
/// You must manually size the `data` to be the appropriate size.
/// For messages sent from the client this is `WOW_SRP_CLIENT_HEADER_LENGTH`,
/// and for messages sent from the server this is `WOW_SRP_TBC_SERVER_HEADER_LENGTH`.
///
/// * `data` is a `length` sized array that will be written to.
/// * `out_error` is a pointer to a single `uint8_t` that will be written to.
///
/// This function can return a null pointer, in which case errors will be in `out_error`.
/// It can return:
/// * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
void wow_srp_tbc_header_crypto_encrypt(WowSrpTBCHeaderCrypto *header,
                                       uint8_t *data,
                                       uint16_t length,
                                       char *out_error);


/// Decrypts the `data`.
///
/// You must manually size the `data` to be the appropriate size.
/// For messages sent from the client this is `WOW_SRP_CLIENT_HEADER_LENGTH`,
/// and for messages sent from the server this is `WOW_SRP_TBC_SERVER_HEADER_LENGTH`.
///
/// * `data` is a `length` sized array that will be written to.
/// * `out_error` is a pointer to a single `uint8_t` that will be written to.
///
/// This function can return a null pointer, in which case errors will be in `out_error`.
/// It can return:
/// * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
void wow_srp_tbc_header_crypto_decrypt(WowSrpTBCHeaderCrypto *header,
                                       uint8_t *data,
                                       uint16_t length,
                                       char *out_error);


/// Free the `WowSrpTBCHeaderCrypto`.
///
/// This must manually be done.
void wow_srp_tbc_header_crypto_free(WowSrpTBCHeaderCrypto *header);


} // extern "C"