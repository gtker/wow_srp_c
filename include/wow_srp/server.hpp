#include <cstdint>

/// Second step of server side authentication.
///
/// Created through `wow_srp_verifier_into_proof`.
struct WowSrpProof;


/// Last step of server side authentication.
///
/// Created through `wow_srp_proof_into_server`.
///
/// This object must be manually freed through `wow_srp_server_free`.
struct WowSrpServer;


/// First step of Server authentication.
/// Converted into a `WowSrpProof` by calling `wow_srp_verifier_into_proof`.
struct WowSrpVerifier;


extern "C" {
/// Returns the server public key as a `WOW_SRP_KEY_LENGTH` sized array.
///
/// This should be passed to the client through `CMD_AUTH_LOGON_CHALLENGE_Server`.
///
/// Will return null if `proof` is null.
const uint8_t *wow_srp_proof_server_public_key(const WowSrpProof *proof);


/// Returns the salt as a `WOW_SRP_KEY_LENGTH` sized array.
///
/// This should be passed to the client through `CMD_AUTH_LOGON_CHALLENGE_Server`.
///
/// Will return null if `proof` is null.
const uint8_t *wow_srp_proof_salt(const WowSrpProof *proof);


/// Convert the `WowSrpProof` into a `WowSrpServer`.
///
/// This should be called after receiving the client public key and proof from the client in
/// `CMD_AUTH_LOGON_PROOF_Client`.
///
/// * `client_public_key` is a `WOW_SRP_KEY_LENGTH` array.
/// * `client_proof` is a `WOW_SRP_PROOF_LENGTH` array.
/// * `out_server_proof` is a `WOW_SRP_PROOF_LENGTH` array that will be written to.
/// * `out_error` is a pointer to a single `uint8_t` that will be written to.
///
/// This function can return a null pointer, in which case errors will be in `out_error`.
/// It can return:
/// * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
/// * `WOW_SRP_ERROR_INVALID_PUBLIC_KEY` if the public key is invalid.
/// * `WOW_SRP_ERROR_PROOFS_DO_NOT_MATCH` if the client proof does not match the server proof.
WowSrpServer *wow_srp_proof_into_server(WowSrpProof *proof,
                                        const uint8_t *client_public_key,
                                        const uint8_t *client_proof,
                                        uint8_t *out_server_proof,
                                        char *out_error);


/// Frees a `WowSrpProof`.
///
/// This should not normally need to be called since `wow_srp_proof_into_server` will
/// free the proof.
void wow_srp_proof_free(WowSrpProof *proof);


/// Returns the session key as a `WOW_SRP_SESSION_KEY_LENGTH` sized array.
///
/// This should be passed to the client through `CMD_AUTH_LOGON_CHALLENGE_Server`.
///
/// Will return null if `proof` is null.
const uint8_t *wow_srp_server_session_key(const WowSrpServer *server);


/// Returns the reconnect data as a `WOW_SRP_RECONNECT_DATA_LENGTH` sized array.
///
/// This should be passed to the client through `CMD_AUTH_RECONNECT_CHALLENGE_Server`.
///
/// Will return null if `proof` is null.
const uint8_t *wow_srp_server_reconnect_challenge_data(const WowSrpServer *server);


/// Returns true if the client proof matches the server proof.
///
/// * `client_data` is a `WOW_SRP_RECONNECT_DATA_LENGTH` length array.
/// * `client_proof` is a `WOW_SRP_PROOF_LENGTH` length array.
/// * `out_error` is a pointer to a single `uint8_t` that will be written to.
///
/// This function can return a null pointer, in which case errors will be in `out_error`.
/// It can return:
/// * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
/// * `WOW_SRP_ERROR_PROOFS_DO_NOT_MATCH` if the client proof does not match the server proof.
bool wow_srp_server_verify_reconnection_attempt(WowSrpServer *server,
                                                const uint8_t *client_data,
                                                const uint8_t *client_proof,
                                                char *out_error);


/// Frees a `WowSrpServer`.
///
/// This must be called manually since no other function will free it.
void wow_srp_server_free(WowSrpServer *server);


/// Creates a `WowSrpVerifier` from a username and password.
/// This should only be used the very first time that a client authenticates.
/// The username, salt, and password verifier should be stored in the database for future lookup,
/// and `wow_srp_verifier_from_database_values` should then be called.
///
/// * `username` is a null terminated string no longer than 16 characters.
/// * `password` is a null terminated string no longer than 16 characters.
/// * `out_error` is a pointer to a single `uint8_t` that will be written to.
///
/// This function can return a null pointer, in which case errors will be in `out_error`.
/// It can return:
/// * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
/// * `WOW_SRP_ERROR_UTF8` if the username/password contains disallowed characters.
/// * `WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME` if the username/password contains disallowed characters.
WowSrpVerifier *wow_srp_verifier_from_username_and_password(const char *username,
                                                            const char *password,
                                                            char *out_error);


/// Creates a `WowSrpVerifier` from a username, password verifier, and salt
/// previously generated from `wow_srp_verifier_from_username_and_password`.
///
/// * `username` is a null terminated string no longer than 16 characters.
/// * `password_verifier` is a `WOW_SRP_KEY_LENGTH` array.
/// * `salt` is a `WOW_SRP_KEY_LENGTH` array.
/// * `out_error` is a pointer to a single `uint8_t` that will be written to.
///
/// This function can return a null pointer, in which case errors will be in `out_error`.
/// It can return:
/// * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
/// * `WOW_SRP_ERROR_UTF8` if the username/password contains disallowed characters.
/// * `WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME` if the username/password contains disallowed characters.
WowSrpVerifier *wow_srp_verifier_from_database_values(const char *username,
                                                      const uint8_t *password_verifier,
                                                      const uint8_t *salt,
                                                      char *out_error);


/// Converts the `WowSrpVerifier` into a `WowSrpProof`.
///
/// This ends the lifetime of the `WowSrpVerifier` and it must not be used again.
///
/// Will return null if `verifier` is null.
WowSrpProof *wow_srp_verifier_into_proof(WowSrpVerifier *verifier);


/// Returns the salt as a `WOW_SRP_KEY_LENGTH` sized byte array.
///
/// This should be stored in the database for future lookup.
///
/// The lifetime of this is tied to the lifetime of the `WowSrpVerifier`.
///
/// Will return null if `verifier` is null.
const uint8_t *wow_srp_verifier_salt(const WowSrpVerifier *verifier);


/// Returns the password verifier as a `WOW_SRP_KEY_LENGTH` sized byte array.
///
/// This should be stored in the database for future lookup.
///
/// The lifetime of this is tied to the lifetime of the `WowSrpVerifier`.
///
/// Will return null if `verifier` is null.
const uint8_t *wow_srp_verifier_password_verifier(const WowSrpVerifier *verifier);


/// Frees a `WowSrpVerifier`.
///
/// This should not normally need to be called since `wow_srp_verifier_into_proof` will
/// free the verifier.
void wow_srp_verifier_free(WowSrpVerifier *verifier);


} // extern "C"