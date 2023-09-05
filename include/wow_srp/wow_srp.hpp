#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

constexpr static const uint8_t CLIENT_HEADER_LENGTH = 6;

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
constexpr static const uint8_t TBC_SERVER_HEADER_LENGTH = 4;
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
constexpr static const uint8_t VANILLA_SERVER_HEADER_LENGTH = 4;
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
constexpr static const uint8_t WRATH_SERVER_HEADER_MINIMUM_LENGTH = 4;
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
constexpr static const uint8_t WRATH_SERVER_HEADER_MAXIMUM_LENGTH = 5;
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/// Length of the password verifier returned by `wow_srp_verifier_password_verifier` in bytes.
///
/// `wow_srp` does not support keys of a smaller size than size.
constexpr static const uint8_t WOW_SRP_KEY_LENGTH = 32;
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/// Length of the session keys produced in bytes.
constexpr static const uint8_t WOW_SRP_SESSION_KEY_LENGTH = 40;
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/// Length of the proofs produced and used in bytes.
constexpr static const uint8_t WOW_SRP_PROOF_LENGTH = 40;
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/// Length of the reconnect data used in bytes.
constexpr static const uint8_t WOW_SRP_RECONNECT_DATA_LENGTH = 40;
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/// Generator used by the server implementation.
///
/// This should be passed to the client through `CMD_AUTH_LOGON_CHALLENGE_Server`.
constexpr static const uint8_t WOW_SRP_GENERATOR = 7;
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/// Used by `out_error` to signify that everything went well.
/// You should initialize your `out_error` variable to this since
/// the variable will not be set to explicit success.
constexpr static const char WOW_SRP_SUCCESS = 0;
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/// Used by `out_error` to signify that one of the required parameters was null.
///
/// If `out_error` is null errors will not be written.
constexpr static const char WOW_SRP_ERROR_NULL_POINTER = 1;
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/// Used by `out_error` to signify that the input string was not valid UTF-8.
constexpr static const char WOW_SRP_ERROR_UTF8 = 2;
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/// Used by `out_error` to signify that the username or password string contained disallowed values.
constexpr static const char WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME = 3;
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/// Used by `out_error` to signify that the public key was invalid.
constexpr static const char WOW_SRP_ERROR_INVALID_PUBLIC_KEY = 4;
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/// Used by `out_error` to signify that the client and server proofs did not match.
constexpr static const char WOW_SRP_ERROR_PROOFS_DO_NOT_MATCH = 5;
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
struct WowSrpClient;
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
struct WowSrpClientChallenge;
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
/// First step of client side authentication.
///
/// Created through `wow_srp_client_user_from_username_and_password`.
struct WowSrpClientUser;
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/// Second step of server side authentication.
///
/// Created through `wow_srp_verifier_into_proof`.
struct WowSrpProof;
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/// Last step of server side authentication.
///
/// Created through `wow_srp_proof_into_server`.
///
/// This object must be manually freed through `wow_srp_server_free`.
struct WowSrpServer;
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
struct WowSrpTbcHeaderCrypto;
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
struct WowSrpTbcProofSeed;
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
struct WowSrpVanillaHeaderCrypto;
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
struct WowSrpVanillaProofSeed;
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/// First step of Server authentication.
/// Converted into a `WowSrpProof` by calling `wow_srp_verifier_into_proof`.
struct WowSrpVerifier;
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
struct WowSrpWrathClientCrypto;
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
struct WowSrpWrathProofSeed;
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
struct WowSrpWrathServerCrypto;
#endif

extern "C" {

extern const uint8_t WOW_SRP_LARGE_SAFE_PRIME_LITTLE_ENDIAN[32];

#if !defined(WOW_SRP_DISABLE_CLIENT)
void wow_srp_client_free(WowSrpClient *client);
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
const uint8_t *wow_srp_client_session_key(WowSrpClient *client);
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
void wow_srp_client_calculate_reconnect_values(WowSrpClient *client,
                                               const uint8_t *server_challenge_data,
                                               uint8_t *out_client_challenge_data,
                                               uint8_t *out_client_proof,
                                               char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
void wow_srp_client_challenge_free(WowSrpClientChallenge *client_challenge);
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
const uint8_t *wow_srp_client_challenge_client_proof(WowSrpClientChallenge *client_challenge);
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
const uint8_t *wow_srp_client_challenge_client_public_key(WowSrpClientChallenge *client_challenge);
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
WowSrpClient *wow_srp_client_challenge_verify_server_proof(WowSrpClientChallenge *client_challenge,
                                                           const uint8_t *server_proof,
                                                           char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
/// Creates a new `WowSrpClientUser` from a username and password.
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
WowSrpClientUser *wow_srp_client_user_from_username_and_password(const char *username,
                                                                 const char *password,
                                                                 char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
/// Converts the `WowSrpClientUser` into a `WowSrpClientChallenge`.
///
/// This should be called after receiving `CMD_AUTH_LOGON_CHALLENGE_Server`.
///
/// * `large_safe_prime` is a `WOW_SRP_KEY_LENGTH` array.
/// * `server_public_key` is a `WOW_SRP_KEY_LENGTH` array.
/// * `salt` is a `WOW_SRP_KEY_LENGTH` array.
/// * `out_error` is a pointer to a single `uint8_t` that will be written to.
///
/// This function can return a null pointer, in which case errors will be in `out_error`.
/// It can return:
/// * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
/// * `WOW_SRP_ERROR_UTF8` if the username/password contains disallowed characters.
/// * `WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME` if the username/password contains disallowed characters.
WowSrpClientChallenge *wow_srp_client_user_into_challenge(WowSrpClientUser *client_user,
                                                          uint8_t generator,
                                                          const uint8_t *large_safe_prime,
                                                          const uint8_t *server_public_key,
                                                          const uint8_t *salt,
                                                          char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
/// Frees a `WowSrpClientUser`.
///
/// This should not normally need to be called since `wow_srp_client_user_into_challenge` will
/// free the object.
void wow_srp_client_user_free(WowSrpClientUser *client_user);
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
void wow_srp_tbc_proof_seed_free(WowSrpTbcProofSeed *seed);
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
WowSrpTbcProofSeed *wow_srp_tbc_proof_seed_new();
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
uint32_t wow_srp_tbc_proof_seed(const WowSrpTbcProofSeed *seed, char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
WowSrpTbcHeaderCrypto *wow_srp_proof_seed_into_tbc_client_header_crypto(WowSrpTbcProofSeed *seed,
                                                                        const char *username,
                                                                        const uint8_t *session_key,
                                                                        uint32_t server_seed,
                                                                        uint8_t *out_client_proof,
                                                                        char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
WowSrpTbcHeaderCrypto *wow_srp_proof_seed_into_tbc_server_header_crypto(WowSrpTbcProofSeed *seed,
                                                                        const char *username,
                                                                        const uint8_t *session_key,
                                                                        const uint8_t *client_proof,
                                                                        uint32_t client_seed,
                                                                        char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
void wow_srp_tbc_header_crypto_free(WowSrpTbcHeaderCrypto *header);
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
void wow_srp_tbc_header_crypto_encrypt(WowSrpTbcHeaderCrypto *header,
                                       uint8_t *data,
                                       uint16_t length,
                                       char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
void wow_srp_tbc_header_crypto_decrypt(WowSrpTbcHeaderCrypto *header,
                                       uint8_t *data,
                                       uint16_t length,
                                       char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
void wow_srp_vanilla_proof_seed_free(WowSrpVanillaProofSeed *seed);
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
WowSrpVanillaProofSeed *wow_srp_vanilla_proof_seed_new();
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
uint32_t wow_srp_vanilla_proof_seed(const WowSrpVanillaProofSeed *seed, char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
WowSrpVanillaHeaderCrypto *wow_srp_proof_seed_into_vanilla_client_header_crypto(WowSrpVanillaProofSeed *seed,
                                                                                const char *username,
                                                                                const uint8_t *session_key,
                                                                                uint32_t server_seed,
                                                                                uint8_t *out_client_proof,
                                                                                char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
WowSrpVanillaHeaderCrypto *wow_srp_proof_seed_into_vanilla_server_header_crypto(WowSrpVanillaProofSeed *seed,
                                                                                const char *username,
                                                                                const uint8_t *session_key,
                                                                                const uint8_t *client_proof,
                                                                                uint32_t client_seed,
                                                                                char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
void wow_srp_vanilla_header_crypto_free(WowSrpVanillaHeaderCrypto *header);
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
void wow_srp_vanilla_header_crypto_encrypt(WowSrpVanillaHeaderCrypto *header,
                                           uint8_t *data,
                                           uint16_t length,
                                           char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
void wow_srp_vanilla_header_crypto_decrypt(WowSrpVanillaHeaderCrypto *header,
                                           uint8_t *data,
                                           uint16_t length,
                                           char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
void wow_srp_wrath_proof_seed_free(WowSrpWrathProofSeed *seed);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
WowSrpWrathProofSeed *wow_srp_wrath_proof_seed_new();
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
uint32_t wow_srp_wrath_proof_seed(const WowSrpWrathProofSeed *seed, char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
WowSrpWrathClientCrypto *wow_srp_proof_seed_into_wrath_client_crypto(WowSrpWrathProofSeed *seed,
                                                                     const char *username,
                                                                     const uint8_t *session_key,
                                                                     uint32_t server_seed,
                                                                     uint8_t *out_client_proof,
                                                                     char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
WowSrpWrathServerCrypto *wow_srp_proof_seed_into_wrath_server_crypto(WowSrpWrathProofSeed *seed,
                                                                     const char *username,
                                                                     const uint8_t *session_key,
                                                                     const uint8_t *client_proof,
                                                                     uint32_t client_seed,
                                                                     char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
void wow_srp_wrath_server_crypto_free(WowSrpWrathServerCrypto *header);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
void wow_srp_wrath_server_crypto_encrypt(WowSrpWrathServerCrypto *header,
                                         uint8_t *data,
                                         uint16_t length,
                                         char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
void wow_srp_wrath_server_crypto_decrypt(WowSrpWrathServerCrypto *header,
                                         uint8_t *data,
                                         uint16_t length,
                                         char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
void wow_srp_wrath_client_crypto_free(WowSrpWrathClientCrypto *header);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
void wow_srp_wrath_client_crypto_encrypt(WowSrpWrathClientCrypto *header,
                                         uint8_t *data,
                                         uint16_t length,
                                         char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
void wow_srp_wrath_client_crypto_decrypt(WowSrpWrathClientCrypto *header,
                                         uint8_t *data,
                                         uint16_t length,
                                         char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/// Returns the server public key as a `WOW_SRP_KEY_LENGTH` sized array.
///
/// This should be passed to the client through `CMD_AUTH_LOGON_CHALLENGE_Server`.
///
/// Will return null if `proof` is null.
const uint8_t *wow_srp_proof_server_public_key(const WowSrpProof *proof);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/// Returns the salt as a `WOW_SRP_KEY_LENGTH` sized array.
///
/// This should be passed to the client through `CMD_AUTH_LOGON_CHALLENGE_Server`.
///
/// Will return null if `proof` is null.
const uint8_t *wow_srp_proof_salt(const WowSrpProof *proof);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
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
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/// Frees a `WowSrpProof`.
///
/// This should not normally need to be called since `wow_srp_proof_into_server` will
/// free the proof.
void wow_srp_proof_free(WowSrpProof *proof);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/// Returns the session key as a `WOW_SRP_SESSION_KEY_LENGTH` sized array.
///
/// This should be passed to the client through `CMD_AUTH_LOGON_CHALLENGE_Server`.
///
/// Will return null if `proof` is null.
const uint8_t *wow_srp_server_session_key(const WowSrpServer *server);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/// Returns the reconnect data as a `WOW_SRP_RECONNECT_DATA_LENGTH` sized array.
///
/// This should be passed to the client through `CMD_AUTH_RECONNECT_CHALLENGE_Server`.
///
/// Will return null if `proof` is null.
const uint8_t *wow_srp_server_reconnect_challenge_data(const WowSrpServer *server);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
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
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/// Frees a `WowSrpServer`.
///
/// This must be called manually since no other function will free it.
void wow_srp_server_free(WowSrpServer *server);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
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
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
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
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/// Converts the `WowSrpVerifier` into a `WowSrpProof`.
///
/// This ends the lifetime of the `WowSrpVerifier` and it must not be used again.
///
/// Will return null if `verifier` is null.
WowSrpProof *wow_srp_verifier_into_proof(WowSrpVerifier *verifier);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/// Returns the salt as a `WOW_SRP_KEY_LENGTH` sized byte array.
///
/// This should be stored in the database for future lookup.
///
/// The lifetime of this is tied to the lifetime of the `WowSrpVerifier`.
///
/// Will return null if `verifier` is null.
const uint8_t *wow_srp_verifier_salt(const WowSrpVerifier *verifier);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/// Returns the password verifier as a `WOW_SRP_KEY_LENGTH` sized byte array.
///
/// This should be stored in the database for future lookup.
///
/// The lifetime of this is tied to the lifetime of the `WowSrpVerifier`.
///
/// Will return null if `verifier` is null.
const uint8_t *wow_srp_verifier_password_verifier(const WowSrpVerifier *verifier);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/// Frees a `WowSrpVerifier`.
///
/// This should not normally need to be called since `wow_srp_verifier_into_proof` will
/// free the verifier.
void wow_srp_verifier_free(WowSrpVerifier *verifier);
#endif

} // extern "C"
