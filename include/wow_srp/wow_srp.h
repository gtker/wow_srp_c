#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define CLIENT_HEADER_LENGTH 6

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
#define WOW_SRP_TBC_SERVER_HEADER_LENGTH 4
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
#define WOW_SRP_VANILLA_SERVER_HEADER_LENGTH 4
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
#define WRATH_SERVER_HEADER_MINIMUM_LENGTH 4
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
#define WRATH_SERVER_HEADER_MAXIMUM_LENGTH 5
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/**
 * Length of the password verifier returned by `wow_srp_verifier_password_verifier` in bytes.
 *
 * `wow_srp` does not support keys of a smaller size than size.
 */
#define WOW_SRP_KEY_LENGTH 32
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/**
 * Length of the session keys produced in bytes.
 */
#define WOW_SRP_SESSION_KEY_LENGTH 40
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/**
 * Length of the proofs produced and used in bytes.
 */
#define WOW_SRP_PROOF_LENGTH 40
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/**
 * Length of the reconnect data used in bytes.
 */
#define WOW_SRP_RECONNECT_DATA_LENGTH 40
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/**
 * Generator used by the server implementation.
 *
 * This should be passed to the client through `CMD_AUTH_LOGON_CHALLENGE_Server`.
 */
#define WOW_SRP_GENERATOR 7
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/**
 * Used by `out_error` to signify that everything went well.
 * You should initialize your `out_error` variable to this since
 * the variable will not be set to explicit success.
 */
#define WOW_SRP_SUCCESS 0
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/**
 * Used by `out_error` to signify that one of the required parameters was null.
 *
 * If `out_error` is null errors will not be written.
 */
#define WOW_SRP_ERROR_NULL_POINTER 1
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/**
 * Used by `out_error` to signify that the input string was not valid UTF-8.
 */
#define WOW_SRP_ERROR_UTF8 2
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/**
 * Used by `out_error` to signify that the username or password string contained disallowed values.
 */
#define WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME 3
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/**
 * Used by `out_error` to signify that the public key was invalid.
 */
#define WOW_SRP_ERROR_INVALID_PUBLIC_KEY 4
#endif

#if !(defined(WOW_SRP_DISABLE_CLIENT) || defined(WOW_SRP_DISABLE_SERVER))
/**
 * Used by `out_error` to signify that the client and server proofs did not match.
 */
#define WOW_SRP_ERROR_PROOFS_DO_NOT_MATCH 5
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
/**
 * Final step of client side authentication.
 *
 * This must be manually freed with `wow_srp_client_free`.
 */
typedef struct WowSrpClient WowSrpClient;
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
/**
 * First part of the client side authentication.
 *
 * Created through `wow_srp_client_challenge_create`.
 */
typedef struct WowSrpClientChallenge WowSrpClientChallenge;
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/**
 * Second step of server side authentication.
 *
 * Created through `wow_srp_verifier_into_proof`.
 */
typedef struct WowSrpProof WowSrpProof;
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/**
 * Last step of server side authentication.
 *
 * Created through `wow_srp_proof_into_server`.
 *
 * This object must be manually freed through `wow_srp_server_free`.
 */
typedef struct WowSrpServer WowSrpServer;
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
/**
 * Header crypto for TBC.
 *
 * Created through `wow_srp_tbc_proof_seed_into_*_header_crypto`.
 *
 * This object must manually be freed.
 */
typedef struct WowSrpTBCHeaderCrypto WowSrpTBCHeaderCrypto;
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
/**
 * First step of header decryption for TBC.
 *
 * Created through `wow_srp_tbc_proof_seed_new`.
 */
typedef struct WowSrpTBCProofSeed WowSrpTBCProofSeed;
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
/**
 * Header crypto for Vanilla.
 *
 * Created through `wow_srp_vanilla_proof_seed_into_*_header_crypto`.
 *
 * This object must manually be freed.
 */
typedef struct WowSrpVanillaHeaderCrypto WowSrpVanillaHeaderCrypto;
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
/**
 * First step of header decryption for Vanilla.
 *
 * Created through `wow_srp_vanilla_proof_seed_new`.
 */
typedef struct WowSrpVanillaProofSeed WowSrpVanillaProofSeed;
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/**
 * First step of Server authentication.
 * Converted into a `WowSrpProof` by calling `wow_srp_verifier_into_proof`.
 */
typedef struct WowSrpVerifier WowSrpVerifier;
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
/**
 * Header crypto for Wrath servers.
 *
 * Created through `wow_srp_wrath_proof_seed_into_client_header_crypto`.
 *
 * This object must manually be freed.
 */
typedef struct WowSrpWrathClientCrypto WowSrpWrathClientCrypto;
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
typedef struct WowSrpWrathProofSeed WowSrpWrathProofSeed;
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
/**
 * Header crypto for Wrath servers.
 *
 * Created through `wow_srp_wrath_proof_seed_into_server_header_crypto`.
 *
 * This object must manually be freed.
 */
typedef struct WowSrpWrathServerCrypto WowSrpWrathServerCrypto;
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

extern const uint8_t WOW_SRP_LARGE_SAFE_PRIME_LITTLE_ENDIAN[32];

#if !defined(WOW_SRP_DISABLE_CLIENT)
/**
 * Returns the session key as a `WOW_SRP_SESSION_KEY_LENGTH` sized array.
 *
 * This should be used for header decryption.
 *
 * Will return null if `proof` is null.
 */
const uint8_t *wow_srp_client_session_key(struct WowSrpClient *client);
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
/**
 * Calculates the client proof for reconnection.
 *
 * * `server_challenge_data` is a `WOW_SRP_RECONNECT_DATA_LENGTH` array.
 * * `out_client_challenge_data` is a `WOW_SRP_RECONNECT_DATA_LENGTH` array that will be written to.
 * * `out_client_proof` is a `WOW_SRP_PROOF_LENGTH` array that will be written to.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 * * `WOW_SRP_ERROR_INVALID_PUBLIC_KEY` if the public key is invalid.
 * * `WOW_SRP_ERROR_PROOFS_DO_NOT_MATCH` if the client proof does not match the server proof.
 */
void wow_srp_client_calculate_reconnect_values(struct WowSrpClient *client,
                                               const uint8_t *server_challenge_data,
                                               uint8_t *out_client_challenge_data,
                                               uint8_t *out_client_proof,
                                               char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
/**
 * Frees a `WowSrpClient`.
 */
void wow_srp_client_free(struct WowSrpClient *client);
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
/**
 * Create a `WowSrpClientChallenge`.
 *
 * This should be called after receiving `CMD_AUTH_LOGON_CHALLENGE_Server`.
 *
 * * `username` is a null terminated string no longer than 16 characters.
 * * `password` is a null terminated string no longer than 16 characters.
 * * `large_safe_prime` is a `WOW_SRP_KEY_LENGTH` array.
 * * `server_public_key` is a `WOW_SRP_KEY_LENGTH` array.
 * * `salt` is a `WOW_SRP_KEY_LENGTH` array.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 * * `WOW_SRP_ERROR_UTF8` if the username/password contains disallowed characters.
 * * `WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME` if the username/password contains disallowed characters.
 * * `WOW_SRP_ERROR_INVALID_PUBLIC_KEY` if the public key is invalid.
 * * `WOW_SRP_ERROR_PROOFS_DO_NOT_MATCH` if the client proof does not match the server proof.
 */
struct WowSrpClientChallenge *wow_srp_client_challenge_create(const char *username,
                                                              const char *password,
                                                              uint8_t generator,
                                                              const uint8_t *large_safe_prime,
                                                              const uint8_t *server_public_key,
                                                              const uint8_t *salt,
                                                              char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
/**
 * Returns the client proof as a `WOW_SRP_PROOF_LENGTH` sized array.
 *
 * This should be passed to the client through `CMD_AUTH_LOGON_PROOF_Client`.
 *
 * Will return null if `proof` is null.
 */
const uint8_t *wow_srp_client_challenge_client_proof(struct WowSrpClientChallenge *client_challenge);
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
/**
 * Returns the client proof as a `WOW_SRP_KEY_LENGTH` sized array.
 *
 * This should be passed to the client through `CMD_AUTH_LOGON_PROOF_Client`.
 *
 * Will return null if `proof` is null.
 */
const uint8_t *wow_srp_client_challenge_client_public_key(struct WowSrpClientChallenge *client_challenge);
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
/**
 * Convert the `WowSrpClientChallenge` into a `WowSrpClient` and
 * verify that the server and client proofs match.
 *
 * * `server_proof` is a `WOW_SRP_PROOF_LENGTH` array.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 * * `WOW_SRP_ERROR_PROOFS_DO_NOT_MATCH` if the client proof does not match the server proof.
 */
struct WowSrpClient *wow_srp_client_challenge_verify_server_proof(struct WowSrpClientChallenge *client_challenge,
                                                                  const uint8_t *server_proof,
                                                                  char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_CLIENT)
/**
 * Frees a `WowSrpClientChallenge`.
 *
 * This should not normally need to be called since `wow_srp_proof_into_server` will
 * free the proof.
 */
void wow_srp_client_challenge_free(struct WowSrpClientChallenge *client_challenge);
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
/**
 * Creates a proof seed.
 *
 * Can not be null.
 */
struct WowSrpTBCProofSeed *wow_srp_tbc_proof_seed_new(void);
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
/**
 * Returns the randomized seed value.
 *
 * Used in `CMD_AUTH_RECONNECT_CHALLENGE_Server`.
 */
uint32_t wow_srp_tbc_proof_seed(const struct WowSrpTBCProofSeed *seed, char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
/**
 * Converts the seed into a `WowSrpTBCHeaderCrypto` for the client.
 *
 * * `username` is a null terminated string no longer than 16 characters.
 * * `session_key` is a `WOW_SRP_SESSION_KEY_LENGTH` array.
 * * `out_client_proof` is a `WOW_SRP_PROOF_LENGTH` array that will be written to.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 * * `WOW_SRP_ERROR_UTF8` if the username/password contains disallowed characters.
 * * `WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME` if the username/password contains disallowed characters.
 */
struct WowSrpTBCHeaderCrypto *wow_srp_tbc_proof_seed_into_client_header_crypto(struct WowSrpTBCProofSeed *seed,
                                                                               const char *username,
                                                                               const uint8_t *session_key,
                                                                               uint32_t server_seed,
                                                                               uint8_t *out_client_proof,
                                                                               char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
/**
 * Converts the seed into a `WowSrpTBCHeaderCrypto` for the server.
 *
 * * `username` is a null terminated string no longer than 16 characters.
 * * `session_key` is a `WOW_SRP_SESSION_KEY_LENGTH` array.
 * * `client_proof` is a `WOW_SRP_PROOF_LENGTH` array.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 * * `WOW_SRP_ERROR_UTF8` if the username/password contains disallowed characters.
 * * `WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME` if the username/password contains disallowed characters.
 */
struct WowSrpTBCHeaderCrypto *wow_srp_tbc_proof_seed_into_server_header_crypto(struct WowSrpTBCProofSeed *seed,
                                                                               const char *username,
                                                                               const uint8_t *session_key,
                                                                               const uint8_t *client_proof,
                                                                               uint32_t client_seed,
                                                                               char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
/**
 * Frees the `WowSrpTBCProofSeed`.
 *
 * This should not normally be called since `wow_srp_tbc_proof_seed_into_tbc_*` functions
 * free this object.
 */
void wow_srp_tbc_proof_seed_free(struct WowSrpTBCProofSeed *seed);
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
/**
 * Encrypts the `data`.
 *
 * You must manually size the `data` to be the appropriate size.
 * For messages sent from the client this is `WOW_SRP_CLIENT_HEADER_LENGTH`,
 * and for messages sent from the server this is `WOW_SRP_TBC_SERVER_HEADER_LENGTH`.
 *
 * * `data` is a `length` sized array that will be written to.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 */
void wow_srp_tbc_header_crypto_encrypt(struct WowSrpTBCHeaderCrypto *header,
                                       uint8_t *data,
                                       uint16_t length,
                                       char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
/**
 * Decrypts the `data`.
 *
 * You must manually size the `data` to be the appropriate size.
 * For messages sent from the client this is `WOW_SRP_CLIENT_HEADER_LENGTH`,
 * and for messages sent from the server this is `WOW_SRP_TBC_SERVER_HEADER_LENGTH`.
 *
 * * `data` is a `length` sized array that will be written to.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 */
void wow_srp_tbc_header_crypto_decrypt(struct WowSrpTBCHeaderCrypto *header,
                                       uint8_t *data,
                                       uint16_t length,
                                       char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_TBC_HEADER)
/**
 * Free the `WowSrpTBCHeaderCrypto`.
 *
 * This must manually be done.
 */
void wow_srp_tbc_header_crypto_free(struct WowSrpTBCHeaderCrypto *header);
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
/**
 * Creates a proof seed.
 *
 * Can not be null.
 */
struct WowSrpVanillaProofSeed *wow_srp_vanilla_proof_seed_new(void);
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
/**
 * Returns the randomized seed value.
 *
 * Used in `CMD_AUTH_RECONNECT_CHALLENGE_Server`.
 */
uint32_t wow_srp_vanilla_proof_seed(const struct WowSrpVanillaProofSeed *seed, char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
/**
 * Converts the seed into a `WowSrpVanillaHeaderCrypto` for the client.
 *
 * * `username` is a null terminated string no longer than 16 characters.
 * * `session_key` is a `WOW_SRP_SESSION_KEY_LENGTH` array.
 * * `out_client_proof` is a `WOW_SRP_PROOF_LENGTH` array that will be written to.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 * * `WOW_SRP_ERROR_UTF8` if the username/password contains disallowed characters.
 * * `WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME` if the username/password contains disallowed characters.
 */
struct WowSrpVanillaHeaderCrypto *wow_srp_vanilla_proof_seed_into_client_header_crypto(struct WowSrpVanillaProofSeed *seed,
                                                                                       const char *username,
                                                                                       const uint8_t *session_key,
                                                                                       uint32_t server_seed,
                                                                                       uint8_t *out_client_proof,
                                                                                       char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
/**
 * Converts the seed into a `WowSrpVanillaHeaderCrypto` for the server.
 *
 * * `username` is a null terminated string no longer than 16 characters.
 * * `session_key` is a `WOW_SRP_SESSION_KEY_LENGTH` array.
 * * `client_proof` is a `WOW_SRP_PROOF_LENGTH` array.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 * * `WOW_SRP_ERROR_UTF8` if the username/password contains disallowed characters.
 * * `WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME` if the username/password contains disallowed characters.
 */
struct WowSrpVanillaHeaderCrypto *wow_srp_vanilla_proof_seed_into_server_header_crypto(struct WowSrpVanillaProofSeed *seed,
                                                                                       const char *username,
                                                                                       const uint8_t *session_key,
                                                                                       const uint8_t *client_proof,
                                                                                       uint32_t client_seed,
                                                                                       char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
/**
 * Frees the `WowSrpVanillaProofSeed`.
 *
 * This should not normally be called since `wow_srp_vanilla_proof_seed_into_vanilla_*` functions
 * free this object.
 */
void wow_srp_vanilla_proof_seed_free(struct WowSrpVanillaProofSeed *seed);
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
/**
 * Encrypts the `data`.
 *
 * You must manually size the `data` to be the appropriate size.
 * For messages sent from the client this is `WOW_SRP_CLIENT_HEADER_LENGTH`,
 * and for messages sent from the server this is `WOW_SRP_VANILLA_SERVER_HEADER_LENGTH`.
 *
 * * `data` is a `length` sized array that will be written to.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 */
void wow_srp_vanilla_header_crypto_encrypt(struct WowSrpVanillaHeaderCrypto *header,
                                           uint8_t *data,
                                           uint16_t length,
                                           char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
/**
 * Decrypts the `data`.
 *
 * You must manually size the `data` to be the appropriate size.
 * For messages sent from the client this is `WOW_SRP_CLIENT_HEADER_LENGTH`,
 * and for messages sent from the server this is `WOW_SRP_VANILLA_SERVER_HEADER_LENGTH`.
 *
 * * `data` is a `length` sized array that will be written to.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 */
void wow_srp_vanilla_header_crypto_decrypt(struct WowSrpVanillaHeaderCrypto *header,
                                           uint8_t *data,
                                           uint16_t length,
                                           char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_VANILLA_HEADER)
/**
 * Free the `WowSrpVanillaHeaderCrypto`.
 *
 * This must manually be done.
 */
void wow_srp_vanilla_header_crypto_free(struct WowSrpVanillaHeaderCrypto *header);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
/**
 * Creates a proof seed.
 *
 * Can not be null.
 */
struct WowSrpWrathProofSeed *wow_srp_wrath_proof_seed_new(void);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
/**
 * Returns the randomized seed value.
 *
 * Used in `CMD_AUTH_RECONNECT_CHALLENGE_Server`.
 */
uint32_t wow_srp_wrath_proof_seed(const struct WowSrpWrathProofSeed *seed, char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
/**
 * Converts the seed into a `WowSrpWrathHeaderCrypto` for the client.
 *
 * * `username` is a null terminated string no longer than 16 characters.
 * * `session_key` is a `WOW_SRP_SESSION_KEY_LENGTH` array.
 * * `out_client_proof` is a `WOW_SRP_PROOF_LENGTH` array that will be written to.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 * * `WOW_SRP_ERROR_UTF8` if the username/password contains disallowed characters.
 * * `WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME` if the username/password contains disallowed characters.
 */
struct WowSrpWrathClientCrypto *wow_srp_proof_seed_into_wrath_client_crypto(struct WowSrpWrathProofSeed *seed,
                                                                            const char *username,
                                                                            const uint8_t *session_key,
                                                                            uint32_t server_seed,
                                                                            uint8_t *out_client_proof,
                                                                            char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
/**
 * Converts the seed into a `WowSrpWrathHeaderCrypto` for the server.
 *
 * * `username` is a null terminated string no longer than 16 characters.
 * * `session_key` is a `WOW_SRP_SESSION_KEY_LENGTH` array.
 * * `client_proof` is a `WOW_SRP_PROOF_LENGTH` array.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 * * `WOW_SRP_ERROR_UTF8` if the username/password contains disallowed characters.
 * * `WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME` if the username/password contains disallowed characters.
 */
struct WowSrpWrathServerCrypto *wow_srp_proof_seed_into_wrath_server_crypto(struct WowSrpWrathProofSeed *seed,
                                                                            const char *username,
                                                                            const uint8_t *session_key,
                                                                            const uint8_t *client_proof,
                                                                            uint32_t client_seed,
                                                                            char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
/**
 * First step of header decryption for Wrath.
 *
 * Created through `wow_srp_wrath_proof_seed_new`.
 */
void wow_srp_wrath_proof_seed_free(struct WowSrpWrathProofSeed *seed);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
/**
 * Encrypts the `data`.
 *
 * You must manually size the `data` to be the appropriate size.
 * For messages sent from the server this is either
 * `WOW_SRP_WRATH_SERVER_MINIMUM_HEADER_LENGTH` or
 * `WOW_SRP_WRATH_SERVER_MAXIMUM_HEADER_LENGTH`, depending on if the first byte
 * has the `0x80` bit set.
 *
 * * `data` is a `length` sized array that will be written to.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 */
void wow_srp_wrath_server_crypto_encrypt(struct WowSrpWrathServerCrypto *header,
                                         uint8_t *data,
                                         uint16_t length,
                                         char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
/**
 * Decrypts the `data`.
 *
 * You must manually size the `data` to be the appropriate size.
 * For messages sent from the client this is `WOW_SRP_CLIENT_HEADER_LENGTH`.
 *
 * * `data` is a `length` sized array that will be written to.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 */
void wow_srp_wrath_server_crypto_decrypt(struct WowSrpWrathServerCrypto *header,
                                         uint8_t *data,
                                         uint16_t length,
                                         char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
/**
 * Free the `WowSrpWrathServerCrypto`.
 *
 * This must manually be done.
 */
void wow_srp_wrath_server_crypto_free(struct WowSrpWrathServerCrypto *header);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
/**
 * Encrypts the `data`.
 *
 * You must manually size the `data` to be the appropriate size.
 * For messages sent from the client this is `WOW_SRP_CLIENT_HEADER_LENGTH`.
 *
 * * `data` is a `length` sized array that will be written to.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 */
void wow_srp_wrath_client_crypto_encrypt(struct WowSrpWrathClientCrypto *header,
                                         uint8_t *data,
                                         uint16_t length,
                                         char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
/**
 * Decrypts the `data`.
 *
 * You must manually size the `data` to be the appropriate size.
 * For messages sent from the server this is either
 * `WOW_SRP_WRATH_SERVER_MINIMUM_HEADER_LENGTH` or
 * `WOW_SRP_WRATH_SERVER_MAXIMUM_HEADER_LENGTH`, depending on if the first byte
 * has the `0x80` bit set.
 *
 * * `data` is a `length` sized array that will be written to.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 */
void wow_srp_wrath_client_crypto_decrypt(struct WowSrpWrathClientCrypto *header,
                                         uint8_t *data,
                                         uint16_t length,
                                         char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_WRATH_HEADER)
/**
 * Free the `WowSrpWrathClientCrypto`.
 *
 * This must manually be done.
 */
void wow_srp_wrath_client_crypto_free(struct WowSrpWrathClientCrypto *header);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/**
 * Returns the server public key as a `WOW_SRP_KEY_LENGTH` sized array.
 *
 * This should be passed to the client through `CMD_AUTH_LOGON_CHALLENGE_Server`.
 *
 * Will return null if `proof` is null.
 */
const uint8_t *wow_srp_proof_server_public_key(const struct WowSrpProof *proof);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/**
 * Returns the salt as a `WOW_SRP_KEY_LENGTH` sized array.
 *
 * This should be passed to the client through `CMD_AUTH_LOGON_CHALLENGE_Server`.
 *
 * Will return null if `proof` is null.
 */
const uint8_t *wow_srp_proof_salt(const struct WowSrpProof *proof);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/**
 * Convert the `WowSrpProof` into a `WowSrpServer`.
 *
 * This should be called after receiving the client public key and proof from the client in
 * `CMD_AUTH_LOGON_PROOF_Client`.
 *
 * * `client_public_key` is a `WOW_SRP_KEY_LENGTH` array.
 * * `client_proof` is a `WOW_SRP_PROOF_LENGTH` array.
 * * `out_server_proof` is a `WOW_SRP_PROOF_LENGTH` array that will be written to.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 * * `WOW_SRP_ERROR_INVALID_PUBLIC_KEY` if the public key is invalid.
 * * `WOW_SRP_ERROR_PROOFS_DO_NOT_MATCH` if the client proof does not match the server proof.
 */
struct WowSrpServer *wow_srp_proof_into_server(struct WowSrpProof *proof,
                                               const uint8_t *client_public_key,
                                               const uint8_t *client_proof,
                                               uint8_t *out_server_proof,
                                               char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/**
 * Frees a `WowSrpProof`.
 *
 * This should not normally need to be called since `wow_srp_proof_into_server` will
 * free the proof.
 */
void wow_srp_proof_free(struct WowSrpProof *proof);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/**
 * Returns the session key as a `WOW_SRP_SESSION_KEY_LENGTH` sized array.
 *
 * This should be passed to the client through `CMD_AUTH_LOGON_CHALLENGE_Server`.
 *
 * Will return null if `proof` is null.
 */
const uint8_t *wow_srp_server_session_key(const struct WowSrpServer *server);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/**
 * Returns the reconnect data as a `WOW_SRP_RECONNECT_DATA_LENGTH` sized array.
 *
 * This should be passed to the client through `CMD_AUTH_RECONNECT_CHALLENGE_Server`.
 *
 * Will return null if `proof` is null.
 */
const uint8_t *wow_srp_server_reconnect_challenge_data(const struct WowSrpServer *server);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/**
 * Returns true if the client proof matches the server proof.
 *
 * * `client_data` is a `WOW_SRP_RECONNECT_DATA_LENGTH` length array.
 * * `client_proof` is a `WOW_SRP_PROOF_LENGTH` length array.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 * * `WOW_SRP_ERROR_PROOFS_DO_NOT_MATCH` if the client proof does not match the server proof.
 */
bool wow_srp_server_verify_reconnection_attempt(struct WowSrpServer *server,
                                                const uint8_t *client_data,
                                                const uint8_t *client_proof,
                                                char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/**
 * Frees a `WowSrpServer`.
 *
 * This must be called manually since no other function will free it.
 */
void wow_srp_server_free(struct WowSrpServer *server);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/**
 * Creates a `WowSrpVerifier` from a username and password.
 * This should only be used the very first time that a client authenticates.
 * The username, salt, and password verifier should be stored in the database for future lookup,
 * and `wow_srp_verifier_from_database_values` should then be called.
 *
 * * `username` is a null terminated string no longer than 16 characters.
 * * `password` is a null terminated string no longer than 16 characters.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 * * `WOW_SRP_ERROR_UTF8` if the username/password contains disallowed characters.
 * * `WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME` if the username/password contains disallowed characters.
 */
struct WowSrpVerifier *wow_srp_verifier_from_username_and_password(const char *username,
                                                                   const char *password,
                                                                   char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/**
 * Creates a `WowSrpVerifier` from a username, password verifier, and salt
 * previously generated from `wow_srp_verifier_from_username_and_password`.
 *
 * * `username` is a null terminated string no longer than 16 characters.
 * * `password_verifier` is a `WOW_SRP_KEY_LENGTH` array.
 * * `salt` is a `WOW_SRP_KEY_LENGTH` array.
 * * `out_error` is a pointer to a single `uint8_t` that will be written to.
 *
 * This function can return a null pointer, in which case errors will be in `out_error`.
 * It can return:
 * * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
 * * `WOW_SRP_ERROR_UTF8` if the username/password contains disallowed characters.
 * * `WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME` if the username/password contains disallowed characters.
 */
struct WowSrpVerifier *wow_srp_verifier_from_database_values(const char *username,
                                                             const uint8_t *password_verifier,
                                                             const uint8_t *salt,
                                                             char *out_error);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/**
 * Converts the `WowSrpVerifier` into a `WowSrpProof`.
 *
 * This ends the lifetime of the `WowSrpVerifier` and it must not be used again.
 *
 * Will return null if `verifier` is null.
 */
struct WowSrpProof *wow_srp_verifier_into_proof(struct WowSrpVerifier *verifier);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/**
 * Returns the salt as a `WOW_SRP_KEY_LENGTH` sized byte array.
 *
 * This should be stored in the database for future lookup.
 *
 * The lifetime of this is tied to the lifetime of the `WowSrpVerifier`.
 *
 * Will return null if `verifier` is null.
 */
const uint8_t *wow_srp_verifier_salt(const struct WowSrpVerifier *verifier);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/**
 * Returns the password verifier as a `WOW_SRP_KEY_LENGTH` sized byte array.
 *
 * This should be stored in the database for future lookup.
 *
 * The lifetime of this is tied to the lifetime of the `WowSrpVerifier`.
 *
 * Will return null if `verifier` is null.
 */
const uint8_t *wow_srp_verifier_password_verifier(const struct WowSrpVerifier *verifier);
#endif

#if !defined(WOW_SRP_DISABLE_SERVER)
/**
 * Frees a `WowSrpVerifier`.
 *
 * This should not normally need to be called since `wow_srp_verifier_into_proof` will
 * free the verifier.
 */
void wow_srp_verifier_free(struct WowSrpVerifier *verifier);
#endif

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
