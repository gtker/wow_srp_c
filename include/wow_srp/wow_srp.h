#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Generator used by the server implementation.
 *
 * This must be provided to clients in order for them to use it.
 */
#define WOW_SRP_GENERATOR 7

#define CLIENT_HEADER_LENGTH 6

#define WOW_SRP_SUCCESS 0

#define WOW_SRP_ERROR_NULL_POINTER 1

#define WOW_SRP_ERROR_UTF8 2

#define WOW_SRP_ERROR_NON_ASCII 3

#define WOW_SRP_ERROR_INVALID_PUBLIC_KEY 4

#define WOW_SRP_ERROR_PROOFS_DO_NOT_MATCH 5

typedef struct WowSrpClient WowSrpClient;

typedef struct WowSrpClientChallenge WowSrpClientChallenge;

typedef struct WowSrpClientUser WowSrpClientUser;

typedef struct WowSrpProof WowSrpProof;

typedef struct WowSrpServer WowSrpServer;

#if defined(WOW_SRP_TBC_HEADER)
typedef struct WowSrpTbcHeaderCrypto WowSrpTbcHeaderCrypto;
#endif

#if defined(WOW_SRP_TBC_HEADER)
typedef struct WowSrpTbcProofSeed WowSrpTbcProofSeed;
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
typedef struct WowSrpVanillaHeaderCrypto WowSrpVanillaHeaderCrypto;
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
typedef struct WowSrpVanillaProofSeed WowSrpVanillaProofSeed;
#endif

typedef struct WowSrpVerifier WowSrpVerifier;

#if defined(WOW_SRP_WRATH_HEADER)
typedef struct WowSrpWrathClientCrypto WowSrpWrathClientCrypto;
#endif

#if defined(WOW_SRP_WRATH_HEADER)
typedef struct WowSrpWrathProofSeed WowSrpWrathProofSeed;
#endif

#if defined(WOW_SRP_WRATH_HEADER)
typedef struct WowSrpWrathServerCrypto WowSrpWrathServerCrypto;
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

extern const uint8_t WOW_SRP_LARGE_SAFE_PRIME_LITTLE_ENDIAN[32];

void wow_srp_client_free(struct WowSrpClient *client);

const uint8_t *wow_srp_client_session_key(struct WowSrpClient *client);

void wow_srp_client_calculate_reconnect_values(struct WowSrpClient *client,
                                               const uint8_t *server_challenge_data,
                                               uint8_t *out_client_challenge_data,
                                               uint8_t *out_client_proof,
                                               char *out_error);

void wow_srp_client_challenge_free(struct WowSrpClientChallenge *client_challenge);

const uint8_t *wow_srp_client_challenge_client_proof(struct WowSrpClientChallenge *client_challenge);

const uint8_t *wow_srp_client_challenge_client_public_key(struct WowSrpClientChallenge *client_challenge);

struct WowSrpClient *wow_srp_client_challenge_verify_server_proof(struct WowSrpClientChallenge *client_challenge,
                                                                  const uint8_t *server_proof,
                                                                  char *out_error);

struct WowSrpClientUser *wow_srp_client_user_from_username_and_password(const char *username,
                                                                        const char *password,
                                                                        char *out_error);

struct WowSrpClientChallenge *wow_srp_client_user_into_challenge(struct WowSrpClientUser *client_user,
                                                                 uint8_t generator,
                                                                 const uint8_t *large_safe_prime,
                                                                 const uint8_t *server_public_key,
                                                                 const uint8_t *salt,
                                                                 char *out_error);

#if defined(WOW_SRP_TBC_HEADER)
void wow_srp_tbc_proof_seed_free(struct WowSrpTbcProofSeed *seed);
#endif

#if defined(WOW_SRP_TBC_HEADER)
struct WowSrpTbcProofSeed *wow_srp_tbc_proof_seed_new(void);
#endif

#if defined(WOW_SRP_TBC_HEADER)
uint32_t wow_srp_tbc_proof_seed(const struct WowSrpTbcProofSeed *seed, char *out_error);
#endif

#if defined(WOW_SRP_TBC_HEADER)
struct WowSrpTbcHeaderCrypto *wow_srp_proof_seed_into_tbc_client_header_crypto(struct WowSrpTbcProofSeed *seed,
                                                                               const char *username,
                                                                               const uint8_t *session_key,
                                                                               uint32_t server_seed,
                                                                               uint8_t *out_client_proof,
                                                                               char *out_error);
#endif

#if defined(WOW_SRP_TBC_HEADER)
struct WowSrpTbcHeaderCrypto *wow_srp_proof_seed_into_tbc_server_header_crypto(struct WowSrpTbcProofSeed *seed,
                                                                               const char *username,
                                                                               const uint8_t *session_key,
                                                                               const uint8_t *client_proof,
                                                                               uint32_t client_seed,
                                                                               char *out_error);
#endif

#if defined(WOW_SRP_TBC_HEADER)
void wow_srp_tbc_header_crypto_free(struct WowSrpTbcHeaderCrypto *header);
#endif

#if defined(WOW_SRP_TBC_HEADER)
void wow_srp_tbc_header_crypto_encrypt(struct WowSrpTbcHeaderCrypto *header,
                                       uint8_t *data,
                                       uint16_t length,
                                       char *out_error);
#endif

#if defined(WOW_SRP_TBC_HEADER)
void wow_srp_tbc_header_crypto_decrypt(struct WowSrpTbcHeaderCrypto *header,
                                       uint8_t *data,
                                       uint16_t length,
                                       char *out_error);
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
void wow_srp_vanilla_proof_seed_free(struct WowSrpVanillaProofSeed *seed);
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
struct WowSrpVanillaProofSeed *wow_srp_vanilla_proof_seed_new(void);
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
uint32_t wow_srp_vanilla_proof_seed(const struct WowSrpVanillaProofSeed *seed, char *out_error);
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
struct WowSrpVanillaHeaderCrypto *wow_srp_proof_seed_into_vanilla_client_header_crypto(struct WowSrpVanillaProofSeed *seed,
                                                                                       const char *username,
                                                                                       const uint8_t *session_key,
                                                                                       uint32_t server_seed,
                                                                                       uint8_t *out_client_proof,
                                                                                       char *out_error);
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
struct WowSrpVanillaHeaderCrypto *wow_srp_proof_seed_into_vanilla_server_header_crypto(struct WowSrpVanillaProofSeed *seed,
                                                                                       const char *username,
                                                                                       const uint8_t *session_key,
                                                                                       const uint8_t *client_proof,
                                                                                       uint32_t client_seed,
                                                                                       char *out_error);
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
void wow_srp_vanilla_header_crypto_free(struct WowSrpVanillaHeaderCrypto *header);
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
void wow_srp_vanilla_header_crypto_encrypt(struct WowSrpVanillaHeaderCrypto *header,
                                           uint8_t *data,
                                           uint16_t length,
                                           char *out_error);
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
void wow_srp_vanilla_header_crypto_decrypt(struct WowSrpVanillaHeaderCrypto *header,
                                           uint8_t *data,
                                           uint16_t length,
                                           char *out_error);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
void wow_srp_wrath_proof_seed_free(struct WowSrpWrathProofSeed *seed);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
struct WowSrpWrathProofSeed *wow_srp_wrath_proof_seed_new(void);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
uint32_t wow_srp_wrath_proof_seed(const struct WowSrpWrathProofSeed *seed, char *out_error);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
struct WowSrpWrathClientCrypto *wow_srp_proof_seed_into_wrath_client_crypto(struct WowSrpWrathProofSeed *seed,
                                                                            const char *username,
                                                                            const uint8_t *session_key,
                                                                            uint32_t server_seed,
                                                                            uint8_t *out_client_proof,
                                                                            char *out_error);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
struct WowSrpWrathServerCrypto *wow_srp_proof_seed_into_wrath_server_crypto(struct WowSrpWrathProofSeed *seed,
                                                                            const char *username,
                                                                            const uint8_t *session_key,
                                                                            const uint8_t *client_proof,
                                                                            uint32_t client_seed,
                                                                            char *out_error);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
void wow_srp_wrath_server_crypto_free(struct WowSrpWrathServerCrypto *header);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
void wow_srp_wrath_server_crypto_encrypt(struct WowSrpWrathServerCrypto *header,
                                         uint8_t *data,
                                         uint16_t length,
                                         char *out_error);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
void wow_srp_wrath_server_crypto_decrypt(struct WowSrpWrathServerCrypto *header,
                                         uint8_t *data,
                                         uint16_t length,
                                         char *out_error);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
void wow_srp_wrath_client_crypto_free(struct WowSrpWrathClientCrypto *header);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
void wow_srp_wrath_client_crypto_encrypt(struct WowSrpWrathClientCrypto *header,
                                         uint8_t *data,
                                         uint16_t length,
                                         char *out_error);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
void wow_srp_wrath_client_crypto_decrypt(struct WowSrpWrathClientCrypto *header,
                                         uint8_t *data,
                                         uint16_t length,
                                         char *out_error);
#endif

void wow_srp_proof_free(struct WowSrpProof *proof);

const uint8_t *wow_srp_proof_server_public_key(const struct WowSrpProof *proof);

const uint8_t *wow_srp_proof_salt(const struct WowSrpProof *proof);

struct WowSrpServer *wow_srp_proof_into_server(struct WowSrpProof *proof,
                                               const uint8_t *client_public_key,
                                               const uint8_t *client_proof,
                                               uint8_t *out_server_proof,
                                               char *out_error);

void wow_srp_server_free(struct WowSrpServer *server);

const uint8_t *wow_srp_server_session_key(const struct WowSrpServer *server);

const uint8_t *wow_srp_server_reconnect_challenge_data(const struct WowSrpServer *server);

bool wow_srp_server_verify_reconnection_attempt(struct WowSrpServer *server,
                                                const uint8_t *client_data,
                                                const uint8_t *client_proof,
                                                char *out_error);

struct WowSrpVerifier *wow_srp_verifier_from_username_and_password(const char *username,
                                                                   const char *password,
                                                                   char *out_error);

struct WowSrpVerifier *wow_srp_verifier_from_database_values(const char *username,
                                                             const uint8_t *password_verifier,
                                                             const uint8_t *salt,
                                                             char *out_error);

struct WowSrpProof *wow_srp_verifier_into_proof(struct WowSrpVerifier *verifier);

const uint8_t *wow_srp_verifier_salt(const struct WowSrpVerifier *verifier);

const uint8_t *wow_srp_verifier_password_verifier(const struct WowSrpVerifier *verifier);

void wow_srp_verifier_free(struct WowSrpVerifier *verifier);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
