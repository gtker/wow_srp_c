#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

/// Generator used by the server implementation.
///
/// This must be provided to clients in order for them to use it.
constexpr static const uint8_t WOW_SRP_GENERATOR = 7;

constexpr static const uint8_t CLIENT_HEADER_LENGTH = 6;

constexpr static const char WOW_SRP_SUCCESS = 0;

constexpr static const char WOW_SRP_ERROR_NULL_POINTER = 1;

constexpr static const char WOW_SRP_ERROR_UTF8 = 2;

constexpr static const char WOW_SRP_ERROR_NON_ASCII = 3;

constexpr static const char WOW_SRP_ERROR_INVALID_PUBLIC_KEY = 4;

constexpr static const char WOW_SRP_ERROR_PROOFS_DO_NOT_MATCH = 5;

struct WowSrpClient;

struct WowSrpClientChallenge;

struct WowSrpClientUser;

struct WowSrpProof;

struct WowSrpServer;

#if defined(WOW_SRP_TBC_HEADER)
struct WowSrpTbcHeaderCrypto;
#endif

#if defined(WOW_SRP_TBC_HEADER)
struct WowSrpTbcProofSeed;
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
struct WowSrpVanillaHeaderCrypto;
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
struct WowSrpVanillaProofSeed;
#endif

struct WowSrpVerifier;

#if defined(WOW_SRP_WRATH_HEADER)
struct WowSrpWrathClientCrypto;
#endif

#if defined(WOW_SRP_WRATH_HEADER)
struct WowSrpWrathProofSeed;
#endif

#if defined(WOW_SRP_WRATH_HEADER)
struct WowSrpWrathServerCrypto;
#endif

extern "C" {

extern const uint8_t WOW_SRP_LARGE_SAFE_PRIME_LITTLE_ENDIAN[32];

void wow_srp_client_free(WowSrpClient *client);

const uint8_t *wow_srp_client_session_key(WowSrpClient *client);

void wow_srp_client_calculate_reconnect_values(WowSrpClient *client,
                                               const uint8_t *server_challenge_data,
                                               uint8_t *out_client_challenge_data,
                                               uint8_t *out_client_proof,
                                               char *out_error);

void wow_srp_client_challenge_free(WowSrpClientChallenge *client_challenge);

const uint8_t *wow_srp_client_challenge_client_proof(WowSrpClientChallenge *client_challenge);

const uint8_t *wow_srp_client_challenge_client_public_key(WowSrpClientChallenge *client_challenge);

WowSrpClient *wow_srp_client_challenge_verify_server_proof(WowSrpClientChallenge *client_challenge,
                                                           const uint8_t *server_proof,
                                                           char *out_error);

WowSrpClientUser *wow_srp_client_user_from_username_and_password(const char *username,
                                                                 const char *password,
                                                                 char *out_error);

WowSrpClientChallenge *wow_srp_client_user_into_challenge(WowSrpClientUser *client_user,
                                                          uint8_t generator,
                                                          const uint8_t *large_safe_prime,
                                                          const uint8_t *server_public_key,
                                                          const uint8_t *salt,
                                                          char *out_error);

#if defined(WOW_SRP_TBC_HEADER)
void wow_srp_tbc_proof_seed_free(WowSrpTbcProofSeed *seed);
#endif

#if defined(WOW_SRP_TBC_HEADER)
WowSrpTbcProofSeed *wow_srp_tbc_proof_seed_new();
#endif

#if defined(WOW_SRP_TBC_HEADER)
uint32_t wow_srp_tbc_proof_seed(const WowSrpTbcProofSeed *seed, char *out_error);
#endif

#if defined(WOW_SRP_TBC_HEADER)
WowSrpTbcHeaderCrypto *wow_srp_proof_seed_into_tbc_client_header_crypto(WowSrpTbcProofSeed *seed,
                                                                        const char *username,
                                                                        const uint8_t *session_key,
                                                                        uint32_t server_seed,
                                                                        uint8_t *out_client_proof,
                                                                        char *out_error);
#endif

#if defined(WOW_SRP_TBC_HEADER)
WowSrpTbcHeaderCrypto *wow_srp_proof_seed_into_tbc_server_header_crypto(WowSrpTbcProofSeed *seed,
                                                                        const char *username,
                                                                        const uint8_t *session_key,
                                                                        const uint8_t *client_proof,
                                                                        uint32_t client_seed,
                                                                        char *out_error);
#endif

#if defined(WOW_SRP_TBC_HEADER)
void wow_srp_tbc_header_crypto_free(WowSrpTbcHeaderCrypto *header);
#endif

#if defined(WOW_SRP_TBC_HEADER)
void wow_srp_tbc_header_crypto_encrypt(WowSrpTbcHeaderCrypto *header,
                                       uint8_t *data,
                                       uint16_t length,
                                       char *out_error);
#endif

#if defined(WOW_SRP_TBC_HEADER)
void wow_srp_tbc_header_crypto_decrypt(WowSrpTbcHeaderCrypto *header,
                                       uint8_t *data,
                                       uint16_t length,
                                       char *out_error);
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
void wow_srp_vanilla_proof_seed_free(WowSrpVanillaProofSeed *seed);
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
WowSrpVanillaProofSeed *wow_srp_vanilla_proof_seed_new();
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
uint32_t wow_srp_vanilla_proof_seed(const WowSrpVanillaProofSeed *seed, char *out_error);
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
WowSrpVanillaHeaderCrypto *wow_srp_proof_seed_into_vanilla_client_header_crypto(WowSrpVanillaProofSeed *seed,
                                                                                const char *username,
                                                                                const uint8_t *session_key,
                                                                                uint32_t server_seed,
                                                                                uint8_t *out_client_proof,
                                                                                char *out_error);
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
WowSrpVanillaHeaderCrypto *wow_srp_proof_seed_into_vanilla_server_header_crypto(WowSrpVanillaProofSeed *seed,
                                                                                const char *username,
                                                                                const uint8_t *session_key,
                                                                                const uint8_t *client_proof,
                                                                                uint32_t client_seed,
                                                                                char *out_error);
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
void wow_srp_vanilla_header_crypto_free(WowSrpVanillaHeaderCrypto *header);
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
void wow_srp_vanilla_header_crypto_encrypt(WowSrpVanillaHeaderCrypto *header,
                                           uint8_t *data,
                                           uint16_t length,
                                           char *out_error);
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
void wow_srp_vanilla_header_crypto_decrypt(WowSrpVanillaHeaderCrypto *header,
                                           uint8_t *data,
                                           uint16_t length,
                                           char *out_error);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
void wow_srp_wrath_proof_seed_free(WowSrpWrathProofSeed *seed);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
WowSrpWrathProofSeed *wow_srp_wrath_proof_seed_new();
#endif

#if defined(WOW_SRP_WRATH_HEADER)
uint32_t wow_srp_wrath_proof_seed(const WowSrpWrathProofSeed *seed, char *out_error);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
WowSrpWrathClientCrypto *wow_srp_proof_seed_into_wrath_client_crypto(WowSrpWrathProofSeed *seed,
                                                                     const char *username,
                                                                     const uint8_t *session_key,
                                                                     uint32_t server_seed,
                                                                     uint8_t *out_client_proof,
                                                                     char *out_error);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
WowSrpWrathServerCrypto *wow_srp_proof_seed_into_wrath_server_crypto(WowSrpWrathProofSeed *seed,
                                                                     const char *username,
                                                                     const uint8_t *session_key,
                                                                     const uint8_t *client_proof,
                                                                     uint32_t client_seed,
                                                                     char *out_error);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
void wow_srp_wrath_server_crypto_free(WowSrpWrathServerCrypto *header);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
void wow_srp_wrath_server_crypto_encrypt(WowSrpWrathServerCrypto *header,
                                         uint8_t *data,
                                         uint16_t length,
                                         char *out_error);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
void wow_srp_wrath_server_crypto_decrypt(WowSrpWrathServerCrypto *header,
                                         uint8_t *data,
                                         uint16_t length,
                                         char *out_error);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
void wow_srp_wrath_client_crypto_free(WowSrpWrathClientCrypto *header);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
void wow_srp_wrath_client_crypto_encrypt(WowSrpWrathClientCrypto *header,
                                         uint8_t *data,
                                         uint16_t length,
                                         char *out_error);
#endif

#if defined(WOW_SRP_WRATH_HEADER)
void wow_srp_wrath_client_crypto_decrypt(WowSrpWrathClientCrypto *header,
                                         uint8_t *data,
                                         uint16_t length,
                                         char *out_error);
#endif

void wow_srp_proof_free(WowSrpProof *proof);

const uint8_t *wow_srp_proof_server_public_key(const WowSrpProof *proof);

const uint8_t *wow_srp_proof_salt(const WowSrpProof *proof);

WowSrpServer *wow_srp_proof_into_server(WowSrpProof *proof,
                                        const uint8_t *client_public_key,
                                        const uint8_t *client_proof,
                                        uint8_t *out_server_proof,
                                        char *out_error);

void wow_srp_server_free(WowSrpServer *server);

const uint8_t *wow_srp_server_session_key(const WowSrpServer *server);

const uint8_t *wow_srp_server_reconnect_challenge_data(const WowSrpServer *server);

bool wow_srp_server_verify_reconnection_attempt(WowSrpServer *server,
                                                const uint8_t *client_data,
                                                const uint8_t *client_proof,
                                                char *out_error);

WowSrpVerifier *wow_srp_verifier_from_username_and_password(const char *username,
                                                            const char *password,
                                                            char *out_error);

WowSrpVerifier *wow_srp_verifier_from_database_values(const char *username,
                                                      const uint8_t *password_verifier,
                                                      const uint8_t *salt,
                                                      char *out_error);

WowSrpProof *wow_srp_verifier_into_proof(WowSrpVerifier *verifier);

const uint8_t *wow_srp_verifier_salt(const WowSrpVerifier *verifier);

const uint8_t *wow_srp_verifier_password_verifier(const WowSrpVerifier *verifier);

void wow_srp_verifier_free(WowSrpVerifier *verifier);

} // extern "C"
