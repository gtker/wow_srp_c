#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

constexpr static const uint8_t CLIENT_HEADER_LENGTH = 6;

#if defined(WOW_SRP_TBC_HEADER)
constexpr static const uint8_t TBC_SERVER_HEADER_LENGTH = 4;
#endif

#if defined(WOW_SRP_VANILLA_HEADER)
constexpr static const uint8_t VANILLA_SERVER_HEADER_LENGTH = 4;
#endif

#if defined(WOW_SRP_WRATH_HEADER)
constexpr static const uint8_t WRATH_SERVER_HEADER_MINIMUM_LENGTH = 4;
#endif

#if defined(WOW_SRP_WRATH_HEADER)
constexpr static const uint8_t WRATH_SERVER_HEADER_MAXIMUM_LENGTH = 5;
#endif

#if (defined(WOW_SRP_CLIENT) || defined(WOW_SRP_SERVER))
/// Generator used by the server implementation.
///
/// This must be provided to clients in order for them to use it.
constexpr static const uint8_t WOW_SRP_GENERATOR = 7;
#endif

#if (defined(WOW_SRP_CLIENT) || defined(WOW_SRP_SERVER))
constexpr static const char WOW_SRP_SUCCESS = 0;
#endif

#if (defined(WOW_SRP_CLIENT) || defined(WOW_SRP_SERVER))
constexpr static const char WOW_SRP_ERROR_NULL_POINTER = 1;
#endif

#if (defined(WOW_SRP_CLIENT) || defined(WOW_SRP_SERVER))
constexpr static const char WOW_SRP_ERROR_UTF8 = 2;
#endif

#if (defined(WOW_SRP_CLIENT) || defined(WOW_SRP_SERVER))
constexpr static const char WOW_SRP_ERROR_NON_ASCII = 3;
#endif

#if (defined(WOW_SRP_CLIENT) || defined(WOW_SRP_SERVER))
constexpr static const char WOW_SRP_ERROR_INVALID_PUBLIC_KEY = 4;
#endif

#if (defined(WOW_SRP_CLIENT) || defined(WOW_SRP_SERVER))
constexpr static const char WOW_SRP_ERROR_PROOFS_DO_NOT_MATCH = 5;
#endif

#if defined(WOW_SRP_CLIENT)
struct WowSrpClient;
#endif

#if defined(WOW_SRP_CLIENT)
struct WowSrpClientChallenge;
#endif

#if defined(WOW_SRP_CLIENT)
struct WowSrpClientUser;
#endif

#if defined(WOW_SRP_SERVER)
struct WowSrpProof;
#endif

#if defined(WOW_SRP_SERVER)
struct WowSrpServer;
#endif

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

#if defined(WOW_SRP_SERVER)
struct WowSrpVerifier;
#endif

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

#if defined(WOW_SRP_CLIENT)
void wow_srp_client_free(WowSrpClient *client);
#endif

#if defined(WOW_SRP_CLIENT)
const uint8_t *wow_srp_client_session_key(WowSrpClient *client);
#endif

#if defined(WOW_SRP_CLIENT)
void wow_srp_client_calculate_reconnect_values(WowSrpClient *client,
                                               const uint8_t *server_challenge_data,
                                               uint8_t *out_client_challenge_data,
                                               uint8_t *out_client_proof,
                                               char *out_error);
#endif

#if defined(WOW_SRP_CLIENT)
void wow_srp_client_challenge_free(WowSrpClientChallenge *client_challenge);
#endif

#if defined(WOW_SRP_CLIENT)
const uint8_t *wow_srp_client_challenge_client_proof(WowSrpClientChallenge *client_challenge);
#endif

#if defined(WOW_SRP_CLIENT)
const uint8_t *wow_srp_client_challenge_client_public_key(WowSrpClientChallenge *client_challenge);
#endif

#if defined(WOW_SRP_CLIENT)
WowSrpClient *wow_srp_client_challenge_verify_server_proof(WowSrpClientChallenge *client_challenge,
                                                           const uint8_t *server_proof,
                                                           char *out_error);
#endif

#if defined(WOW_SRP_CLIENT)
WowSrpClientUser *wow_srp_client_user_from_username_and_password(const char *username,
                                                                 const char *password,
                                                                 char *out_error);
#endif

#if defined(WOW_SRP_CLIENT)
WowSrpClientChallenge *wow_srp_client_user_into_challenge(WowSrpClientUser *client_user,
                                                          uint8_t generator,
                                                          const uint8_t *large_safe_prime,
                                                          const uint8_t *server_public_key,
                                                          const uint8_t *salt,
                                                          char *out_error);
#endif

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

#if defined(WOW_SRP_SERVER)
void wow_srp_proof_free(WowSrpProof *proof);
#endif

#if defined(WOW_SRP_SERVER)
const uint8_t *wow_srp_proof_server_public_key(const WowSrpProof *proof);
#endif

#if defined(WOW_SRP_SERVER)
const uint8_t *wow_srp_proof_salt(const WowSrpProof *proof);
#endif

#if defined(WOW_SRP_SERVER)
WowSrpServer *wow_srp_proof_into_server(WowSrpProof *proof,
                                        const uint8_t *client_public_key,
                                        const uint8_t *client_proof,
                                        uint8_t *out_server_proof,
                                        char *out_error);
#endif

#if defined(WOW_SRP_SERVER)
void wow_srp_server_free(WowSrpServer *server);
#endif

#if defined(WOW_SRP_SERVER)
const uint8_t *wow_srp_server_session_key(const WowSrpServer *server);
#endif

#if defined(WOW_SRP_SERVER)
const uint8_t *wow_srp_server_reconnect_challenge_data(const WowSrpServer *server);
#endif

#if defined(WOW_SRP_SERVER)
bool wow_srp_server_verify_reconnection_attempt(WowSrpServer *server,
                                                const uint8_t *client_data,
                                                const uint8_t *client_proof,
                                                char *out_error);
#endif

#if defined(WOW_SRP_SERVER)
WowSrpVerifier *wow_srp_verifier_from_username_and_password(const char *username,
                                                            const char *password,
                                                            char *out_error);
#endif

#if defined(WOW_SRP_SERVER)
WowSrpVerifier *wow_srp_verifier_from_database_values(const char *username,
                                                      const uint8_t *password_verifier,
                                                      const uint8_t *salt,
                                                      char *out_error);
#endif

#if defined(WOW_SRP_SERVER)
WowSrpProof *wow_srp_verifier_into_proof(WowSrpVerifier *verifier);
#endif

#if defined(WOW_SRP_SERVER)
const uint8_t *wow_srp_verifier_salt(const WowSrpVerifier *verifier);
#endif

#if defined(WOW_SRP_SERVER)
const uint8_t *wow_srp_verifier_password_verifier(const WowSrpVerifier *verifier);
#endif

#if defined(WOW_SRP_SERVER)
void wow_srp_verifier_free(WowSrpVerifier *verifier);
#endif

} // extern "C"
