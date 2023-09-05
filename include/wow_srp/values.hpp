#include <cstdint>

constexpr static const uint8_t CLIENT_HEADER_LENGTH = 6;


/// Length of the password verifier returned by `wow_srp_verifier_password_verifier` in bytes.
///
/// `wow_srp` does not support keys of a smaller size than size.
constexpr static const uint8_t WOW_SRP_KEY_LENGTH = 32;


/// Length of the session keys produced in bytes.
constexpr static const uint8_t WOW_SRP_SESSION_KEY_LENGTH = 40;


/// Length of the proofs produced and used in bytes.
constexpr static const uint8_t WOW_SRP_PROOF_LENGTH = 40;


/// Length of the reconnect data used in bytes.
constexpr static const uint8_t WOW_SRP_RECONNECT_DATA_LENGTH = 40;


/// Generator used by the server implementation.
///
/// This should be passed to the client through `CMD_AUTH_LOGON_CHALLENGE_Server`.
constexpr static const uint8_t WOW_SRP_GENERATOR = 7;


/// Used by `out_error` to signify that everything went well.
/// You should initialize your `out_error` variable to this since
/// the variable will not be set to explicit success.
constexpr static const char WOW_SRP_SUCCESS = 0;


/// Used by `out_error` to signify that one of the required parameters was null.
///
/// If `out_error` is null errors will not be written.
constexpr static const char WOW_SRP_ERROR_NULL_POINTER = 1;


/// Used by `out_error` to signify that the input string was not valid UTF-8.
constexpr static const char WOW_SRP_ERROR_UTF8 = 2;


/// Used by `out_error` to signify that the username or password string contained disallowed values.
constexpr static const char WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME = 3;


/// Used by `out_error` to signify that the public key was invalid.
constexpr static const char WOW_SRP_ERROR_INVALID_PUBLIC_KEY = 4;


/// Used by `out_error` to signify that the client and server proofs did not match.
constexpr static const char WOW_SRP_ERROR_PROOFS_DO_NOT_MATCH = 5;


extern "C" {
extern const uint8_t WOW_SRP_LARGE_SAFE_PRIME_LITTLE_ENDIAN[32];
} // extern "C"