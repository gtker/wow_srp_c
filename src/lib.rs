#[cfg(feature = "client")]
mod client;
mod header_crypto;
#[cfg(feature = "server")]
mod server;
mod util;

pub use values::*;

#[cfg(any(feature = "client", feature = "server"))]
mod values {
    use std::ffi::c_char;
    use wow_srp::LARGE_SAFE_PRIME_LITTLE_ENDIAN;

    /// Generator used by the server implementation.
    ///
    /// This must be provided to clients in order for them to use it.
    pub const WOW_SRP_GENERATOR: u8 = 7;

    pub const CLIENT_HEADER_LENGTH: u8 = 6;

    /// Large safe prime used by the server implementation.
    ///
    /// This must be provided to clients in order for them to use it.
    #[no_mangle]
    pub static WOW_SRP_LARGE_SAFE_PRIME_LITTLE_ENDIAN: [u8; 32] = LARGE_SAFE_PRIME_LITTLE_ENDIAN;

    pub const WOW_SRP_SUCCESS: c_char = 0;
    pub const WOW_SRP_ERROR_NULL_POINTER: c_char = 1;
    pub const WOW_SRP_ERROR_UTF8: c_char = 2;
    pub const WOW_SRP_ERROR_NON_ASCII: c_char = 3;
    pub const WOW_SRP_ERROR_INVALID_PUBLIC_KEY: c_char = 4;
    pub const WOW_SRP_ERROR_PROOFS_DO_NOT_MATCH: c_char = 5;
}
