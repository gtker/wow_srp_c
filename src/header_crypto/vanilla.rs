use crate::util::is_null_mut;
use crate::util::{
    char_ptr_to_string, free_box_ptr, is_null, read_array, retake_ownership, write_array,
    write_error,
};
use crate::WOW_SRP_ERROR_PROOFS_DO_NOT_MATCH;
use std::ffi::c_char;
use wow_srp::vanilla_header::HeaderCrypto as HeaderCryptoInner;
use wow_srp::vanilla_header::ProofSeed as ProofSeedInner;

pub const VANILLA_SERVER_HEADER_LENGTH: u8 = 4;

pub struct WowSrpVanillaProofSeed(ProofSeedInner);

#[no_mangle]
pub extern "C" fn wow_srp_vanilla_proof_seed_free(seed: *mut WowSrpVanillaProofSeed) {
    free_box_ptr(seed)
}

#[no_mangle]
pub extern "C" fn wow_srp_vanilla_proof_seed_new() -> *mut WowSrpVanillaProofSeed {
    let seed = Box::new(WowSrpVanillaProofSeed(ProofSeedInner::new()));

    Box::into_raw(seed)
}

#[no_mangle]
pub extern "C" fn wow_srp_vanilla_proof_seed(
    seed: *const WowSrpVanillaProofSeed,
    out_error: *mut c_char,
) -> u32 {
    let Some(seed) = is_null(seed, out_error) else {
        return 0;
    };

    seed.0.seed()
}

#[no_mangle]
pub extern "C" fn wow_srp_proof_seed_into_vanilla_client_header_crypto(
    seed: *mut WowSrpVanillaProofSeed,
    username: *const c_char,
    session_key: *const u8,
    server_seed: u32,
    out_client_proof: *mut u8,
    out_error: *mut c_char,
) -> *mut WowSrpVanillaHeaderCrypto {
    let Some(seed) = retake_ownership(seed, out_error) else {
        return std::ptr::null_mut();
    };

    let Some(username) = char_ptr_to_string(username, out_error) else {
        return std::ptr::null_mut();
    };

    let Some(session_key) = read_array(session_key, out_error) else {
        return std::ptr::null_mut();
    };

    let (client_proof, header_crypto) =
        (*seed)
            .0
            .into_proof_and_header_crypto(&username, session_key, server_seed);

    write_array(out_client_proof, client_proof.as_slice());

    let header_crypto = Box::new(WowSrpVanillaHeaderCrypto::new(header_crypto));

    Box::into_raw(header_crypto)
}

#[no_mangle]
pub extern "C" fn wow_srp_proof_seed_into_vanilla_server_header_crypto(
    seed: *mut WowSrpVanillaProofSeed,
    username: *const c_char,
    session_key: *const u8,
    client_proof: *const u8,
    client_seed: u32,
    out_error: *mut c_char,
) -> *mut WowSrpVanillaHeaderCrypto {
    let Some(seed) = retake_ownership(seed, out_error) else {
        return std::ptr::null_mut();
    };

    let Some(username) = char_ptr_to_string(username, out_error) else {
        return std::ptr::null_mut();
    };

    let Some(session_key) = read_array(session_key, out_error) else {
        return std::ptr::null_mut();
    };

    let Some(client_proof) = read_array(client_proof, out_error) else {
        return std::ptr::null_mut();
    };

    let Ok(header) =
        (*seed)
            .0
            .into_header_crypto(&username, session_key, client_proof, client_seed)
    else {
        write_error(out_error, WOW_SRP_ERROR_PROOFS_DO_NOT_MATCH);
        return std::ptr::null_mut();
    };

    let header_crypto = Box::new(WowSrpVanillaHeaderCrypto::new(header));

    Box::into_raw(header_crypto)
}

pub struct WowSrpVanillaHeaderCrypto(HeaderCryptoInner);

impl WowSrpVanillaHeaderCrypto {
    pub fn new(inner: HeaderCryptoInner) -> Self {
        Self(inner)
    }
}

#[no_mangle]
pub extern "C" fn wow_srp_vanilla_header_crypto_free(header: *mut WowSrpVanillaHeaderCrypto) {
    free_box_ptr(header)
}

#[no_mangle]
pub extern "C" fn wow_srp_vanilla_header_crypto_encrypt(
    header: *mut WowSrpVanillaHeaderCrypto,
    data: *mut u8,
    length: u16,
    out_error: *mut c_char,
) {
    if length == 0 {
        return;
    }

    let Some(header) = is_null_mut(header, out_error) else {
        return;
    };

    let data = unsafe { std::slice::from_raw_parts_mut(data, length.into()) };

    header.0.encrypt(data);
}

#[no_mangle]
pub extern "C" fn wow_srp_vanilla_header_crypto_decrypt(
    header: *mut WowSrpVanillaHeaderCrypto,
    data: *mut u8,
    length: u16,
    out_error: *mut c_char,
) {
    if length == 0 {
        return;
    }

    let Some(header) = is_null_mut(header, out_error) else {
        return;
    };

    let data = unsafe { std::slice::from_raw_parts_mut(data, length.into()) };

    header.0.decrypt(data);
}
