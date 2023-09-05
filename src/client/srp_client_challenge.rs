use crate::client::srp_client::WowSrpClient;
use crate::util::{free_box_ptr, is_null, read_array, retake_ownership, write_error};
use crate::WOW_SRP_ERROR_PROOFS_DO_NOT_MATCH;
use std::ffi::c_char;
use wow_srp::client::SrpClientChallenge as SrpClientChallengeInner;

pub struct WowSrpClientChallenge(SrpClientChallengeInner);

impl WowSrpClientChallenge {
    pub(crate) fn new(inner: SrpClientChallengeInner) -> Self {
        Self(inner)
    }
}

#[no_mangle]
pub extern "C" fn wow_srp_client_challenge_free(client_challenge: *mut WowSrpClientChallenge) {
    free_box_ptr(client_challenge)
}

#[no_mangle]
pub extern "C" fn wow_srp_client_challenge_client_proof(
    client_challenge: *mut WowSrpClientChallenge,
) -> *const u8 {
    let Some(server) = is_null(client_challenge, std::ptr::null_mut()) else {
        return std::ptr::null();
    };

    server.0.client_proof() as *const u8
}

#[no_mangle]
pub extern "C" fn wow_srp_client_challenge_client_public_key(
    client_challenge: *mut WowSrpClientChallenge,
) -> *const u8 {
    let Some(server) = is_null(client_challenge, std::ptr::null_mut()) else {
        return std::ptr::null();
    };

    server.0.client_public_key() as *const u8
}

#[no_mangle]
pub extern "C" fn wow_srp_client_challenge_verify_server_proof(
    client_challenge: *mut WowSrpClientChallenge,
    server_proof: *const u8,
    out_error: *mut c_char,
) -> *mut WowSrpClient {
    let Some(server_proof) = read_array(server_proof, out_error) else {
        return std::ptr::null_mut();
    };

    let Some(client_challenge) = retake_ownership(client_challenge, out_error) else {
        return std::ptr::null_mut();
    };

    let Ok(client) = (*client_challenge).0.verify_server_proof(server_proof) else {
        write_error(out_error, WOW_SRP_ERROR_PROOFS_DO_NOT_MATCH);
        return std::ptr::null_mut();
    };

    let client = WowSrpClient::new(client);
    let client = Box::new(client);

    Box::into_raw(client)
}
