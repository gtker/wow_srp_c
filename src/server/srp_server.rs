use crate::util::{free_box_ptr, is_null, is_null_mut, read_array};
use std::ffi::c_char;
use wow_srp::server::SrpServer as SrpServerInner;

pub struct WowSrpServer(SrpServerInner);

impl WowSrpServer {
    pub fn new(inner: SrpServerInner) -> Self {
        Self(inner)
    }
}
#[no_mangle]
pub extern "C" fn wow_srp_server_free(server: *mut WowSrpServer) {
    free_box_ptr(server)
}

#[no_mangle]
pub extern "C" fn wow_srp_server_session_key(server: *const WowSrpServer) -> *const u8 {
    let Some(server) = is_null(server, std::ptr::null_mut()) else {
        return std::ptr::null();
    };

    server.0.session_key().as_ptr()
}

#[no_mangle]
pub extern "C" fn wow_srp_server_reconnect_challenge_data(
    server: *const WowSrpServer,
) -> *const u8 {
    let Some(server) = is_null(server, std::ptr::null_mut()) else {
        return std::ptr::null();
    };

    server.0.reconnect_challenge_data().as_ptr()
}

#[no_mangle]
pub extern "C" fn wow_srp_server_verify_reconnection_attempt(
    server: *mut WowSrpServer,
    client_data: *const u8,
    client_proof: *const u8,
    out_error: *mut c_char,
) -> bool {
    let Some(server) = is_null_mut(server, out_error) else {
        return false;
    };

    let Some(client_data) = read_array(client_data, out_error) else {
        return false;
    };

    let Some(client_proof) = read_array(client_proof, out_error) else {
        return false;
    };

    server
        .0
        .verify_reconnection_attempt(client_data, client_proof)
}
