use crate::util::{free_box_ptr, is_null, is_null_mut, read_array};
use std::ffi::c_char;
use wow_srp::client::SrpClient as SrpClientInner;

pub struct WowSrpClient(SrpClientInner, [u8; 40]);

impl WowSrpClient {
    pub(crate) fn new(inner: SrpClientInner) -> Self {
        Self(inner, [0_u8; 40])
    }
}

#[no_mangle]
pub extern "C" fn wow_srp_client_free(client: *mut WowSrpClient) {
    free_box_ptr(client)
}

#[no_mangle]
pub extern "C" fn wow_srp_client_session_key(client: *mut WowSrpClient) -> *const u8 {
    let Some(client) = is_null_mut(client, std::ptr::null_mut()) else {
        return std::ptr::null();
    };

    // TODO: New version of wow_srp removes this
    let session_key = client.0.session_key();
    client.1 = session_key;

    &client.1 as *const u8
}

#[no_mangle]
pub extern "C" fn wow_srp_client_calculate_reconnect_values(
    client: *mut WowSrpClient,
    server_challenge_data: *const u8,
    out_client_challenge_data: *mut u8,
    out_client_proof: *mut u8,
    out_error: *mut c_char,
) {
    let Some(client) = is_null(client, out_error) else {
        return;
    };

    let Some(server_challenge_data) = read_array(server_challenge_data, out_error) else {
        return;
    };

    let reconnect_data = (*client)
        .0
        .calculate_reconnect_values(server_challenge_data);

    for (i, d) in reconnect_data.challenge_data.iter().enumerate() {
        unsafe { out_client_challenge_data.offset(i as isize).write(*d) };
    }

    for (i, d) in reconnect_data.proof.iter().enumerate() {
        unsafe { out_client_proof.offset(i as isize).write(*d) };
    }
}
