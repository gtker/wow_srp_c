use crate::client::srp_client_challenge::WowSrpClientChallenge;
use crate::util::{char_ptr_to_string, read_array, read_public_key, retake_ownership};
use std::ffi::c_char;
use wow_srp::client::SrpClientUser as SrpClientUserInner;

pub struct WowSrpClientUser(SrpClientUserInner);

#[no_mangle]
pub extern "C" fn wow_srp_client_user_from_username_and_password(
    username: *const c_char,
    password: *const c_char,
    out_error: *mut c_char,
) -> *mut WowSrpClientUser {
    let Some(username) = char_ptr_to_string(username, out_error) else {
        return std::ptr::null_mut();
    };

    let Some(password) = char_ptr_to_string(password, out_error) else {
        return std::ptr::null_mut();
    };

    let v = Box::new(WowSrpClientUser(SrpClientUserInner::new(
        username, password,
    )));

    Box::into_raw(v)
}

#[no_mangle]
pub extern "C" fn wow_srp_client_user_into_challenge(
    client_user: *mut WowSrpClientUser,
    generator: u8,
    large_safe_prime: *const u8,
    server_public_key: *const u8,
    salt: *const u8,
    out_error: *mut c_char,
) -> *mut WowSrpClientChallenge {
    let Some(large_safe_prime) = read_array(large_safe_prime, out_error) else {
        return std::ptr::null_mut();
    };

    let Some(server_public_key) = read_public_key(server_public_key, out_error) else {
        return std::ptr::null_mut();
    };

    let Some(salt) = read_array(salt, out_error) else {
        return std::ptr::null_mut();
    };

    let Some(client_user) = retake_ownership(client_user, out_error) else {
        return std::ptr::null_mut();
    };

    let challenge =
        client_user
            .0
            .into_challenge(generator, large_safe_prime, server_public_key, salt);

    let challenge = Box::new(WowSrpClientChallenge::new(challenge));

    Box::into_raw(challenge)
}
