use crate::client::srp_client_challenge::WowSrpClientChallenge;
use crate::util::{
    char_ptr_to_string, free_box_ptr, read_array, read_public_key, retake_ownership,
};
use std::ffi::c_char;
use wow_srp::client::SrpClientUser as SrpClientUserInner;

/// First step of client side authentication.
///
/// Created through `wow_srp_client_user_from_username_and_password`.
pub struct WowSrpClientUser(SrpClientUserInner);

/// Creates a new `WowSrpClientUser` from a username and password.
///
/// * `username` is a null terminated string no longer than 16 characters.
/// * `password` is a null terminated string no longer than 16 characters.
/// * `out_error` is a pointer to a single `uint8_t` that will be written to.
///
/// This function can return a null pointer, in which case errors will be in `out_error`.
/// It can return:
/// * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
/// * `WOW_SRP_ERROR_UTF8` if the username/password contains disallowed characters.
/// * `WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME` if the username/password contains disallowed characters.
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

/// Converts the `WowSrpClientUser` into a `WowSrpClientChallenge`.
///
/// This should be called after receiving `CMD_AUTH_LOGON_CHALLENGE_Server`.
///
/// * `large_safe_prime` is a `WOW_SRP_KEY_LENGTH` array.
/// * `server_public_key` is a `WOW_SRP_KEY_LENGTH` array.
/// * `salt` is a `WOW_SRP_KEY_LENGTH` array.
/// * `out_error` is a pointer to a single `uint8_t` that will be written to.
///
/// This function can return a null pointer, in which case errors will be in `out_error`.
/// It can return:
/// * `WOW_SRP_ERROR_NULL_POINTER` if any pointer is null.
/// * `WOW_SRP_ERROR_UTF8` if the username/password contains disallowed characters.
/// * `WOW_SRP_ERROR_CHARACTERS_NOT_ALLOWED_IN_NAME` if the username/password contains disallowed characters.
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

/// Frees a `WowSrpClientUser`.
///
/// This should not normally need to be called since `wow_srp_client_user_into_challenge` will
/// free the object.
#[no_mangle]
pub extern "C" fn wow_srp_client_user_free(client_user: *mut WowSrpClientUser) {
    free_box_ptr(client_user)
}
