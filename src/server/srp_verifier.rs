use crate::server::srp_proof::WowSrpProof;
use crate::util::{char_ptr_to_string, free_box_ptr, is_null, read_array, retake_ownership};
use std::ffi::c_char;
use wow_srp::server::SrpVerifier as SrpVerifierInner;

pub struct WowSrpVerifier(SrpVerifierInner);

#[no_mangle]
pub extern "C" fn wow_srp_verifier_from_username_and_password(
    username: *const c_char,
    password: *const c_char,
    out_error: *mut c_char,
) -> *mut WowSrpVerifier {
    let Some(username) = char_ptr_to_string(username, out_error) else {
        return std::ptr::null_mut();
    };

    let Some(password) = char_ptr_to_string(password, out_error) else {
        return std::ptr::null_mut();
    };

    let v = Box::new(WowSrpVerifier(
        SrpVerifierInner::from_username_and_password(username, password),
    ));

    Box::into_raw(v)
}
#[no_mangle]
pub extern "C" fn wow_srp_verifier_from_database_values(
    username: *const c_char,
    password_verifier: *const u8,
    salt: *const u8,
    out_error: *mut c_char,
) -> *mut WowSrpVerifier {
    let Some(username) = char_ptr_to_string(username, out_error) else {
        return std::ptr::null_mut();
    };

    let Some(password_verifier) = read_array(password_verifier, out_error) else {
        return std::ptr::null_mut();
    };

    let Some(salt) = read_array(salt, out_error) else {
        return std::ptr::null_mut();
    };

    let b = Box::new(WowSrpVerifier(SrpVerifierInner::from_database_values(
        username,
        password_verifier,
        salt,
    )));

    Box::into_raw(b)
}

#[no_mangle]
pub extern "C" fn wow_srp_verifier_into_proof(verifier: *mut WowSrpVerifier) -> *mut WowSrpProof {
    if verifier.is_null() {
        return std::ptr::null_mut();
    }

    let Some(v) = retake_ownership(verifier, std::ptr::null_mut()) else {
        return std::ptr::null_mut();
    };
    let v = Box::new(WowSrpProof::new(v.0.into_proof()));

    Box::into_raw(v)
}

#[no_mangle]
pub extern "C" fn wow_srp_verifier_salt(verifier: *const WowSrpVerifier) -> *const u8 {
    let Some(verifier) = is_null(verifier, std::ptr::null_mut()) else {
        return std::ptr::null();
    };

    verifier.0.salt() as *const u8
}

#[no_mangle]
pub extern "C" fn wow_srp_verifier_password_verifier(verifier: *const WowSrpVerifier) -> *const u8 {
    let Some(verifier) = is_null(verifier, std::ptr::null_mut()) else {
        return std::ptr::null();
    };

    verifier.0.password_verifier() as *const u8
}

#[no_mangle]
pub extern "C" fn wow_srp_verifier_free(verifier: *mut WowSrpVerifier) {
    free_box_ptr(verifier)
}
