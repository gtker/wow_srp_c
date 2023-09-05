use crate::util::{free_box_ptr, is_null_mut};
use std::ffi::c_char;
use wow_srp::vanilla_header::HeaderCrypto as HeaderCryptoInner;

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
