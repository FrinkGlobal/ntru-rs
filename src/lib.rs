extern crate libc;

pub mod types;
pub mod rand;
pub mod encparams;
mod ffi;

use types::{NtruEncKeyPair, NtruEncPubKey, NtruError};
use encparams::NtruEncParams;
use rand::NtruRandContext;

/// Key generation
///
/// Generates a NtruEncrypt key pair.
/// If a deterministic RNG is used, the key pair will be deterministic for a given random seed;
/// otherwise, the key pair will be completely random.
pub fn gen_key_pair(params: &NtruEncParams, rand_context: &NtruRandContext)
                        -> Result<NtruEncKeyPair, NtruError> {
    let mut kp: NtruEncKeyPair = Default::default();
    let result = unsafe {ffi::ntru_gen_key_pair(params, &mut kp, rand_context)};
    if result == 0 {
        Ok(kp)
    } else {
        Err(NtruError::from_uint8_t(result))
    }
}

pub fn encrypt(msg: &[u8], public: &NtruEncPubKey, params: &NtruEncParams,
                rand_ctx: &NtruRandContext) -> Result<Box<[u8]>, NtruError> {
    let mut enc = vec![0u8; params.enc_len() as usize];
    let result = unsafe {ffi::ntru_encrypt(if msg.len() > 0 {&msg[0]} else {std::ptr::null()},
                         msg.len() as u16, public, params, rand_ctx, &mut enc[0])};

    if result == 0 {
        Ok(enc.into_boxed_slice())
    } else {
        Err(NtruError::from_uint8_t(result))
    }
}

pub fn decrypt(enc: &[u8], kp: &NtruEncKeyPair, params: &NtruEncParams)
                -> Result<Box<[u8]>, NtruError> {
    let mut dec = vec![0u8; params.max_msg_len() as usize];
    let mut dec_len = 0u16;
    let result = unsafe {ffi::ntru_decrypt(&enc[0], kp, params, &mut dec[0], &mut dec_len)};

    if result == 0 {
        let mut final_dec = Vec::with_capacity(dec_len as usize);
        for i in 0..(dec_len as usize) {
            final_dec.push(dec[i]);
        }
        Ok(final_dec.into_boxed_slice())
    } else {
        Err(NtruError::from_uint8_t(result))
    }
}

pub fn sha1(input: &[u8]) -> [u8; 20] {
    let mut digest = [0u8; 20];
    unsafe { ffi::ntru_sha1(&input[0], input.len() as u16, &mut digest[0])};
    digest
}
