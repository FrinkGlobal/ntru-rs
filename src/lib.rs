extern crate libc;

pub mod types;
pub mod rand;
pub mod encparams;
mod ffi;

use types::{NtruEncKeyPair, NtruError};
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
