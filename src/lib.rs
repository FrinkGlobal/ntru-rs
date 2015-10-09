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
// * @param params the NtruEncrypt parameters to use
// * @param kp pointer to write the key pair to (output parameter)
// * @param rand_ctx an initialized random number generator. See ntru_rand_init() in rand.h.
// * @return NTRU_SUCCESS for success, or a NTRU_ERR_ code for failure
// */
pub fn generate_key_pair(params: &NtruEncParams, rand_context: &NtruRandContext)
                        -> Result<NtruEncKeyPair, NtruError> {
    let mut kp: NtruEncKeyPair = Default::default();
    let result = unsafe {ffi::ntru_gen_key_pair(params, &mut kp, rand_context)};
    if result == 0 {
        Ok(kp)
    } else {
        Err(NtruError::from_uint8_t(result))
    }
}
