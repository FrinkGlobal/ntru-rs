//! NTRUEncrypt implementation for Rust
//!
//! This library implements the NtruEncrypt library in Rust. It is an interface to libntru, even
//! though many of the methds are being implemented in pure Rust. The plan is to gradually
//! implement the library natively. It uses this library since it has proven to be faster than the
//! original NTRUEncrypt implementation. In any case, it is much faster than usual encryption /
//! decryption mecanisms, and quantum-proof. More on NTRUEncrypt
//! [here](https://en.wikipedia.org/wiki/NTRUEncrypt).
//!
//! To use it you only need to include the following in your crate:
//! ```
//! extern crate ntru;
//!```
//!
//! NTRUEncrypt uses its own keys, that must be generated with the included random key generator,
//! and must not be used for other applications such as NTRUSign or NTRUNMLS. Here is an example of
//! use:
//!
//! ```
//! use ntru::rand::NTRU_RNG_DEFAULT;
//! use ntru::encparams::NTRU_DEFAULT_PARAMS_256_BITS;
//!
//! let rand_ctx = ntru::rand::init(&NTRU_RNG_DEFAULT).ok().unwrap();
//! let kp = ntru::generate_key_pair(&NTRU_DEFAULT_PARAMS_256_BITS, &rand_ctx).ok().unwrap();
//! ```
//!
//! This creates a key pair that can be uses to encrypt and decrypt messages:
//!
//! ```
//! # use ntru::rand::NTRU_RNG_DEFAULT;
//! use ntru::encparams::NTRU_DEFAULT_PARAMS_256_BITS;
//! #
//! # let rand_ctx = ntru::rand::init(&NTRU_RNG_DEFAULT).ok().unwrap();
//! # let kp = ntru::generate_key_pair(&NTRU_DEFAULT_PARAMS_256_BITS, &rand_ctx).ok().unwrap();
//!
//! let msg = b"Hello from Rust!";
//! let encrypted = ntru::encrypt(msg, kp.get_public(), &NTRU_DEFAULT_PARAMS_256_BITS,
//!                               &rand_ctx).ok().unwrap();
//! let decrypted = ntru::decrypt(&encrypted, &kp, &NTRU_DEFAULT_PARAMS_256_BITS).ok().unwrap();
//!
//! assert_eq!(&msg[..], &decrypted[..]);
//! ```
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
/// Generates a NtruEncrypt key pair. If a deterministic RNG is used, the key pair will be
/// deterministic for a given random seed; otherwise, the key pair will be completely random.
pub fn generate_key_pair(params: &NtruEncParams, rand_context: &NtruRandContext)
                        -> Result<NtruEncKeyPair, NtruError> {
    let mut kp: NtruEncKeyPair = Default::default();
    let result = unsafe {
                    ffi::ntru_gen_key_pair(params, &mut kp, rand_context.get_c_rand_ctx())
                 };
    if result == 0 {
        Ok(kp)
    } else {
        Err(NtruError::from_uint8_t(result))
    }
}

/// Encrypts a message
///
/// If a deterministic RNG is used, the encrypted message will also be deterministic for a given
/// combination of plain text, key, and random seed. See P1363.1 section 9.2.2.
/// The parameters needed are the following:
/// * msg: The message to encrypt as an ```u8``` slice.
/// * public: The public key to encrypt the message with.
/// * params: The NtruEncrypt parameters to use.
/// * and_ctx: An initialized random number generator.
pub fn encrypt(msg: &[u8], public: &NtruEncPubKey, params: &NtruEncParams,
                rand_ctx: &NtruRandContext) -> Result<Box<[u8]>, NtruError> {
    let mut enc = vec![0u8; params.enc_len() as usize];
    let result = unsafe { ffi::ntru_encrypt(if msg.len() > 0 {&msg[0]} else {std::ptr::null()},
                          msg.len() as u16, public, params, rand_ctx.get_c_rand_ctx(),
                          &mut enc[0]) };

    if result == 0 {
        Ok(enc.into_boxed_slice())
    } else {
        Err(NtruError::from_uint8_t(result))
    }
}

/// Decrypts a message.
///
/// See P1363.1 section 9.2.3. The parameters needed are the following:
/// * enc: The message to decrypt as an ```u8``` slice.
/// * kp: A key pair that contains the public key the message was encrypted with, and the
///       corresponding private key.
/// * params: Parameters the message was encrypted with
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
