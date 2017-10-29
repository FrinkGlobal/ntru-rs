//! This crate implements the NTRU encryption library in Rust. It is an interface to libntru, even
//! though many of the methods are being implemented in pure Rust. The plan is to gradually
//! implement the library natively. It uses this library since it has proven to be faster than the
//! original NTRU encryption implementation. In any case, it is much faster than usual encryption /
//! decryption mecanisms, and quantum-proof. More on NTRU encryption
//! [here](https://en.wikipedia.org/wiki/NTRUEncrypt).
//!
//! To use it you only need to include the following in your crate:
//!
//! ```
//! extern crate ntru;
//! ```
//!
//! NTRU encryption uses its own keys, that must be generated with the included random key
//! generator, and must not be used for other applications such as NTRU signing or NTRUNMLS.
//!
//! # Examples
//!
//! ```
//! use ntru::rand::RNG_DEFAULT;
//! use ntru::encparams::DEFAULT_PARAMS_256_BITS;
//!
//! let rand_ctx = ntru::rand::init(&RNG_DEFAULT).unwrap();
//! let kp = ntru::generate_key_pair(&DEFAULT_PARAMS_256_BITS, &rand_ctx).unwrap();
//! ```
//!
//! This creates a key pair that can be uses to encrypt and decrypt messages:
//!
//! ```
//! # use ntru::rand::RNG_DEFAULT;
//! use ntru::encparams::DEFAULT_PARAMS_256_BITS;
//! #
//! # let rand_ctx = ntru::rand::init(&RNG_DEFAULT).unwrap();
//! # let kp = ntru::generate_key_pair(&DEFAULT_PARAMS_256_BITS, &rand_ctx).unwrap();
//!
//! let msg = b"Hello from Rust!";
//! let encrypted = ntru::encrypt(msg, kp.get_public(), &DEFAULT_PARAMS_256_BITS,
//!                               &rand_ctx).unwrap();
//! let decrypted = ntru::decrypt(&encrypted, &kp, &DEFAULT_PARAMS_256_BITS).unwrap();
//!
//! assert_eq!(&msg[..], &decrypted[..]);
//! ```

#![forbid(missing_docs, warnings)]
#![deny(deprecated, improper_ctypes, non_shorthand_field_patterns, overflowing_literals,
    plugin_as_library, private_no_mangle_fns, private_no_mangle_statics, stable_features,
    unconditional_recursion, unknown_lints, unused, unused_allocation, unused_attributes,
    unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates, unused_import_braces,
    unused_qualifications, unused_results, variant_size_differences)]

extern crate libc;

pub mod types;
pub mod rand;
pub mod encparams;
mod ffi;

use types::{KeyPair, PrivateKey, PublicKey, Error};
use encparams::EncParams;
use rand::RandContext;

/// Key generation
///
/// Generates a NTRU encryption key pair. If a deterministic RNG is used, the key pair will be
/// deterministic for a given random seed; otherwise, the key pair will be completely random.
pub fn generate_key_pair(params: &EncParams, rand_context: &RandContext) -> Result<KeyPair, Error> {
    let mut kp: KeyPair = Default::default();
    let result = unsafe { ffi::ntru_gen_key_pair(params, &mut kp, rand_context) };
    if result == 0 {
        Ok(kp)
    } else {
        Err(Error::from(result))
    }
}

/// Key generation with multiple public keys
///
/// Generates `num_pub` Ntru encryption key pairs. They all share a private key but their public
/// keys differ. The private key decrypts messages encrypted for any of the public keys. Note that
/// when decrypting, the public key of the key pair passed into `ntru_decrypt()` must match the
/// public key used for encrypting the message. If a deterministic RNG is used, the key pair will
/// be deterministic for a given random seed; otherwise, the key pair will be completely random.
pub fn generate_multiple_key_pairs(
    params: &EncParams,
    rand_context: &RandContext,
    num_pub: usize,
) -> Result<(PrivateKey, Box<[PublicKey]>), Error> {
    let mut private: PrivateKey = Default::default();
    let mut public: Vec<PublicKey> = Vec::with_capacity(num_pub);
    for _ in 0..num_pub {
        public.push(Default::default());
    }
    let result = unsafe {
        ffi::ntru_gen_key_pair_multi(
            params,
            &mut private,
            &mut public[0],
            rand_context,
            num_pub as u32,
        )
    };
    if result == 0 {
        Ok((private, public.into_boxed_slice()))
    } else {
        Err(Error::from(result))
    }
}

/// New public key
///
/// Generates a new public key for an existing private key. The new public key can be used
/// interchangeably with the existing public key(s). Generating n keys via
/// `ntru::generate_multiple_key_pairs()` is more efficient than generating one and then calling
/// `ntru_gen_pub()` n-1 times, so if the number of public keys needed is known beforehand and if
/// speed matters, `ntru_gen_key_pair_multi()` should be used. Note that when decrypting, the public
/// key of the key pair passed into `ntru_decrypt()` must match the public key used for encrypting
/// the message. If a deterministic RNG is used, the key will be deterministic for a given random
/// seed; otherwise, the key will be completely random.
pub fn generate_public(
    params: &EncParams,
    private: &PrivateKey,
    rand_context: &RandContext,
) -> Result<PublicKey, Error> {
    let mut public: PublicKey = Default::default();
    let result = unsafe { ffi::ntru_gen_pub(params, private, &mut public, rand_context) };
    if result == 0 {
        Ok(public)
    } else {
        Err(Error::from(result))
    }
}

/// Encrypts a message
///
/// If a deterministic RNG is used, the encrypted message will also be deterministic for a given
/// combination of plain text, key, and random seed. See P1363.1 section 9.2.2.
/// The parameters needed are the following:
/// * `msg`: The message to encrypt as an ```u8``` slice.
/// * `public`: The public key to encrypt the message with.
/// * `params`: The NTRU encryption parameters to use.
/// * `and_ctx`: An initialized random number generator.
pub fn encrypt(
    msg: &[u8],
    public: &PublicKey,
    params: &EncParams,
    rand_ctx: &RandContext,
) -> Result<Box<[u8]>, Error> {
    let mut enc = vec![0u8; params.enc_len() as usize];
    let result = unsafe {
        ffi::ntru_encrypt(
            if !msg.is_empty() {
                &msg[0]
            } else {
                std::ptr::null()
            },
            msg.len() as u16,
            public,
            params,
            rand_ctx,
            &mut enc[0],
        )
    };

    if result == 0 {
        Ok(enc.into_boxed_slice())
    } else {
        Err(Error::from(result))
    }
}

/// Decrypts a message.
///
/// See P1363.1 section 9.2.3. The parameters needed are the following:
/// * enc: The message to decrypt as an ```u8``` slice.
/// * kp: A key pair that contains the public key the message was encrypted with, and the
///       corresponding private key.
/// * params: Parameters the message was encrypted with
pub fn decrypt(enc: &[u8], kp: &KeyPair, params: &EncParams) -> Result<Box<[u8]>, Error> {
    let mut dec = vec![0u8; params.max_msg_len() as usize];
    let mut dec_len = 0u16;
    let result = unsafe { ffi::ntru_decrypt(&enc[0], kp, params, &mut dec[0], &mut dec_len) };

    if result == 0 {
        let mut final_dec = Vec::with_capacity(dec_len as usize);
        final_dec.extend(dec.into_iter().take(dec_len as usize));
        Ok(final_dec.into_boxed_slice())
    } else {
        Err(Error::from(result))
    }
}
