//! Rand module
//!
//! This module includes all the needed structs and functions to interact with the randomness
//! needed by NTRUEncrypt. Both, key generation and encryption need a source of randomness, for
//! that they need a NtruRandContext, that can be generated from a NtruRandGen. The recommended RNG
//! is the ```NTRU_RNG_DEFAULT```. If needed, in this module random data can be generated with the
//! ```generate()``` function. Also both random ```NtruTernPoly``` and ```NtruProdPoly``` can be
//! generated.
use std::{slice, ptr};
use libc::{c_void, uint8_t, uint16_t};
use types::NtruError;
use super::ffi;

/// A random context for key generation and encryption
#[repr(C)]
pub struct NtruRandContext {
    rand_gen: *const NtruRandGen,
    /// For deterministic RNGs
    seed: *const uint8_t,
    /// For deterministic RNGs
    seed_len: uint16_t,
    state: *const c_void,
}

impl Default for NtruRandContext {
    fn default() -> NtruRandContext {
        NtruRandContext {rand_gen: &mut NTRU_RNG_DEFAULT, seed: ptr::null(), seed_len: 0,
                            state: &mut 0 as *mut _ as *mut c_void}
    }
}

impl Drop for NtruRandContext {
    fn drop(&mut self) {
        let result = unsafe { ffi::ntru_rand_release(self) };
        if result != 0 { panic!() }
    }
}

impl NtruRandContext {
    pub fn get_seed(&self) -> &[u8] { unsafe {slice::from_raw_parts(self.seed,
                                                                    self.seed_len as usize)} }
    pub fn set_seed(&mut self, seed: &[u8]) {
        self.seed_len = seed.len() as uint16_t;
        self.seed = &seed[0];
    }
    pub fn get_rng(&self) -> &NtruRandGen { unsafe { &*self.rand_gen } }
}

#[repr(C)]
pub struct NtruRandGen {
    init_fn: unsafe extern fn(rand_ctx: *mut NtruRandContext, rand_gen: *const NtruRandGen)
                           -> uint8_t,
    /// A pointer to a function that takes an array and an array size, and fills the array with
    /// random data
    generate_fn: unsafe extern fn(rand_data: *mut uint8_t, len: uint16_t,
                               rand_ctx: *const NtruRandContext) -> uint8_t,
    release_fn: unsafe extern fn(rand_ctx: *mut NtruRandContext) -> uint8_t,
}

impl NtruRandGen {
    /// Initialize a new random contex
    pub fn init(&self, rand_gen: &NtruRandGen) -> Result<NtruRandContext, NtruError> {
        let mut rand_ctx: NtruRandContext = Default::default();
        let result = unsafe {(self.init_fn)(&mut rand_ctx, rand_gen)};
        if result == 1 {
            Ok(rand_ctx)
        } else {
            Err(NtruError::Prng)
        }
    }

    /// Generate random data
    pub fn generate(&self, length: u16, rand_ctx: &NtruRandContext)
                    -> Result<Box<[u8]>, NtruError> {
        let mut plain = vec![0u8; length as usize];
        let result = unsafe {(self.generate_fn)(&mut plain[0], length, rand_ctx)};

        if result == 1 {
            Ok(plain.into_boxed_slice())
        } else {
            Err(NtruError::Prng)
        }
    }
}

#[cfg(target_os = "windows")]
/// Default Windows RNG, CryptGenRandom()
pub const NTRU_RNG_WINCRYPT: NtruRandGen = NtruRandGen {init: ffi::ntru_rand_wincrypt_init,
                                                        generate: ffi::ntru_rand_wincrypt_generate,
                                                        release: ffi::ntru_rand_wincrypt_release};
#[cfg(target_os = "windows")]
/// Default RNG (CryptGenRandom() on Windows)
pub const NTRU_RNG_DEFAULT: NtruRandGen = NTRU_RNG_WINCRYPT;

#[cfg(not(target_os = "windows"))]
/// Unix default RNG, /dev/urandom
pub const NTRU_RNG_DEVURANDOM: NtruRandGen = NtruRandGen {
        init_fn: ffi::ntru_rand_devurandom_init,
        generate_fn: ffi::ntru_rand_devurandom_generate,
        release_fn: ffi::ntru_rand_devurandom_release
};
#[cfg(not(target_os = "windows"))]
/// Unix RNG, /dev/random
pub const NTRU_RNG_DEVRANDOM: NtruRandGen = NtruRandGen {
    init_fn: ffi::ntru_rand_devrandom_init,
    generate_fn: ffi::ntru_rand_devrandom_generate,
    release_fn: ffi::ntru_rand_devrandom_release
};
#[cfg(not(target_os = "windows"))]
/// default RNG (/dev/urandom on *nix)
pub const NTRU_RNG_DEFAULT: NtruRandGen = NTRU_RNG_DEVURANDOM;

/// Deterministic RNG based on IGF-2
pub const NTRU_RNG_IGF2: NtruRandGen = NtruRandGen {init_fn: ffi::ntru_rand_igf2_init,
                                                    generate_fn: ffi::ntru_rand_igf2_generate,
                                                    release_fn: ffi::ntru_rand_igf2_release};

/// Initialize a new rand context
pub fn init(rand_gen: &NtruRandGen) -> Result<NtruRandContext, NtruError> {
    let mut rand_ctx: NtruRandContext = Default::default();
    let result = unsafe { ffi::ntru_rand_init(&mut rand_ctx, rand_gen) };
    if result == 0 {
        Ok(rand_ctx)
    } else {
        Err(NtruError::from_uint8_t(result))
    }
}

/// Generate a new deterministic rand context
pub fn init_det(rand_gen: &NtruRandGen, seed: &[u8]) -> Result<NtruRandContext, NtruError> {
    let mut rand_ctx: NtruRandContext = Default::default();
    let result = unsafe { ffi::ntru_rand_init_det(&mut rand_ctx, rand_gen,
                            &seed[0] as *const uint8_t, seed.len() as uint16_t) };
    if result == 0 {
        Ok(rand_ctx)
    } else {
        Err(NtruError::from_uint8_t(result))
    }
}

/// Generate random data
pub fn generate(length: u16, rand_ctx: &NtruRandContext) -> Result<Box<[u8]>, NtruError> {
    let mut plain = vec![0u8; length as usize];
    let result = unsafe { ffi::ntru_rand_generate(&mut plain[0], length, rand_ctx) };

    if result == 0 {
        Ok(plain.into_boxed_slice())
    } else {
        Err(NtruError::from_uint8_t(result))
    }
}
