//! Rand module
//!
//! This module includes all the needed structs and functions to interact with the randomness
//! needed by NTRUEncrypt. Both, key generation and encryption need a source of randomness, for
//! that they need a NtruRandContext, that can be generated from a NtruRandGen. The recommended RNG
//! is the ```NTRU_RNG_DEFAULT```. If needed, in this module random data can be generated with the
//! ```generate()``` function. Also both random ```NtruTernPoly``` and ```NtruProdPoly``` can be
//! generated.
use std::{slice, ptr};
use libc::{uint8_t, uint16_t};
use types::{NtruError, NtruTernPoly};
use super::ffi;

/// A random context for key generation and encryption
pub struct NtruRandContext {
    rand_ctx: ffi::CNtruRandContext,
}

impl Default for NtruRandContext {
    fn default() -> NtruRandContext {
        NtruRandContext {
            rand_ctx: ffi::CNtruRandContext {
                rand_gen: &mut NTRU_RNG_DEFAULT,
                seed: ptr::null(),
                seed_len: 0,
                state: ptr::null(),
            },
        }
    }
}

impl Drop for NtruRandContext {
    fn drop(&mut self) {
        let result = unsafe { ffi::ntru_rand_release(&mut self.rand_ctx) };
        if result != 0 {
            panic!()
        }
    }
}

impl NtruRandContext {
    pub unsafe fn get_c_rand_ctx(&self) -> &ffi::CNtruRandContext {
        &self.rand_ctx
    }

    pub fn get_seed(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.rand_ctx.seed, self.rand_ctx.seed_len as usize) }
    }

    pub fn set_seed(&mut self, seed: &[u8]) {
        self.rand_ctx.seed_len = seed.len() as uint16_t;
        self.rand_ctx.seed = &seed[0];
    }

    pub fn get_rng(&self) -> &NtruRandGen {
        unsafe { &*self.rand_ctx.rand_gen }
    }
}

#[repr(C)]
pub struct NtruRandGen {
    init_fn: unsafe extern "C" fn(rand_ctx: *mut ffi::CNtruRandContext,
                                  rand_gen: *const NtruRandGen)
                                  -> uint8_t,
    /// A pointer to a function that takes an array and an array size, and fills the array with
    /// random data
    generate_fn: unsafe extern "C" fn(rand_data: *mut uint8_t,
                                          len: uint16_t,
                                          rand_ctx: *const ffi::CNtruRandContext)
                                          -> uint8_t,
    release_fn: unsafe extern "C" fn(rand_ctx: *mut ffi::CNtruRandContext) -> uint8_t,
}

impl NtruRandGen {
    /// Initialize a new random contex
    pub fn init(&self, rand_gen: &NtruRandGen) -> Result<NtruRandContext, NtruError> {
        let mut rand_ctx: NtruRandContext = Default::default();
        let result = unsafe { (self.init_fn)(&mut rand_ctx.rand_ctx, rand_gen) };
        if result == 1 {
            Ok(rand_ctx)
        } else {
            Err(NtruError::Prng)
        }
    }

    /// Generate random data
    pub fn generate(&self,
                    length: u16,
                    rand_ctx: &NtruRandContext)
                    -> Result<Box<[u8]>, NtruError> {
        let mut plain = vec![0u8; length as usize];
        let result = unsafe { (self.generate_fn)(&mut plain[0], length, &rand_ctx.rand_ctx) };

        if result == 1 {
            Ok(plain.into_boxed_slice())
        } else {
            Err(NtruError::Prng)
        }
    }
}

#[cfg(target_os = "windows")]
/// Default Windows RNG, CryptGenRandom()
pub const NTRU_RNG_WINCRYPT: NtruRandGen = NtruRandGen {
    init: ffi::ntru_rand_wincrypt_init,
    generate: ffi::ntru_rand_wincrypt_generate,
    release: ffi::ntru_rand_wincrypt_release,
};

#[cfg(not(target_os = "windows"))]
/// Unix default RNG, /dev/urandom
pub const NTRU_RNG_DEVURANDOM: NtruRandGen = NtruRandGen {
    init_fn: ffi::ntru_rand_devurandom_init,
    generate_fn: ffi::ntru_rand_devurandom_generate,
    release_fn: ffi::ntru_rand_devurandom_release,
};
#[cfg(not(target_os = "windows"))]
/// Unix RNG, /dev/random
pub const NTRU_RNG_DEVRANDOM: NtruRandGen = NtruRandGen {
    init_fn: ffi::ntru_rand_devrandom_init,
    generate_fn: ffi::ntru_rand_devrandom_generate,
    release_fn: ffi::ntru_rand_devrandom_release,
};

/// Default RNG
///
/// CTR_DRBG seeded from /dev/urandom (on *nix) or CryptGenRandom() (on Windows)
pub const NTRU_RNG_DEFAULT: NtruRandGen = NtruRandGen {
    init_fn: ffi::ntru_rand_default_init,
    generate_fn: ffi::ntru_rand_default_generate,
    release_fn: ffi::ntru_rand_default_release,
};

/// Deterministic RNG based on IGF-2
pub const NTRU_RNG_IGF2: NtruRandGen = NtruRandGen {
    init_fn: ffi::ntru_rand_igf2_init,
    generate_fn: ffi::ntru_rand_igf2_generate,
    release_fn: ffi::ntru_rand_igf2_release,
};

/// Initialize a new rand context
pub fn init(rand_gen: &NtruRandGen) -> Result<NtruRandContext, NtruError> {
    let mut rand_ctx: NtruRandContext = Default::default();
    let result = unsafe { ffi::ntru_rand_init(&mut rand_ctx.rand_ctx, rand_gen) };
    if result == 0 {
        Ok(rand_ctx)
    } else {
        Err(NtruError::from_uint8_t(result))
    }
}

/// Generate a new deterministic rand context
pub fn init_det(rand_gen: &NtruRandGen, seed: &[u8]) -> Result<NtruRandContext, NtruError> {
    let mut rand_ctx: NtruRandContext = Default::default();
    let result = unsafe {
        ffi::ntru_rand_init_det(&mut rand_ctx.rand_ctx,
                                rand_gen,
                                &seed[0],
                                seed.len() as uint16_t)
    };
    if result == 0 {
        Ok(rand_ctx)
    } else {
        Err(NtruError::from_uint8_t(result))
    }
}

/// Generate random data
pub fn generate(length: u16, rand_ctx: &NtruRandContext) -> Result<Box<[u8]>, NtruError> {
    let mut plain = vec![0u8; length as usize];
    let result = unsafe { ffi::ntru_rand_generate(&mut plain[0], length, &rand_ctx.rand_ctx) };

    if result == 0 {
        Ok(plain.into_boxed_slice())
    } else {
        Err(NtruError::from_uint8_t(result))
    }
}

impl NtruTernPoly {
    /// Random ternary polynomial
    ///
    /// Generates a random ternary polynomial. If an error occurs, it will return None.
    pub fn rand(n: u16,
                num_ones: u16,
                num_neg_ones: u16,
                rand_ctx: &NtruRandContext)
                -> Option<NtruTernPoly> {
        let mut poly: NtruTernPoly = Default::default();
        let result = unsafe {
            ffi::ntru_rand_tern(n, num_ones, num_neg_ones, &mut poly, &rand_ctx.rand_ctx)
        };

        if result == 0 {
            None
        } else {
            Some(poly)
        }
    }
}
