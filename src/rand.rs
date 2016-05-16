//! Rand module
//!
//! This module includes all the needed structs and functions to interact with the randomness
//! needed by NTRUEncrypt. Both, key generation and encryption need a source of randomness, for
//! that they need a RandContext, that can be generated from a RandGen. The recommended RNG
//! is the ```RNG_DEFAULT```. If needed, in this module random data can be generated with the
//! ```generate()``` function. Also both random ```TernPoly``` and ```ProdPoly``` can be
//! generated.
use std::{slice, ptr};
use libc::{uint8_t, uint16_t};
use types::{Error, TernPoly};
use super::ffi;

/// A random context for key generation and encryption
pub struct RandContext {
    /// The actual C-compatible RandContext
    rand_ctx: ffi::CNtruRandContext,
}

impl Default for RandContext {
    fn default() -> RandContext {
        RandContext {
            rand_ctx: ffi::CNtruRandContext {
                rand_gen: &mut RNG_DEFAULT,
                seed: ptr::null(),
                seed_len: 0,
                state: ptr::null(),
            },
        }
    }
}

impl Drop for RandContext {
    fn drop(&mut self) {
        let result = unsafe { ffi::ntru_rand_release(&mut self.rand_ctx) };
        if result != 0 {
            panic!()
        }
    }
}

impl RandContext {
    /// Gets the native struct representing the RandContext
    ///
    /// *Note: this will be deprecated in the future once the Drop trait can be safely implemented
    /// in native structs.*
    pub unsafe fn get_c_rand_ctx(&self) -> &ffi::CNtruRandContext {
        &self.rand_ctx
    }

    /// Gets the seed for the RandContext
    pub fn get_seed(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.rand_ctx.seed, self.rand_ctx.seed_len as usize) }
    }

    /// Gets the RNG of the RandContext
    pub fn get_rng(&self) -> &RandGen {
        unsafe { &*self.rand_ctx.rand_gen }
    }
}

#[repr(C)]
/// Random number generator
pub struct RandGen {
    /// Random number generator initialization function
    init_fn: unsafe extern "C" fn(rand_ctx: *mut ffi::CNtruRandContext,
                                      rand_gen: *const RandGen)
                                      -> uint8_t,
    /// A pointer to a function that takes an array and an array size, and fills the array with
    /// random data
    generate_fn: unsafe extern "C" fn(rand_data: *mut uint8_t,
                                          len: uint16_t,
                                          rand_ctx: *const ffi::CNtruRandContext)
                                          -> uint8_t,
    /// The rng release function
    release_fn: unsafe extern "C" fn(rand_ctx: *mut ffi::CNtruRandContext) -> uint8_t,
}

impl RandGen {
    /// Initialize a new random contex
    pub fn init(&self, rand_gen: &RandGen) -> Result<RandContext, Error> {
        let mut rand_ctx: RandContext = Default::default();
        let result = unsafe { (self.init_fn)(&mut rand_ctx.rand_ctx, rand_gen) };
        if result == 1 {
            Ok(rand_ctx)
        } else {
            Err(Error::Prng)
        }
    }

    /// Generate random data
    pub fn generate(&self, length: u16, rand_ctx: &RandContext) -> Result<Box<[u8]>, Error> {
        let mut plain = vec![0u8; length as usize];
        let result = unsafe { (self.generate_fn)(&mut plain[0], length, &rand_ctx.rand_ctx) };

        if result == 1 {
            Ok(plain.into_boxed_slice())
        } else {
            Err(Error::Prng)
        }
    }
}

#[cfg(target_os = "windows")]
/// Default Windows RNG, CryptGenRandom()
pub const RNG_WINCRYPT: RandGen = RandGen {
    init_fn: ffi::ntru_rand_wincrypt_init,
    generate_fn: ffi::ntru_rand_wincrypt_generate,
    release_fn: ffi::ntru_rand_wincrypt_release,
};

#[cfg(not(target_os = "windows"))]
/// Unix default RNG, /dev/urandom
pub const RNG_DEVURANDOM: RandGen = RandGen {
    init_fn: ffi::ntru_rand_devurandom_init,
    generate_fn: ffi::ntru_rand_devurandom_generate,
    release_fn: ffi::ntru_rand_devurandom_release,
};
#[cfg(not(target_os = "windows"))]
/// Unix RNG, /dev/random
pub const RNG_DEVRANDOM: RandGen = RandGen {
    init_fn: ffi::ntru_rand_devrandom_init,
    generate_fn: ffi::ntru_rand_devrandom_generate,
    release_fn: ffi::ntru_rand_devrandom_release,
};

/// Default RNG
///
/// CTR_DRBG seeded from /dev/urandom (on *nix) or CryptGenRandom() (on Windows)
pub const RNG_DEFAULT: RandGen = RandGen {
    init_fn: ffi::ntru_rand_default_init,
    generate_fn: ffi::ntru_rand_default_generate,
    release_fn: ffi::ntru_rand_default_release,
};

/// Deterministic RNG based on CTR_DRBG
pub const RNG_CTR_DRBG: RandGen = RandGen {
    init_fn: ffi::ntru_rand_ctr_drbg_init,
    generate_fn: ffi::ntru_rand_ctr_drbg_generate,
    release_fn: ffi::ntru_rand_ctr_drbg_release,
};

/// Initialize a new rand context
pub fn init(rand_gen: &RandGen) -> Result<RandContext, Error> {
    let mut rand_ctx: RandContext = Default::default();
    let result = unsafe { ffi::ntru_rand_init(&mut rand_ctx.rand_ctx, rand_gen) };
    if result == 0 {
        Ok(rand_ctx)
    } else {
        Err(Error::from(result))
    }
}

/// Generate a new deterministic rand context
pub fn init_det(rand_gen: &RandGen, seed: &[u8]) -> Result<RandContext, Error> {
    let mut rand_ctx: RandContext = Default::default();
    let result = unsafe {
        ffi::ntru_rand_init_det(&mut rand_ctx.rand_ctx,
                                rand_gen,
                                &seed[0],
                                seed.len() as uint16_t)
    };
    if result == 0 {
        Ok(rand_ctx)
    } else {
        Err(Error::from(result))
    }
}

/// Generate random data
pub fn generate(length: u16, rand_ctx: &RandContext) -> Result<Box<[u8]>, Error> {
    let mut plain = vec![0u8; length as usize];
    let result = unsafe { ffi::ntru_rand_generate(&mut plain[0], length, &rand_ctx.rand_ctx) };

    if result == 0 {
        Ok(plain.into_boxed_slice())
    } else {
        Err(Error::from(result))
    }
}

impl TernPoly {
    /// Random ternary polynomial
    ///
    /// Generates a random ternary polynomial. If an error occurs, it will return None.
    pub fn rand(n: u16,
                num_ones: u16,
                num_neg_ones: u16,
                rand_ctx: &RandContext)
                -> Option<TernPoly> {
        let mut poly: TernPoly = Default::default();
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
