use libc::{c_void, uint8_t, uint16_t};
use types::{NtruError, NtruTernPoly};
use super::ffi;

#[repr(C)]
pub struct NtruRandContext {
    rand_gen: *mut NtruRandGen,
    /// For deterministic RNGs
    seed: *const uint8_t,
    /// For deterministic RNGs
    seed_len: uint16_t,
    state: *mut c_void,
}

impl Default for NtruRandContext {
    fn default() -> NtruRandContext {
        NtruRandContext {rand_gen: &mut NTRU_RNG_DEFAULT, seed: &0, seed_len: 0,
                            state: &mut 0 as *mut _ as *mut c_void}
    }
}

impl NtruRandContext {
    pub fn release(&mut self) {
        let result = unsafe {ffi::ntru_rand_release(self)};
        if result != 0 {
            panic!()
        }
    }

    pub fn get_seed_len(&self) -> u16 { self.seed_len }
}

#[repr(C)]
pub struct NtruRandGen {
    init: unsafe extern fn(rand_ctx: *mut NtruRandContext, rand_gen: *mut NtruRandGen)
                            -> uint8_t,
    /// A pointer to a function that takes an array and an array size, and fills the array with
    /// random data
    generate: unsafe extern fn(rand_data: *const uint8_t, len: uint16_t,
                                rand_ctx: *mut NtruRandContext) -> uint8_t,
    release: unsafe extern fn(rand_ctx: *mut NtruRandContext) -> uint8_t,
}

#[cfg(target_os = "windows")]
pub const NTRU_RNG_WINCRYPT: NtruRandGen = NtruRandGen {init: ffi::ntru_rand_wincrypt_init,
                                                        generate: ffi::ntru_rand_wincrypt_generate,
                                                        release: ffi::ntru_rand_wincrypt_release};
#[cfg(target_os = "windows")]
pub const NTRU_RNG_DEFAULT: NtruRandGen = NTRU_RNG_WINCRYPT;

#[cfg(not(target_os = "windows"))]
pub const NTRU_RNG_DEVURANDOM: NtruRandGen = NtruRandGen {
        init: ffi::ntru_rand_devurandom_init,
        generate: ffi::ntru_rand_devurandom_generate,
        release: ffi::ntru_rand_devurandom_release
};
#[cfg(not(target_os = "windows"))]
pub const NTRU_RNG_DEVRANDOM: NtruRandGen = NtruRandGen {
        init: ffi::ntru_rand_devrandom_init,
        generate: ffi::ntru_rand_devrandom_generate,
        release: ffi::ntru_rand_devrandom_release
};
#[cfg(not(target_os = "windows"))]
pub const NTRU_RNG_DEFAULT: NtruRandGen = NTRU_RNG_DEVURANDOM;

pub const NTRU_RNG_IGF2: NtruRandGen = NtruRandGen {init: ffi::ntru_rand_igf2_init,
                                                    generate: ffi::ntru_rand_igf2_generate,
                                                    release: ffi::ntru_rand_igf2_release};

pub fn init(rand_gen: &NtruRandGen)
            -> Result<NtruRandContext, NtruError> {
    let mut rand_ctx: NtruRandContext = Default::default();
    let result = unsafe {ffi::ntru_rand_init(&mut rand_ctx, rand_gen)};
    if result == 0 {
        Ok(rand_ctx)
    } else {
        Err(NtruError::from_uint8_t(result))
    }
}

pub fn init_det(rand_gen: &NtruRandGen, seed: &[u8])
            -> Result<NtruRandContext, NtruError> {
    let mut rand_ctx: NtruRandContext = Default::default();
    let result = unsafe {ffi::ntru_rand_init_det(&mut rand_ctx, rand_gen,
                            &seed[0] as *const uint8_t, seed.len() as uint16_t)};
    if result == 0 {
        Ok(rand_ctx)
    } else {
        Err(NtruError::from_uint8_t(result))
    }
}
// pub fn generate(rand_data: *const uint8_t, len: uint16_t,
//                             rand_ctx: *const NtruRandContext) -> uint8_t;

/// Random ternary polynomial
///
/// Generates a random ternary polynomial. If an error occurs, it will return None.
pub fn tern(n: u16, num_ones: u16, num_neg_ones: u16, rand_ctx: &NtruRandContext)
            -> Option<NtruTernPoly> {
    let mut poly: NtruTernPoly = Default::default();
    let result = unsafe {ffi::ntru_rand_tern(n, num_ones, num_neg_ones, &mut poly, rand_ctx)};

    if result == 0 {
        None
    } else {
        Some(poly)
    }
}
