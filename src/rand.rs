use libc::{c_void, uint8_t, uint16_t};
use ffi::{ntru_rand_init, ntru_rand_init_det};
use types::NtruError;

#[cfg(target_os = "windows")]
use ffi::{ntru_rand_wincrypt_init, ntru_rand_wincrypt_generate, ntru_rand_wincrypt_release};

#[cfg(not(target_os = "windows"))]
use ffi::{ntru_rand_devurandom_init, ntru_rand_devurandom_generate, ntru_rand_devurandom_release,
            ntru_rand_devrandom_init, ntru_rand_devrandom_generate, ntru_rand_devrandom_release};

use ffi::{ntru_rand_igf2_init, ntru_rand_igf2_generate, ntru_rand_igf2_release};

#[repr(C)]
pub struct NtruRandContext {
    rand_gen: NtruRandGen,
    /// For deterministic RNGs
    seed: *const u8,
    /// For deterministic RNGs
    seed_len: u16,
    state: *mut c_void,
}

impl Default for NtruRandContext {
    fn default() -> NtruRandContext {
        NtruRandContext {rand_gen: NTRU_RNG_DEFAULT, seed: &0, seed_len: 0,
                            state: &mut 0 as *mut _ as *mut c_void}
    }
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
pub const NTRU_RNG_WINCRYPT: NtruRandGen = NtruRandGen {init: ntru_rand_wincrypt_init,
                                                        generate: ntru_rand_wincrypt_generate,
                                                        release: ntru_rand_wincrypt_release};
#[cfg(target_os = "windows")]
pub const NTRU_RNG_DEFAULT: NtruRandGen = NTRU_RNG_WINCRYPT;

#[cfg(not(target_os = "windows"))]
pub const NTRU_RNG_DEVURANDOM: NtruRandGen = NtruRandGen {init: ntru_rand_devurandom_init,
                                                          generate: ntru_rand_devurandom_generate,
                                                          release: ntru_rand_devurandom_release};
#[cfg(not(target_os = "windows"))]
pub const NTRU_RNG_DEVRANDOM: NtruRandGen = NtruRandGen {init: ntru_rand_devrandom_init,
                                                         generate: ntru_rand_devrandom_generate,
                                                         release: ntru_rand_devrandom_release};
#[cfg(not(target_os = "windows"))]
pub const NTRU_RNG_DEFAULT: NtruRandGen = NTRU_RNG_DEVURANDOM;

pub const NTRU_RNG_IGF2: NtruRandGen = NtruRandGen {init: ntru_rand_igf2_init,
                                                    generate: ntru_rand_igf2_generate,
                                                    release: ntru_rand_igf2_release};

pub fn init(rand_gen: &NtruRandGen)
            -> Result<NtruRandContext, NtruError> {
    let mut rand_ctx: NtruRandContext = Default::default();
    let result = unsafe {ntru_rand_init(&mut rand_ctx, rand_gen)};
    if result == 0 {
        Ok(rand_ctx)
    } else {
        Err(NtruError::from_uint8_t(result))
    }
}

pub fn init_det(rand_gen: &NtruRandGen, seed: &[u8])
            -> Result<NtruRandContext, NtruError> {
    let mut rand_ctx: NtruRandContext = Default::default();
    let result = unsafe {ntru_rand_init_det(&mut rand_ctx, rand_gen, &seed[0] as *const uint8_t,
                                            seed.len() as uint16_t)};
    if result == 0 {
        Ok(rand_ctx)
    } else {
        Err(NtruError::from_uint8_t(result))
    }
}
// pub fn generate(rand_data: *const uint8_t, len: uint16_t,
//                             rand_ctx: *const NtruRandContext) -> uint8_t;
// pub fn release(rand_ctx: *mut NtruRandContext) -> uint8_t;
