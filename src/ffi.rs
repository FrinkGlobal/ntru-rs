use libc::{uint16_t, uint8_t, c_void};

use encparams::NtruEncParams;
use types::NtruEncKeyPair;
use rand::{NtruRandContext, NtruRandGen};

#[link(name = "ntru")]
extern {
    pub fn ntru_gen_key_pair(params: *const NtruEncParams, kp: *mut NtruEncKeyPair,
                        rand_ctx: *const NtruRandContext) -> uint8_t;

    pub fn ntru_sha1(input: *const uint8_t, input_len: uint16_t, digest: *mut uint8_t) -> c_void;
    pub fn ntru_sha1_4way(input: *const *const uint8_t, input_len: uint16_t,
                            digest: *mut *mut uint8_t) -> c_void;
    pub fn ntru_sha256(input: *const uint8_t, input_len: uint16_t, digest: *mut uint8_t) -> c_void;
    pub fn ntru_sha256_4way(input: *const *const uint8_t, input_len: uint16_t,
                            digest: *mut *mut uint8_t) -> c_void;
    pub fn ntru_rand_init(rand_ctx: *mut NtruRandContext, rand_gen: *const NtruRandGen) -> uint8_t;
    pub fn ntru_rand_init_det(rand_ctx: *mut NtruRandContext, rand_gen: *const NtruRandGen,
                                seed: *const uint8_t, seed_len: uint16_t) -> uint8_t;
    pub fn ntru_rand_generate(rand_data: *const uint8_t, len: uint16_t,
                                rand_ctx: *const NtruRandContext) -> uint8_t;
    pub fn ntru_rand_release(rand_ctx: *mut NtruRandContext) -> uint8_t;


    #[cfg(target_os = "windows")]
    pub fn ntru_rand_wincrypt_init(rand_ctx: *mut NtruRandContext, rand_gen: *mut NtruRandGen)
                                    -> uint8_t;
    #[cfg(target_os = "windows")]
    pub fn ntru_rand_wincrypt_generate(rand_data: *const uint8_t, len: uint16_t,
                                        rand_ctx: *mut NtruRandContext) -> uint8_t;
    #[cfg(target_os = "windows")]
    pub fn ntru_rand_wincrypt_release(rand_ctx: *mut NtruRandContext) -> uint8_t;

    #[cfg(not(target_os = "windows"))]
    pub fn ntru_rand_devrandom_init(rand_ctx: *mut NtruRandContext, rand_gen: *mut NtruRandGen)
                                    -> uint8_t;
    #[cfg(not(target_os = "windows"))]
    pub fn ntru_rand_devrandom_generate(rand_data: *const uint8_t, len: uint16_t,
                                        rand_ctx: *mut NtruRandContext) -> uint8_t;
    #[cfg(not(target_os = "windows"))]
    pub fn ntru_rand_devrandom_release(rand_ctx: *mut NtruRandContext) -> uint8_t;

    #[cfg(not(target_os = "windows"))]
    pub fn ntru_rand_devurandom_init(rand_ctx: *mut NtruRandContext, rand_gen: *mut NtruRandGen)
                                        -> uint8_t;
    #[cfg(not(target_os = "windows"))]
    pub fn ntru_rand_devurandom_generate(rand_data: *const uint8_t, len: uint16_t,
                                        rand_ctx: *mut NtruRandContext) -> uint8_t;
    #[cfg(not(target_os = "windows"))]
    pub fn ntru_rand_devurandom_release(rand_ctx: *mut NtruRandContext) -> uint8_t;

    pub fn ntru_rand_igf2_init(rand_ctx: *mut NtruRandContext, rand_gen: *mut NtruRandGen)
                                -> uint8_t;
    pub fn ntru_rand_igf2_generate(rand_data: *const uint8_t, len: uint16_t,
                                    rand_ctx: *mut NtruRandContext) -> uint8_t;
    pub fn ntru_rand_igf2_release(rand_ctx: *mut NtruRandContext) -> uint8_t;
}
