use libc::{uint16_t, int16_t, uint8_t, c_void};

use encparams::NtruEncParams;
use types::{NtruIntPoly, NtruTernPoly, NtruProdPoly, NtruEncKeyPair, NtruEncPubKey};
use rand::{NtruRandContext, NtruRandGen};

#[link(name = "ntru")]
extern {
    // ntru.h
    pub fn ntru_gen_key_pair(params: *const NtruEncParams, kp: *mut NtruEncKeyPair,
                        rand_ctx: *const NtruRandContext) -> uint8_t;
    pub fn ntru_encrypt(msg: *const uint8_t, msg_len: uint16_t, public: *const NtruEncPubKey,
                        params: *const NtruEncParams, rand_ctx: *const NtruRandContext,
                        enc: *const uint8_t) -> uint8_t;
    pub fn ntru_decrypt(enc: *const uint8_t, kp: *const NtruEncKeyPair,
                        params: *const NtruEncParams, dec: *const uint8_t,
                        dec_len: *const uint16_t) -> uint8_t;

    // hash.h
    pub fn ntru_sha1(input: *const uint8_t, input_len: uint16_t, digest: *mut uint8_t) -> c_void;
    pub fn ntru_sha1_4way(input: *const *const uint8_t, input_len: uint16_t,
                            digest: *mut *mut uint8_t) -> c_void;
    pub fn ntru_sha256(input: *const uint8_t, input_len: uint16_t, digest: *mut uint8_t) -> c_void;
    pub fn ntru_sha256_4way(input: *const *const uint8_t, input_len: uint16_t,
                            digest: *mut *mut uint8_t) -> c_void;

    // rand.h
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

    // poly.h
    pub fn ntru_rand_tern(n: uint16_t, num_ones: uint16_t, num_neg_ones: uint16_t,
                            poly: *mut NtruTernPoly, rand_ctx: *const NtruRandContext) -> uint8_t;
    pub fn ntru_mult_tern(a: *const NtruIntPoly, b: *const NtruTernPoly, c: *mut NtruIntPoly,
                            mod_mask: uint16_t) -> uint8_t;
    pub fn ntru_mult_prod(a: *const NtruIntPoly, b: *const NtruProdPoly, c: *mut NtruIntPoly,
                            mod_mask: uint16_t) -> uint8_t;
    pub fn ntru_add_int(a: *mut NtruIntPoly, b: *const NtruIntPoly);
    pub fn ntru_mod_mask(p: *mut NtruIntPoly, mod_mask: uint16_t);
    pub fn ntru_mult_fac(a: *mut NtruIntPoly, factor: int16_t);
    pub fn ntru_mod_center(p: *mut NtruIntPoly, modulus: uint16_t);
    pub fn ntru_mod3(p: *mut NtruIntPoly);

    // key.h
    pub fn ntru_export_pub(key: *const NtruEncPubKey, arr: *mut uint8_t);
    pub fn ntru_import_pub(arr: *const uint8_t, key: *mut NtruEncPubKey) -> uint16_t;
}
