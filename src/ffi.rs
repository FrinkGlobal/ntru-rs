use libc::{uint16_t, int16_t, uint8_t};

use encparams::EncParams;
use types::{IntPoly, ProdPoly, TernPoly, KeyPair, PrivPoly, PublicKey, PrivateKey};
use rand::{RandContext, RandGen};

extern "C" {
    // ntru.h
    pub fn ntru_gen_key_pair(params: *const EncParams,
                             kp: *mut KeyPair,
                             rand_ctx: *const RandContext)
                             -> uint8_t;
    pub fn ntru_gen_key_pair_multi(params: *const EncParams,
                                   private: *mut PrivateKey,
                                   public: *mut PublicKey,
                                   rand_ctx: *const RandContext,
                                   num_pub: u32)
                                   -> uint8_t;
    pub fn ntru_gen_pub(params: *const EncParams,
                        private: *const PrivateKey,
                        public: *mut PublicKey,
                        rand_ctx: *const RandContext)
                        -> uint8_t;
    pub fn ntru_encrypt(msg: *const uint8_t,
                        msg_len: uint16_t,
                        public: *const PublicKey,
                        params: *const EncParams,
                        rand_ctx: *const RandContext,
                        enc: *mut uint8_t)
                        -> uint8_t;
    pub fn ntru_decrypt(enc: *const uint8_t,
                        kp: *const KeyPair,
                        params: *const EncParams,
                        dec: *mut uint8_t,
                        dec_len: *mut uint16_t)
                        -> uint8_t;

    // hash.h
    pub fn ntru_sha1(input: *const uint8_t, input_len: uint16_t, digest: *mut uint8_t);
    pub fn ntru_sha1_4way(input: *const *const uint8_t,
                          input_len: uint16_t,
                          digest: *mut *mut uint8_t);
    pub fn ntru_sha1_8way(input: *const *const uint8_t,
                          input_len: uint16_t,
                          digest: *mut *mut uint8_t);
    pub fn ntru_sha256(input: *const uint8_t, input_len: uint16_t, digest: *mut uint8_t);
    pub fn ntru_sha256_4way(input: *const *const uint8_t,
                            input_len: uint16_t,
                            digest: *mut *mut uint8_t);
    pub fn ntru_sha256_8way(input: *const *const uint8_t,
                            input_len: uint16_t,
                            digest: *mut *mut uint8_t);

    // rand.h
    pub fn ntru_rand_init(rand_ctx: *mut RandContext, rand_gen: *const RandGen) -> uint8_t;
    pub fn ntru_rand_init_det(rand_ctx: *mut RandContext,
                              rand_gen: *const RandGen,
                              seed: *const uint8_t,
                              seed_len: uint16_t)
                              -> uint8_t;
    pub fn ntru_rand_generate(rand_data: *mut uint8_t,
                              len: uint16_t,
                              rand_ctx: *const RandContext)
                              -> uint8_t;
    pub fn ntru_rand_release(rand_ctx: *mut RandContext) -> uint8_t;

    #[cfg(target_os = "windows")]
    pub fn ntru_rand_wincrypt_init(rand_ctx: *mut RandContext,
                                   rand_gen: *const RandGen)
                                   -> uint8_t;
    #[cfg(target_os = "windows")]
    pub fn ntru_rand_wincrypt_generate(rand_data: *mut uint8_t,
                                       len: uint16_t,
                                       rand_ctx: *const RandContext)
                                       -> uint8_t;
    #[cfg(target_os = "windows")]
    pub fn ntru_rand_wincrypt_release(rand_ctx: *mut RandContext) -> uint8_t;

    #[cfg(not(target_os = "windows"))]
    pub fn ntru_rand_devrandom_init(rand_ctx: *mut RandContext,
                                    rand_gen: *const RandGen)
                                    -> uint8_t;
    #[cfg(not(target_os = "windows"))]
    pub fn ntru_rand_devrandom_generate(rand_data: *mut uint8_t,
                                        len: uint16_t,
                                        rand_ctx: *const RandContext)
                                        -> uint8_t;
    #[cfg(not(target_os = "windows"))]
    pub fn ntru_rand_devrandom_release(rand_ctx: *mut RandContext) -> uint8_t;

    #[cfg(not(target_os = "windows"))]
    pub fn ntru_rand_devurandom_init(rand_ctx: *mut RandContext,
                                     rand_gen: *const RandGen)
                                     -> uint8_t;
    #[cfg(not(target_os = "windows"))]
    pub fn ntru_rand_devurandom_generate(rand_data: *mut uint8_t,
                                         len: uint16_t,
                                         rand_ctx: *const RandContext)
                                         -> uint8_t;
    #[cfg(not(target_os = "windows"))]
    pub fn ntru_rand_devurandom_release(rand_ctx: *mut RandContext) -> uint8_t;

    pub fn ntru_rand_default_init(rand_ctx: *mut RandContext, rand_gen: *const RandGen) -> uint8_t;
    pub fn ntru_rand_default_generate(rand_data: *mut uint8_t,
                                      len: uint16_t,
                                      rand_ctx: *const RandContext)
                                      -> uint8_t;
    pub fn ntru_rand_default_release(rand_ctx: *mut RandContext) -> uint8_t;

    pub fn ntru_rand_ctr_drbg_init(rand_ctx: *mut RandContext,
                                   rand_gen: *const RandGen)
                                   -> uint8_t;
    pub fn ntru_rand_ctr_drbg_generate(rand_data: *mut uint8_t,
                                       len: uint16_t,
                                       rand_ctx: *const RandContext)
                                       -> uint8_t;
    pub fn ntru_rand_ctr_drbg_release(rand_ctx: *mut RandContext) -> uint8_t;

    // poly.h
    pub fn ntru_rand_tern(n: uint16_t,
                          num_ones: uint16_t,
                          num_neg_ones: uint16_t,
                          poly: *mut TernPoly,
                          rand_ctx: *const RandContext)
                          -> uint8_t;
    pub fn ntru_mult_tern(a: *const IntPoly,
                          b: *const TernPoly,
                          c: *mut IntPoly,
                          mod_mask: uint16_t)
                          -> uint8_t;
    pub fn ntru_mult_prod(a: *const IntPoly,
                          b: *const ProdPoly,
                          c: *mut IntPoly,
                          mod_mask: uint16_t)
                          -> uint8_t;
    pub fn ntru_mult_priv(a: *const PrivPoly,
                          b: *const IntPoly,
                          c: *mut IntPoly,
                          mod_mask: uint16_t)
                          -> uint8_t;
    pub fn ntru_mult_int(a: *const IntPoly,
                         b: *const IntPoly,
                         c: *mut IntPoly,
                         mod_mask: uint16_t)
                         -> uint8_t;
    pub fn ntru_add(a: *mut IntPoly, b: *const IntPoly);
    pub fn ntru_sub(a: *mut IntPoly, b: *const IntPoly);
    pub fn ntru_mod_mask(p: *mut IntPoly, mod_mask: uint16_t);
    pub fn ntru_mult_fac(a: *mut IntPoly, factor: int16_t);
    pub fn ntru_mod_center(p: *mut IntPoly, modulus: uint16_t);
    pub fn ntru_mod3(p: *mut IntPoly);
    pub fn ntru_to_arr(p: *const IntPoly, q: uint16_t, a: *mut uint8_t);
    pub fn ntru_from_arr(arr: *const uint8_t, n: uint16_t, q: uint16_t, p: *mut IntPoly);
    pub fn ntru_invert(a: *const PrivPoly, mod_mask: uint16_t, fq: *mut IntPoly) -> uint8_t;

    // key.h
    pub fn ntru_export_pub(key: *const PublicKey, arr: *mut uint8_t);
    pub fn ntru_import_pub(arr: *const uint8_t, key: *mut PublicKey) -> uint16_t;

    pub fn ntru_export_priv(key: *const PrivateKey, arr: *mut uint8_t) -> uint16_t;
    pub fn ntru_import_priv(arr: *const uint8_t, key: *mut PrivateKey);

    pub fn ntru_params_from_priv_key(key: *const PrivateKey, params: *mut EncParams) -> uint8_t;
}
