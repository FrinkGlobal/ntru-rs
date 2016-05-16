#![forbid(missing_docs, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]

#[macro_use]
extern crate ntru;
extern crate crypto;
extern crate rand;

use crypto::digest::Digest;
use crypto::sha1::Sha1;

use rand::Rng;

use ntru::encparams::{EncParams, ALL_PARAM_SETS};
use ntru::rand::{RNG_DEFAULT, RNG_CTR_DRBG};
use ntru::types::{IntPoly, TernPoly, PrivateKey, PublicKey, KeyPair};

fn encrypt_poly(m: IntPoly, r: &TernPoly, h: &IntPoly, q: u16) -> IntPoly {
    let (mut e, _) = h.mult_tern(r, q);
    e = e + m;
    e.mod_mask(q - 1);
    e
}

fn decrypt_poly(e: IntPoly, private: &PrivateKey, modulus: u16) -> IntPoly {
    let (mut d, _) = if private.get_t().is_product() {
        e.mult_prod(private.get_t().get_poly_prod(), modulus - 1)
    } else {
        e.mult_tern(private.get_t().get_poly_tern(), modulus - 1)
    };
    d.mod_mask(modulus - 1);
    d.mult_fac(3);
    d = d + e;
    d.mod_center(modulus);
    d.mod3();
    for i in 0..d.get_coeffs().len() {
        if d.get_coeffs()[i] == 2 {
            d.set_coeff(i, -1)
        }
    }
    d
}

fn gen_key_pair(seed: &str, params: &EncParams) -> KeyPair {
    let seed_u8 = seed.as_bytes();
    let rng = RNG_CTR_DRBG;
    let mut rand_ctx = ntru::rand::init_det(&rng, seed_u8).unwrap();
    rand_ctx.set_seed(seed_u8);

    ntru::generate_key_pair(params, &rand_ctx).unwrap()
}

fn sha1(input: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.input(input);

    let mut digest = [0u8; 20];
    hasher.result(&mut digest);
    digest
}

#[test]
fn it_keygen() {
    let param_arr = &ALL_PARAM_SETS;

    for params in param_arr {
        let rand_ctx = ntru::rand::init(&RNG_DEFAULT).unwrap();
        let mut kp = ntru::generate_key_pair(&params, &rand_ctx).unwrap();

        // Encrypt a random message
        let m = TernPoly::rand(params.get_n(),
                               params.get_n() / 3,
                               params.get_n() / 3,
                               &rand_ctx)
                    .unwrap();
        let m_int = m.to_int_poly();

        let r = TernPoly::rand(params.get_n(),
                               params.get_n() / 3,
                               params.get_n() / 3,
                               &rand_ctx)
                    .unwrap();

        let e = encrypt_poly(m_int.clone(), &r, &kp.get_public().get_h(), params.get_q());

        // Decrypt and verify
        let c = decrypt_poly(e, &kp.get_private(), params.get_q());
        assert_eq!(m_int, c);

        // Test deterministic key generation
        kp = gen_key_pair("my test password", &params);
        let rng = RNG_CTR_DRBG;
        let rand_ctx2 = ntru::rand::init_det(&rng, b"my test password").unwrap();
        let kp2 = ntru::generate_key_pair(&params, &rand_ctx2).unwrap();

        assert_eq!(kp, kp2);
    }
}

// Tests ntru_encrypt() with a non-deterministic RNG
fn test_encr_decr_nondet(params: &EncParams) {
    let rng = RNG_DEFAULT;
    let rand_ctx = ntru::rand::init(&rng).unwrap();
    let kp = ntru::generate_key_pair(params, &rand_ctx).unwrap();

    // Randomly choose the number of public keys for testing ntru::generate_multiple_key_pairs and
    // ntru::generate_public
    let num_pub_keys: usize = rand::thread_rng().gen_range(1, 10);

    // Create a key pair with multiple public keys (using ntru_gen_key_pair_multi)
    let (priv_multi1, pub_multi1) = ntru::generate_multiple_key_pairs(params,
                                                                      &rand_ctx,
                                                                      num_pub_keys)
                                        .unwrap();

    // Create a key pair with multiple public keys (using ntru::generate_public)
    let kp_multi2 = ntru::generate_key_pair(params, &rand_ctx).unwrap();
    let mut pub_multi2 = Vec::with_capacity(num_pub_keys);
    for _ in 0..num_pub_keys {
        pub_multi2.push(ntru::generate_public(params, kp_multi2.get_private(), &rand_ctx).unwrap());
    }

    let max_len = params.max_msg_len();
    let plain = ntru::rand::generate(max_len as u16, &rand_ctx).unwrap();

    for plain_len in 0..max_len + 1 {
        // Test single public key
        let encrypted = ntru::encrypt(&plain[0..plain_len as usize],
                                      kp.get_public(),
                                      params,
                                      &rand_ctx)
                            .unwrap();
        let decrypted = ntru::decrypt(&encrypted, &kp, params).unwrap();

        for i in 0..plain_len {
            assert_eq!(plain[i as usize], decrypted[i as usize]);
        }

        // Test multiple public keys
        for i in 0..num_pub_keys {
            let rand_value = rand::thread_rng().gen_range(1, 100);
            if rand_value % 100 != 0 {
                continue;
            }

            // Test priv_multi1/pub_multi1
            let encrypted = ntru::encrypt(&plain[0..plain_len as usize],
                                          &pub_multi1[i],
                                          params,
                                          &rand_ctx)
                                .unwrap();

            let kp_decrypt1 = KeyPair::new(priv_multi1.clone(), pub_multi1[i].clone());
            let decrypted = ntru::decrypt(&encrypted, &kp_decrypt1, params).unwrap();
            for i in 0..plain_len {
                assert_eq!(plain[i as usize], decrypted[i as usize]);
            }

            // Test kp_multi2 + pub_multi2
            let public = if i == 0 {
                kp_multi2.get_public()
            } else {
                &pub_multi2[i - 1]
            };
            let encrypted = ntru::encrypt(&plain[0..plain_len as usize], public, params, &rand_ctx)
                                .unwrap();

            let kp_decrypt2 = KeyPair::new(kp_multi2.get_private().clone(), public.clone());
            let decrypted = ntru::decrypt(&encrypted, &kp_decrypt2, params).unwrap();
            for i in 0..plain_len {
                assert_eq!(plain[i as usize], decrypted[i as usize]);
            }
        }
    }
}


// Tests ntru_encrypt() with a deterministic RNG
fn test_encr_decr_det(params: &EncParams, digest_expected: &[u8]) {
    let kp = gen_key_pair("seed value for key generation", params);
    let pub_arr = kp.get_public().export(params);

    let pub2 = PublicKey::import(&pub_arr);
    assert_eq!(kp.get_public().get_h(), pub2.get_h());

    let max_len = params.max_msg_len();
    let rng_plaintext = RNG_CTR_DRBG;
    let plain_seed = b"seed value for plaintext";

    let rand_ctx_plaintext = ntru::rand::init_det(&rng_plaintext, plain_seed).unwrap();
    let plain = ntru::rand::generate(max_len as u16, &rand_ctx_plaintext).unwrap();
    let plain2 = plain.clone();

    let seed = b"seed value";
    let seed2 = b"seed value";

    let rng = RNG_CTR_DRBG;
    let rand_ctx = ntru::rand::init_det(&rng, seed).unwrap();
    let rng2 = RNG_CTR_DRBG;
    let rand_ctx2 = ntru::rand::init_det(&rng2, seed2).unwrap();

    for plain_len in 0..max_len as usize {
        let encrypted = ntru::encrypt(&plain[0..plain_len], kp.get_public(), params, &rand_ctx)
                            .unwrap();
        let encrypted2 = ntru::encrypt(&plain2[0..plain_len], &pub2, params, &rand_ctx2).unwrap();

        for (i, c) in encrypted.iter().enumerate() {
            assert_eq!(*c, encrypted2[i]);
        }

        let decrypted = ntru::decrypt(&encrypted, &kp, params).unwrap();

        for i in 0..plain_len {
            assert_eq!(plain[i], decrypted[i]);
        }
    }

    let encrypted = ntru::encrypt(&plain, kp.get_public(), params, &rand_ctx).unwrap();
    let digest = sha1(&encrypted);
    assert_eq!(digest, digest_expected);
}

#[test]
fn it_encr_decr() {
    let param_arr = ALL_PARAM_SETS;

    // SHA-1 digests of deterministic ciphertexts, one set for big-endian environments and one for
    // little-endian ones. If/when the CTR_DRBG implementation is made endian independent, only one
    // set of digests will be needed here.
    let digests_expected: [[u8; 20]; 18] =
        // EES401EP1
        [[0x57, 0x73, 0xd6, 0x3e, 0x2e, 0x77, 0xdd, 0x9d, 0xcc, 0xa3, 0xdb, 0x66, 0xff, 0xd5,
          0x4d, 0x19, 0xba, 0xed, 0x6b, 0x31],
         // EES449EP1
         [0x66, 0xe0, 0x14, 0x46, 0xe6, 0x65, 0x3d, 0x56, 0x8d, 0x1b, 0xb5, 0x0c, 0xde, 0x69,
          0x8e, 0xcd, 0xb7, 0xce, 0xf5, 0x24],
         // EES677EP1
         [0xb6, 0x22, 0x91, 0xac, 0x0a, 0x45, 0xb9, 0xbe, 0xc7, 0x2c, 0x87, 0x17, 0xe8, 0xa3,
          0xcd, 0xb2, 0xd0, 0x52, 0x9f, 0x62],
         // EES1087EP2
         [0xea, 0x00, 0x48, 0x44, 0x92, 0x36, 0x3a, 0xc7, 0xf6, 0x7f, 0xbd, 0x2e, 0x47, 0xcb,
          0xf3, 0x9c, 0x05, 0x2a, 0xf8, 0xa0],
         // EES541EP1
         [0x2e, 0xe0, 0x43, 0x63, 0xf2, 0xbe, 0x74, 0xf8, 0xcd, 0x68, 0xd4, 0x32, 0x96, 0xb5,
          0x0c, 0x8c, 0x17, 0xb8, 0x43, 0x67],
         // EES613EP1
         [0xf1, 0xd4, 0x92, 0xb8, 0x93, 0xa5, 0xdf, 0xa2, 0x9e, 0xef, 0x9f, 0xcc, 0x4c, 0x09,
          0x9a, 0x32, 0x5f, 0xa6, 0x9a, 0x1c],
         // EES887EP1
         [0x22, 0x66, 0xc4, 0x24, 0x1f, 0xc7, 0xd0, 0x5d, 0x0e, 0x37, 0x1a, 0x1e, 0xfa, 0xe9,
          0x98, 0xea, 0x8e, 0x5c, 0xaf, 0xc0],
         // EES1171EP1
         [0xeb, 0x3d, 0x03, 0xca, 0xf9, 0xf7, 0x46, 0xeb, 0xbe, 0x13, 0xaa, 0x1f, 0x3b, 0xb5,
          0x62, 0x5b, 0x70, 0x53, 0xa6, 0x57],
         // EES659EP1
         [0xc2, 0xad, 0x7e, 0x9d, 0xb1, 0x32, 0x33, 0xc9, 0x39, 0x56, 0xa5, 0x7e, 0x32, 0x55,
          0x29, 0x25, 0xb8, 0x64, 0x05, 0xcd],
         // EES761EP1
         [0x9b, 0xfe, 0xde, 0xe7, 0x36, 0x44, 0x17, 0xb6, 0x71, 0xa3, 0xdf, 0xc8, 0x40, 0x89,
          0xde, 0x9c, 0x12, 0x72, 0xff, 0xfd],
         // EES1087EP1
         [0xba, 0xda, 0x5b, 0xb1, 0x43, 0x4a, 0x3a, 0x94, 0x3d, 0xaf, 0x34, 0xa4, 0xe3, 0x5b,
          0x0d, 0x50, 0x3c, 0x97, 0xc9, 0x73],
         // EES1499EP1
         [0xbe, 0x7f, 0x85, 0xdf, 0x8c, 0x9e, 0xc2, 0x8c, 0x94, 0xbe, 0xee, 0xab, 0x0e, 0x0b,
          0x27, 0x48, 0xb8, 0x6e, 0xfe, 0x78],
         // EES401EP2
         [0xae, 0xe3, 0x60, 0x4d, 0x21, 0x7b, 0xaf, 0x83, 0x06, 0x28, 0xb3, 0xf8, 0xa3, 0xea,
          0x51, 0x7d, 0x0e, 0xf6, 0x61, 0xe2],
         // EES439EP1
         [0x52, 0x30, 0x00, 0xb7, 0xc3, 0x09, 0x0b, 0xf5, 0xb0, 0xc1, 0x23, 0x94, 0xc2, 0x50,
          0x7f, 0x6a, 0x09, 0x6b, 0xce, 0x77],
         // EES443EP1
         [0xb7, 0x2d, 0xc0, 0xd5, 0x69, 0xb5, 0x9d, 0x8c, 0xe0, 0xdf, 0x6d, 0x86, 0xd8, 0x0f,
          0x8f, 0xef, 0xbd, 0x6b, 0x85, 0x85],
         // EES593EP1
         [0x08, 0xe4, 0x1a, 0x41, 0x8c, 0x46, 0x92, 0xcf, 0xaf, 0xf7, 0xd9, 0x73, 0xee, 0x25,
          0x63, 0xeb, 0x42, 0x17, 0xed, 0xcd],
         // EES587EP1
         [0x87, 0x46, 0x03, 0xf5, 0x1b, 0xaa, 0xed, 0xe9, 0xfc, 0x8f, 0x28, 0x0f, 0xed, 0xf4,
          0x59, 0xe2, 0x3a, 0x68, 0x53, 0x30],
         // EES743EP1
         [0xb4, 0x39, 0x0d, 0x54, 0x9a, 0x21, 0xf3, 0x27, 0x4f, 0xa7, 0xe7, 0x46, 0xd8, 0x03,
          0x68, 0x46, 0x7d, 0x96, 0xee, 0xee]];

    for (i, param) in param_arr.iter().enumerate() {
        test_encr_decr_nondet(param);
        test_encr_decr_det(param, &digests_expected[i]);
    }
}
