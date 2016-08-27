#![forbid(missing_docs, warnings)]
#![deny(deprecated, improper_ctypes, non_shorthand_field_patterns, overflowing_literals,
    plugin_as_library, private_no_mangle_fns, private_no_mangle_statics, stable_features,
    unconditional_recursion, unknown_lints, unsafe_code, unused, unused_allocation,
    unused_attributes, unused_comparisons, unused_features, unused_parens, while_true)]
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
    let rand_ctx = ntru::rand::init_det(&rng, seed_u8).unwrap();

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
    let (priv_multi1, pub_multi1) =
        ntru::generate_multiple_key_pairs(params, &rand_ctx, num_pub_keys).unwrap();

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
        [[0xdf, 0xad, 0xcd, 0x25, 0x01, 0x9f, 0x3d, 0xb1, 0x06, 0x5f,
         0x15, 0xbe, 0x8f, 0x69, 0xfd, 0x23, 0x88, 0x88, 0x2a, 0xc8],
        // EES449EP1
        [0xc3, 0x8b, 0x8d, 0xdc, 0xfd, 0xef, 0xf8, 0x1b, 0xa6, 0x57,
         0xeb, 0x66, 0x49, 0xe8, 0xe9, 0x4d, 0x70, 0xab, 0xce, 0x02],
        // EES677EP1
        [0xfd, 0xa8, 0xb1, 0xdb, 0x96, 0xc4, 0x3a, 0xeb, 0x0c, 0x07,
         0xef, 0xf7, 0xc0, 0xf4, 0x73, 0x59, 0x6e, 0xd9, 0x97, 0xb7],
        // EES1087EP2
        [0xe7, 0x53, 0xd6, 0x89, 0xc6, 0x06, 0x3d, 0xf1, 0x12, 0xf1,
         0xeb, 0x8b, 0xd8, 0x7c, 0x26, 0x67, 0xc9, 0xe5, 0x4a, 0x0e],
        // EES541EP1
        [0x7a, 0x5d, 0x41, 0x88, 0x70, 0xef, 0x4f, 0xf3, 0xdf, 0xb9,
         0xa8, 0x76, 0x00, 0x00, 0x6d, 0x65, 0x61, 0xe0, 0xce, 0x44],
        // EES613EP1
        [0x69, 0x7b, 0x0a, 0x4f, 0xd6, 0x41, 0x04, 0x3f, 0x91, 0xe9,
         0xb0, 0xa9, 0x42, 0xfe, 0x66, 0x4e, 0xcc, 0x4e, 0xbb, 0xd7],
        // EES887EP1
        [0xac, 0x3a, 0x51, 0xd6, 0xaf, 0x6c, 0x38, 0xa8, 0x67, 0xde,
         0xc8, 0xfe, 0xf7, 0xaf, 0x4a, 0x28, 0x6e, 0x30, 0xad, 0x98],
        // EES1171EP1
        [0x5f, 0x34, 0x5f, 0xf7, 0x32, 0x13, 0x06, 0x55, 0x6b, 0xb7,
         0x02, 0x7d, 0xb3, 0x16, 0xef, 0x84, 0x09, 0xe9, 0xa0, 0xff],
        // EES659EP1
        [0x2e, 0x35, 0xd4, 0xa6, 0x99, 0xb8, 0x5e, 0x06, 0x47, 0x61,
         0x68, 0x20, 0x26, 0xb0, 0x17, 0xa9, 0xc6, 0x37, 0xb7, 0x8e],
        // EES761EP1
        [0x15, 0xde, 0x51, 0xbb, 0xc0, 0xe0, 0x39, 0xf2, 0xb6, 0x0e,
         0x98, 0xa7, 0xae, 0x10, 0xbf, 0xfd, 0x02, 0xcc, 0x76, 0x43],
        // EES1087EP1
        [0x29, 0xac, 0x2d, 0x21, 0x29, 0x79, 0x98, 0x89, 0x1c, 0xa0,
         0x6c, 0xed, 0x7d, 0x68, 0x29, 0x9b, 0xb4, 0x9f, 0xe4, 0xd0],
        // EES1499EP1
        [0x2f, 0xf9, 0x32, 0x25, 0xbc, 0xd5, 0xad, 0xc4, 0x4b, 0x19,
         0xca, 0xe6, 0x52, 0x89, 0x2e, 0x29, 0x38, 0x5a, 0x61, 0xd7],
        // EES401EP2
        [0xaf, 0x39, 0x02, 0xd5, 0xaa, 0xab, 0x29, 0xaa, 0x01, 0x99,
         0xd1, 0xf4, 0x0f, 0x02, 0x35, 0x58, 0x71, 0x58, 0xdb, 0xdb],
        // EES439EP1
        [0xa3, 0xd6, 0x5f, 0x7d, 0x5d, 0x66, 0x49, 0x1e, 0x15, 0xbc,
         0xba, 0xf0, 0xfa, 0x07, 0x9d, 0xd3, 0x33, 0xf5, 0x9f, 0x37],
        // EES443EP1
        [0xac, 0xea, 0xa3, 0xc8, 0x05, 0x8b, 0x23, 0x68, 0xaa, 0x9a,
         0x3c, 0x9b, 0xdb, 0x7f, 0xbe, 0x7b, 0x49, 0x03, 0x94, 0xc8],
        // EES593EP1
        [0x49, 0xfb, 0x90, 0x33, 0xaf, 0x12, 0xc7, 0x29, 0x17, 0x47,
         0xf2, 0x09, 0xb9, 0xc3, 0x5d, 0xf4, 0x21, 0x5a, 0xbf, 0x98],
        // EES587EP1
        [0x69, 0xa8, 0x36, 0x3d, 0xe1, 0xec, 0x9e, 0x89, 0xa1, 0x0a,
         0xa5, 0xb7, 0x35, 0xbe, 0x5b, 0x75, 0xb6, 0xd8, 0xe1, 0x9a],
        // EES743EP1
        [0x93, 0xfe, 0x81, 0xd5, 0x79, 0x2e, 0x34, 0xd8, 0xe3, 0x1f,
         0xe5, 0x03, 0xb9, 0x06, 0xdc, 0x4f, 0x28, 0xb9, 0xaf, 0x37]];

    for (i, param) in param_arr.iter().enumerate() {
        test_encr_decr_nondet(param);
        test_encr_decr_det(param, &digests_expected[i]);
    }
}
