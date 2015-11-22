#![forbid(missing_docs, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]

extern crate ntru;
extern crate crypto;

use crypto::digest::Digest;
use crypto::sha1::Sha1;

use ntru::encparams::{NtruEncParams, ALL_PARAM_SETS};
use ntru::rand::{NTRU_RNG_DEFAULT, NTRU_RNG_IGF2};
use ntru::types::{NtruIntPoly, NtruTernPoly, NtruEncPrivKey, NtruEncPubKey, NtruEncKeyPair};

mod poly;
mod key;

fn encrypt_poly(m: NtruIntPoly, r: &NtruTernPoly, h: &NtruIntPoly, q: u16) -> NtruIntPoly {
    let (mut e, _) = h.mult_tern(r, q);
    e = e + m;
    e.mod_mask(q-1);
    e
}

fn decrypt_poly(e: NtruIntPoly, private: &NtruEncPrivKey, modulus: u16)  -> NtruIntPoly {
    let (mut d, _) = if private.get_t().is_product() {
        e.mult_prod(private.get_t().get_poly_prod(), modulus-1)
    } else {
        e.mult_tern(private.get_t().get_poly_tern(), modulus-1)
    };
    d.mod_mask(modulus-1);
    d.mult_fac(3);
    d = d + e;
    d.mod_center(modulus);
    d.mod3();
    for i in 0..d.get_coeffs().len() {
        if d.get_coeffs()[i] == 2 { d.set_coeff(i, -1)}
    }
    d
}

fn gen_key_pair(seed: &str, params: &NtruEncParams) -> NtruEncKeyPair {
    let seed_u8 = seed.as_bytes();
    let rng = NTRU_RNG_IGF2;
    let mut rand_ctx = ntru::rand::init_det(&rng, seed_u8).ok().unwrap();
    rand_ctx.set_seed(seed_u8);

    ntru::generate_key_pair(params, &rand_ctx).ok().unwrap()
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
        let rand_ctx = ntru::rand::init(&NTRU_RNG_DEFAULT).ok().unwrap();
        let mut kp = ntru::generate_key_pair(&params, &rand_ctx).ok().unwrap();

        // Encrypt a random message
        let m = NtruTernPoly::rand(params.get_n(), params.get_n()/3, params.get_n()/3,
                                   &rand_ctx).unwrap();
        let m_int = m.to_int_poly();

        let r = NtruTernPoly::rand(params.get_n(), params.get_n()/3, params.get_n()/3,
                                   &rand_ctx).unwrap();

        let e = encrypt_poly(m_int.clone(), &r, &kp.get_public().get_h(), params.get_q());

        // Decrypt and verify
        let c = decrypt_poly(e, &kp.get_private(), params.get_q());
        assert_eq!(m_int, c);

        // Test deterministic key generation
        kp = gen_key_pair("my test password", &params);
        let rng = NTRU_RNG_IGF2;
        let rand_ctx2 = ntru::rand::init_det(&rng, b"my test password").ok().unwrap();
        let kp2 = ntru::generate_key_pair(&params, &rand_ctx2).ok().unwrap();

        assert_eq!(kp, kp2);
    }
}

// Tests ntru_encrypt() with a non-deterministic RNG
fn test_encr_decr_nondet(params: &NtruEncParams) {
    let rng = NTRU_RNG_DEFAULT;
    let rand_ctx = ntru::rand::init(&rng).ok().unwrap();
    let kp = ntru::generate_key_pair(params, &rand_ctx).ok().unwrap();

    let max_len = params.max_msg_len();
    let plain = ntru::rand::generate(max_len as u16, &rand_ctx).ok().unwrap();

    for plain_len in 0..max_len+1 {
        let encrypted = ntru::encrypt(&plain[0..plain_len as usize], kp.get_public(), params,
                                        &rand_ctx).ok().unwrap();
        let decrypted = ntru::decrypt(&encrypted, &kp, params).ok().unwrap();

        for i in 0..plain_len {
            assert_eq!(plain[i as usize], decrypted[i as usize]);
        }
    }
}


// Tests ntru_encrypt() with a deterministic RNG
fn test_encr_decr_det(params: &NtruEncParams, digest_expected: &[u8]) {
    let kp = gen_key_pair("seed value for key generation", params);
    let pub_arr = kp.get_public().export(params);

    let pub2 = NtruEncPubKey::import(&pub_arr);
    assert_eq!(kp.get_public().get_h(), pub2.get_h());

    let max_len = params.max_msg_len();
    let rng_plaintext = NTRU_RNG_IGF2;
    let plain_seed = b"seed value for plaintext";

    let rand_ctx_plaintext = ntru::rand::init_det(&rng_plaintext, plain_seed).ok().unwrap();
    let plain = ntru::rand::generate(max_len as u16, &rand_ctx_plaintext).ok().unwrap();
    let plain2 = plain.clone();

    let seed = b"seed value";
    let seed2 = b"seed value";

    let rng = NTRU_RNG_IGF2;
    let rand_ctx = ntru::rand::init_det(&rng, seed).ok().unwrap();
    let rng2 = NTRU_RNG_IGF2;
    let rand_ctx2 = ntru::rand::init_det(&rng2, seed2).ok().unwrap();

    for plain_len in 0..max_len as usize {
        let encrypted = ntru::encrypt(&plain[0..plain_len], kp.get_public(), params,
                                      &rand_ctx).ok().unwrap();
        let encrypted2 = ntru::encrypt(&plain2[0..plain_len], &pub2, params,
                                       &rand_ctx2).ok().unwrap();

        for i in 0..encrypted.len() {
            assert_eq!(encrypted[i], encrypted2[i]);
        }

        let decrypted = ntru::decrypt(&encrypted, &kp, params).ok().unwrap();

        for i in 0..plain_len {
            assert_eq!(plain[i], decrypted[i]);
        }
    }

    let encrypted = ntru::encrypt(&plain, kp.get_public(), params,
                                  &rand_ctx).ok().unwrap();
    let digest = sha1(&encrypted);
    assert_eq!(digest, digest_expected);
}

#[test]
fn it_encr_decr() {
    let param_arr = ALL_PARAM_SETS;

    // SHA-1 digests of deterministic ciphertexts
    let digests_expected: [[u8; 20]; 18] = [
        [0xf8, 0x39, 0xbf, 0xb6, 0xa4, 0x99, 0x50, 0xde, 0xd0, 0x9f, // EES401EP1
         0xce, 0x55, 0xac, 0x23, 0xf1, 0x8e, 0x11, 0x0f, 0x76, 0x3d],
        [0x01, 0x6a, 0xbe, 0xae, 0x79, 0xdd, 0xf7, 0x9c, 0x90, 0x70, // EES449EP1
         0x02, 0x2e, 0x7e, 0x70, 0x05, 0xc4, 0xcb, 0x87, 0x8c, 0x60],
        [0xff, 0x5a, 0xfb, 0x06, 0xe0, 0xbe, 0xf9, 0x96, 0x7b, 0x2f, // EES677EP1
         0x6c, 0xde, 0x43, 0x8f, 0x2f, 0x48, 0xf3, 0x2b, 0x90, 0x8b],
        [0xc1, 0xbe, 0x9a, 0x9b, 0x85, 0xba, 0xa4, 0x0a, 0xc9, 0x45, // EES1087EP2
         0xa4, 0x92, 0xdf, 0xd3, 0x34, 0x03, 0x6b, 0x1b, 0x77, 0x29],
        [0xdb, 0xa4, 0x6f, 0xb2, 0xb1, 0xf0, 0x8d, 0xb1, 0xe3, 0x07, // EES541EP1
         0xf9, 0xb4, 0x4b, 0x96, 0x9e, 0xa9, 0x83, 0x56, 0x77, 0x69],
        [0x0c, 0x70, 0xf6, 0x40, 0x96, 0xfa, 0xaf, 0x26, 0xb4, 0xc0, // EES613EP1
         0x2d, 0xcd, 0xe4, 0x16, 0xc0, 0x56, 0xda, 0xbd, 0xbd, 0x6f],
        [0xb0, 0x39, 0xe6, 0xa3, 0xb7, 0x08, 0x60, 0x90, 0x5e, 0x39, // EES887EP1
         0xdb, 0xac, 0x9b, 0xba, 0xa2, 0xb8, 0xd9, 0x68, 0x91, 0x5a],
        [0x3d, 0x98, 0x20, 0xc1, 0xcf, 0xdf, 0x59, 0x77, 0x5a, 0x4a, // EES1171EP1
         0x1a, 0x1a, 0xb7, 0xed, 0xa0, 0x4b, 0x6c, 0xfa, 0x67, 0x72],
        [0x5d, 0x45, 0x53, 0xed, 0xb8, 0xce, 0xff, 0x84, 0x4f, 0x09, // EES659EP1
         0x49, 0x82, 0x5c, 0x06, 0x35, 0x2a, 0xc9, 0x71, 0xfa, 0x17],
        [0x85, 0xb9, 0xbe, 0x9b, 0x89, 0x64, 0x24, 0x06, 0x6b, 0x38, // EES761EP1
         0x76, 0x7c, 0x7e, 0x2a, 0xc6, 0x12, 0x48, 0x7a, 0x36, 0x62],
        [0x07, 0x6f, 0x5f, 0x62, 0x7f, 0x81, 0xdb, 0xd8, 0x0d, 0x26, // EES1087EP1
         0x2e, 0x1a, 0x64, 0x8c, 0x68, 0x02, 0xb3, 0xaf, 0x18, 0xa7],
        [0xf3, 0x16, 0xdf, 0x16, 0xe9, 0xa3, 0x4c, 0x40, 0x30, 0xff, // EES1499EP1
         0x5d, 0x66, 0xd8, 0x53, 0x2b, 0x07, 0x8a, 0x17, 0x48, 0xb4],
        [0x7f, 0xbb, 0x91, 0x11, 0xea, 0x2e, 0x59, 0x5d, 0x25, 0x42, // EES401EP2
         0xea, 0x07, 0x88, 0x05, 0x1a, 0xab, 0x37, 0xda, 0x9b, 0x33],
        [0x55, 0x76, 0x32, 0x9f, 0x18, 0x0a, 0xbb, 0x14, 0x63, 0xd9, // EES439EP1
         0x23, 0xc3, 0x5d, 0xd0, 0x8e, 0x17, 0xa5, 0xa2, 0x61, 0x75],
        [0x5e, 0xe5, 0x6c, 0x47, 0xde, 0x6e, 0x2f, 0x9c, 0x5f, 0x47, // EES443EP1
         0x7, 0x46, 0xe9, 0x1f, 0x90, 0xb3, 0x47, 0x7d, 0x40, 0x38],
        [0xb9, 0x40, 0x15, 0xbe, 0x43, 0xb9, 0x0f, 0xb3, 0x27, 0xfe, // EES593EP1
         0x41, 0x8a, 0x44, 0x76, 0x9e, 0xfe, 0xbe, 0xe5, 0x82, 0xae],
        [0xbd, 0xa1, 0xf5, 0x07, 0x48, 0x9e, 0x49, 0x94, 0xca, 0x18, // EES587EP1
         0x3e, 0x4d, 0xa5, 0xf7, 0xee, 0x8a, 0x23, 0x67, 0x62, 0xf9],
        [0xbd, 0xd9, 0x2a, 0x79, 0x89, 0x07, 0x9f, 0x64, 0xf9, 0x35, // EES743EP1
         0xb6, 0x90, 0x4f, 0xd3, 0xfa, 0x70, 0xc9, 0xf9, 0x30, 0xb0],
    ];

    for i in 0..param_arr.len() {
        test_encr_decr_nondet(&param_arr[i]);
        test_encr_decr_det(&param_arr[i], &digests_expected[i]);
    }
}
