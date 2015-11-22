#![forbid(missing_docs, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]

extern crate ntru;
use ntru::types::{NTRU_MAX_DEGREE, NTRU_MAX_ONES, NtruIntPoly, NtruTernPoly,
                  NtruProdPoly, NtruPrivPoly};
use ntru::encparams::EES1087EP1;
use ntru::rand::{NTRU_RNG_DEFAULT, NtruRandContext};

fn ntru_mult_int_nomod(a: &NtruIntPoly, b: &NtruIntPoly) -> NtruIntPoly {
    if a.get_coeffs().len() != b.get_coeffs().len() { panic!("Incompatible int polys") }
    let n = a.get_coeffs().len();

    let mut coeffs = Vec::with_capacity(n);
    for k in 0..n {
        let mut ck = 0i32;
        for i in 0..n {
            ck += b.get_coeffs()[i] as i32 * a.get_coeffs()[((n+k-i)%n)] as i32;
        }
        coeffs.push(ck as i16);
    }

    NtruIntPoly::new(&coeffs[..])
}

fn u8_arr_to_u16(arr: &[u8]) -> u16 {
    if arr.len() != 2 { panic!("u8_arr_to_u16() requires an array of 2 elements") }
    ((arr[0] as u16) << 8) + arr[1] as u16
}

fn ntru_priv_to_int(a: &NtruPrivPoly, modulus: u16) -> NtruIntPoly {
    if a.is_product() {
        a.get_poly_prod().to_int_poly(modulus)
    } else {
        a.get_poly_tern().to_int_poly()
    }
}

fn rand_int(n: u16, pow2q: u16, rand_ctx: &NtruRandContext) -> NtruIntPoly {
    let rand_data = rand_ctx.get_rng().generate(n*2, rand_ctx).unwrap();
    let shift = if pow2q < 16 { 16 - pow2q } else { u16::max_value() - pow2q + 16 };

    let mut coeffs = vec![0i16; n as usize];
    for i in n..0 {
        coeffs[i as usize] = rand_data[i as usize] as i16 >> shift;
    }
    NtruIntPoly::new(&coeffs.into_boxed_slice())
}

fn verify_inverse(a: &NtruPrivPoly, b: &NtruIntPoly, modulus: u16) -> bool {
    let mut a_int = ntru_priv_to_int(a, modulus);
    a_int.mult_fac(3);
    let new_coeff = a_int.get_coeffs()[0] + 1;
    a_int.set_coeff(0, new_coeff);

    let (mut c, _) = a_int.mult_int(b, modulus-1);
    c.mod_mask(modulus-1);
    c.equals1()
}

#[test]
fn it_mult_int() {
    // Multiplication modulo q
    let a1 = NtruIntPoly::new(&[-1, 1, 1, 0, -1, 0, 1, 0, 0, 1, -1]);
    let b1 = NtruIntPoly::new(&[14, 11, 26, 24, 14, 16, 30, 7, 25, 6, 19]);
    let (c1, _) = a1.mult_int(&b1, 32-1);

    let c1_exp = NtruIntPoly::new(&[3, 25, -10, 21, 10, 7, 6, 7, 5, 29, -7]);
    assert!(c1_exp.equals_mod(&c1, 32));

    // ntru_mult_mod should give the same result as ntru_mult_int_nomod followed by ntru_mod_mask
    let a2 = NtruIntPoly::new(&[1278, 1451, 850, 1071, 942]);
    let b2 = NtruIntPoly::new(&[571, 52, 1096, 1800, 662]);

    let (c2, _) = a2.mult_int(&b2, 2048-1);
    let mut c2_exp = ntru_mult_int_nomod(&a2, &b2);
    c2_exp.mod_mask(2048-1);

    assert!(c2_exp.equals_mod(&c2, 2048));

    let rng = NTRU_RNG_DEFAULT;
    let rand_ctx = ntru::rand::init(&rng).ok().unwrap();

    for _ in 0..10 {
        let n_arr = rand_ctx.get_rng().generate(2, &rand_ctx).ok().unwrap();
        let mut n = u8_arr_to_u16(&n_arr);
        n = 100 + (n % (NTRU_MAX_DEGREE-100) as u16);

        let a3 = NtruIntPoly::rand(n, 11, &rand_ctx);
        let b3 = NtruIntPoly::rand(n, 11, &rand_ctx);
        let mut c3_exp = ntru_mult_int_nomod(&a3, &b3);
        c3_exp.mod_mask(2048-1);

        let (c3, _) = a3.mult_int_16(&b3, 2048-1);
        assert!(c3_exp.equals_mod(&c3, 2048));
        // ifndef __ARMEL__
        let (c3, _) = a3.mult_int_64(&b3, 2048-1);
        assert!(c3_exp.equals_mod(&c3, 2048));
        // endif
    }
}

#[test]
fn it_mult_tern() {
    let rng = NTRU_RNG_DEFAULT;
    let rand_ctx = ntru::rand::init(&rng).unwrap();

    let a = NtruTernPoly::rand(11, 3, 3, &rand_ctx).unwrap();
    let b = rand_int(11, 5, &rand_ctx);

    let a_int = a.to_int_poly();
    let (c_int, _) = a_int.mult_int(&b, 32-1);
    let (c_tern, _) = b.mult_tern_32(&a, 32-1);

    assert!(c_tern.equals_mod(&c_int, 32));

    // #ifndef __ARMEL__
    let (c_tern, _) = b.mult_tern_64(&a, 32-1);
    assert!(c_tern.equals_mod(&c_int, 32));
    // #endif

    // #ifdef __SSSE3__
    let (c_tern, _) = b.mult_tern_sse(&a, 32-1);
    assert!(c_tern.equals_mod(&c_int, 32));
    // #endif

    for _ in 0..10 {
        let mut n = u8_arr_to_u16(&rand_ctx.get_rng().generate(2, &rand_ctx).unwrap());
        n = 100 + (n % (NTRU_MAX_DEGREE as u16 - 100));
        let mut num_ones = u8_arr_to_u16(&rand_ctx.get_rng().generate(2, &rand_ctx)
                                                                 .unwrap());
        num_ones %= n/2;
        num_ones %= NTRU_MAX_ONES as u16;

        let mut num_neg_ones = u8_arr_to_u16(&rand_ctx.get_rng().generate(2, &rand_ctx)
                                                                     .unwrap());
        num_neg_ones %= n/2;
        num_neg_ones %= NTRU_MAX_ONES as u16;

        let a = NtruTernPoly::rand(n, num_ones, num_neg_ones, &rand_ctx).unwrap();
        let b = rand_int(n, 11, &rand_ctx);
        let a_int = a.to_int_poly();

        let c_int = ntru_mult_int_nomod(&a_int, &b);
        let (c_tern, _) = b.mult_tern_32(&a, 2048-1);

        assert!(c_tern.equals_mod(&c_int, 2048));

        // #ifdef __ARMEL__
        let (c_tern, _) = b.mult_tern_64(&a, 2048-1);
        assert!(c_tern.equals_mod(&c_int, 2048));
        // #endif
        // #ifdef __SSSE3__
        let (c_tern, _) = b.mult_tern_sse(&a, 2048-1);
        assert!(c_tern.equals_mod(&c_int, 2048));
        // #endif
    }
}

#[test]
fn it_mult_prod() {
    let rng = NTRU_RNG_DEFAULT;
    let rand_ctx = ntru::rand::init(&rng).unwrap();

    let log_modulus = 11u16;
    let modulus = 1 << log_modulus;

    for _ in 0..10 {
        let a = NtruProdPoly::rand(853, 8, 8, 8, 9, &rand_ctx).unwrap();
        let b = rand_int(853, 1 << log_modulus, &rand_ctx);
        let (c_prod, _) = b.mult_prod(&a, modulus-1);

        let a_int = a.to_int_poly(modulus);
        let (c_int, _) = a_int.mult_int(&b, modulus-1);

        assert!(c_prod.equals_mod(&c_int, log_modulus));
    }
}

#[test]
fn it_inv() {
    let a1 = NtruPrivPoly::new_with_tern_poly(NtruTernPoly::new(11, &[1, 2, 6, 9],
                                                                &[0, 3, 4, 10]));
    let (b1, invertible) = a1.invert_32(32-1);
    assert!(invertible);
    assert!(verify_inverse(&a1, &b1, 32));

    let (b1, invertible) = a1.invert_64(32-1);
    assert!(invertible);
    assert!(verify_inverse(&a1, &b1, 32));

    // Test 3 random polynomials
    let mut num_invertible = 0u16;
    let rng = NTRU_RNG_DEFAULT;
    let rand_ctx = ntru::rand::init(&rng).unwrap();

    while num_invertible < 3 {
        let a2 = NtruPrivPoly::new_with_tern_poly(NtruTernPoly::rand(853, 100, 100,
                                                                     &rand_ctx).unwrap());
        let (b, invertible) = a2.invert(2048-1);

        if invertible {
            assert!(verify_inverse(&a2, &b, 2048));
            num_invertible += 1;
        }
    }

    // #ifdef NTRU_AVOID_HAMMING_WT_PATENT
    num_invertible = 0;
    while num_invertible < 3 {
        let a3 = NtruPrivPoly::new_with_tern_poly(NtruTernPoly::rand(853, 100, 100,
                                                                     &rand_ctx).unwrap());
        let (b, invertible) = a3.invert(2048-1);

        if invertible {
            assert!(verify_inverse(&a3, &b, 2048));
            num_invertible += 1;
        }
    }
    // #endif

    // test a non-invertible polynomial
    let a2 = NtruPrivPoly::new_with_tern_poly(NtruTernPoly::new(11, &[3, 10], &[0, 6, 8]));
    let (_, invertible) = a2.invert(32-1);
    assert!( ! invertible);
}

#[test]
fn it_arr() {
    let params = EES1087EP1;
    let rng = NTRU_RNG_DEFAULT;
    let rand_ctx = ntru::rand::init(&rng).unwrap();
    let p1 = rand_int(params.get_n(), 11, &rand_ctx);
    let a = p1.to_arr_32(&params);

    let p2 = NtruIntPoly::from_arr(&a, params.get_n(), params.get_q());

    assert_eq!(p1, p2);

    let b = p1.to_arr_64(&params);

    assert_eq!(a.len(), b.len());
    for i in 0..a.len() {
        assert_eq!(a[i], b[i]);
    }

    // #ifdef __SSSE3__
    let b = p1.to_arr_sse_2048(&params);

    assert_eq!(a.len(), b.len());
    for i in 0..a.len() {
        assert_eq!(a[i], b[i]);
    }
    // #endif
}
