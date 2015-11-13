extern crate ntru;
use ntru::types::{NtruIntPoly, NtruPrivPoly};
use ntru::encparams::{NTRU_INT_POLY_SIZE, NTRU_MAX_DEGREE};
use ntru::rand::NTRU_RNG_DEFAULT;

fn ntru_mult_int_nomod(a: &NtruIntPoly, b: &NtruIntPoly) -> NtruIntPoly {
    if a.get_n() != b.get_n() { panic!("Incompatible int polys") }
    let n = a.get_n() as usize;

    let mut coeffs = [0i16; NTRU_INT_POLY_SIZE];
    for k in 0..n {
        let mut ck = 0i32;
        for i in 0..n {
            ck += b.get_coeffs()[i] as i32 * a.get_coeffs()[((n+k-i)%n)] as i32;
        }
        coeffs[k] = ck as i16;
    }

    NtruIntPoly::new(n as u16, &coeffs)
}

fn u8_arr_to_u16(arr: &[u8]) -> u16 {
    if arr.len() != 2 { panic!("u8_arr_to_u16() requires an array of 2 elements") }
    ((arr[0] as u16) << 8) + arr[1] as u16
}

#[test]
fn it_mult_int() {
    // Multiplication modulo q
    let a1 = NtruIntPoly::new(11, &[-1, 1, 1, 0, -1, 0, 1, 0, 0, 1, -1]);
    let b1 = NtruIntPoly::new(11, &[14, 11, 26, 24, 14, 16, 30, 7, 25, 6, 19]);
    let (c1, _) = a1.mult_int(&b1, 32-1);

    let c1_exp = NtruIntPoly::new(11, &[3, 25, -10, 21, 10, 7, 6, 7, 5, 29, -7]);
    assert!(c1_exp.equals_mod(&c1, 32));

    // ntru_mult_mod should give the same result as ntru_mult_int_nomod followed by ntru_mod_mask
    let a2 = NtruIntPoly::new(5, &[1278, 1451, 850, 1071, 942]);
    let b2 = NtruIntPoly::new(5, &[571, 52, 1096, 1800, 662]);

    let (c2, _) = a2.mult_int(&b2, 2048-1);
    let mut c2_exp = ntru_mult_int_nomod(&a2, &b2);
    c2_exp.mod_mask(2048-1);

    assert!(c2_exp.equals_mod(&c2, 2048));

    let rng = NTRU_RNG_DEFAULT;
    let rand_ctx = ntru::rand::init(&rng).ok().unwrap();

    for _ in 0..10 {
        let n_arr = rand_ctx.get_rand_gen().generate(2, &rand_ctx).ok().unwrap();
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
fn test_mult_tern() {
//     NtruRandGen rng = NTRU_RNG_DEFAULT;
//     NtruRandContext rand_ctx;
//     uint8_t valid = ntru_rand_init(&rand_ctx, &rng) == NTRU_SUCCESS;
//
//     NtruTernPoly a;
//     valid &= ntru_rand_tern(11, 3, 3, &a, &rand_ctx);
//     NtruIntPoly b;
//     valid &= rand_int(11, 5, &b, &rand_ctx);
//     NtruIntPoly a_int;
//     ntru_tern_to_int(&a, &a_int);
//     NtruIntPoly c_int;
//     ntru_mult_int(&a_int, &b, &c_int, 32-1);
//     NtruIntPoly c_tern;
//     ntru_mult_tern_32(&b, &a, &c_tern, 32-1);
//     valid &= equals_int_mod(&c_tern, &c_int, 32);
// #ifndef __ARMEL__
//     ntru_mult_tern_64(&b, &a, &c_tern, 32-1);
//     valid &= equals_int_mod(&c_tern, &c_int, 32);
// #endif
// #ifdef __SSSE3__
//     ntru_mult_tern_sse(&b, &a, &c_tern, 32-1);
//     valid &= equals_int_mod(&c_tern, &c_int, 32);
// #endif
//
//     int i;
//     for (i=0; i<10; i++) {
//         uint16_t N;
//         valid &= rand_ctx.rand_gen->generate((uint8_t*)&N, sizeof N, &rand_ctx);
//         N = 100 + (N%(NTRU_MAX_DEGREE-100));
//         uint16_t num_ones;
//         valid &= rand_ctx.rand_gen->generate((uint8_t*)&num_ones, sizeof num_ones, &rand_ctx);
//         num_ones %= N/2;
//         num_ones %= NTRU_MAX_ONES;
//         uint16_t num_neg_ones;
//         valid &= rand_ctx.rand_gen->generate((uint8_t*)&num_neg_ones, sizeof num_neg_ones, &rand_ctx);
//         num_neg_ones %= N/2;
//         num_neg_ones %= NTRU_MAX_ONES;
//         valid &= ntru_rand_tern(N, num_ones, num_neg_ones, &a, &rand_ctx);
//         valid &= rand_int(N, 11, &b, &rand_ctx);
//         ntru_tern_to_int(&a, &a_int);
//         ntru_mult_int_nomod(&a_int, &b, &c_int);
//         ntru_mult_tern_32(&b, &a, &c_tern, 2048-1);
//         valid &= equals_int_mod(&c_tern, &c_int, 2048);
// #ifndef __ARMEL__
//         ntru_mult_tern_64(&b, &a, &c_tern, 2048-1);
//         valid &= equals_int_mod(&c_tern, &c_int, 2048);
// #endif
// #ifdef __SSSE3__
//         ntru_mult_tern_sse(&b, &a, &c_tern, 2048-1);
//         valid &= equals_int_mod(&c_tern, &c_int, 2048);
// #endif
//     }
//
//     valid &= ntru_rand_release(&rand_ctx) == NTRU_SUCCESS;
//
//     print_result("test_mult_tern", valid);
//     return valid;
}

#[test]
fn test_mult_prod() {
    // uint8_t valid = 1;
    // uint16_t i;
    // NtruRandGen rng = NTRU_RNG_DEFAULT;
    // NtruRandContext rand_ctx;
    // valid &= ntru_rand_init(&rand_ctx, &rng) == NTRU_SUCCESS;
    // uint16_t log_modulus = 11;
    // uint16_t modulus = 1 << log_modulus;
    // for (i=0; i<10; i++) {
    //     NtruProdPoly a;
    //     valid &= ntru_rand_prod(853, 8, 8, 8, 9, &a, &rand_ctx);
    //     NtruIntPoly b;
    //     valid &= rand_int(853, 1<<log_modulus, &b, &rand_ctx);
    //     NtruIntPoly c_prod;
    //     ntru_mult_prod(&b, &a, &c_prod, modulus-1);
    //     NtruIntPoly a_int;
    //     ntru_prod_to_int(&a, &a_int, modulus);
    //     NtruIntPoly c_int;
    //     ntru_mult_int(&a_int, &b, &c_int, modulus-1);
    //     valid &= equals_int_mod(&c_prod, &c_int, log_modulus);
    // }
    // valid &= ntru_rand_release(&rand_ctx) == NTRU_SUCCESS;
    //
    // print_result("test_mult_prod", valid);
    // return valid;
}

// fn verify_inverse(a: &NtruPrivPoly, b: &NtruIntPoly, modulus: u16) -> bool {
//     let mut a_int = a.to_int(modulus);
//     a_int.mult_fac(3);
//     a_int.set_coeff(0, a_int.get_coeffs()[0] + 1);
//
//     let mut c = a_int.mult_int(b, modulus-1);
//     c.mod_mask(modulus-1);
//     assert_eq!(&c, 1);

    // NtruIntPoly c, a_int;
    //
    // ntru_priv_to_int(a, &a_int, modulus);
    // ntru_mult_fac(&a_int, 3);
    // a_int.coeffs[0] += 1;
    //
    // ntru_mult_int(&a_int, b, &c, modulus-1);
    // ntru_mod_mask(&c, modulus-1);
    // return ntru_equals1(&c);
// }

#[test]
fn test_inv() {
    // TODO
}

#[test]
fn test_arr() {
    // TODO
}