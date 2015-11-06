extern crate ntru;
use ntru::types::NtruIntPoly;
use ntru::encparams::NTRU_INT_POLY_SIZE;

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

//     NtruRandGen rng = NTRU_RNG_DEFAULT;
//     NtruRandContext rand_ctx;
//     valid &= ntru_rand_init(&rand_ctx, &rng) == NTRU_SUCCESS;
//     int i;
//     for (i=0; i<10; i++) {
//         uint16_t N;
//         valid &= rand_ctx.rand_gen->generate((uint8_t*)&N, sizeof N, &rand_ctx);
//         N = 100 + (N%(NTRU_MAX_DEGREE-100));
//         NtruIntPoly a3, b3, c3, c3_exp;
//         valid &= rand_int(N, 11, &a3, &rand_ctx);
//         valid &= rand_int(N, 11, &b3, &rand_ctx);
//         valid &= ntru_mult_int_nomod(&a3, &b3, &c3_exp);
//         ntru_mod_mask(&c3_exp, 2048-1);
//         valid &= ntru_mult_int_16(&a3, &b3, &c3, 2048-1);
//         valid &= equals_int_mod(&c3_exp, &c3, 2048);
// #ifndef __ARMEL__
//         valid &= ntru_mult_int_64(&a3, &b3, &c3, 2048-1);
//         valid &= equals_int_mod(&c3_exp, &c3, 2048);
// #endif
//     }
//
//     valid &= ntru_rand_release(&rand_ctx) == NTRU_SUCCESS;
//     print_result("test_mult_int", valid);
//     return valid;
}
