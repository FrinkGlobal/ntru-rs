extern crate ntru;
use ntru::types::NtruIntPoly;
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
