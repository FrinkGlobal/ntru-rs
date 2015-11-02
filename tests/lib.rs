extern crate ntru;

use ntru::encparams::{NtruEncParams, ALL_PARAM_SETS};
use ntru::rand::{NtruRandGen, NTRU_RNG_DEFAULT, NTRU_RNG_IGF2};
use ntru::types::{NtruIntPoly, NtruTernPoly, NtruEncPrivKey, NtruEncKeyPair};

fn encrypt_poly(m: NtruIntPoly, r: &NtruTernPoly, h: &NtruIntPoly, q: u16) -> NtruIntPoly {
    let (mut e, _) = h.mult_tern(r, q);
    e = e + m;
    e.mod_mask(q-1);
    e
}

fn decrypt_poly(e: NtruIntPoly, private: &NtruEncPrivKey, modulus: u16)  -> NtruIntPoly {
    let (mut d, _) = if private.get_t().get_prod_flag() > 0 {
        e.mult_prod(private.get_t().get_poly_prod(), modulus-1)
    } else {
        e.mult_tern(private.get_t().get_poly_tern(), modulus-1)
    };
    d.mod_mask(modulus-1);
    d.mult_fac(3);
    d = d + e;
    d.mod_center(modulus);
    d.mod3();
    for i in 0..d.get_n() {
        if d.get_coeffs()[i as usize] == 2 { d.set_coeff(i as usize, -1)}
    }
    d
}

fn gen_key_pair(seed: &str, params: &NtruEncParams) -> NtruEncKeyPair {
    let seed_u8 = seed.as_bytes();
    let rng = NTRU_RNG_IGF2;
    let mut rand_ctx = ntru::rand::init_det(&rng, seed_u8).ok().unwrap();
    rand_ctx.set_seed(seed_u8);

    let kp = ntru::gen_key_pair(params, &rand_ctx).ok().unwrap();
    rand_ctx.release();
    kp
}

#[test]
fn it_keygen() {
    let param_arr = &ALL_PARAM_SETS;

    for params in param_arr {
        let mut rand_ctx = ntru::rand::init(&NTRU_RNG_DEFAULT).ok().unwrap();
        let mut kp = ntru::gen_key_pair(&params, &rand_ctx).ok().unwrap();

        // Encrypt a random message
        let m = ntru::rand::tern(params.get_n(), params.get_n()/3, params.get_n()/3,
                                    &rand_ctx).unwrap();
        let m_int = m.to_int_poly();

        let r = ntru::rand::tern(params.get_n(), params.get_n()/3, params.get_n()/3,
                                    &rand_ctx).unwrap();
        rand_ctx.release();

        let e = encrypt_poly(m_int, &r, &kp.get_public().get_h(), params.get_q());

        // Decrypt and verify
        let c = decrypt_poly(e, &kp.get_private(), params.get_q());
        assert_eq!(m_int, c);

        // Test deterministic key generation
        kp = gen_key_pair("my test password", &params);
        let rng: NtruRandGen = NTRU_RNG_IGF2;
        let mut rand_ctx2 = ntru::rand::init_det(&rng, b"my test password").ok().unwrap();
        let kp2 = ntru::gen_key_pair(&params, &rand_ctx2).ok().unwrap();
        rand_ctx2.release();

        assert_eq!(kp, kp2);
    }
}
