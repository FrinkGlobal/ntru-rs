extern crate ntru;

use ntru::encparams::ALL_PARAM_SETS;
use ntru::rand::NTRU_RNG_DEFAULT;
use ntru::types::{NtruIntPoly, NtruTernPoly, NtruEncPrivKey};

fn encrypt_poly(m: NtruIntPoly, r: &NtruTernPoly, h: &NtruIntPoly, q: u16) -> NtruIntPoly {
    let (mut e, _) = h.mult_tern(r, q);
    println!("{:?}", h);
    e = e + m;
    e.mod_mask(q-1);
    e
}

fn decrypt_poly(e: NtruIntPoly, private: &NtruEncPrivKey, modulus: u16)  -> NtruIntPoly {
    let (mut d, _) = e.mult_prod(private.get_t().get_poly().get_prod(), modulus-1);
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

#[test]
fn it_keygen() {
    let param_arr = &ALL_PARAM_SETS;

    for params in param_arr {
        let mut rand_ctx = ntru::rand::init(&NTRU_RNG_DEFAULT).ok().unwrap();
        let kp = ntru::gen_key_pair(&params, &rand_ctx).ok().unwrap();
        println!("{:?}", kp);

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

        // /* test deterministic key generation */
        // valid &= gen_key_pair("my test password", &params, &kp) == NTRU_SUCCESS;
        // char seed2_char[19];
        // strcpy(seed2_char, "my test password");
        // uint8_t seed2[strlen(seed2_char)];
        // str_to_uint8(seed2_char, seed2);
        // NtruEncKeyPair kp2;
        // NtruRandGen rng = NTRU_RNG_IGF2;
        // NtruRandContext rand_ctx2;
        // ntru_rand_init_det(&rand_ctx2, &rng, seed2, strlen(seed2_char));
        // valid &= ntru_gen_key_pair(&params, &kp2, &rand_ctx2) == NTRU_SUCCESS;
        // ntru_rand_release(&rand_ctx2);
        // valid &= equals_key_pair(&kp, &kp2);
    }
}
