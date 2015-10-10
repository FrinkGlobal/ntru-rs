extern crate ntru;

use ntru::encparams::ALL_PARAM_SETS;
use ntru::rand::NTRU_RNG_DEFAULT;
use ntru::types::{NtruIntPoly, NtruTernPoly, NtruEncKeyPair};

fn encrypt_poly(m: NtruIntPoly, r: &NtruTernPoly, h: &NtruIntPoly, q: u16) -> NtruIntPoly {
    let (e, _) = ntru::mult_tern(h, r, q);
    (e + m).mod_mask(q-1)
}

#[test]
fn it_keygen() {
    let param_arr = &ALL_PARAM_SETS;

    for params in param_arr {
        let kp: NtruEncKeyPair = Default::default();
        let mut rand_ctx = ntru::rand::init(&NTRU_RNG_DEFAULT).ok().unwrap();

        // Encrypt a random message
        let m = ntru::rand::tern(params.get_n(), params.get_n()/3, params.get_n()/3,
                                    &rand_ctx).unwrap();
        let m_int = m.to_int_poly();

        let r = ntru::rand::tern(params.get_n(), params.get_n()/3, params.get_n()/3,
                                    &rand_ctx).unwrap();
        rand_ctx.release();

        let e = encrypt_poly(m_int, &r, &kp.get_public().get_h(), params.get_q());
    }
}
