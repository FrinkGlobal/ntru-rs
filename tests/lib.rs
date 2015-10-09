extern crate ntru;

use ntru::generate_key_pair;
use ntru::encparams::ALL_PARAM_SETS;
use ntru::rand::NTRU_RNG_DEFAULT;
use ntru::types::NtruEncKeyPair;

// fn encrypt_poly(m: &NtruIntPoly, r: &NtruTernPoly, h: &NtruIntPoly, q: u16) -> NtruIntPoly {
//     ntru_mult_tern(h, r, e, q);
//     ntru_add_int(e, m);
//     ntru_mod_mask(e, q-1);
// }

#[test]
fn it_keygen() {
    let param_arr = &ALL_PARAM_SETS;
    let valid = 1i8;

    for params in param_arr {
        let kp: NtruEncKeyPair = Default::default();
        let mut rand_ctx = ntru::rand::init(&NTRU_RNG_DEFAULT).ok().unwrap();

        // Encrypt a random message
        let m = ntru::rand::tern(params.get_n(), params.get_n()/3, params.get_n()/3,
                                    &rand_ctx).unwrap();
        let m_int = m.to_int_poly();

        let r = ntru::rand::tern(params.get_n(), params.get_n()/3, params.get_n()/3,
                                    &rand_ctx).unwrap();

        //let e = encrypt_poly(&m_int, &r, &kp.get_pub().get_h(), params.get_q());
    }
}
