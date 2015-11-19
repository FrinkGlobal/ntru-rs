extern crate ntru;
use ntru::encparams::{EES439EP1, EES1087EP2, ALL_PARAM_SETS};
use ntru::rand::NTRU_RNG_DEFAULT;
use ntru::types::{NtruEncPubKey, NtruEncPrivKey, NtruPrivPoly, NtruIntPoly};

fn ntru_priv_to_int(a: &NtruPrivPoly, modulus: u16) -> NtruIntPoly {
    if a.get_prod_flag() != 0 {
        a.get_poly_prod().to_int_poly(modulus)
    } else {
        a.get_poly_tern().to_int_poly()
    }
}

#[test]
fn it_export_import() {
    // #ifndef NTRU_AVOID_HAMMING_WT_PATENT
    let param_arr = [EES439EP1, EES1087EP2];
    // #else
    // NtruEncParams param_arr[] = {EES1087EP2};
    // #endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

    for params in param_arr.into_iter() {
        let rng = NTRU_RNG_DEFAULT;
        let rand_ctx = ntru::rand::init(&rng).unwrap();
        let kp = ntru::generate_key_pair(&params, &rand_ctx).unwrap();

        // Test public key
        let pub_arr = kp.get_public().export(&params);
        let imp_pub = NtruEncPubKey::import(&pub_arr);
        assert_eq!(kp.get_public().get_h(), imp_pub.get_h());

        // Test private key
        let priv_arr = kp.get_private().export(&params);
        let imp_priv = NtruEncPrivKey::import(&priv_arr);

        let t_int1 = ntru_priv_to_int(imp_priv.get_t(), params.get_q());
        let t_int2 = ntru_priv_to_int(kp.get_private().get_t(), params.get_q());

        assert_eq!(t_int1, t_int2);
    }
}

#[test]
fn it_params_from_key() {
    let param_arr = ALL_PARAM_SETS;

    for params in param_arr.into_iter() {
        let rng = NTRU_RNG_DEFAULT;
        let rand_ctx = ntru::rand::init(&rng).unwrap();

        let kp = ntru::generate_key_pair(&params, &rand_ctx).unwrap();

        let params2 = kp.get_private().get_params().unwrap();
        assert_eq!(params, &params2);
    }

    for i in 0..param_arr.len() {
        let params1 = &param_arr[i];

        for j in 0..param_arr.len() {
            let params2 = &param_arr[j];
            if params1 == params2 {
                assert_eq!(i, j);
            } else {
                assert!(i != j);
            }
        }
    }
}
