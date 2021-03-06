#![forbid(missing_docs, warnings)]
#![deny(deprecated, improper_ctypes, non_shorthand_field_patterns, overflowing_literals,
    plugin_as_library, private_no_mangle_fns, private_no_mangle_statics, stable_features,
    unconditional_recursion, unknown_lints, unsafe_code, unused, unused_allocation,
    unused_attributes, unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates, unused_import_braces,
    unused_qualifications, unused_results, variant_size_differences)]

extern crate ntru;
use ntru::encparams::{EES439EP1, EES1087EP2, ALL_PARAM_SETS};
use ntru::rand::RNG_DEFAULT;
use ntru::types::{PublicKey, PrivateKey, PrivPoly, IntPoly};

fn ntru_priv_to_int(a: &PrivPoly, modulus: u16) -> IntPoly {
    if a.is_product() {
        a.get_poly_prod().to_int_poly(modulus)
    } else {
        a.get_poly_tern().to_int_poly()
    }
}

#[test]
fn it_export_import() {
    let param_arr = [EES439EP1, EES1087EP2];

    for params in &param_arr {
        let rng = RNG_DEFAULT;
        let rand_ctx = ntru::rand::init(&rng).unwrap();
        let kp = ntru::generate_key_pair(params, &rand_ctx).unwrap();

        // Test public key
        let pub_arr = kp.get_public().export(params);
        let imp_pub = PublicKey::import(&pub_arr);
        assert_eq!(kp.get_public().get_h(), imp_pub.get_h());

        // Test private key
        let priv_arr = kp.get_private().export(params);
        let imp_priv = PrivateKey::import(&priv_arr);

        let t_int1 = ntru_priv_to_int(imp_priv.get_t(), params.get_q());
        let t_int2 = ntru_priv_to_int(kp.get_private().get_t(), params.get_q());

        assert_eq!(t_int1, t_int2);
    }
}

#[test]
fn it_params_from_key() {
    let param_arr = ALL_PARAM_SETS;

    for params in &param_arr {
        let rng = RNG_DEFAULT;
        let rand_ctx = ntru::rand::init(&rng).unwrap();

        let kp = ntru::generate_key_pair(params, &rand_ctx).unwrap();

        let params2 = kp.get_private().get_params().unwrap();
        assert_eq!(params, &params2);
    }

    for (i, params1) in param_arr.iter().enumerate() {
        for (j, params2) in param_arr.iter().enumerate() {
            if params1 == params2 {
                assert_eq!(i, j);
            } else {
                assert!(i != j);
            }
        }
    }
}
