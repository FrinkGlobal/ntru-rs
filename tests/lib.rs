extern crate ntru;

use ntru::generate_key_pair;
use ntru::encparams::ALL_PARAM_SETS;
use ntru::rand::NTRU_RNG_DEFAULT;
use ntru::types::NtruEncKeyPair;

#[test]
fn it_keygen() {
    let param_arr = &ALL_PARAM_SETS;
    let valid = 1i8;

    for params in param_arr {
        let kp: NtruEncKeyPair = Default::default();
        let mut rand_ctx = ntru::rand::init(&NTRU_RNG_DEFAULT).ok().unwrap();
        // TODO
    }
}
