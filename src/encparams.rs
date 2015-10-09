use libc::{c_char, c_void, uint16_t, uint8_t};
use ffi::{ntru_sha1, ntru_sha1_4way, ntru_sha256, ntru_sha256_4way};

/// Max N value for all param sets; +1 for ntru_invert_...()
pub const NTRU_MAX_DEGREE: usize = (1499+1);
/// (Max #coefficients + 16) rounded to a multiple of 8
pub const NTRU_INT_POLY_SIZE: usize = ((NTRU_MAX_DEGREE+16+7)&0xFFF8);
/// max(df1, df2, df3, dg)
pub const NTRU_MAX_ONES: usize = 499;

/// A set of parameters for NtruEncrypt
#[repr(C)]
pub struct NtruEncParams {
    /// Name of the parameter set
    name: [c_char; 11],
    /// Number of polynomial coefficients
    n: u16,
    /// Modulus
    q: u16,
    /// Product flag, 1 for product-form private keys, 0 for ternary
    prod_flag: u8,
    /// Number of ones in the private polynomial f1 (if prod=1) or f (if prod=0)
    df1: u16,
    /// Number of ones in the private polynomial f2; ignored if prod=0
    df2: u16,
    /// Number of ones in the private polynomial f3; ignored if prod=0
    df3: u16,
    /// Minimum acceptable number of -1's, 0's, and 1's in the polynomial m' in the last encryption
    /// step
    dm0: u16,
    /// Number of random bits to prepend to the message
    db: u16,
    /// A parameter for the Index Generation Function
    c: u16,
    /// Minimum number of hash calls for the IGF to make
    min_calls_r: u16,
    /// Minimum number of calls to generate the masking polynomial
    min_calls_mask: u16,
    /// Whether to hash the seed in the MGF first (1) or use the seed directly (0)
    hash_seed: u8,
    /// Three bytes that uniquely identify the parameter set
    oid: [u8; 3],
    /// Hash function, e.g. ntru_sha256
    hash: unsafe extern fn(input: *const uint8_t, input_len: uint16_t, digest: *mut uint8_t)
                            -> c_void,
    /// Hash function for 4 inputs, e.g. ntru_sha256_4way
    hash_4way: unsafe extern fn(input: *const *const uint8_t, input_len: uint16_t,
                                digest: *mut *mut uint8_t) -> c_void,
    /// output length of the hash function
    hlen: u16,
    /// number of bits of the public key to hash
    pklen: u16,
}

// /// Produce a `CStr` reference out of a static string literal.
// ///
// /// This macro provides a convenient way to use string literals in
// /// expressions where a `CStr` reference is expected.
// /// The macro parameter does not need to end with `"\0"`, it is
// /// appended by the macro.
// ///
// /// # Example
// ///
// /// ```rust
// ///
// /// #[macro_use]
// /// extern crate c_string;
// ///
// /// extern crate libc;
// ///
// /// fn main() {
// ///     unsafe { libc::puts(c_str!("Hello, world!").as_ptr()) };
// /// }
// /// ```
// #[macro_export]
// macro_rules! c_str {
//     ($lit:expr) => {
//         // Currently, there is no working way to concatenate a byte string
//         // literal out of bytestring or string literals. Otherwise, we could
//         // use from_static_bytes and accept byte strings as well.
//         // See https://github.com/rust-lang/rfcs/pull/566
//         unsafe {
//             CStr::from_ptr(concat!($lit, "\0").as_ptr() as *const c_char)
//         }
//     }
// }

const EES401EP1: NtruEncParams = NtruEncParams {
    name: [69, 69, 83, 52, 48, 49, 69, 80, 49, 0, 0], // EES401EP1
    n: 401,
    q: 2048,
    prod_flag: 0,
    df1: 113, df2: 0, df3: 0,
    dm0: 113,
    db: 112,
    c: 11,
    min_calls_r: 32,
    min_calls_mask: 9,
    hash_seed: 1,
    oid: [0, 2, 4],
    hash: ntru_sha1,
    hash_4way: ntru_sha1_4way,
    hlen: 20,
    pklen: 114,
};

const EES449EP1: NtruEncParams = NtruEncParams {
    name: [69, 69, 83, 52, 52, 57, 69, 80, 49, 0, 0], // EES449EP1
    n: 449,
    q: 2048,
    prod_flag: 0,
    df1: 134,
    df2: 0,
    df3: 0,
    dm0: 134,
    db: 128,
    c: 9,
    min_calls_r: 31,
    min_calls_mask: 9,
    hash_seed: 1,
    oid: [0, 3, 3],
    hash: ntru_sha1,
    hash_4way: ntru_sha1_4way,
    hlen: 20,
    pklen: 128,
};

const EES677EP1: NtruEncParams = NtruEncParams {
    name: [69, 69, 83, 54, 55, 55, 69, 80, 49, 0, 0], // EES677EP1
    n: 677,
    q: 2048,
    prod_flag: 0,
    df1: 157,
    df2: 0,
    df3: 0,
    dm0: 157,
    db: 192,
    c: 11,
    min_calls_r: 27,
    min_calls_mask: 9,
    hash_seed: 1,
    oid: [0, 5, 3],
    hash: ntru_sha256,
    hash_4way: ntru_sha256_4way,
    hlen: 32,
    pklen: 192,
};

const EES1087EP2: NtruEncParams = NtruEncParams {
    name: [69, 69, 83, 49, 48, 56, 55, 69, 80, 50, 0], // EES1087EP2
    n: 1087,
    q: 2048,
    prod_flag: 0,
    df1: 120,
    df2: 0,
    df3: 0,
    dm0: 120,
    db: 256,
    c: 13,
    min_calls_r: 25,
    min_calls_mask: 14,
    hash_seed: 1,
    oid: [0, 6, 3],
    hash: ntru_sha256,
    hash_4way: ntru_sha256_4way,
    hlen: 32,
    pklen: 256,
};

const EES541EP1: NtruEncParams = NtruEncParams {
    name: [69, 69, 83, 53, 52, 49, 69, 80, 49, 0, 0], // EES541EP1
    n: 541,
    q: 2048,
    prod_flag: 0,
    df1: 49,
    df2: 0,
    df3: 0,
    dm0: 49,
    db: 112,
    c: 12,
    min_calls_r: 15,
    min_calls_mask: 11,
    hash_seed: 1,
    oid: [0, 2, 5],
    hash: ntru_sha1,
    hash_4way: ntru_sha1_4way,
    hlen: 20,
    pklen: 112,
};

const EES613EP1: NtruEncParams = NtruEncParams {
    name: [69, 69, 83, 54, 49, 51, 69, 80, 49, 0, 0], // EES613EP1
    n: 613,
    q: 2048,
    prod_flag: 0,
    df1: 55,
    df2: 0,
    df3: 0,
    dm0: 55,
    db: 128,
    c: 11,
    min_calls_r: 16,
    min_calls_mask: 13,
    hash_seed: 1,
    oid: [0, 3, 4],
    hash: ntru_sha1,
    hash_4way: ntru_sha1_4way,
    hlen: 20,
    pklen: 128,
};

const EES887EP1: NtruEncParams = NtruEncParams {
    name: [69, 69, 83, 56, 56, 55, 69, 80, 49, 0, 0], // EES887EP1
    n: 887,
    q: 2048,
    prod_flag: 0,
    df1: 81,
    df2: 0,
    df3: 0,
    dm0: 81,
    db: 192,
    c: 10,
    min_calls_r: 13,
    min_calls_mask: 12,
    hash_seed: 1,
    oid: [0, 5, 4],
    hash: ntru_sha256,
    hash_4way: ntru_sha256_4way,
    hlen: 32,
    pklen: 192,
};

const EES1171EP1: NtruEncParams = NtruEncParams {
    name: [69, 69, 83, 49, 49, 55, 49, 69, 80, 49, 0], // EES1171EP1
    n: 1171,
    q: 2048,
    prod_flag: 0,
    df1: 106,
    df2: 0,
    df3: 0,
    dm0: 106,
    db: 256,
    c: 12,
    min_calls_r: 20,
    min_calls_mask: 15,
    hash_seed: 1,
    oid: [0, 6, 4],
    hash: ntru_sha256,
    hash_4way: ntru_sha256_4way,
    hlen: 32,
    pklen: 256,
};

const EES659EP1: NtruEncParams = NtruEncParams {
    name: [69, 69, 83, 54, 53, 57, 69, 80, 49, 0, 0], // EES659EP1
    n: 659,
    q: 2048,
    prod_flag: 0,
    df1: 38,
    df2: 0,
    df3: 0,
    dm0: 38,
    db: 112,
    c: 11,
    min_calls_r: 11,
    min_calls_mask: 14,
    hash_seed: 1,
    oid: [0, 2, 6],
    hash: ntru_sha1,
    hash_4way: ntru_sha1_4way,
    hlen: 20,
    pklen: 112,
};

const EES761EP1: NtruEncParams = NtruEncParams {
    name: [69, 69, 83, 55, 54, 49, 69, 80, 49, 0, 0], // EES761EP1
    n: 761,
    q: 2048,
    prod_flag: 0,
    df1: 42,
    df2: 0,
    df3: 0,
    dm0: 42,
    db: 128,
    c: 12,
    min_calls_r: 13,
    min_calls_mask: 16,
    hash_seed: 1,
    oid: [0, 3, 5],
    hash: ntru_sha1,
    hash_4way: ntru_sha1_4way,
    hlen: 20,
    pklen: 128,
};

const EES1087EP1: NtruEncParams = NtruEncParams {
    name: [69, 69, 83, 49, 48, 56, 55, 69, 80, 49, 0], // EES1087EP1
    n: 1087,
    q: 2048,
    prod_flag: 0,
    df1: 63,
    df2: 0,
    df3: 0,
    dm0: 63,
    db: 192,
    c: 13,
    min_calls_r: 13,
    min_calls_mask: 14,
    hash_seed: 1,
    oid: [0, 5, 5],
    hash: ntru_sha256,
    hash_4way: ntru_sha256_4way,
    hlen: 32,
    pklen: 192,
};

const EES1499EP1: NtruEncParams = NtruEncParams {
    name: [69, 69, 83, 49, 52, 57, 57, 69, 80, 49, 0], // EES1499EP1
    n: 1499,
    q: 2048,
    prod_flag: 0,
    df1: 79,
    df2: 0,
    df3: 0,
    dm0: 79,
    db: 256,
    c: 13,
    min_calls_r: 17,
    min_calls_mask: 19,
    hash_seed: 1,
    oid: [0, 6, 5],
    hash: ntru_sha256,
    hash_4way: ntru_sha256_4way,
    hlen: 32,
    pklen: 256,
};

const EES401EP2: NtruEncParams = NtruEncParams {
    name: [69, 69, 83, 52, 48, 49, 69, 80, 50, 0, 0], // EES401EP2
    n: 401,
    q: 2048,
    prod_flag: 1,
    df1: 8,
    df2: 8,
    df3: 6,
    dm0: 101,
    db: 112,
    c: 11,
    min_calls_r: 10,
    min_calls_mask: 6,
    hash_seed: 1,
    oid: [0, 2, 16],
    hash: ntru_sha1,
    hash_4way: ntru_sha1_4way,
    hlen: 20,
    pklen: 112,
};

const EES439EP1: NtruEncParams = NtruEncParams {
    name: [69, 69, 83, 52, 51, 57, 69, 80, 49, 0, 0], // EES439EP1
    n: 439,
    q: 2048,
    prod_flag: 1,
    df1: 9,
    df2: 8,
    df3: 5,
    dm0: 112,
    db: 128,
    c: 9,
    min_calls_r: 15,
    min_calls_mask: 6,
    hash_seed: 1,
    oid: [0, 3, 16],
    hash: ntru_sha1,
    hash_4way: ntru_sha1_4way,
    hlen: 20,
    pklen: 128,
};

const EES593EP1: NtruEncParams = NtruEncParams {
    name: [69, 69, 83, 53, 57, 51, 69, 80, 49, 0, 0], // EES593EP1
    n: 593,
    q: 2048,
    prod_flag: 1,
    df1: 10,
    df2: 10,
    df3: 8,
    dm0: 158,
    db: 192,
    c: 11,
    min_calls_r: 12,
    min_calls_mask: 5,
    hash_seed: 1,
    oid: [0, 5, 16],
    hash: ntru_sha256,
    hash_4way: ntru_sha256_4way,
    hlen: 32,
    pklen: 192,
};

const EES743EP1: NtruEncParams = NtruEncParams {
    name: [69, 69, 83, 55, 52, 51, 69, 80, 49, 0, 0], // EES743EP1
    n: 743,
    q: 2048,
    prod_flag: 1,
    df1: 11,
    df2: 11,
    df3: 15,
    dm0: 204,
    db: 256,
    c: 13,
    min_calls_r: 12,
    min_calls_mask: 7,
    hash_seed: 1,
    oid: [0, 6, 16],
    hash: ntru_sha256,
    hash_4way: ntru_sha256_4way,
    hlen: 32,
    pklen: 256,
};

// uint16_t ntru_enc_len(const NtruEncParams *params) {
//     return ntru_enc_len_Nq(params->N, params->q);
// }
//
// uint16_t ntru_enc_len_Nq(uint16_t N, uint16_t q) {
//     /* make sure q is a power of 2 */
//     if (q & (q-1))
//         return 0;
//
//     uint16_t len_bits = N * ntru_log2(q);
//     uint16_t len_bytes = (len_bits+7) / 8;
//     return len_bytes;
// }

pub const ALL_PARAM_SETS: [NtruEncParams; 16] = [EES401EP1, EES449EP1, EES677EP1, EES1087EP2,
                                            EES541EP1, EES613EP1, EES887EP1, EES1171EP1, EES659EP1,
                                            EES761EP1, EES1087EP1, EES1499EP1, EES401EP2,
                                            EES439EP1, EES593EP1, EES743EP1];
