//! NTRU encryption parameters
//!
//! This module contains the parameters for NTRU encryption. Theese parameters must be used when
//! encrypting, decrypting and generating key pairs. The recomendation is to use the default
//! parameters for each level of security, and not use the deprecated parameters. The recommended
//! parameters are the following:
//!
//! * `DEFAULT_PARAMS_112_BITS` for 112 bits of security.
//! * `DEFAULT_PARAMS_128_BITS` for 128 bits of security.
//! * `DEFAULT_PARAMS_192_BITS` for 192 bits of security.
//! * `DEFAULT_PARAMS_256_BITS` for 256 bits of security.
//!
use libc::{c_char, uint16_t, uint8_t};
use std::fmt;
use super::ffi;

/// A set of parameters for NTRU encryption
#[repr(C)]
pub struct EncParams {
    /// Name of the parameter set
    name: [c_char; 11],
    /// Number of polynomial coefficients
    n: uint16_t,
    /// Modulus
    q: uint16_t,
    /// Product flag, 1 for product-form private keys, 0 for ternary
    prod_flag: uint8_t,
    /// Number of ones in the private polynomial f1 (if prod=1) or f (if prod=0)
    df1: uint16_t,
    /// Number of ones in the private polynomial f2; ignored if prod=0
    df2: uint16_t,
    /// Number of ones in the private polynomial f3; ignored if prod=0
    df3: uint16_t,
    /// Number of ones in the polynomial g (used during key generation)
    dg: uint16_t,
    /// Minimum acceptable number of -1's, 0's, and 1's in the polynomial m' in the last encryption
    /// step
    dm0: uint16_t,
    /// Number of random bits to prepend to the message
    db: uint16_t,
    /// A parameter for the Index Generation Function
    c: uint16_t,
    /// Minimum number of hash calls for the IGF to make
    min_calls_r: uint16_t,
    /// Minimum number of calls to generate the masking polynomial
    min_calls_mask: uint16_t,
    /// Whether to hash the seed in the MGF first (1) or use the seed directly (0)
    hash_seed: uint8_t,
    /// Three bytes that uniquely identify the parameter set
    oid: [uint8_t; 3],
    /// Hash function, e.g. ntru_sha256
    hash: unsafe extern "C" fn(input: *const uint8_t,
                                   input_len: uint16_t,
                                   digest: *mut uint8_t),
    /// Hash function for 4 inputs, e.g. ntru_sha256_4way
    hash_4way: unsafe extern "C" fn(input: *const *const uint8_t,
                                        input_len: uint16_t,
                                        digest: *mut *mut uint8_t),
    /// Hash function for 8 inputs, e.g. ntru_sha256_8way
    hash_8way: unsafe extern "C" fn(input: *const *const uint8_t,
                                        input_len: uint16_t,
                                        digest: *mut *mut uint8_t),
    /// output length of the hash function
    hlen: uint16_t,
    /// number of bits of the public key to hash
    pklen: uint16_t,
}

impl Default for EncParams {
    fn default() -> EncParams {
        EncParams {
            name: [0; 11],
            n: 0,
            q: 0,
            prod_flag: 0,
            df1: 0,
            df2: 0,
            df3: 0,
            dg: 0,
            dm0: 0,
            db: 0,
            c: 0,
            min_calls_r: 0,
            min_calls_mask: 0,
            hash_seed: 0,
            oid: [0; 3],
            hash: ffi::ntru_sha1,
            hash_4way: ffi::ntru_sha1_4way,
            hash_8way: ffi::ntru_sha1_8way,
            hlen: 0,
            pklen: 0,
        }
    }
}

impl PartialEq for EncParams {
    fn eq(&self, other: &EncParams) -> bool {
        self.name == other.name && self.n == other.n && self.q == other.q &&
        self.prod_flag == other.prod_flag && self.df1 == other.df1 &&
        (self.prod_flag == 0 || (self.df2 == other.df2 && self.df3 == other.df3)) &&
        self.dm0 == other.dm0 && self.db == other.db && self.c == other.c &&
        self.min_calls_r == other.min_calls_r &&
        self.min_calls_mask == other.min_calls_mask &&
        self.hash_seed == other.hash_seed && self.oid == other.oid &&
        {
            let input = [0u8; 100];
            let mut hash1 = [0u8; 256];
            let mut hash2 = [0u8; 256];
            unsafe { (self.hash)(&input[0], 100, &mut hash1[0]) };
            unsafe { (other.hash)(&input[0], 100, &mut hash2[0]) };

            for (i, b) in hash1.iter().enumerate() {
                if *b != hash2[i] {
                    return false;
                }
            }
            true
        } && self.hlen == other.hlen && self.pklen == other.pklen
    }
}


impl fmt::Debug for EncParams {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut name = String::with_capacity(10);
        for c in &self.name {
            name.push(*c as u8 as char);
        }
        write!(f, "param: {}", name)
    }
}

impl EncParams {
    /// Get the name of the parameter set
    pub fn get_name(&self) -> String {
        let slice: [u8; 11] = [self.name[0] as u8,
                               self.name[1] as u8,
                               self.name[2] as u8,
                               self.name[3] as u8,
                               self.name[4] as u8,
                               self.name[5] as u8,
                               self.name[6] as u8,
                               self.name[7] as u8,
                               self.name[8] as u8,
                               self.name[9] as u8,
                               self.name[10] as u8];
        String::from_utf8_lossy(&slice).into_owned()
    }

    /// Get the number of polynomial coefficients
    pub fn get_n(&self) -> u16 {
        self.n
    }

    /// Get the modulus
    pub fn get_q(&self) -> u16 {
        self.q
    }

    /// Get the number of random bits to prepend to the message
    pub fn get_db(&self) -> u16 {
        self.db
    }

    /// Maximum message length
    pub fn max_msg_len(&self) -> u8 {
        (self.n / 2 * 3 / 8 - 1 - self.db / 8) as u8
    }

    /// Encryption length
    pub fn enc_len(&self) -> u16 {
        if self.q & (self.q - 1) != 0 {
            0
        } else {
            let len_bits = self.n * EncParams::log2(self.q) as u16;
            (len_bits + 7) / 8
        }
    }

    /// Public key length
    pub fn public_len(&self) -> u16 {
        4 + self.enc_len()
    }

    /// Private key length
    pub fn private_len(&self) -> u16 {
        let bits_per_idx = EncParams::log2(self.n - 1) as u16 + 1;
        if self.prod_flag == 1 {
            let poly1_len = 4 + (bits_per_idx * 2 * self.df1 + 7) / 8;
            let poly2_len = 4 + (bits_per_idx * 2 * self.df2 + 7) / 8;
            let poly3_len = 4 + (bits_per_idx * 2 * self.df3 + 7) / 8;

            5 + poly1_len + poly2_len + poly3_len
        } else {
            5 + 4 + (bits_per_idx * 2 * self.df1 + 7) / 8
        }
    }

    fn log2(n: u16) -> u8 {
        let mut n = n;
        let mut log = 0;
        while n > 1 {
            n /= 2;
            log += 1;
        }
        log
    }
}

/// An IEEE 1361.1 parameter set that gives 112 bits of security and is optimized for key size.
pub const EES401EP1: EncParams = EncParams {
    name: [69, 69, 83, 52, 48, 49, 69, 80, 49, 0, 0], // EES401EP1
    n: 401,
    q: 2048,
    prod_flag: 0,
    df1: 113,
    df2: 0,
    df3: 0,
    dg: 133,
    dm0: 113,
    db: 112,
    c: 11,
    min_calls_r: 32,
    min_calls_mask: 9,
    hash_seed: 1,
    oid: [0, 2, 4],
    hash: ffi::ntru_sha1,
    hash_4way: ffi::ntru_sha1_4way,
    hash_8way: ffi::ntru_sha1_8way,
    hlen: 20,
    pklen: 114,
};

/// An IEEE 1361.1 parameter set that gives 128 bits of security and is optimized for key size.
pub const EES449EP1: EncParams = EncParams {
    name: [69, 69, 83, 52, 52, 57, 69, 80, 49, 0, 0], // EES449EP1
    n: 449,
    q: 2048,
    prod_flag: 0,
    df1: 134,
    df2: 0,
    df3: 0,
    dg: 149,
    dm0: 134,
    db: 128,
    c: 9,
    min_calls_r: 31,
    min_calls_mask: 9,
    hash_seed: 1,
    oid: [0, 3, 3],
    hash: ffi::ntru_sha1,
    hash_4way: ffi::ntru_sha1_4way,
    hash_8way: ffi::ntru_sha1_8way,
    hlen: 20,
    pklen: 128,
};

/// An IEEE 1361.1 parameter set that gives 192 bits of security and is optimized for key size.
pub const EES677EP1: EncParams = EncParams {
    name: [69, 69, 83, 54, 55, 55, 69, 80, 49, 0, 0], // EES677EP1
    n: 677,
    q: 2048,
    prod_flag: 0,
    df1: 157,
    df2: 0,
    df3: 0,
    dg: 225,
    dm0: 157,
    db: 192,
    c: 11,
    min_calls_r: 27,
    min_calls_mask: 9,
    hash_seed: 1,
    oid: [0, 5, 3],
    hash: ffi::ntru_sha256,
    hash_4way: ffi::ntru_sha256_4way,
    hash_8way: ffi::ntru_sha256_8way,
    hlen: 32,
    pklen: 192,
};

/// An IEEE 1361.1 parameter set that gives 256 bits of security and is optimized for key size.
pub const EES1087EP2: EncParams = EncParams {
    name: [69, 69, 83, 49, 48, 56, 55, 69, 80, 50, 0], // EES1087EP2
    n: 1087,
    q: 2048,
    prod_flag: 0,
    df1: 120,
    df2: 0,
    df3: 0,
    dg: 362,
    dm0: 120,
    db: 256,
    c: 13,
    min_calls_r: 25,
    min_calls_mask: 14,
    hash_seed: 1,
    oid: [0, 6, 3],
    hash: ffi::ntru_sha256,
    hash_4way: ffi::ntru_sha256_4way,
    hash_8way: ffi::ntru_sha256_8way,
    hlen: 32,
    pklen: 256,
};

/// An IEEE 1361.1 parameter set that gives 112 bits of security and is a tradeoff between key size
/// and encryption/decryption speed.
pub const EES541EP1: EncParams = EncParams {
    name: [69, 69, 83, 53, 52, 49, 69, 80, 49, 0, 0], // EES541EP1
    n: 541,
    q: 2048,
    prod_flag: 0,
    df1: 49,
    df2: 0,
    df3: 0,
    dg: 180,
    dm0: 49,
    db: 112,
    c: 12,
    min_calls_r: 15,
    min_calls_mask: 11,
    hash_seed: 1,
    oid: [0, 2, 5],
    hash: ffi::ntru_sha1,
    hash_4way: ffi::ntru_sha1_4way,
    hash_8way: ffi::ntru_sha1_8way,
    hlen: 20,
    pklen: 112,
};

/// An IEEE 1361.1 parameter set that gives 128 bits of security and is a tradeoff between key
/// size and encryption/decryption speed.
pub const EES613EP1: EncParams = EncParams {
    name: [69, 69, 83, 54, 49, 51, 69, 80, 49, 0, 0], // EES613EP1
    n: 613,
    q: 2048,
    prod_flag: 0,
    df1: 55,
    df2: 0,
    df3: 0,
    dg: 204,
    dm0: 55,
    db: 128,
    c: 11,
    min_calls_r: 16,
    min_calls_mask: 13,
    hash_seed: 1,
    oid: [0, 3, 4],
    hash: ffi::ntru_sha1,
    hash_4way: ffi::ntru_sha1_4way,
    hash_8way: ffi::ntru_sha1_8way,
    hlen: 20,
    pklen: 128,
};

/// An IEEE 1361.1 parameter set that gives 192 bits of security and is a tradeoff between key size
/// and encryption/decryption speed.
pub const EES887EP1: EncParams = EncParams {
    name: [69, 69, 83, 56, 56, 55, 69, 80, 49, 0, 0], // EES887EP1
    n: 887,
    q: 2048,
    prod_flag: 0,
    df1: 81,
    df2: 0,
    df3: 0,
    dg: 295,
    dm0: 81,
    db: 192,
    c: 10,
    min_calls_r: 13,
    min_calls_mask: 12,
    hash_seed: 1,
    oid: [0, 5, 4],
    hash: ffi::ntru_sha256,
    hash_4way: ffi::ntru_sha256_4way,
    hash_8way: ffi::ntru_sha256_8way,
    hlen: 32,
    pklen: 192,
};

/// An IEEE 1361.1 parameter set that gives 256 bits of security and is a tradeoff between key size
/// and encryption/decryption speed.
pub const EES1171EP1: EncParams = EncParams {
    name: [69, 69, 83, 49, 49, 55, 49, 69, 80, 49, 0], // EES1171EP1
    n: 1171,
    q: 2048,
    prod_flag: 0,
    df1: 106,
    df2: 0,
    df3: 0,
    dg: 390,
    dm0: 106,
    db: 256,
    c: 12,
    min_calls_r: 20,
    min_calls_mask: 15,
    hash_seed: 1,
    oid: [0, 6, 4],
    hash: ffi::ntru_sha256,
    hash_4way: ffi::ntru_sha256_4way,
    hash_8way: ffi::ntru_sha256_8way,
    hlen: 32,
    pklen: 256,
};

/// An IEEE 1361.1 parameter set that gives 112 bits of security and is optimized for
/// encryption/decryption speed.
pub const EES659EP1: EncParams = EncParams {
    name: [69, 69, 83, 54, 53, 57, 69, 80, 49, 0, 0], // EES659EP1
    n: 659,
    q: 2048,
    prod_flag: 0,
    df1: 38,
    df2: 0,
    df3: 0,
    dg: 219,
    dm0: 38,
    db: 112,
    c: 11,
    min_calls_r: 11,
    min_calls_mask: 14,
    hash_seed: 1,
    oid: [0, 2, 6],
    hash: ffi::ntru_sha1,
    hash_4way: ffi::ntru_sha1_4way,
    hash_8way: ffi::ntru_sha1_8way,
    hlen: 20,
    pklen: 112,
};

/// An IEEE 1361.1 parameter set that gives 128 bits of security and is optimized for
/// encryption/decryption speed.
pub const EES761EP1: EncParams = EncParams {
    name: [69, 69, 83, 55, 54, 49, 69, 80, 49, 0, 0], // EES761EP1
    n: 761,
    q: 2048,
    prod_flag: 0,
    df1: 42,
    df2: 0,
    df3: 0,
    dg: 253,
    dm0: 42,
    db: 128,
    c: 12,
    min_calls_r: 13,
    min_calls_mask: 16,
    hash_seed: 1,
    oid: [0, 3, 5],
    hash: ffi::ntru_sha1,
    hash_4way: ffi::ntru_sha1_4way,
    hash_8way: ffi::ntru_sha1_8way,
    hlen: 20,
    pklen: 128,
};

/// An IEEE 1361.1 parameter set that gives 192 bits of security and is optimized for
/// encryption/decryption speed.
pub const EES1087EP1: EncParams = EncParams {
    name: [69, 69, 83, 49, 48, 56, 55, 69, 80, 49, 0], // EES1087EP1
    n: 1087,
    q: 2048,
    prod_flag: 0,
    df1: 63,
    df2: 0,
    df3: 0,
    dg: 362,
    dm0: 63,
    db: 192,
    c: 13,
    min_calls_r: 13,
    min_calls_mask: 14,
    hash_seed: 1,
    oid: [0, 5, 5],
    hash: ffi::ntru_sha256,
    hash_4way: ffi::ntru_sha256_4way,
    hash_8way: ffi::ntru_sha256_8way,
    hlen: 32,
    pklen: 192,
};

/// An IEEE 1361.1 parameter set that gives 256 bits of security and is optimized for
/// encryption/decryption speed.
pub const EES1499EP1: EncParams = EncParams {
    name: [69, 69, 83, 49, 52, 57, 57, 69, 80, 49, 0], // EES1499EP1
    n: 1499,
    q: 2048,
    prod_flag: 0,
    df1: 79,
    df2: 0,
    df3: 0,
    dg: 499,
    dm0: 79,
    db: 256,
    c: 13,
    min_calls_r: 17,
    min_calls_mask: 19,
    hash_seed: 1,
    oid: [0, 6, 5],
    hash: ffi::ntru_sha256,
    hash_4way: ffi::ntru_sha256_4way,
    hash_8way: ffi::ntru_sha256_8way,
    hlen: 32,
    pklen: 256,
};

/// A product-form parameter set that gives 112 bits of security.
pub const EES401EP2: EncParams = EncParams {
    name: [69, 69, 83, 52, 48, 49, 69, 80, 50, 0, 0], // EES401EP2
    n: 401,
    q: 2048,
    prod_flag: 1,
    df1: 8,
    df2: 8,
    df3: 6,
    dg: 133,
    dm0: 101,
    db: 112,
    c: 11,
    min_calls_r: 10,
    min_calls_mask: 6,
    hash_seed: 1,
    oid: [0, 2, 16],
    hash: ffi::ntru_sha1,
    hash_4way: ffi::ntru_sha1_4way,
    hash_8way: ffi::ntru_sha1_8way,
    hlen: 20,
    pklen: 112,
};

/// **DEPRECATED** A product-form parameter set that gives 128 bits of security.
///
/// **Deprecated**, use EES443EP1 instead.
pub const EES439EP1: EncParams = EncParams {
    name: [69, 69, 83, 52, 51, 57, 69, 80, 49, 0, 0], // EES439EP1
    n: 439,
    q: 2048,
    prod_flag: 1,
    df1: 9,
    df2: 8,
    df3: 5,
    dg: 146,
    dm0: 112,
    db: 128,
    c: 9,
    min_calls_r: 15,
    min_calls_mask: 6,
    hash_seed: 1,
    oid: [0, 3, 16],
    hash: ffi::ntru_sha1,
    hash_4way: ffi::ntru_sha1_4way,
    hash_8way: ffi::ntru_sha1_8way,
    hlen: 20,
    pklen: 128,
};

/// A product-form parameter set that gives 128 bits of security.
pub const EES443EP1: EncParams = EncParams {
    name: [69, 69, 83, 52, 52, 51, 69, 80, 49, 0, 0],
    n: 443,
    q: 2048,
    prod_flag: 1,
    df1: 9,
    df2: 8,
    df3: 5,
    dg: 148,
    dm0: 115,
    db: 128,
    c: 9,
    min_calls_r: 8,
    min_calls_mask: 5,
    hash_seed: 1,
    oid: [0, 3, 17],
    hash: ffi::ntru_sha256,
    hash_4way: ffi::ntru_sha256_4way,
    hash_8way: ffi::ntru_sha256_8way,
    hlen: 32,
    pklen: 128,
};

/// **DEPRECATED** A product-form parameter set that gives 192 bits of security.
///
/// **Deprecated**, use EES587EP1 instead.
pub const EES593EP1: EncParams = EncParams {
    name: [69, 69, 83, 53, 57, 51, 69, 80, 49, 0, 0], // EES593EP1
    n: 593,
    q: 2048,
    prod_flag: 1,
    df1: 10,
    df2: 10,
    df3: 8,
    dg: 197,
    dm0: 158,
    db: 192,
    c: 11,
    min_calls_r: 12,
    min_calls_mask: 5,
    hash_seed: 1,
    oid: [0, 5, 16],
    hash: ffi::ntru_sha256,
    hash_4way: ffi::ntru_sha256_4way,
    hash_8way: ffi::ntru_sha256_8way,
    hlen: 32,
    pklen: 192,
};

/// A product-form parameter set that gives 192 bits of security.
pub const EES587EP1: EncParams = EncParams {
    name: [69, 69, 83, 53, 56, 55, 69, 80, 49, 0, 0],
    n: 587,
    q: 2048,
    prod_flag: 1,
    df1: 10,
    df2: 10,
    df3: 8,
    dg: 196,
    dm0: 157,
    db: 192,
    c: 11,
    min_calls_r: 13,
    min_calls_mask: 7,
    hash_seed: 1,
    oid: [0, 5, 17],
    hash: ffi::ntru_sha256,
    hash_4way: ffi::ntru_sha256_4way,
    hash_8way: ffi::ntru_sha256_8way,
    hlen: 32,
    pklen: 192,
};

/// A product-form parameter set that gives 256 bits of security.
pub const EES743EP1: EncParams = EncParams {
    name: [69, 69, 83, 55, 52, 51, 69, 80, 49, 0, 0], // EES743EP1
    n: 743,
    q: 2048,
    prod_flag: 1,
    df1: 11,
    df2: 11,
    df3: 15,
    dg: 247,
    dm0: 204,
    db: 256,
    c: 13,
    min_calls_r: 12,
    min_calls_mask: 7,
    hash_seed: 1,
    oid: [0, 6, 16],
    hash: ffi::ntru_sha256,
    hash_4way: ffi::ntru_sha256_4way,
    hash_8way: ffi::ntru_sha256_8way,
    hlen: 32,
    pklen: 256,
};

/// The default parameter set for 112 bits of security.
pub const DEFAULT_PARAMS_112_BITS: EncParams = EES541EP1;

/// The default parameter set for 128 bits of security.
pub const DEFAULT_PARAMS_128_BITS: EncParams = EES613EP1;

/// The default parameter set for 192 bits of security.
pub const DEFAULT_PARAMS_192_BITS: EncParams = EES887EP1;

/// The default parameter set for 256 bits of security.
pub const DEFAULT_PARAMS_256_BITS: EncParams = EES1171EP1;

/// All parameter sets, in an array
pub const ALL_PARAM_SETS: [EncParams; 18] =
    [EES401EP1, EES449EP1, EES677EP1, EES1087EP2, EES541EP1, EES613EP1, EES887EP1, EES1171EP1,
     EES659EP1, EES761EP1, EES1087EP1, EES1499EP1, EES401EP2, EES439EP1, EES443EP1, EES593EP1,
     EES587EP1, EES743EP1];
