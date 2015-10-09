use std::default::Default;
use libc::uint8_t;

use encparams::NTRU_INT_POLY_SIZE;
use encparams::NTRU_MAX_ONES;

/// A polynomial with integer coefficients.
#[repr(C)]
struct NtruIntPoly {
    n: u16,
    coeffs: [i16; NTRU_INT_POLY_SIZE],
}

impl Default for NtruIntPoly {
    fn default() -> NtruIntPoly {
        NtruIntPoly {n: 0, coeffs: [0; NTRU_INT_POLY_SIZE]}
    }
}

/// A ternary polynomial, i.e. all coefficients are equal to -1, 0, or 1.
#[repr(C)]
struct NtruTernPoly {
    n: u16,
    num_ones: u16,
    num_neg_ones: u16,
    ones: [u16; NTRU_MAX_ONES],
    neg_ones: [u16; NTRU_MAX_ONES],
}

impl Default for NtruTernPoly {
    fn default() -> NtruTernPoly {
        NtruTernPoly {n: 0, num_ones: 0, num_neg_ones: 0, ones: [0; NTRU_MAX_ONES],
                    neg_ones: [0; NTRU_MAX_ONES]}
    }
}

/// A product-form polynomial, i.e. a polynomial of the form f1*f2+f3 where f1,f2,f3 are very
/// sparsely populated ternary polynomials.
#[repr(C)]
struct NtruProdPoly {
    n: u16,
    f1: NtruTernPoly,
    f2: NtruTernPoly,
    f3: NtruTernPoly,
}

impl Default for NtruProdPoly {
    fn default() -> NtruProdPoly {
        NtruProdPoly {n: 0, f1: Default::default(), f2: Default::default(), f3: Default::default()}
    }
}

/// Private polynomial, can be ternary or product-form
#[repr(C)]
struct NtruPrivPoly { // maybe we could do conditional compilation?
    /// Whether the polynomial is in product form
    prod_flag: u8,
    prod: NtruProdPoly,
//     union {
//         NtruTernPoly tern;
// #ifndef NTRU_AVOID_HAMMING_WT_PATENT
//         NtruProdPoly prod;
// #endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
//     } poly;
}

impl Default for NtruPrivPoly {
    fn default() -> NtruPrivPoly {
        NtruPrivPoly {prod_flag: 0, prod: Default::default()}
    }
}

/// NtruEncrypt private key
#[repr(C)]
struct NtruEncPrivKey {
    q: u16,
    t: NtruPrivPoly,
}

impl Default for NtruEncPrivKey {
    fn default() -> NtruEncPrivKey {
        NtruEncPrivKey {q: 0, t: Default::default()}
    }
}

/// NtruEncrypt public key
#[repr(C)]
struct NtruEncPubKey {
    q: u16,
    h: NtruIntPoly,
}

impl Default for NtruEncPubKey {
    fn default() -> NtruEncPubKey {
        NtruEncPubKey {q: 0, h: Default::default()}
    }
}

/// NtruEncrypt key pair
#[repr(C)]
pub struct NtruEncKeyPair {
    private: NtruEncPrivKey,
    public: NtruEncPubKey,
}

impl Default for NtruEncKeyPair {
    fn default() -> NtruEncKeyPair {
        NtruEncKeyPair {private: Default::default(), public: Default::default()}
    }
}

pub enum NtruError {
    /// Out of memory error
    OutOfMemory,
    /// TODO: Not sure what this error is for
    Prng,
    /// Message is too long
    MessageTooLong,
    /// Invalid maximum length
    InvalidMaxLength,
    /// TODO: Not sure about this neither
    Md0Violation,
    /// No zero pad TODO: better explanation
    NoZeroPad,
    /// Invalid encoding of the message. TODO: Probably not needed in Rust
    InvalidEncoding,
    /// Null argument. TODO: probably not needed in Rust
    NullArgument,
    /// Unknown parameter set. TODO: better explanation? Needed in Rust?
    UnknownParamSet,
    /// Invalid parameter. TODO: better explanation? Needed in Rust?
    InvalidParam,
}

impl NtruError {
    pub fn from_uint8_t(err: uint8_t) -> NtruError {
        match err {
            1 => NtruError::OutOfMemory,
            2 => NtruError::Prng,
            3 => NtruError::MessageTooLong,
            4 => NtruError::InvalidMaxLength,
            5 => NtruError::Md0Violation,
            6 => NtruError::NoZeroPad,
            7 => NtruError::InvalidEncoding,
            8 => NtruError::NullArgument,
            9 => NtruError::UnknownParamSet,
            10 => NtruError::InvalidParam,
            _ => unreachable!(),
        }
    }
}
