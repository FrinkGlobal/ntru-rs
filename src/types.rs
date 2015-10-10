use std::ops::Add;
use std::default::Default;
use libc::{int16_t, uint8_t, uint16_t};
use super::ffi;
use encparams::NTRU_INT_POLY_SIZE;
use encparams::NTRU_MAX_ONES;

/// A polynomial with integer coefficients.
#[repr(C)]
pub struct NtruIntPoly {
    n: uint16_t,
    coeffs: [int16_t; NTRU_INT_POLY_SIZE],
}

impl Default for NtruIntPoly {
    fn default() -> NtruIntPoly {
        NtruIntPoly {n: 0, coeffs: [0; NTRU_INT_POLY_SIZE]}
    }
}

impl Clone for NtruIntPoly {
    fn clone(&self) -> NtruIntPoly {
        NtruIntPoly {n: self.n, coeffs: self.coeffs}
    }
}

impl Add for NtruIntPoly {
    type Output = NtruIntPoly;
    fn add(self, rhs: NtruIntPoly) -> Self::Output {
        let mut out = self.clone();
        unsafe {ffi::ntru_add_int(&mut out, &rhs)};
        out
    }
}

impl NtruIntPoly {
    pub fn mod_mask(&mut self, mod_mask: u16) -> NtruIntPoly {
        unsafe {ffi::ntru_mod_mask(self, mod_mask)}
        self.clone()
    }
}

/// A ternary polynomial, i.e. all coefficients are equal to -1, 0, or 1.
#[repr(C)]
pub struct NtruTernPoly {
    n: uint16_t,
    num_ones: uint16_t,
    num_neg_ones: uint16_t,
    ones: [uint16_t; NTRU_MAX_ONES],
    neg_ones: [uint16_t; NTRU_MAX_ONES],
}

impl Default for NtruTernPoly {
    fn default() -> NtruTernPoly {
        NtruTernPoly {n: 0, num_ones: 0, num_neg_ones: 0, ones: [0; NTRU_MAX_ONES],
                    neg_ones: [0; NTRU_MAX_ONES]}
    }
}

impl NtruTernPoly {
    /// Ternary to general integer polynomial
    ///
    /// Converts a NtruTernPoly to an equivalent NtruIntPoly.
    pub fn to_int_poly(&self) -> NtruIntPoly {
        NtruIntPoly {n: self.n,
        coeffs: {
            let mut coeffs = [0; NTRU_INT_POLY_SIZE];

            for i in 0..self.num_ones {
                coeffs[self.ones[i as usize] as usize] = 1;
            }
            for i in 0..self.num_neg_ones {
                coeffs[self.neg_ones[i as usize] as usize] = -1;
            }

            coeffs
        }}
    }
}

/// A product-form polynomial, i.e. a polynomial of the form f1*f2+f3 where f1,f2,f3 are very
/// sparsely populated ternary polynomials.
#[repr(C)]
struct NtruProdPoly {
    n: uint16_t,
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
    prod_flag: uint8_t,
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
pub struct NtruEncPrivKey {
    q: uint16_t,
    t: NtruPrivPoly,
}

impl Default for NtruEncPrivKey {
    fn default() -> NtruEncPrivKey {
        NtruEncPrivKey {q: 0, t: Default::default()}
    }
}

/// NtruEncrypt public key
#[repr(C)]
pub struct NtruEncPubKey {
    q: uint16_t,
    h: NtruIntPoly,
}

impl Default for NtruEncPubKey {
    fn default() -> NtruEncPubKey {
        NtruEncPubKey {q: 0, h: Default::default()}
    }
}

impl NtruEncPubKey {
    pub fn get_q(&self) -> u16 { self.q }
    pub fn get_h(&self) -> &NtruIntPoly { &self.h }
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

impl NtruEncKeyPair {
    pub fn get_private(&self) -> &NtruEncPrivKey { &self.private }
    pub fn get_public(&self) -> &NtruEncPubKey { &self.public }
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
