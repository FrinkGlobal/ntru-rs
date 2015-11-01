use std::ops::Add;
use std::default::Default;
use std::fmt;
use std::mem;
use libc::{int16_t, uint8_t, uint16_t};
use super::ffi;
use encparams::NTRU_INT_POLY_SIZE;
use encparams::NTRU_MAX_ONES;

/// A polynomial with integer coefficients.
#[repr(C)]
#[derive(Copy)]
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

impl fmt::Debug for NtruIntPoly {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{ n: {}, coeffs: [{}...{}] }}", self.n, self.coeffs[0],
                self.coeffs[NTRU_INT_POLY_SIZE-1])
    }
}

impl PartialEq for NtruIntPoly {
    fn eq(&self, other: &NtruIntPoly) -> bool {
        self.n == other.n && {
            for i in 0..self.n as usize {
                if self.coeffs[i] != other.coeffs[i] { return false }
            }
            true
        }
    }
}

impl NtruIntPoly {
    pub fn get_n(&self) -> u16 { self.n }
    pub fn get_coeffs(&self) -> &[i16; NTRU_INT_POLY_SIZE] { &self.coeffs }
    pub fn set_coeff(&mut self, index: usize, value: i16) { self.coeffs[index] = value }

    pub fn mod_mask(&mut self, mod_mask: u16) {
        unsafe {ffi::ntru_mod_mask(self, mod_mask)}
    }

    pub fn mult_tern(&self, b: &NtruTernPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe {ffi::ntru_mult_tern(self, b, &mut c, mod_mask)};
        (c, result == 1)
    }

    pub fn mult_prod(&self, b: &NtruProdPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe {ffi::ntru_mult_prod(self, b, &mut c, mod_mask)};
        (c, result == 1)
    }

    pub fn mult_fac(&mut self, factor: i16) {
        unsafe {ffi::ntru_mult_fac(self, factor)}
    }

    pub fn mod_center(&mut self, modulus: u16) {
        unsafe {ffi::ntru_mod_center(self, modulus)}
    }

    pub fn mod3(&mut self) {
        unsafe {ffi::ntru_mod3(self)}
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

impl fmt::Debug for NtruTernPoly {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
            "{{ n: {}, num_ones: {}, num_neg_ones: {}, ones: [{}...{}], neg_ones: [{}...{}] }}",
                self.n, self.num_ones, self.num_neg_ones, self.ones[0], self.ones[NTRU_MAX_ONES-1],
                self.neg_ones[0], self.neg_ones[NTRU_MAX_ONES-1])
    }
}

impl PartialEq for NtruTernPoly {
    fn eq(&self, other: &NtruTernPoly) -> bool {
        self.n == other.n && self.num_ones == other.num_ones &&
        self.num_neg_ones == other.num_neg_ones && {
            for i in 0..NTRU_MAX_ONES-1 {
                if self.ones[i] != other.ones[i] { return false }
                if self.neg_ones[i] != other.neg_ones[i] { return false }
            }
            true
        }
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
#[derive(Debug, PartialEq)]
pub struct NtruProdPoly {
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

/// The size of the union in 16 bit words
const PRIVUNION_SIZE: usize = 3004;

#[repr(C)]
struct PrivUnion {
    data: [uint16_t; PRIVUNION_SIZE],
}

impl Default for PrivUnion {
    fn default() -> PrivUnion {
        PrivUnion {data: [0; PRIVUNION_SIZE]}
    }
}

impl fmt::Debug for PrivUnion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{ data: [...] }}")
    }
}

impl PrivUnion {
    unsafe fn tern(&self) -> &NtruTernPoly {
        mem::transmute(&self.data)
    }
    unsafe fn prod(&self) -> &NtruProdPoly {
        mem::transmute(&self.data)
    }
}

/// Private polynomial, can be ternary or product-form
#[repr(C)]
#[derive(Debug)]
pub struct NtruPrivPoly { // maybe we could do conditional compilation?
    /// Whether the polynomial is in product form
    prod_flag: uint8_t,
    poly: PrivUnion,
}

impl Default for NtruPrivPoly {
    fn default() -> NtruPrivPoly {
        NtruPrivPoly {prod_flag: 0, poly: Default::default()}
    }
}

impl PartialEq for NtruPrivPoly {
    fn eq(&self, other: &NtruPrivPoly) -> bool {
        self.prod_flag == other.prod_flag && {
            if self.prod_flag > 0 { self.get_poly_prod() == other.get_poly_prod() }
            else { self.get_poly_tern() == other.get_poly_tern() }
        }
    }
}

impl NtruPrivPoly {
    pub fn get_prod_flag(&self) -> u8 { self.prod_flag }
    pub fn get_poly_prod(&self) -> &NtruProdPoly {
        if self.prod_flag != 1 {
            panic!("Trying to get NtruPrivPoly from an union that is NtruTernPoly.");
        }
        unsafe { &*self.poly.prod() }
    }
    pub fn get_poly_tern(&self) -> &NtruTernPoly {
        if self.prod_flag != 0 {
            panic!("Trying to get NtruTernPoly from an union that is NtruProdPoly.");
        }
        unsafe { &*self.poly.tern() }
    }
}

/// NtruEncrypt private key
#[repr(C)]
#[derive(Debug, PartialEq)]
pub struct NtruEncPrivKey {
    q: uint16_t,
    t: NtruPrivPoly,
}

impl Default for NtruEncPrivKey {
    fn default() -> NtruEncPrivKey {
        NtruEncPrivKey {q: 0, t: Default::default()}
    }
}

impl NtruEncPrivKey {
    pub fn get_q(&self) -> u16 { self.q }
    pub fn get_t(&self) -> &NtruPrivPoly { &self.t }
}

/// NtruEncrypt public key
#[repr(C)]
#[derive(Debug, PartialEq)]
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
#[derive(Debug, PartialEq)]
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
