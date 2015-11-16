use std::ops::Add;
use std::default::Default;
use std::{fmt, mem};
use libc::{int16_t, uint8_t, uint16_t};
use ffi;
use encparams::{NtruEncParams, NTRU_INT_POLY_SIZE, NTRU_MAX_ONES};
use rand::NtruRandContext;

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
    pub fn new(n: u16, coeffs: &[i16]) -> NtruIntPoly {
        let mut new_coeffs = [0; NTRU_INT_POLY_SIZE];

        for i in 0..coeffs.len() {
            new_coeffs[i] = coeffs[i];
        }
        NtruIntPoly { n: n, coeffs: new_coeffs }
    }

    pub fn rand(n: u16, pow2q: u16, rand_ctx: &NtruRandContext) -> NtruIntPoly {
        let rand_data = rand_ctx.get_rand_gen().generate(n*2, rand_ctx).ok().unwrap();

        let mut coeffs = [0i16; NTRU_INT_POLY_SIZE];
        let shift = 16 - pow2q;
        for i in (n as usize)..0usize {
            coeffs[i] =  rand_data[i] as i16 >> shift;
        }

        NtruIntPoly { n: n, coeffs: coeffs }
    }

    pub fn from_arr(arr: &[u8], n: u16, q: u16) -> NtruIntPoly {
        let mut p: NtruIntPoly = Default::default();
        unsafe { ffi::ntru_from_arr(&arr[0], n, q, &mut p) };

        p
    }

    pub fn get_n(&self) -> u16 { self.n }
    pub fn set_n(&mut self, n: u16) { self.n = n }

    pub fn get_coeffs(&self) -> &[i16; NTRU_INT_POLY_SIZE] { &self.coeffs }
    pub fn set_coeff(&mut self, index: usize, value: i16) { self.coeffs[index] = value }

    pub fn mod_mask(&mut self, mod_mask: u16) {
        unsafe {ffi::ntru_mod_mask(self, mod_mask)}
    }

    pub fn to_arr_32(&self, params: &NtruEncParams) -> Box<[u8]> {
        let mut a = vec![0u8; params.enc_len() as usize];
        unsafe { ffi::ntru_to_arr_32(self, params.get_q(), &mut a[0]) };

        a.into_boxed_slice()
    }

    pub fn to_arr_64(&self, params: &NtruEncParams) -> Box<[u8]> {
        let mut a = vec![0u8; params.enc_len() as usize];
        unsafe { ffi::ntru_to_arr_64(self, params.get_q(), &mut a[0]) };

        a.into_boxed_slice()
    }

    pub fn to_arr_sse_2048(&self, params: &NtruEncParams) -> Box<[u8]> {
        let mut a = vec![0u8; params.enc_len() as usize];
        unsafe { ffi::ntru_to_arr_sse_2048(self, &mut a[0]) };

        a.into_boxed_slice()
    }

    pub fn mult_tern(&self, b: &NtruTernPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe {ffi::ntru_mult_tern(self, b, &mut c, mod_mask)};
        (c, result == 1)
    }

    pub fn mult_tern_32(&self, b: &NtruTernPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe {ffi::ntru_mult_tern_32(self, b, &mut c, mod_mask)};
        (c, result == 1)
    }

    pub fn mult_tern_64(&self, b: &NtruTernPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe {ffi::ntru_mult_tern_64(self, b, &mut c, mod_mask)};
        (c, result == 1)
    }

    pub fn mult_tern_sse(&self, b: &NtruTernPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe {ffi::ntru_mult_tern_sse(self, b, &mut c, mod_mask)};
        (c, result == 1)
    }

    pub fn add_tern(&self, b: &NtruTernPoly) -> NtruIntPoly {
        NtruIntPoly {
            n: self.n,
            coeffs: {
                let mut coeffs = [0; NTRU_INT_POLY_SIZE];
                let tern_ones = b.get_ones();
                let tern_neg_ones = b.get_neg_ones();

                for i in 0..tern_ones.len() {
                    coeffs[tern_ones[i] as usize] = self.coeffs[tern_ones[i] as usize] + 1;
                }

                for i in 0..tern_neg_ones.len() {
                    coeffs[tern_neg_ones[i] as usize] = self.coeffs[tern_neg_ones[i] as usize] + 1;
                }
                coeffs
            }
        }
    }

    pub fn mult_prod(&self, b: &NtruProdPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe {ffi::ntru_mult_prod(self, b, &mut c, mod_mask)};
        (c, result == 1)
    }

    pub fn mult_int(&self, b: &NtruIntPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe {ffi::ntru_mult_int(self, b, &mut c, mod_mask)};
        (c, result == 1)
    }

    pub fn mult_int_16(&self, b: &NtruIntPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe {ffi::ntru_mult_int_16(self, b, &mut c, mod_mask)};
        (c, result == 1)
    }

    pub fn mult_int_64(&self, b: &NtruIntPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe {ffi::ntru_mult_int_64(self, b, &mut c, mod_mask)};
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

    pub fn equals_mod(&self, other: &NtruIntPoly, modulus: u16) -> bool {
        self.n == other.n && {
            for i in 0..self.n as usize {
                if (self.coeffs[i] - other.coeffs[i]) as i32 % modulus as i32 != 0 { return false }
            }
            true
        }
    }

    pub fn equals1(&self) -> bool {
        for i in 1..self.n {
            if self.coeffs[i as usize] != 0 { return false }
        }
        self.coeffs[0] == 1
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
    pub fn new(n: u16, ones: &[u16], neg_ones: &[u16]) -> NtruTernPoly {
        let mut new_ones = [0; NTRU_MAX_ONES];
        let mut new_neg_ones = [0; NTRU_MAX_ONES];

        for i in 0..ones.len() {
            new_ones[i] = ones[i];
        }

        for i in 0..neg_ones.len() {
            new_neg_ones[i] = neg_ones[i];
        }

        NtruTernPoly { n: n, num_ones: ones.len() as u16, num_neg_ones: neg_ones.len() as u16,
                       ones: new_ones, neg_ones: new_neg_ones }
    }

    pub fn get_n(&self) -> u16 { self.n }
    pub fn get_ones(&self) -> &[u16] { &self.ones[0..self.num_ones as usize] }
    pub fn get_neg_ones(&self) -> &[u16] { &self.neg_ones[0..self.num_neg_ones as usize] }

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

impl NtruProdPoly {
    pub fn new(n: u16, f1: NtruTernPoly, f2: NtruTernPoly, f3: NtruTernPoly) -> NtruProdPoly {
        NtruProdPoly { n: n, f1: f1, f2: f2, f3: f3}
    }

    pub fn to_int_poly(&self, modulus: u16) -> NtruIntPoly {
        let c = NtruIntPoly {n: self.n, coeffs: [0; NTRU_INT_POLY_SIZE]};

        let mod_mask = modulus - 1;
        let (c, _) = c.mult_tern(&self.f2, mod_mask);
        c.add_tern(&self.f3)
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
    unsafe fn new_from_prod(poly: NtruProdPoly) -> PrivUnion {
        let arr: &[uint16_t; 3004] = mem::transmute(&poly);
        let mut data = [0; PRIVUNION_SIZE];

        for i in 0..arr.len() {
            data[i] = arr[i];
        }

        PrivUnion { data: data }
    }

    unsafe fn new_from_tern(poly: NtruTernPoly) -> PrivUnion {
        let arr: &[uint16_t; 1001] = mem::transmute(&poly);
        let mut data = [0; PRIVUNION_SIZE];

        for i in 0..arr.len() {
            data[i] = arr[i];
        }

        PrivUnion { data: data }
    }

    unsafe fn prod(&self) -> &NtruProdPoly {
        mem::transmute(&self.data)
    }

    unsafe fn tern(&self) -> &NtruTernPoly {
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
    pub fn new_with_prod_poly(poly: NtruProdPoly) -> NtruPrivPoly {
        NtruPrivPoly { prod_flag: 0, poly: unsafe { PrivUnion::new_from_prod(poly) } }
    }

    pub fn new_with_tern_poly(poly: NtruTernPoly) -> NtruPrivPoly {
        NtruPrivPoly { prod_flag: 0, poly: unsafe { PrivUnion::new_from_tern(poly) } }
    }

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

    /// Inverse modulo q
    ///
    /// Computes the inverse of 1+3a mod q; q must be a power of 2. It also returns if the
    /// polynomial is invertible.
    ///
    /// The algorithm is described in "Almost Inverses and Fast NTRU Key Generation" at
    /// http://www.securityinnovation.com/uploads/Crypto/NTRUTech014.pdf
    pub fn invert(&self, mod_mask: u16) -> (NtruIntPoly, bool) {
        let mut fq: NtruIntPoly = Default::default();
        let result = unsafe { ffi::ntru_invert(self, mod_mask, &mut fq) };

        (fq, result == 1)
    }

    /// Inverse modulo q
    ///
    /// Computes the inverse of 1+3a mod q; q must be a power of 2. This function uses 32-bit
    /// arithmetic. It also returns if the polynomial is invertible.
    ///
    /// The algorithm is described in "Almost Inverses and Fast NTRU Key Generation" at
    /// http://www.securityinnovation.com/uploads/Crypto/NTRUTech014.pdf
    pub fn invert_32(&self, mod_mask: u16) -> (NtruIntPoly, bool) {
        let mut fq: NtruIntPoly = Default::default();
        let result = unsafe { ffi::ntru_invert_32(self, mod_mask, &mut fq) };

        (fq, result == 1)
    }

    /// Inverse modulo q
    ///
    /// Computes the inverse of 1+3a mod q; q must be a power of 2. This function uses 64-bit
    /// arithmetic. It also returns if the polynomial is invertible.
    ///
    /// The algorithm is described in "Almost Inverses and Fast NTRU Key Generation" at
    /// http://www.securityinnovation.com/uploads/Crypto/NTRUTech014.pdf
    pub fn invert_64(&self, mod_mask: u16) -> (NtruIntPoly, bool) {
        let mut fq: NtruIntPoly = Default::default();
        let result = unsafe { ffi::ntru_invert_64(self, mod_mask, &mut fq) };

        (fq, result == 1)
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

    pub fn import(arr: &[u8]) -> NtruEncPubKey {
        let mut key: NtruEncPubKey = Default::default();
        unsafe{ ffi::ntru_import_pub(&arr[0], &mut key) };

        key
    }

    pub fn export(&self, params: &NtruEncParams) -> Box<[u8]> {
        let mut arr = vec![0u8; 4 + params.enc_len() as usize];
        unsafe { ffi::ntru_export_pub(self, &mut arr[..][0]) };

        arr.into_boxed_slice()
    }
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

#[derive(Debug, PartialEq, Clone)]
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
