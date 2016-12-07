//! NTRU type definitions
//!
//! This module includes all the needed structs and enums for NTRU encryption library. All of them
//! with their needed methods.
use std::ops::{Add, Sub};
use std::default::Default;
use std::{fmt, mem, error};
use libc::{int16_t, uint8_t, uint16_t};
use ffi;
use encparams::EncParams;
use rand::RandContext;

/// Max `N` value for all param sets; +1 for `ntru_invert_...()`
pub const MAX_DEGREE: usize = (1499 + 1);
/// (Max `coefficients` + 16) rounded to a multiple of 8
const INT_POLY_SIZE: usize = ((MAX_DEGREE + 16 + 7) & 0xFFF8);
/// `max(df1, df2, df3, dg)`
pub const MAX_ONES: usize = 499;

#[repr(C)]
/// A polynomial with integer coefficients.
pub struct IntPoly {
    /// The number of coefficients
    n: uint16_t,
    /// The coefficients
    coeffs: [int16_t; INT_POLY_SIZE],
}

impl Default for IntPoly {
    fn default() -> IntPoly {
        IntPoly {
            n: 0,
            coeffs: [0; INT_POLY_SIZE],
        }
    }
}

impl Clone for IntPoly {
    fn clone(&self) -> IntPoly {
        let mut new_coeffs = [0i16; INT_POLY_SIZE];
        new_coeffs.clone_from_slice(&self.coeffs);

        IntPoly {
            n: self.n,
            coeffs: new_coeffs,
        }
    }
}

impl Add for IntPoly {
    type Output = IntPoly;
    fn add(self, rhs: IntPoly) -> Self::Output {
        let mut out = self.clone();
        unsafe { ffi::ntru_add(&mut out, &rhs) };
        out
    }
}

impl Sub for IntPoly {
    type Output = IntPoly;
    fn sub(self, rhs: IntPoly) -> Self::Output {
        let mut out = self.clone();
        unsafe { ffi::ntru_sub(&mut out, &rhs) };
        out
    }
}

impl fmt::Debug for IntPoly {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "{{ n: {}, coeffs: [{}...{}] }}",
               self.n,
               self.coeffs[0],
               self.coeffs[INT_POLY_SIZE - 1])
    }
}

impl PartialEq for IntPoly {
    fn eq(&self, other: &IntPoly) -> bool {
        self.n == other.n &&
        {
            for i in 0..self.n as usize {
                if self.coeffs[i] != other.coeffs[i] {
                    return false;
                }
            }
            true
        }
    }
}

impl IntPoly {
    /// Create a new IntPoly
    pub fn new(coeffs: &[i16]) -> IntPoly {
        let mut new_coeffs = [0; INT_POLY_SIZE];

        for (i, coeff) in coeffs.iter().enumerate() {
            new_coeffs[i] = *coeff;
        }
        IntPoly {
            n: coeffs.len() as u16,
            coeffs: new_coeffs,
        }
    }

    /// Create a new random IntPoly
    pub fn rand(n: u16, pow2q: u16, rand_ctx: &RandContext) -> IntPoly {
        let rand_data = rand_ctx.get_rng().generate(n * 2, rand_ctx).unwrap();

        let mut coeffs = [0i16; INT_POLY_SIZE];
        let shift = 16 - pow2q;
        for i in (n as usize)..0usize {
            coeffs[i] = rand_data[i] as i16 >> shift;
        }

        IntPoly {
            n: n,
            coeffs: coeffs,
        }
    }

    /// Convert array to IntPoly
    pub fn from_arr(arr: &[u8], n: u16, q: u16) -> IntPoly {
        let mut p: IntPoly = Default::default();
        unsafe { ffi::ntru_from_arr(&arr[0], n, q, &mut p) };

        p
    }

    /// Get the coefficients
    pub fn get_coeffs(&self) -> &[i16] {
        &self.coeffs[0..self.n as usize]
    }

    /// Set the coefficients
    pub fn set_coeffs(&mut self, coeffs: &[i16]) {
        self.coeffs = [0; INT_POLY_SIZE];
        for (i, coeff) in coeffs.iter().enumerate() {
            self.coeffs[i] = *coeff;
        }
    }

    /// Set a coefficient
    pub fn set_coeff(&mut self, index: usize, value: i16) {
        self.coeffs[index] = value
    }

    /// Modifies the IntPoly with the given mask
    pub fn mod_mask(&mut self, mod_mask: u16) {
        unsafe { ffi::ntru_mod_mask(self, mod_mask) };
    }

    /// Converts the IntPoly to a byte array using 32 bit arithmetic
    pub fn to_arr(&self, params: &EncParams) -> Box<[u8]> {
        let mut a = vec![0u8; params.enc_len() as usize];
        unsafe { ffi::ntru_to_arr(self, params.get_q(), &mut a[0]) };

        a.into_boxed_slice()
    }

    /// General polynomial by ternary polynomial multiplication
    ///
    /// Multiplies a IntPoly by a TernPoly. The number of coefficients must be the same for both
    /// polynomials. It also returns if the number of coefficients differ or not.
    pub fn mult_tern(&self, b: &TernPoly, mod_mask: u16) -> (IntPoly, bool) {
        if self.n != b.n {
            panic!("To multiply a IntPoly by a TernPoly the number of coefficients must \
                    be the same for both polynomials")
        }
        let mut c: IntPoly = Default::default();
        let result = unsafe { ffi::ntru_mult_tern(self, b, &mut c, mod_mask) };
        (c, result == 1)
    }

    /// Add a ternary polynomial
    ///
    /// Adds a ternary polynomial to the general polynomial. Returns a new general polynomial.
    pub fn add_tern(&self, b: &TernPoly) -> IntPoly {
        IntPoly {
            n: self.n,
            coeffs: {
                let mut coeffs = [0; INT_POLY_SIZE];
                let tern_ones = b.get_ones();
                let tern_neg_ones = b.get_neg_ones();

                for one in tern_ones.iter() {
                    coeffs[*one as usize] = self.coeffs[*one as usize] + 1;
                }

                for neg_one in tern_neg_ones.iter() {
                    coeffs[*neg_one as usize] = self.coeffs[*neg_one as usize] + 1;
                }
                coeffs
            },
        }
    }

    /// General polynomial by product-form polynomial multiplication
    ///
    /// Multiplies a IntPoly by a ProdPoly. The number of coefficients must be the same for both
    /// polynomials. It also returns if the number of coefficients differ or not.
    pub fn mult_prod(&self, b: &ProdPoly, mod_mask: u16) -> (IntPoly, bool) {
        if self.n != b.n {
            panic!("To multiply a IntPoly by a ProdPoly the number of coefficients must \
                    be the same for both polynomials")
        }
        let mut c: IntPoly = Default::default();
        let result = unsafe { ffi::ntru_mult_prod(self, b, &mut c, mod_mask) };
        (c, result == 1)
    }

    /// General polynomial by private polynomial multiplication
    ///
    /// Multiplies a IntPoly by a PrivPoly, i.e. a TernPoly or a ProdPoly. The number of
    /// coefficients must be the same for both polynomials. It also returns if the number of
    /// coefficients differ or not.
    pub fn mult_priv(&self, b: &PrivPoly, mod_mask: u16) -> (IntPoly, bool) {
        if (b.is_product() && self.n != b.get_poly_prod().n) ||
           (!b.is_product() && self.n != b.get_poly_tern().n) {
            panic!("To multiply a IntPoly by a ProdPoly the number of coefficients must \
                    be the same for both polynomials")
        }
        let mut c: IntPoly = Default::default();
        let result = unsafe { ffi::ntru_mult_priv(b, self, &mut c, mod_mask) };
        (c, result == 1)
    }

    /// General polynomial by general polynomial multiplication
    ///
    /// Multiplies a IntPoly by another IntPoly, i.e. a TernPoly or a ProdPoly. The number of
    /// coefficients must be the same for both polynomials. It also returns if the number of
    /// coefficients differ or not.
    pub fn mult_int(&self, b: &IntPoly, mod_mask: u16) -> (IntPoly, bool) {
        let mut c: IntPoly = Default::default();
        let result = unsafe { ffi::ntru_mult_int(self, b, &mut c, mod_mask) };
        (c, result == 1)
    }

    /// Multiply by factor
    pub fn mult_fac(&mut self, factor: i16) {
        unsafe { ffi::ntru_mult_fac(self, factor) };
    }

    /// Calls `ntru_mod_center()` in this polinomial.
    pub fn mod_center(&mut self, modulus: u16) {
        unsafe { ffi::ntru_mod_center(self, modulus) };
    }

    /// Calls `ntru_mod3()` in this polinomial.
    pub fn mod3(&mut self) {
        unsafe { ffi::ntru_mod3(self) };
    }

    /// Check if both polynomials are equals given a modulus
    pub fn equals_mod(&self, other: &IntPoly, modulus: u16) -> bool {
        self.n == other.n &&
        {
            for i in 0..self.n as usize {
                if (self.coeffs[i] - other.coeffs[i]) as i32 % modulus as i32 != 0 {
                    return false;
                }
            }
            true
        }
    }

    /// Check if the IntPoly equals 1
    pub fn equals1(&self) -> bool {
        for i in 1..self.n {
            if self.coeffs[i as usize] != 0 {
                return false;
            }
        }
        self.coeffs[0] == 1
    }
}

#[repr(C)]
/// A ternary polynomial, i.e. all coefficients are equal to -1, 0, or 1.
pub struct TernPoly {
    n: uint16_t,
    num_ones: uint16_t,
    num_neg_ones: uint16_t,
    ones: [uint16_t; MAX_ONES],
    neg_ones: [uint16_t; MAX_ONES],
}

impl Default for TernPoly {
    fn default() -> TernPoly {
        TernPoly {
            n: 0,
            num_ones: 0,
            num_neg_ones: 0,
            ones: [0; MAX_ONES],
            neg_ones: [0; MAX_ONES],
        }
    }
}

impl Clone for TernPoly {
    fn clone(&self) -> TernPoly {
        let mut new_ones = [0u16; MAX_ONES];
        new_ones.clone_from_slice(&self.ones);
        let mut new_neg_ones = [0u16; MAX_ONES];
        new_neg_ones.clone_from_slice(&self.neg_ones);

        TernPoly {
            n: self.n,
            num_ones: self.num_ones,
            num_neg_ones: self.num_neg_ones,
            ones: new_ones,
            neg_ones: new_neg_ones,
        }
    }
}

impl fmt::Debug for TernPoly {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "{{ n: {}, num_ones: {}, num_neg_ones: {}, ones: [{}...{}], neg_ones: [{}...{}] }}",
               self.n,
               self.num_ones,
               self.num_neg_ones,
               self.ones[0],
               self.ones[MAX_ONES - 1],
               self.neg_ones[0],
               self.neg_ones[MAX_ONES - 1])
    }
}

impl PartialEq for TernPoly {
    fn eq(&self, other: &TernPoly) -> bool {
        self.n == other.n && self.num_ones == other.num_ones &&
        self.num_neg_ones == other.num_neg_ones &&
        {
            for i in 0..MAX_ONES {
                if self.ones[i] != other.ones[i] {
                    return false;
                }
                if self.neg_ones[i] != other.neg_ones[i] {
                    return false;
                }
            }
            true
        }
    }
}

impl TernPoly {
    /// Creates a new TernPoly
    pub fn new(n: u16, ones: &[u16], neg_ones: &[u16]) -> TernPoly {
        let mut new_ones = [0; MAX_ONES];
        let mut new_neg_ones = [0; MAX_ONES];

        for (i, one) in ones.iter().enumerate() {
            new_ones[i] = *one;
        }

        for (i, neg_one) in neg_ones.iter().enumerate() {
            new_neg_ones[i] = *neg_one;
        }

        TernPoly {
            n: n,
            num_ones: ones.len() as u16,
            num_neg_ones: neg_ones.len() as u16,
            ones: new_ones,
            neg_ones: new_neg_ones,
        }
    }

    /// Get the
    pub fn get_n(&self) -> u16 {
        self.n
    }

    /// Get +1 coefficients
    pub fn get_ones(&self) -> &[u16] {
        &self.ones[0..self.num_ones as usize]
    }

    /// Get -1 coefficients
    pub fn get_neg_ones(&self) -> &[u16] {
        &self.neg_ones[0..self.num_neg_ones as usize]
    }

    /// Ternary to general integer polynomial
    ///
    /// Converts a TernPoly to an equivalent IntPoly.
    pub fn to_int_poly(&self) -> IntPoly {
        IntPoly {
            n: self.n,
            coeffs: {
                let mut coeffs = [0; INT_POLY_SIZE];

                for i in 0..self.num_ones {
                    coeffs[self.ones[i as usize] as usize] = 1;
                }
                for i in 0..self.num_neg_ones {
                    coeffs[self.neg_ones[i as usize] as usize] = -1;
                }

                coeffs
            },
        }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone)]
/// A product-form polynomial, i.e. a polynomial of the form f1*f2+f3 where f1,f2,f3 are very
/// sparsely populated ternary polynomials.
pub struct ProdPoly {
    n: uint16_t,
    f1: TernPoly,
    f2: TernPoly,
    f3: TernPoly,
}

impl Default for ProdPoly {
    fn default() -> ProdPoly {
        ProdPoly {
            n: 0,
            f1: Default::default(),
            f2: Default::default(),
            f3: Default::default(),
        }
    }
}

impl ProdPoly {
    /// Creates a new `ProdPoly` from three `TernPoly`s
    pub fn new(n: u16, f1: TernPoly, f2: TernPoly, f3: TernPoly) -> ProdPoly {
        ProdPoly {
            n: n,
            f1: f1,
            f2: f2,
            f3: f3,
        }
    }

    /// Random product-form polynomial
    ///
    /// Generates a random product-form polynomial consisting of 3 random ternary polynomials.
    /// Parameters:
    ///
    /// * *N*: the number of coefficients, must be MAX_DEGREE or less
    /// * *df1*: number of ones and negative ones in the first ternary polynomial
    /// * *df2*: number of ones and negative ones in the second ternary polynomial
    /// * *df3_ones*: number of ones ones in the third ternary polynomial
    /// * *df3_neg_ones*: number of negative ones in the third ternary polynomial
    /// * *rand_ctx*: a random number generator
    pub fn rand(n: u16,
                df1: u16,
                df2: u16,
                df3_ones: u16,
                df3_neg_ones: u16,
                rand_ctx: &RandContext)
                -> Option<ProdPoly> {
        let f1 = TernPoly::rand(n, df1, df1, rand_ctx);
        if f1.is_none() {
            return None;
        }
        let f1 = f1.unwrap();

        let f2 = TernPoly::rand(n, df2, df2, rand_ctx);
        if f2.is_none() {
            return None;
        }
        let f2 = f2.unwrap();

        let f3 = TernPoly::rand(n, df3_ones, df3_neg_ones, rand_ctx);
        if f3.is_none() {
            return None;
        }
        let f3 = f3.unwrap();

        Some(ProdPoly::new(n, f1, f2, f3))
    }

    /// Returns an IntPoly equivalent to the ProdPoly
    pub fn to_int_poly(&self, modulus: u16) -> IntPoly {
        let c = IntPoly {
            n: self.n,
            coeffs: [0; INT_POLY_SIZE],
        };

        let mod_mask = modulus - 1;
        let (c, _) = c.mult_tern(&self.f2, mod_mask);
        c.add_tern(&self.f3)
    }
}

/// The size of the union in 16 bit words
const PRIVUNION_SIZE: usize = 3004;

#[repr(C)]
/// Union for the private key polynomial
struct PrivUnion {
    /// The union data as a 2-byte array
    data: [uint16_t; PRIVUNION_SIZE],
}

impl Default for PrivUnion {
    fn default() -> PrivUnion {
        PrivUnion { data: [0; PRIVUNION_SIZE] }
    }
}

impl Clone for PrivUnion {
    fn clone(&self) -> PrivUnion {
        let mut new_data = [0u16; PRIVUNION_SIZE];
        for (i, data) in self.data.iter().enumerate() {
            new_data[i] = *data
        }
        PrivUnion { data: new_data }
    }
}

impl PrivUnion {
    /// Create a new union from a ProdPoly
    unsafe fn new_from_prod(poly: ProdPoly) -> PrivUnion {
        let arr: &[uint16_t; 3004] = mem::transmute(&poly);
        let mut data = [0; PRIVUNION_SIZE];

        for (i, b) in arr.iter().enumerate() {
            data[i] = *b;
        }

        PrivUnion { data: data }
    }

    /// Create a new union from a TernPoly
    unsafe fn new_from_tern(poly: TernPoly) -> PrivUnion {
        let arr: &[uint16_t; 1001] = mem::transmute(&poly);
        let mut data = [0; PRIVUNION_SIZE];

        for (i, b) in arr.iter().enumerate() {
            data[i] = *b;
        }

        PrivUnion { data: data }
    }

    /// Get the union as a ProdPoly
    unsafe fn prod(&self) -> &ProdPoly {
        mem::transmute(&self.data)
    }

    /// Get the union as a TernPoly
    unsafe fn tern(&self) -> &TernPoly {
        mem::transmute(&self.data)
    }
}

#[repr(C)]
#[derive(Clone)]
/// Private polynomial, can be ternary or product-form
pub struct PrivPoly {
    // maybe we could do conditional compilation?
    /// Whether the polynomial is in product form
    prod_flag: uint8_t,
    poly: PrivUnion,
}

impl Default for PrivPoly {
    fn default() -> PrivPoly {
        PrivPoly {
            prod_flag: 0,
            poly: Default::default(),
        }
    }
}

impl fmt::Debug for PrivPoly {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_product() {
            write!(f, "PrivPoly {{ prod_poly: {:?} }}", self.get_poly_prod())
        } else {
            write!(f, "PrivPoly {{ tern_poly: {:?} }}", self.get_poly_tern())
        }
    }
}

impl PartialEq for PrivPoly {
    fn eq(&self, other: &PrivPoly) -> bool {
        self.prod_flag == other.prod_flag &&
        {
            if self.prod_flag > 0 {
                self.get_poly_prod() == other.get_poly_prod()
            } else {
                self.get_poly_tern() == other.get_poly_tern()
            }
        }
    }
}

impl PrivPoly {
    /// Create a new PrivPoly with a ProdPoly
    pub fn new_with_prod_poly(poly: ProdPoly) -> PrivPoly {
        PrivPoly {
            prod_flag: 1,
            poly: unsafe { PrivUnion::new_from_prod(poly) },
        }
    }

    /// Create a new PrivPoly with a TernPoly
    pub fn new_with_tern_poly(poly: TernPoly) -> PrivPoly {
        PrivPoly {
            prod_flag: 0,
            poly: unsafe { PrivUnion::new_from_tern(poly) },
        }
    }

    /// If the PrivPoly contains a ProdPoly
    pub fn is_product(&self) -> bool {
        self.prod_flag == 1
    }

    /// Get the ProdPoly of the union
    ///
    /// Panics if the union is actually a TernPoly
    pub fn get_poly_prod(&self) -> &ProdPoly {
        if self.prod_flag != 1 {
            panic!("Trying to get PrivPoly from an union that is TernPoly.");
        }
        unsafe { &*self.poly.prod() }
    }

    /// Get the TernPoly of the union
    ///
    /// Panics if the union is actually a ProdPoly
    pub fn get_poly_tern(&self) -> &TernPoly {
        if self.prod_flag != 0 {
            panic!("Trying to get TernPoly from an union that is ProdPoly.");
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
    pub fn invert(&self, mod_mask: u16) -> (IntPoly, bool) {
        let mut fq: IntPoly = Default::default();
        let result = unsafe { ffi::ntru_invert(self, mod_mask, &mut fq) };

        (fq, result == 1)
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone)]
/// NTRU encryption private key
pub struct PrivateKey {
    q: uint16_t,
    t: PrivPoly,
}

impl Default for PrivateKey {
    fn default() -> PrivateKey {
        PrivateKey {
            q: 0,
            t: Default::default(),
        }
    }
}

impl PrivateKey {
    /// Gets the q parameter of the PrivateKey
    pub fn get_q(&self) -> u16 {
        self.q
    }

    /// Gets the tparameter of the PrivateKey
    pub fn get_t(&self) -> &PrivPoly {
        &self.t
    }

    /// Get params from the private key
    pub fn get_params(&self) -> Result<EncParams, Error> {
        let mut params: EncParams = Default::default();
        let result = unsafe { ffi::ntru_params_from_priv_key(self, &mut params) };

        if result == 0 {
            Ok(params)
        } else {
            Err(Error::from(result))
        }
    }

    /// Import private key
    pub fn import(arr: &[u8]) -> PrivateKey {
        let mut key: PrivateKey = Default::default();
        unsafe { ffi::ntru_import_priv(&arr[0], &mut key) };

        key
    }

    /// Export private key
    pub fn export(&self, params: &EncParams) -> Box<[u8]> {
        let mut arr = vec![0u8; params.private_len() as usize];
        let _ = unsafe { ffi::ntru_export_priv(self, &mut arr[..][0]) };

        arr.into_boxed_slice()
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone)]
/// NTRU encryption public key
pub struct PublicKey {
    q: uint16_t,
    h: IntPoly,
}

impl Default for PublicKey {
    fn default() -> PublicKey {
        PublicKey {
            q: 0,
            h: Default::default(),
        }
    }
}

impl PublicKey {
    /// Get the q parameter of the PublicKey
    pub fn get_q(&self) -> u16 {
        self.q
    }

    /// Get the h parameter of the PublicKey
    pub fn get_h(&self) -> &IntPoly {
        &self.h
    }

    /// Import a public key
    pub fn import(arr: &[u8]) -> PublicKey {
        let mut key: PublicKey = Default::default();
        let _ = unsafe { ffi::ntru_import_pub(&arr[0], &mut key) };

        key
    }

    /// Export public key
    pub fn export(&self, params: &EncParams) -> Box<[u8]> {
        let mut arr = vec![0u8; params.public_len() as usize];
        unsafe { ffi::ntru_export_pub(self, &mut arr[..][0]) };

        arr.into_boxed_slice()
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone)]
/// NTRU encryption key pair
pub struct KeyPair {
    /// Private key
    private: PrivateKey,
    /// Public key
    public: PublicKey,
}

impl Default for KeyPair {
    fn default() -> KeyPair {
        KeyPair {
            private: Default::default(),
            public: Default::default(),
        }
    }
}

impl KeyPair {
    /// Generate a new key pair
    pub fn new(private: PrivateKey, public: PublicKey) -> KeyPair {
        KeyPair {
            private: private,
            public: public,
        }
    }

    /// Get params from the key pair
    pub fn get_params(&self) -> Result<EncParams, Error> {
        self.private.get_params()
    }

    /// The private key
    pub fn get_private(&self) -> &PrivateKey {
        &self.private
    }
    /// The public key
    pub fn get_public(&self) -> &PublicKey {
        &self.public
    }
}

/// The error enum
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Error {
    /// Out of memory error.
    OutOfMemory,
    /// Error in the random number generator.
    Prng,
    /// Message is too long.
    MessageTooLong,
    /// Invalid maximum length.
    InvalidMaxLength,
    /// MD0 violation.
    Md0Violation,
    /// No zero pad.
    NoZeroPad,
    /// Invalid encoding of the message.
    InvalidEncoding,
    /// Null argument.
    NullArgument,
    /// Unknown parameter set.
    UnknownParamSet,
    /// Invalid parameter.
    InvalidParam,
    /// Invalid key.
    InvalidKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<uint8_t> for Error {
    fn from(error: uint8_t) -> Error {
        match error {
            1 => Error::OutOfMemory,
            2 => Error::Prng,
            3 => Error::MessageTooLong,
            4 => Error::InvalidMaxLength,
            5 => Error::Md0Violation,
            6 => Error::NoZeroPad,
            7 => Error::InvalidEncoding,
            8 => Error::NullArgument,
            9 => Error::UnknownParamSet,
            10 => Error::InvalidParam,
            11 => Error::InvalidKey,
            _ => unreachable!(),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::OutOfMemory => "Out of memory error.",
            Error::Prng => "Error in the random number generator.",
            Error::MessageTooLong => "Message is too long.",
            Error::InvalidMaxLength => "Invalid maximum length.",
            Error::Md0Violation => "MD0 violation.",
            Error::NoZeroPad => "No zero pad.",
            Error::InvalidEncoding => "Invalid encoding of the message.",
            Error::NullArgument => "Null argument.",
            Error::UnknownParamSet => "Unknown parameter set.",
            Error::InvalidParam => "Invalid parameter.",
            Error::InvalidKey => "Invalid key.",
        }
    }
}
