//! NTRUEncrypt type definitions
//!
//! This module includes all the needed structs and enums for NTRUEncrypt. All of them with their
//! needed methods.
use std::ops::{Add, Sub};
use std::default::Default;
use std::{fmt, mem};
use libc::{int16_t, uint8_t, uint16_t};
use ffi;
use encparams::NtruEncParams;
use rand::NtruRandContext;

/// Max N value for all param sets; +1 for ntru_invert_...()
pub const NTRU_MAX_DEGREE: usize = (1499 + 1);
/// (Max #coefficients + 16) rounded to a multiple of 8
const NTRU_INT_POLY_SIZE: usize = ((NTRU_MAX_DEGREE + 16 + 7) & 0xFFF8);
/// max(df1, df2, df3, dg)
pub const NTRU_MAX_ONES: usize = 499;

/// A polynomial with integer coefficients.
#[repr(C)]
pub struct NtruIntPoly {
    /// The number of coefficients
    n: uint16_t,
    /// The coefficients
    coeffs: [int16_t; NTRU_INT_POLY_SIZE],
}

impl Default for NtruIntPoly {
    fn default() -> NtruIntPoly {
        NtruIntPoly {
            n: 0,
            coeffs: [0; NTRU_INT_POLY_SIZE],
        }
    }
}

impl Clone for NtruIntPoly {
    fn clone(&self) -> NtruIntPoly {
        let mut new_coeffs = [0i16; NTRU_INT_POLY_SIZE];
        for i in 0..self.n as usize {
            new_coeffs[i] = self.coeffs[i];
        }
        NtruIntPoly {
            n: self.n,
            coeffs: new_coeffs,
        }
    }
}

impl Add for NtruIntPoly {
    type Output = NtruIntPoly;
    fn add(self, rhs: NtruIntPoly) -> Self::Output {
        let mut out = self.clone();
        unsafe { ffi::ntru_add(&mut out, &rhs) };
        out
    }
}

impl Sub for NtruIntPoly {
    type Output = NtruIntPoly;
    fn sub(self, rhs: NtruIntPoly) -> Self::Output {
        let mut out = self.clone();
        unsafe { ffi::ntru_sub(&mut out, &rhs) };
        out
    }
}

impl fmt::Debug for NtruIntPoly {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "{{ n: {}, coeffs: [{}...{}] }}",
               self.n,
               self.coeffs[0],
               self.coeffs[NTRU_INT_POLY_SIZE - 1])
    }
}

impl PartialEq for NtruIntPoly {
    fn eq(&self, other: &NtruIntPoly) -> bool {
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

impl NtruIntPoly {
    /// Create a new NtruIntPoly
    pub fn new(coeffs: &[i16]) -> NtruIntPoly {
        let mut new_coeffs = [0; NTRU_INT_POLY_SIZE];

        for i in 0..coeffs.len() {
            new_coeffs[i] = coeffs[i];
        }
        NtruIntPoly {
            n: coeffs.len() as u16,
            coeffs: new_coeffs,
        }
    }

    /// Create a new random NtruIntPoly
    pub fn rand(n: u16, pow2q: u16, rand_ctx: &NtruRandContext) -> NtruIntPoly {
        let rand_data = rand_ctx.get_rng().generate(n * 2, rand_ctx).unwrap();

        let mut coeffs = [0i16; NTRU_INT_POLY_SIZE];
        let shift = 16 - pow2q;
        for i in (n as usize)..0usize {
            coeffs[i] = rand_data[i] as i16 >> shift;
        }

        NtruIntPoly {
            n: n,
            coeffs: coeffs,
        }
    }

    /// Convert array to NtruIntPoly
    pub fn from_arr(arr: &[u8], n: u16, q: u16) -> NtruIntPoly {
        let mut p: NtruIntPoly = Default::default();
        unsafe { ffi::ntru_from_arr(&arr[0], n, q, &mut p) };

        p
    }

    /// Get the coefficients
    pub fn get_coeffs(&self) -> &[i16] {
        &self.coeffs[0..self.n as usize]
    }
    /// Set the coefficients
    pub fn set_coeffs(&mut self, coeffs: &[i16]) {
        self.coeffs = [0; NTRU_INT_POLY_SIZE];
        for i in 0..coeffs.len() {
            self.coeffs[i] = coeffs[i];
        }
    }
    /// Set a coefficient
    pub fn set_coeff(&mut self, index: usize, value: i16) {
        self.coeffs[index] = value
    }

    pub fn mod_mask(&mut self, mod_mask: u16) {
        unsafe { ffi::ntru_mod_mask(self, mod_mask) };
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

    /// General polynomial by ternary polynomial multiplication
    ///
    /// Multiplies a NtruIntPoly by a NtruTernPoly. The number of coefficients must be the same for
    /// both polynomials. It also returns if the number of coefficients differ or not.
    pub fn mult_tern(&self, b: &NtruTernPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        if self.n != b.n {
            panic!("To multiply a NtruIntPoly by a NtruTernPoly the number of coefficients must \
                    be the same for both polynomials")
        }
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe { ffi::ntru_mult_tern(self, b, &mut c, mod_mask) };
        (c, result == 1)
    }

    /// General polynomial by ternary polynomial multiplication
    ///
    /// Multiplies a NtruIntPoly by a NtruTernPoly. The number of coefficients must be the same for
    /// both polynomials. Uses 32-bit arithmetic. It also returns if the number of coefficients
    /// differ or not.
    pub fn mult_tern_32(&self, b: &NtruTernPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        if self.n != b.n {
            panic!("To multiply a NtruIntPoly by a NtruTernPoly the number of coefficients must \
                    be the same for both polynomials")
        }
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe { ffi::ntru_mult_tern_32(self, b, &mut c, mod_mask) };
        (c, result == 1)
    }

    /// General polynomial by ternary polynomial multiplication
    ///
    /// Multiplies a NtruIntPoly by a NtruTernPoly. The number of coefficients must be the same for
    /// both polynomials. Uses 64-bit arithmetic. It also returns if the number of coefficients
    /// differ or not.
    pub fn mult_tern_64(&self, b: &NtruTernPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        if self.n != b.n {
            panic!("To multiply a NtruIntPoly by a NtruTernPoly the number of coefficients must \
                    be the same for both polynomials")
        }
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe { ffi::ntru_mult_tern_64(self, b, &mut c, mod_mask) };
        (c, result == 1)
    }

    /// General polynomial by ternary polynomial multiplication, SSSE3 version
    ///
    /// Multiplies a NtruIntPoly by a NtruTernPoly. The number of coefficients must be the same for
    /// both polynomials. This variant requires SSSE3 support. It also returns if the number of
    /// coefficients differ or not.
    pub fn mult_tern_sse(&self, b: &NtruTernPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        if self.n != b.n {
            panic!("To multiply a NtruIntPoly by a NtruTernPoly the number of coefficients must \
                    be the same for both polynomials")
        }
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe { ffi::ntru_mult_tern_sse(self, b, &mut c, mod_mask) };
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
            },
        }
    }

    /// General polynomial by product-form polynomial multiplication
    ///
    /// Multiplies a NtruIntPoly by a NtruProdPoly. The number of coefficients must be the same for
    /// both polynomials. It also returns if the number of coefficients differ or not.
    pub fn mult_prod(&self, b: &NtruProdPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        if self.n != b.n {
            panic!("To multiply a NtruIntPoly by a NtruProdPoly the number of coefficients must \
                    be the same for both polynomials")
        }
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe { ffi::ntru_mult_prod(self, b, &mut c, mod_mask) };
        (c, result == 1)
    }

    /// General polynomial by private polynomial multiplication
    ///
    /// Multiplies a NtruIntPoly by a NtruPrivPoly, i.e. a NtruTernPoly or a NtruProdPoly. The
    /// number of coefficients must be the same for both polynomials. It also returns if the number
    /// of coefficients differ or not.
    pub fn mult_priv(&self, b: &NtruPrivPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        if (b.is_product() && self.n != b.get_poly_prod().n) ||
           (!b.is_product() && self.n != b.get_poly_tern().n) {
            panic!("To multiply a NtruIntPoly by a NtruProdPoly the number of coefficients must \
                    be the same for both polynomials")
        }
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe { ffi::ntru_mult_priv(b, self, &mut c, mod_mask) };
        (c, result == 1)
    }

    pub fn mult_int(&self, b: &NtruIntPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe { ffi::ntru_mult_int(self, b, &mut c, mod_mask) };
        (c, result == 1)
    }

    pub fn mult_int_16(&self, b: &NtruIntPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe { ffi::ntru_mult_int_16(self, b, &mut c, mod_mask) };
        (c, result == 1)
    }

    pub fn mult_int_64(&self, b: &NtruIntPoly, mod_mask: u16) -> (NtruIntPoly, bool) {
        let mut c: NtruIntPoly = Default::default();
        let result = unsafe { ffi::ntru_mult_int_64(self, b, &mut c, mod_mask) };
        (c, result == 1)
    }

    /// Multiply by factor
    pub fn mult_fac(&mut self, factor: i16) {
        unsafe { ffi::ntru_mult_fac(self, factor) };
    }

    pub fn mod_center(&mut self, modulus: u16) {
        unsafe { ffi::ntru_mod_center(self, modulus) };
    }

    pub fn mod3(&mut self) {
        unsafe { ffi::ntru_mod3(self) };
    }

    /// Check if both polynomials are equals given a modulus
    pub fn equals_mod(&self, other: &NtruIntPoly, modulus: u16) -> bool {
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

    // Check if the NtruIntPoly equals 1
    pub fn equals1(&self) -> bool {
        for i in 1..self.n {
            if self.coeffs[i as usize] != 0 {
                return false;
            }
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
        NtruTernPoly {
            n: 0,
            num_ones: 0,
            num_neg_ones: 0,
            ones: [0; NTRU_MAX_ONES],
            neg_ones: [0; NTRU_MAX_ONES],
        }
    }
}

impl Clone for NtruTernPoly {
    fn clone(&self) -> NtruTernPoly {
        let mut new_ones = [0u16; NTRU_MAX_ONES];
        let mut new_neg_ones = [0u16; NTRU_MAX_ONES];

        for i in 0..self.num_ones as usize {
            new_ones[i] = self.ones[i]
        }
        for i in 0..self.num_neg_ones as usize {
            new_neg_ones[i] = self.neg_ones[i]
        }

        NtruTernPoly {
            n: self.n,
            num_ones: self.num_ones,
            num_neg_ones: self.num_neg_ones,
            ones: new_ones,
            neg_ones: new_neg_ones,
        }
    }
}

impl fmt::Debug for NtruTernPoly {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "{{ n: {}, num_ones: {}, num_neg_ones: {}, ones: [{}...{}], neg_ones: [{}...{}] }}",
               self.n,
               self.num_ones,
               self.num_neg_ones,
               self.ones[0],
               self.ones[NTRU_MAX_ONES - 1],
               self.neg_ones[0],
               self.neg_ones[NTRU_MAX_ONES - 1])
    }
}

impl PartialEq for NtruTernPoly {
    fn eq(&self, other: &NtruTernPoly) -> bool {
        self.n == other.n && self.num_ones == other.num_ones &&
        self.num_neg_ones == other.num_neg_ones &&
        {
            for i in 0..NTRU_MAX_ONES {
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

        NtruTernPoly {
            n: n,
            num_ones: ones.len() as u16,
            num_neg_ones: neg_ones.len() as u16,
            ones: new_ones,
            neg_ones: new_neg_ones,
        }
    }

    // /// Random ternary polynomial
    // ///
    // /// Generates a random ternary polynomial. If an error occurs, it will return None.
    // pub fn rand(n: u16, num_ones: u16, num_neg_ones: u16, rand_ctx: &NtruRandContext)
    //             -> Option<NtruTernPoly> {
    //     let mut poly: NtruTernPoly = Default::default();
    //     let result = unsafe { ffi::ntru_rand_tern(n, num_ones, num_neg_ones, &mut poly,
    //                                               &rand_ctx.rand_ctx) };
    //
    //     if result == 0 {
    //         None
    //     } else {
    //         Some(poly)
    //     }
    // }

    pub fn get_n(&self) -> u16 {
        self.n
    }
    pub fn get_ones(&self) -> &[u16] {
        &self.ones[0..self.num_ones as usize]
    }
    pub fn get_neg_ones(&self) -> &[u16] {
        &self.neg_ones[0..self.num_neg_ones as usize]
    }

    /// Ternary to general integer polynomial
    ///
    /// Converts a NtruTernPoly to an equivalent NtruIntPoly.
    pub fn to_int_poly(&self) -> NtruIntPoly {
        NtruIntPoly {
            n: self.n,
            coeffs: {
                let mut coeffs = [0; NTRU_INT_POLY_SIZE];

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

/// A product-form polynomial, i.e. a polynomial of the form f1*f2+f3 where f1,f2,f3 are very
/// sparsely populated ternary polynomials.
#[repr(C)]
#[derive(Debug, PartialEq, Clone)]
pub struct NtruProdPoly {
    n: uint16_t,
    f1: NtruTernPoly,
    f2: NtruTernPoly,
    f3: NtruTernPoly,
}

impl Default for NtruProdPoly {
    fn default() -> NtruProdPoly {
        NtruProdPoly {
            n: 0,
            f1: Default::default(),
            f2: Default::default(),
            f3: Default::default(),
        }
    }
}

impl NtruProdPoly {
    pub fn new(n: u16, f1: NtruTernPoly, f2: NtruTernPoly, f3: NtruTernPoly) -> NtruProdPoly {
        NtruProdPoly {
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
    /// * *N*: the number of coefficients, must be NTRU_MAX_DEGREE or less
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
                rand_ctx: &NtruRandContext)
                -> Option<NtruProdPoly> {
        let f1 = NtruTernPoly::rand(n, df1, df1, rand_ctx);
        if f1.is_none() {
            return None;
        }
        let f1 = f1.unwrap();

        let f2 = NtruTernPoly::rand(n, df2, df2, rand_ctx);
        if f2.is_none() {
            return None;
        }
        let f2 = f2.unwrap();

        let f3 = NtruTernPoly::rand(n, df3_ones, df3_neg_ones, rand_ctx);
        if f3.is_none() {
            return None;
        }
        let f3 = f3.unwrap();

        Some(NtruProdPoly::new(n, f1, f2, f3))
    }

    pub fn to_int_poly(&self, modulus: u16) -> NtruIntPoly {
        let c = NtruIntPoly {
            n: self.n,
            coeffs: [0; NTRU_INT_POLY_SIZE],
        };

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
        PrivUnion { data: [0; PRIVUNION_SIZE] }
    }
}

impl Clone for PrivUnion {
    fn clone(&self) -> PrivUnion {
        let mut new_data = [0u16; PRIVUNION_SIZE];
        for i in 0..self.data.len() {
            new_data[i] = self.data[i]
        }
        PrivUnion { data: new_data }
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
#[derive(Clone)]
pub struct NtruPrivPoly {
    // maybe we could do conditional compilation?
    /// Whether the polynomial is in product form
    prod_flag: uint8_t,
    poly: PrivUnion,
}

impl Default for NtruPrivPoly {
    fn default() -> NtruPrivPoly {
        NtruPrivPoly {
            prod_flag: 0,
            poly: Default::default(),
        }
    }
}

impl fmt::Debug for NtruPrivPoly {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_product() {
            write!(f,
                   "NtruPrivPoly {{ prod_poly: {:?} }}",
                   self.get_poly_prod())
        } else {
            write!(f,
                   "NtruPrivPoly {{ tern_poly: {:?} }}",
                   self.get_poly_tern())
        }
    }
}

impl PartialEq for NtruPrivPoly {
    fn eq(&self, other: &NtruPrivPoly) -> bool {
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

impl NtruPrivPoly {
    /// Create a new NtruPrivPoly with a NtruProdPoly
    pub fn new_with_prod_poly(poly: NtruProdPoly) -> NtruPrivPoly {
        NtruPrivPoly {
            prod_flag: 1,
            poly: unsafe { PrivUnion::new_from_prod(poly) },
        }
    }

    /// Create a new NtruPrivPoly with a NtruTernPoly
    pub fn new_with_tern_poly(poly: NtruTernPoly) -> NtruPrivPoly {
        NtruPrivPoly {
            prod_flag: 0,
            poly: unsafe { PrivUnion::new_from_tern(poly) },
        }
    }

    /// If the NtruPrivPoly contains a NtruProdPoly
    pub fn is_product(&self) -> bool {
        self.prod_flag == 1
    }

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
#[derive(Debug, PartialEq, Clone)]
pub struct NtruEncPrivKey {
    q: uint16_t,
    t: NtruPrivPoly,
}

impl Default for NtruEncPrivKey {
    fn default() -> NtruEncPrivKey {
        NtruEncPrivKey {
            q: 0,
            t: Default::default(),
        }
    }
}

impl NtruEncPrivKey {
    pub fn get_q(&self) -> u16 {
        self.q
    }
    pub fn get_t(&self) -> &NtruPrivPoly {
        &self.t
    }

    /// Get params from the private key
    pub fn get_params(&self) -> Result<NtruEncParams, NtruError> {
        let mut params: NtruEncParams = Default::default();
        let result = unsafe { ffi::ntru_params_from_priv_key(self, &mut params) };

        if result == 0 {
            Ok(params)
        } else {
            Err(NtruError::from_uint8_t(result))
        }
    }

    /// Import private key
    pub fn import(arr: &[u8]) -> NtruEncPrivKey {
        let mut key: NtruEncPrivKey = Default::default();
        unsafe { ffi::ntru_import_priv(&arr[0], &mut key) };

        key
    }

    /// Export private key
    pub fn export(&self, params: &NtruEncParams) -> Box<[u8]> {
        let mut arr = vec![0u8; params.private_len() as usize];
        let _ = unsafe { ffi::ntru_export_priv(self, &mut arr[..][0]) };

        arr.into_boxed_slice()
    }
}

/// NtruEncrypt public key
#[repr(C)]
#[derive(Debug, PartialEq, Clone)]
pub struct NtruEncPubKey {
    q: uint16_t,
    h: NtruIntPoly,
}

impl Default for NtruEncPubKey {
    fn default() -> NtruEncPubKey {
        NtruEncPubKey {
            q: 0,
            h: Default::default(),
        }
    }
}

impl NtruEncPubKey {
    pub fn get_q(&self) -> u16 {
        self.q
    }
    pub fn get_h(&self) -> &NtruIntPoly {
        &self.h
    }

    /// Import a public key
    pub fn import(arr: &[u8]) -> NtruEncPubKey {
        let mut key: NtruEncPubKey = Default::default();
        let _ = unsafe { ffi::ntru_import_pub(&arr[0], &mut key) };

        key
    }

    /// Export public key
    pub fn export(&self, params: &NtruEncParams) -> Box<[u8]> {
        let mut arr = vec![0u8; params.public_len() as usize];
        unsafe { ffi::ntru_export_pub(self, &mut arr[..][0]) };

        arr.into_boxed_slice()
    }
}

/// NtruEncrypt key pair
#[repr(C)]
#[derive(Debug, PartialEq, Clone)]
pub struct NtruEncKeyPair {
    /// Private key
    private: NtruEncPrivKey,
    /// Public key
    public: NtruEncPubKey,
}

impl Default for NtruEncKeyPair {
    fn default() -> NtruEncKeyPair {
        NtruEncKeyPair {
            private: Default::default(),
            public: Default::default(),
        }
    }
}

impl NtruEncKeyPair {
    /// Generate a new key pair
    pub fn new(private: NtruEncPrivKey, public: NtruEncPubKey) -> NtruEncKeyPair {
        NtruEncKeyPair {
            private: private,
            public: public,
        }
    }

    /// Get params from the key pair
    pub fn get_params(&self) -> Result<NtruEncParams, NtruError> {
        self.private.get_params()
    }

    /// The private key
    pub fn get_private(&self) -> &NtruEncPrivKey {
        &self.private
    }
    /// The public key
    pub fn get_public(&self) -> &NtruEncPubKey {
        &self.public
    }
}

/// The error enum
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum NtruError {
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

impl NtruError {
    /// Get the NtruError from the original uint8_t libntru error.
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
            11 => NtruError::InvalidKey,
            _ => unreachable!(),
        }
    }
}
