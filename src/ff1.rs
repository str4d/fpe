//! A Rust implementation of the FF1 algorithm, specified in
//! [NIST Special Publication 800-38G](http://dx.doi.org/10.6028/NIST.SP.800-38G).

use aes::block_cipher_trait::{generic_array::GenericArray, BlockCipher};
use byteorder::{BigEndian, WriteBytesExt};
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{
    identities::{One, Zero},
    ToPrimitive,
};

#[derive(Debug, PartialEq)]
enum Radix {
    /// A radix in [2..2^16]. It uses floating-point arithmetic.
    Any(u32),
    /// A radix 2^i for i in [1..16]. It does not use floating-point arithmetic.
    PowerTwo { radix: u32, log_radix: u8 },
}

impl Radix {
    pub fn from(radix: u32) -> Result<Self, ()> {
        // radix must be in range [2..2^16]
        if radix < 2 || radix > (1 << 16) {
            return Err(());
        }

        let mut tmp = radix;
        let mut log_radix = None;
        let mut found_bit = false;

        // 2^16 is 17 bits
        for i in 0..17 {
            if tmp & 1 != 0 {
                // Only a single bit can be set for PowerTwo
                if found_bit {
                    log_radix = None;
                } else {
                    log_radix = Some(i);
                    found_bit = true;
                }
            }
            tmp >>= 1;
        }
        Ok(match log_radix {
            Some(log_radix) => Radix::PowerTwo { radix, log_radix },
            None => Radix::Any(radix),
        })
    }

    /// Calculates b = ceil(ceil(v * log2(radix)) / 8).
    fn calculate_b(&self, v: usize) -> usize {
        match *self {
            Radix::Any(r) => (v as f64 * f64::from(r).log2() / 8f64).ceil() as usize,
            Radix::PowerTwo { log_radix, .. } => ((v * log_radix as usize) + 7) / 8,
        }
    }

    fn to_biguint(&self) -> BigUint {
        BigUint::from(self.to_u32())
    }

    fn to_u32(&self) -> u32 {
        match *self {
            Radix::Any(r) => r,
            Radix::PowerTwo { radix, .. } => radix,
        }
    }
}

/// For a given base, a finite, ordered sequence of numerals for the base.
pub trait NumeralString: Sized {
    /// Returns whether this numeral string is valid for the base radix.
    fn is_valid(&self, radix: u32) -> bool;

    /// Returns the number of numerals in this numeral string.
    fn len(&self) -> usize;

    /// Splits this numeral string into two sections X[..u] and X[u..].
    fn split(&self, u: usize) -> (Self, Self);

    /// Concatenates two numeral strings.
    fn concat(a: Self, b: Self) -> Self;

    /// The number that this numeral string represents in the base radix
    /// when the numerals are valued in decreasing order of significance
    /// (big-endian order).
    fn num_radix(&self, radix: &BigUint) -> BigUint;

    /// Given a non-negative integer x less than radix<sup>m</sup>, returns
    /// the representation of x as a string of m numerals in base radix,
    /// in decreasing order of significance (big-endian order).
    fn str_radix(x: BigUint, radix: &BigUint, m: usize) -> Self;
}

/// A numeral string that supports radixes in [2..2^16).
pub struct FlexibleNumeralString(Vec<u16>);

impl From<Vec<u16>> for FlexibleNumeralString {
    fn from(v: Vec<u16>) -> Self {
        FlexibleNumeralString(v)
    }
}

impl From<FlexibleNumeralString> for Vec<u16> {
    fn from(fns: FlexibleNumeralString) -> Self {
        fns.0
    }
}

impl NumeralString for FlexibleNumeralString {
    fn is_valid(&self, radix: u32) -> bool {
        self.0.iter().all(|n| (u32::from(*n) < radix))
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn split(&self, u: usize) -> (Self, Self) {
        let mut front = self.0.clone();
        let back = front.split_off(u);
        (FlexibleNumeralString(front), FlexibleNumeralString(back))
    }

    fn concat(mut a: Self, mut b: Self) -> Self {
        a.0.append(&mut b.0);
        a
    }

    fn num_radix(&self, radix: &BigUint) -> BigUint {
        let mut res = BigUint::zero();
        for i in &self.0 {
            res *= radix;
            res += BigUint::from(*i);
        }
        res
    }

    fn str_radix(mut x: BigUint, radix: &BigUint, m: usize) -> Self {
        let mut res = vec![0; m];
        for i in 0..m {
            res[m - 1 - i] = (&x % radix).to_u16().unwrap();
            x /= radix;
        }
        FlexibleNumeralString(res)
    }
}

/// A numeral string with radix 2.
pub struct BinaryNumeralString(Vec<u8>);

impl BinaryNumeralString {
    /// Creates a BinaryNumeralString from a byte slice, with each byte
    /// interpreted in little-endian bit order.
    pub fn from_bytes_le(s: &[u8]) -> Self {
        let mut data = Vec::with_capacity(s.len() * 8);
        for n in s {
            let mut tmp = *n;
            for _ in 0..8 {
                data.push(tmp & 1);
                tmp >>= 1;
            }
        }
        BinaryNumeralString(data)
    }

    /// Returns a Vec<u8>, with each byte written from the BinaryNumeralString
    /// in little-endian bit order.
    pub fn to_bytes_le(&self) -> Vec<u8> {
        // We should always have a multiple of eight bits
        assert_eq!((self.0.len() + 7) / 8, self.0.len() / 8);
        let mut data = Vec::with_capacity(self.0.len() / 8);
        let mut acc = 0;
        let mut shift = 0;
        for n in &self.0 {
            acc += n << shift;
            shift += 1;
            if shift == 8 {
                data.push(acc);
                acc = 0;
                shift = 0;
            }
        }
        data
    }
}

impl NumeralString for BinaryNumeralString {
    fn is_valid(&self, radix: u32) -> bool {
        self.0.iter().all(|n| (u32::from(*n) < radix))
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn split(&self, u: usize) -> (Self, Self) {
        let mut front = self.0.clone();
        let back = front.split_off(u);
        (BinaryNumeralString(front), BinaryNumeralString(back))
    }

    fn concat(mut a: Self, mut b: Self) -> Self {
        a.0.append(&mut b.0);
        a
    }

    fn num_radix(&self, radix: &BigUint) -> BigUint {
        let zero = BigUint::zero();
        let one = BigUint::one();
        // Check that radix == 2
        assert!((radix & &one).is_zero());
        assert_eq!(radix >> 1, one);
        let mut res = zero;
        for i in &self.0 {
            res <<= 1;
            if *i != 0 {
                res += &one;
            }
        }
        res
    }

    fn str_radix(mut x: BigUint, radix: &BigUint, m: usize) -> Self {
        let one = BigUint::one();
        // Check that radix == 2
        assert!((radix & &one).is_zero());
        assert_eq!(radix >> 1, one);
        let mut res = vec![0; m];
        for i in 0..m {
            if x.is_odd() {
                res[m - 1 - i] = 1;
            }
            x >>= 1;
        }
        BinaryNumeralString(res)
    }
}

fn pow(x: &BigUint, e: usize) -> BigUint {
    let mut res = BigUint::one();
    for _ in 0..e {
        res *= x;
    }
    res
}

fn generate_s<CIPH: BlockCipher>(ciph: &CIPH, r: &[u8], d: usize) -> Vec<u8> {
    let mut s = Vec::from(r);
    s.reserve(d);
    {
        let mut j = 0u128;
        while s.len() < d {
            j += 1;
            let mut block = j.to_be_bytes();
            for k in 0..16 {
                block[k] ^= r[k];
            }
            ciph.encrypt_block(&mut GenericArray::from_mut_slice(&mut block));
            s.extend_from_slice(&block[..]);
        }
    }
    s.truncate(d);
    s
}

/// A struct for performing FF1 encryption and decryption operations.
pub struct FF1<CIPH: BlockCipher> {
    ciph: CIPH,
    radix: Radix,
    radix_bi: BigUint,
}

impl<CIPH: BlockCipher> FF1<CIPH> {
    fn prf(&self, x: &[u8]) -> [u8; 16] {
        let m = x.len() / 16;
        let mut y = [0u8; 16];
        for j in 0..m {
            for i in 0..16 {
                y[i] ^= x[j * 16 + i];
            }
            self.ciph
                .encrypt_block(&mut GenericArray::from_mut_slice(&mut y));
        }
        y
    }

    /// Creates a new FF1 object for the given key and radix.
    ///
    /// Returns an error if the given radix is not in [2..2^16].
    pub fn new(key: &[u8], radix: u32) -> Result<Self, ()> {
        let ciph = CIPH::new(GenericArray::from_slice(key));
        let radix = Radix::from(radix)?;
        let radix_bi = radix.to_biguint();
        Ok(FF1 {
            ciph,
            radix,
            radix_bi,
        })
    }

    /// Encrypts the given numeral string.
    ///
    /// Returns an error if the numeral string is not in the required radix.
    pub fn encrypt<NS: NumeralString>(&self, tweak: &[u8], x: &NS) -> Result<NS, ()> {
        if !x.is_valid(self.radix.to_u32()) {
            return Err(());
        }

        let n = x.len();
        let t = tweak.len();

        // 1. Let u = floor(n / 2); v = n - u
        let u = n / 2;
        let v = n - u;

        // 2. Let A = X[1..u]; B = X[u + 1..n].
        let (mut x_a, mut x_b) = x.split(u);

        // 3. Let b = ceil(ceil(v * log2(radix)) / 8).
        let b = self.radix.calculate_b(v);

        // 4. Let d = 4 * ceil(b / 4) + 4.
        let d = 4 * ((b + 3) / 4) + 4;

        // 5. Let P = [1, 2, 1] || [radix] || [10] || [u mod 256] || [n] || [t].
        let mut p = vec![1, 2, 1];
        p.write_u24::<BigEndian>(self.radix.to_u32()).unwrap();
        p.write_u8(10).unwrap();
        p.write_u8(u as u8).unwrap();
        p.write_u32::<BigEndian>(n as u32).unwrap();
        p.write_u32::<BigEndian>(t as u32).unwrap();

        //  6i. Let Q = T || [0]^((-t-b-1) mod 16) || [i] || [NUM(B, radix)].
        let q_base = {
            let val = ((((-(t as i32) - (b as i32) - 1) % 16) + 16) % 16) as usize;
            let mut q = Vec::from(tweak);
            q.resize(t + val, 0);
            q
        };
        for i in 0..10 {
            let mut q = q_base.clone();
            q.write_u8(i).unwrap();
            let q_bytes = x_b.num_radix(&self.radix_bi).to_bytes_be();
            for _ in 0..(b - q_bytes.len()) {
                q.write_u8(0).unwrap();
            }
            q.extend(q_bytes);

            // 6ii. Let R = PRF(P || Q).
            let r = self.prf(&[&p[..], &q[..]].concat());

            // 6iii. Let S be the first d bytes of R.
            let s = generate_s(&self.ciph, &r[..], d);

            // 6iv. Let y = NUM(S).
            let y = BigUint::from_bytes_be(&s);

            // 6v. If i is even, let m = u; else, let m = v.
            let m = if i % 2 == 0 { u } else { v };

            // 6vi. Let c = (NUM(A, radix) + y) mod radix^m.
            let c = (x_a.num_radix(&self.radix_bi) + y) % pow(&self.radix_bi, m);

            // 6vii. Let C = STR(c, radix).
            let x_c = NS::str_radix(c, &self.radix_bi, m);

            // 6viii. Let A = B.
            x_a = x_b;

            // 6ix. Let B = C.
            x_b = x_c;
        }

        // 7. Return A || B.
        Ok(NS::concat(x_a, x_b))
    }

    /// Decrypts the given numeral string.
    ///
    /// Returns an error if the numeral string is not in the required radix.
    pub fn decrypt<NS: NumeralString>(&self, tweak: &[u8], x: &NS) -> Result<NS, ()> {
        if !x.is_valid(self.radix.to_u32()) {
            return Err(());
        }

        let n = x.len();
        let t = tweak.len();

        // 1. Let u = floor(n / 2); v = n - u
        let u = n / 2;
        let v = n - u;

        // 2. Let A = X[1..u]; B = X[u + 1..n].
        let (mut x_a, mut x_b) = x.split(u);

        // 3. Let b = ceil(ceil(v * log2(radix)) / 8).
        let b = self.radix.calculate_b(v);

        // 4. Let d = 4 * ceil(b / 4) + 4.
        let d = 4 * ((b + 3) / 4) + 4;

        // 5. Let P = [1, 2, 1] || [radix] || [10] || [u mod 256] || [n] || [t].
        let mut p = vec![1, 2, 1];
        p.write_u24::<BigEndian>(self.radix.to_u32()).unwrap();
        p.write_u8(10).unwrap();
        p.write_u8(u as u8).unwrap();
        p.write_u32::<BigEndian>(n as u32).unwrap();
        p.write_u32::<BigEndian>(t as u32).unwrap();

        //  6i. Let Q = T || [0]^((-t-b-1) mod 16) || [i] || [NUM(A, radix)].
        let q_base = {
            let val = ((((-(t as i32) - (b as i32) - 1) % 16) + 16) % 16) as usize;
            let mut q = Vec::from(tweak);
            q.resize(t + val, 0);
            q
        };
        for i in 0..10 {
            let i = 9 - i;
            let mut q = q_base.clone();
            q.write_u8(i).unwrap();
            let q_bytes = x_a.num_radix(&self.radix_bi).to_bytes_be();
            for _ in 0..(b - q_bytes.len()) {
                q.write_u8(0).unwrap();
            }
            q.extend(q_bytes);

            // 6ii. Let R = PRF(P || Q).
            let r = self.prf(&[&p[..], &q[..]].concat());

            // 6iii. Let S be the first d bytes of R.
            let s = generate_s(&self.ciph, &r[..], d);

            // 6iv. Let y = NUM(S).
            let y = BigInt::from(BigUint::from_bytes_be(&s));

            // 6v. If i is even, let m = u; else, let m = v.
            let m = if i % 2 == 0 { u } else { v };

            // 6vi. Let c = (NUM(B, radix) - y) mod radix^m.
            let modulus = BigInt::from(pow(&self.radix_bi, m));
            let mut c = (BigInt::from(x_b.num_radix(&self.radix_bi)) - y) % &modulus;
            if c.sign() == Sign::Minus {
                // use ((x % m) + m) % m to ensure it is in range
                c += &modulus;
                c %= modulus;
            }
            let c = c.to_biguint().unwrap();

            // 6vii. Let C = STR(c, radix).
            let x_c = NS::str_radix(c, &self.radix_bi, m);

            // 6viii. Let B = A.
            x_b = x_a;

            // 6ix. Let A = C.
            x_a = x_c;
        }

        // 7. Return A || B.
        Ok(NS::concat(x_a, x_b))
    }
}

#[cfg(test)]
mod tests {
    use aes::{Aes128, Aes192, Aes256};

    use super::{BinaryNumeralString, FlexibleNumeralString, NumeralString, Radix, FF1};

    #[test]
    fn ns_is_valid() {
        let radix = 10;
        let ns = FlexibleNumeralString::from(vec![0, 5, 9]);
        assert!(ns.is_valid(radix));

        let ns = FlexibleNumeralString::from(vec![0, 5, 10]);
        assert!(!ns.is_valid(radix));
    }

    #[test]
    fn radix() {
        assert_eq!(Radix::from(1), Err(()));
        assert_eq!(
            Radix::from(2),
            Ok(Radix::PowerTwo {
                radix: 2,
                log_radix: 1,
            })
        );
        assert_eq!(Radix::from(3), Ok(Radix::Any(3)));
        assert_eq!(
            Radix::from(4),
            Ok(Radix::PowerTwo {
                radix: 4,
                log_radix: 2,
            })
        );
        assert_eq!(Radix::from(5), Ok(Radix::Any(5)));
        assert_eq!(Radix::from(6), Ok(Radix::Any(6)));
        assert_eq!(Radix::from(7), Ok(Radix::Any(7)));
        assert_eq!(
            Radix::from(8),
            Ok(Radix::PowerTwo {
                radix: 8,
                log_radix: 3,
            })
        );
        assert_eq!(
            Radix::from(32768),
            Ok(Radix::PowerTwo {
                radix: 32768,
                log_radix: 15,
            })
        );
        assert_eq!(Radix::from(65535), Ok(Radix::Any(65535)));
        assert_eq!(
            Radix::from(65536),
            Ok(Radix::PowerTwo {
                radix: 65536,
                log_radix: 16,
            })
        );
        assert_eq!(Radix::from(65537), Err(()));
    }

    #[test]
    fn test_vectors() {
        enum AesType {
            AES128,
            AES192,
            AES256,
        };

        struct TestVector {
            aes: AesType,
            key: Vec<u8>,
            radix: u32,
            tweak: Vec<u8>,
            pt: Vec<u16>,
            ct: Vec<u16>,
        };

        let test_vectors = vec![
            // From https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf
            TestVector {
                // Sample #1
                aes: AesType::AES128,
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C,
                ],
                radix: 10,
                tweak: vec![],
                pt: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                ct: vec![2, 4, 3, 3, 4, 7, 7, 4, 8, 4],
            },
            TestVector {
                // Sample #2
                aes: AesType::AES128,
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C,
                ],
                radix: 10,
                tweak: vec![0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30],
                pt: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                ct: vec![6, 1, 2, 4, 2, 0, 0, 7, 7, 3],
            },
            TestVector {
                // Sample #3
                aes: AesType::AES128,
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C,
                ],
                radix: 36,
                tweak: vec![
                    0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37,
                ],
                pt: vec![
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                ],
                ct: vec![
                    10, 9, 29, 31, 4, 0, 22, 21, 21, 9, 20, 13, 30, 5, 0, 9, 14, 30, 22,
                ],
            },
            TestVector {
                // Sample #4
                aes: AesType::AES192,
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
                ],
                radix: 10,
                tweak: vec![],
                pt: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                ct: vec![2, 8, 3, 0, 6, 6, 8, 1, 3, 2],
            },
            TestVector {
                // Sample #5
                aes: AesType::AES192,
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
                ],
                radix: 10,
                tweak: vec![0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30],
                pt: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                ct: vec![2, 4, 9, 6, 6, 5, 5, 5, 4, 9],
            },
            TestVector {
                // Sample #6
                aes: AesType::AES192,
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
                ],
                radix: 36,
                tweak: vec![
                    0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37,
                ],
                pt: vec![
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                ],
                ct: vec![
                    33, 11, 19, 3, 20, 31, 3, 5, 19, 27, 10, 32, 33, 31, 3, 2, 34, 28, 27,
                ],
            },
            TestVector {
                // Sample #7
                aes: AesType::AES256,
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F, 0x7F, 0x03,
                    0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94,
                ],
                radix: 10,
                tweak: vec![],
                pt: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                ct: vec![6, 6, 5, 7, 6, 6, 7, 0, 0, 9],
            },
            TestVector {
                // Sample #8
                aes: AesType::AES256,
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F, 0x7F, 0x03,
                    0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94,
                ],
                radix: 10,
                tweak: vec![0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30],
                pt: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                ct: vec![1, 0, 0, 1, 6, 2, 3, 4, 6, 3],
            },
            TestVector {
                // Sample #9
                aes: AesType::AES256,
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F, 0x7F, 0x03,
                    0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94,
                ],
                radix: 36,
                tweak: vec![
                    0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37,
                ],
                pt: vec![
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                ],
                ct: vec![
                    33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13,
                ],
            },
            // From https://github.com/capitalone/fpe/blob/master/ff1/ff1_test.go
            TestVector {
                aes: AesType::AES256,
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F, 0x7F, 0x03,
                    0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94,
                ],
                radix: 36,
                tweak: vec![],
                pt: vec![
                    33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13, 33,
                    28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13, 33, 28, 8,
                    10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13, 33, 28, 8, 10, 0,
                    10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13, 33, 28, 8, 10, 0, 10,
                    35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13, 33, 28, 8, 10, 0, 10, 35,
                    17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13, 33, 28, 8, 10, 0, 10, 35, 17, 2,
                    10, 31, 34, 10, 21,
                ],
                // lwulibfp1ju3ksztumqomwenpv7duy9q7pg7zf3eg3rjlfy46gmgkqjfwvromfjjktmbey8meqk9zkcmgvkv4s9ll5ctozme1hf15w7xo6zsylqcr0nbx9jbf10umzok
                ct: vec![
                    21, 32, 30, 21, 18, 11, 15, 25, 1, 19, 30, 3, 20, 28, 35, 29, 30, 22, 26, 24,
                    22, 32, 14, 23, 25, 31, 7, 13, 30, 34, 9, 26, 7, 25, 16, 7, 35, 15, 3, 14, 16,
                    3, 27, 19, 21, 15, 34, 4, 6, 16, 22, 16, 20, 26, 19, 15, 32, 31, 27, 24, 22,
                    15, 19, 19, 20, 29, 22, 11, 14, 34, 8, 22, 14, 26, 20, 9, 35, 20, 12, 22, 16,
                    31, 20, 31, 4, 28, 9, 21, 21, 5, 12, 29, 24, 35, 22, 14, 1, 17, 15, 1, 5, 32,
                    7, 33, 24, 6, 35, 28, 34, 21, 26, 12, 27, 0, 23, 11, 33, 9, 19, 11, 15, 1, 0,
                    30, 22, 35, 24, 20,
                ],
            },
            // Zcash test vectors
            // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/ff1.py
            TestVector {
                aes: AesType::AES256,
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F, 0x7F, 0x03,
                    0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94,
                ],
                radix: 2,
                tweak: vec![],
                pt: vec![0; 88],
                ct: vec![
                    0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0,
                    0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1,
                    0, 0, 1, 1, 0, 0, 1, 1, 1, 1,
                ],
            },
            TestVector {
                aes: AesType::AES256,
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F, 0x7F, 0x03,
                    0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94,
                ],
                radix: 2,
                tweak: vec![],
                pt: vec![
                    0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0,
                    0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1,
                    0, 0, 1, 1, 0, 0, 1, 1, 1, 1,
                ],
                ct: vec![
                    1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0,
                    0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1,
                    0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1,
                    1, 1, 1, 1, 0, 1, 1, 0, 0, 0,
                ],
            },
            TestVector {
                aes: AesType::AES256,
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F, 0x7F, 0x03,
                    0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94,
                ],
                radix: 2,
                tweak: vec![],
                pt: vec![
                    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
                    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
                    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
                    0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
                ],
                ct: vec![
                    0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1,
                    1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
                    0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0,
                    1, 1, 0, 0, 1, 0, 0, 1, 1, 0,
                ],
            },
            TestVector {
                aes: AesType::AES256,
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F, 0x7F, 0x03,
                    0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94,
                ],
                radix: 2,
                tweak: vec![
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
                    42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
                    62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81,
                    82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100,
                    101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
                    117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132,
                    133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148,
                    149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164,
                    165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180,
                    181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196,
                    197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212,
                    213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228,
                    229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244,
                    245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
                ],
                pt: vec![
                    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
                    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
                    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
                    0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
                ],
                ct: vec![
                    0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1,
                    1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1,
                    1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1,
                    1, 0, 1, 0, 1, 0, 0, 0, 1, 1,
                ],
            },
        ];

        for tv in test_vectors {
            let (ct, pt) = match tv.aes {
                AesType::AES128 => {
                    let ff = FF1::<Aes128>::new(&tv.key, tv.radix).unwrap();
                    (
                        ff.encrypt(&tv.tweak, &FlexibleNumeralString::from(tv.pt.clone())),
                        ff.decrypt(&tv.tweak, &FlexibleNumeralString::from(tv.ct.clone())),
                    )
                }
                AesType::AES192 => {
                    let ff = FF1::<Aes192>::new(&tv.key, tv.radix).unwrap();
                    (
                        ff.encrypt(&tv.tweak, &FlexibleNumeralString::from(tv.pt.clone())),
                        ff.decrypt(&tv.tweak, &FlexibleNumeralString::from(tv.ct.clone())),
                    )
                }
                AesType::AES256 => {
                    let ff = FF1::<Aes256>::new(&tv.key, tv.radix).unwrap();
                    (
                        ff.encrypt(&tv.tweak, &FlexibleNumeralString::from(tv.pt.clone())),
                        ff.decrypt(&tv.tweak, &FlexibleNumeralString::from(tv.ct.clone())),
                    )
                }
            };
            assert_eq!(Vec::from(ct.unwrap()), tv.ct);
            assert_eq!(Vec::from(pt.unwrap()), tv.pt);
        }
    }

    #[test]
    fn test_vectors_binary() {
        struct TestVector {
            key: Vec<u8>,
            radix: u32,
            tweak: Vec<u8>,
            pt: Vec<u8>,
            ct: Vec<u8>,
            bpt: Vec<u8>,
            bct: Vec<u8>,
        };

        let test_vectors = vec![
            // Zcash test vectors
            TestVector {
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F, 0x7F, 0x03,
                    0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94,
                ],
                radix: 2,
                tweak: vec![],
                pt: vec![0; 88],
                ct: vec![
                    0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0,
                    0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1,
                    0, 0, 1, 1, 0, 0, 1, 1, 1, 1,
                ],
                bpt: vec![
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                bct: vec![
                    0x90, 0xac, 0xee, 0x3f, 0x83, 0xcd, 0xe7, 0xae, 0x56, 0x22, 0xf3,
                ],
            },
            TestVector {
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F, 0x7F, 0x03,
                    0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94,
                ],
                radix: 2,
                tweak: vec![],
                pt: vec![
                    0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0,
                    0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1,
                    0, 0, 1, 1, 0, 0, 1, 1, 1, 1,
                ],
                ct: vec![
                    1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0,
                    0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1,
                    0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1,
                    1, 1, 1, 1, 0, 1, 1, 0, 0, 0,
                ],
                bpt: vec![
                    0x90, 0xac, 0xee, 0x3f, 0x83, 0xcd, 0xe7, 0xae, 0x56, 0x22, 0xf3,
                ],
                bct: vec![
                    0x5b, 0x8b, 0xf1, 0x20, 0xf3, 0x9b, 0xab, 0x85, 0x27, 0xea, 0x1b,
                ],
            },
        ];

        for tv in test_vectors {
            let (ct, pt, bct, bpt) = {
                let ff = FF1::<Aes256>::new(&tv.key, tv.radix).unwrap();
                (
                    ff.encrypt(&tv.tweak, &BinaryNumeralString(tv.pt.clone()))
                        .unwrap(),
                    ff.decrypt(&tv.tweak, &BinaryNumeralString(tv.ct.clone()))
                        .unwrap(),
                    ff.encrypt(&tv.tweak, &BinaryNumeralString::from_bytes_le(&tv.bpt))
                        .unwrap(),
                    ff.decrypt(&tv.tweak, &BinaryNumeralString::from_bytes_le(&tv.bct))
                        .unwrap(),
                )
            };
            assert_eq!(pt.to_bytes_le(), tv.bpt);
            assert_eq!(ct.to_bytes_le(), tv.bct);
            assert_eq!(bpt.to_bytes_le(), tv.bpt);
            assert_eq!(bct.to_bytes_le(), tv.bct);
            assert_eq!(pt.0, tv.pt);
            assert_eq!(ct.0, tv.ct);
            assert_eq!(bpt.0, tv.pt);
            assert_eq!(bct.0, tv.ct);
        }
    }
}
