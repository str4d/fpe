//! A Rust implementation of the FF1 algorithm, specified in
//! [NIST Special Publication 800-38G](http://dx.doi.org/10.6028/NIST.SP.800-38G).

use core::cmp;

use cipher::{
    generic_array::GenericArray, Block, BlockCipher, BlockEncrypt, BlockEncryptMut, InnerIvInit,
    KeyInit,
};

#[cfg(test)]
use static_assertions::const_assert;

mod error;
pub use error::{InvalidRadix, NumeralStringError};

#[cfg(feature = "alloc")]
mod alloc;
#[cfg(feature = "alloc")]
pub use self::alloc::{BinaryNumeralString, FlexibleNumeralString};

#[cfg(test)]
mod test_vectors;

#[cfg(test)]
mod ff1_18;

/// The minimum allowed numeral string length for any radix.
const MIN_NS_LEN: u32 = 2;
/// The maximum allowed numeral string length for any radix.
const MAX_NS_LEN: usize = u32::MAX as usize;

/// The minimum allowed value of radix^minlen.
///
/// Defined in [NIST SP 800-38G Revision 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf).
#[cfg(test)]
const MIN_NS_DOMAIN_SIZE: u32 = 1_000_000;

/// `minlen` such that `2^minlen >= MIN_NS_DOMAIN_SIZE`.
const MIN_RADIX_2_NS_LEN: u32 = 20;
/// `log_10(MIN_NS_DOMAIN_SIZE)`
const LOG_10_MIN_NS_DOMAIN_SIZE: f64 = 6.0;

#[cfg(test)]
const_assert!((1 << MIN_RADIX_2_NS_LEN) >= MIN_NS_DOMAIN_SIZE);

#[derive(Debug, PartialEq)]
enum Radix {
    /// A radix in [2..2^16]. It uses floating-point arithmetic.
    Any { radix: u32, min_len: u32 },
    /// A radix 2^i for i in [1..16]. It does not use floating-point arithmetic.
    PowerTwo {
        radix: u32,
        min_len: u32,
        log_radix: u8,
    },
}

impl Radix {
    fn from_u32(radix: u32) -> Result<Self, InvalidRadix> {
        // radix must be in range [2..=2^16]
        if !(2..=(1 << 16)).contains(&radix) {
            return Err(InvalidRadix(radix));
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
            Some(log_radix) => Radix::PowerTwo {
                radix,
                min_len: cmp::max(
                    (MIN_RADIX_2_NS_LEN + u32::from(log_radix) - 1) / u32::from(log_radix),
                    MIN_NS_LEN,
                ),
                log_radix,
            },
            None => {
                use libm::{ceil, log10};
                let min_len = ceil(LOG_10_MIN_NS_DOMAIN_SIZE / log10(f64::from(radix))) as u32;
                Radix::Any { radix, min_len }
            }
        })
    }

    fn check_ns_length(&self, ns_len: usize) -> Result<(), NumeralStringError> {
        let min_len = match *self {
            Radix::Any { min_len, .. } => min_len as usize,
            Radix::PowerTwo { min_len, .. } => min_len as usize,
        };
        let max_len = MAX_NS_LEN;

        if ns_len < min_len {
            Err(NumeralStringError::TooShort { ns_len, min_len })
        } else if ns_len > max_len {
            Err(NumeralStringError::TooLong { ns_len, max_len })
        } else {
            Ok(())
        }
    }

    /// Calculates b = ceil(ceil(v * log2(radix)) / 8).
    fn calculate_b(&self, v: usize) -> usize {
        use libm::{ceil, log2};
        match *self {
            Radix::Any { radix, .. } => ceil(v as f64 * log2(f64::from(radix)) / 8f64) as usize,
            Radix::PowerTwo { log_radix, .. } => ((v * log_radix as usize) + 7) / 8,
        }
    }

    fn to_u32(&self) -> u32 {
        match *self {
            Radix::Any { radix, .. } => radix,
            Radix::PowerTwo { radix, .. } => radix,
        }
    }
}

/// An integer.
pub trait Numeral {
    /// Type used for byte representations.
    type Bytes: AsRef<[u8]>;

    /// Returns the integer interpreted from the given bytes in big-endian order.
    fn from_bytes(s: impl Iterator<Item = u8>) -> Self;

    /// Returns the big-endian byte representation of this integer.
    fn to_bytes(&self, b: usize) -> Self::Bytes;

    /// Compute (self + other) mod radix^m
    fn add_mod_exp(self, other: Self, radix: u32, m: usize) -> Self;

    /// Compute (self - other) mod radix^m
    fn sub_mod_exp(self, other: Self, radix: u32, m: usize) -> Self;
}

/// For a given base, a finite, ordered sequence of numerals for the base.
pub trait NumeralString: Sized {
    /// The type used for numeric operations.
    type Num: Numeral;

    /// Returns whether this numeral string is valid for the base radix.
    fn is_valid(&self, radix: u32) -> bool;

    /// Returns the number of numerals in this numeral string.
    fn numeral_count(&self) -> usize;

    /// Splits this numeral string into two sections X[..u] and X[u..].
    fn split(&self, u: usize) -> (Self, Self);

    /// Concatenates two numeral strings.
    fn concat(a: Self, b: Self) -> Self;

    /// The number that this numeral string represents in the base radix
    /// when the numerals are valued in decreasing order of significance
    /// (big-endian order).
    fn num_radix(&self, radix: u32) -> Self::Num;

    /// Given a non-negative integer x less than radix<sup>m</sup>, returns
    /// the representation of x as a string of m numerals in base radix,
    /// in decreasing order of significance (big-endian order).
    fn str_radix(x: Self::Num, radix: u32, m: usize) -> Self;
}

#[derive(Clone)]
struct Prf<CIPH: BlockCipher + BlockEncrypt> {
    state: cbc::Encryptor<CIPH>,
    // Contains the output when offset = 0, and partial input otherwise
    buf: [Block<CIPH>; 1],
    offset: usize,
}

impl<CIPH: BlockCipher + BlockEncrypt + Clone> Prf<CIPH> {
    fn new(ciph: &CIPH) -> Self {
        let ciph = ciph.clone();
        Prf {
            state: cbc::Encryptor::inner_iv_init(ciph, GenericArray::from_slice(&[0; 16])),
            buf: [Block::<CIPH>::default()],
            offset: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let to_read = cmp::min(self.buf[0].len() - self.offset, data.len());
            self.buf[0][self.offset..self.offset + to_read].copy_from_slice(&data[..to_read]);
            self.offset += to_read;
            data = &data[to_read..];

            if self.offset == self.buf[0].len() {
                self.state.encrypt_blocks_mut(&mut self.buf);
                self.offset = 0;
            }
        }
    }

    /// Returns the current PRF output.
    ///
    /// The caller MUST ensure that the PRF has processed an integer number of blocks.
    fn output(&self) -> &Block<CIPH> {
        assert_eq!(self.offset, 0);
        &self.buf[0]
    }
}

fn generate_s<'a, CIPH: BlockEncrypt>(
    ciph: &'a CIPH,
    r: &'a Block<CIPH>,
    d: usize,
) -> impl Iterator<Item = u8> + 'a {
    r.clone()
        .into_iter()
        .chain((1..((d + 15) / 16) as u128).flat_map(move |j| {
            let mut block = r.clone();
            for (b, j) in block.iter_mut().zip(j.to_be_bytes().iter()) {
                *b ^= j;
            }
            ciph.encrypt_block(&mut block);
            block.into_iter()
        }))
        .take(d)
}

/// A struct for performing FF1 encryption and decryption operations
/// using the default 10 Feistel rounds
pub type FF1<CIPH> = FF1fr<10, CIPH>;

/// A struct for performing hardened FF1 encryption and decryption operations
/// using 18 Feistel rounds
pub type FF1h<CIPH> = FF1fr<18, CIPH>;

/// A struct for performing FF1 encryption and decryption operations.
/// with an adjustable number of Feistel rounds
pub struct FF1fr<const FEISTEL_ROUNDS: u8, CIPH: BlockCipher> {
    ciph: CIPH,
    radix: Radix,
}

impl<const FEISTEL_ROUNDS: u8, CIPH: BlockCipher + KeyInit> FF1fr<FEISTEL_ROUNDS, CIPH> {
    /// Creates a new FF1 object for the given key and radix.
    ///
    /// Returns an error if the given radix is not in [2..2^16].
    pub fn new(key: &[u8], radix: u32) -> Result<Self, InvalidRadix> {
        let ciph = CIPH::new(GenericArray::from_slice(key));
        let radix = Radix::from_u32(radix)?;
        Ok(FF1fr { ciph, radix })
    }
}

impl<const FEISTEL_ROUNDS: u8, CIPH: BlockCipher + BlockEncrypt + Clone>
    FF1fr<FEISTEL_ROUNDS, CIPH>
{
    /// Encrypts the given numeral string.
    ///
    /// Returns an error if the numeral string is not in the required radix.
    #[allow(clippy::many_single_char_names)]
    pub fn encrypt<NS: NumeralString>(
        &self,
        tweak: &[u8],
        x: &NS,
    ) -> Result<NS, NumeralStringError> {
        if !x.is_valid(self.radix.to_u32()) {
            return Err(NumeralStringError::InvalidForRadix(self.radix.to_u32()));
        }
        self.radix.check_ns_length(x.numeral_count())?;

        let n = x.numeral_count();
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
        let mut p = [1, 2, 1, 0, 0, 0, 10, u as u8, 0, 0, 0, 0, 0, 0, 0, 0];
        p[3..6].copy_from_slice(&self.radix.to_u32().to_be_bytes()[1..]);
        p[8..12].copy_from_slice(&(n as u32).to_be_bytes());
        p[12..16].copy_from_slice(&(t as u32).to_be_bytes());

        //  6i. Let Q = T || [0]^((-t-b-1) mod 16) || [i] || [NUM(B, radix)].
        // 6ii. Let R = PRF(P || Q).
        let mut prf = Prf::new(&self.ciph);
        prf.update(&p);
        prf.update(tweak);
        for _ in 0..((((-(t as i32) - (b as i32) - 1) % 16) + 16) % 16) {
            prf.update(&[0]);
        }
        for i in 0..FEISTEL_ROUNDS {
            let mut prf = prf.clone();
            prf.update(&[i]);
            prf.update(x_b.num_radix(self.radix.to_u32()).to_bytes(b).as_ref());
            let r = prf.output();

            // 6iii. Let S be the first d bytes of R.
            let s = generate_s(&self.ciph, r, d);

            // 6iv. Let y = NUM(S).
            let y = NS::Num::from_bytes(s);

            // 6v. If i is even, let m = u; else, let m = v.
            let m = if i % 2 == 0 { u } else { v };

            // 6vi. Let c = (NUM(A, radix) + y) mod radix^m.
            let c = x_a
                .num_radix(self.radix.to_u32())
                .add_mod_exp(y, self.radix.to_u32(), m);

            // 6vii. Let C = STR(c, radix).
            let x_c = NS::str_radix(c, self.radix.to_u32(), m);

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
    #[allow(clippy::many_single_char_names)]
    pub fn decrypt<NS: NumeralString>(
        &self,
        tweak: &[u8],
        x: &NS,
    ) -> Result<NS, NumeralStringError> {
        if !x.is_valid(self.radix.to_u32()) {
            return Err(NumeralStringError::InvalidForRadix(self.radix.to_u32()));
        }
        self.radix.check_ns_length(x.numeral_count())?;

        let n = x.numeral_count();
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
        let mut p = [1, 2, 1, 0, 0, 0, 10, u as u8, 0, 0, 0, 0, 0, 0, 0, 0];
        p[3..6].copy_from_slice(&self.radix.to_u32().to_be_bytes()[1..]);
        p[8..12].copy_from_slice(&(n as u32).to_be_bytes());
        p[12..16].copy_from_slice(&(t as u32).to_be_bytes());

        //  6i. Let Q = T || [0]^((-t-b-1) mod 16) || [i] || [NUM(A, radix)].
        // 6ii. Let R = PRF(P || Q).
        let mut prf = Prf::new(&self.ciph);
        prf.update(&p);
        prf.update(tweak);
        for _ in 0..((((-(t as i32) - (b as i32) - 1) % 16) + 16) % 16) {
            prf.update(&[0]);
        }
        for i in 0..FEISTEL_ROUNDS {
            let i = FEISTEL_ROUNDS - 1 - i;
            let mut prf = prf.clone();
            prf.update(&[i]);
            prf.update(x_a.num_radix(self.radix.to_u32()).to_bytes(b).as_ref());
            let r = prf.output();

            // 6iii. Let S be the first d bytes of R.
            let s = generate_s(&self.ciph, r, d);

            // 6iv. Let y = NUM(S).
            let y = NS::Num::from_bytes(s);

            // 6v. If i is even, let m = u; else, let m = v.
            let m = if i % 2 == 0 { u } else { v };

            // 6vi. Let c = (NUM(B, radix) - y) mod radix^m.
            let c = x_b
                .num_radix(self.radix.to_u32())
                .sub_mod_exp(y, self.radix.to_u32(), m);

            // 6vii. Let C = STR(c, radix).
            let x_c = NS::str_radix(c, self.radix.to_u32(), m);

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
    use super::{
        InvalidRadix, Radix, LOG_10_MIN_NS_DOMAIN_SIZE, MIN_NS_DOMAIN_SIZE, MIN_NS_LEN,
        MIN_RADIX_2_NS_LEN,
    };

    #[test]
    fn log_10_min_ns_domain_size() {
        use libm::pow;
        assert_eq!(
            pow(10.0, LOG_10_MIN_NS_DOMAIN_SIZE),
            f64::from(MIN_NS_DOMAIN_SIZE)
        );
    }

    #[test]
    fn radix() {
        assert_eq!(Radix::from_u32(1), Err(InvalidRadix(1)));
        assert_eq!(
            Radix::from_u32(2),
            Ok(Radix::PowerTwo {
                radix: 2,
                min_len: MIN_RADIX_2_NS_LEN,
                log_radix: 1,
            })
        );
        assert_eq!(
            Radix::from_u32(3),
            Ok(Radix::Any {
                radix: 3,
                min_len: 13,
            })
        );
        assert_eq!(
            Radix::from_u32(4),
            Ok(Radix::PowerTwo {
                radix: 4,
                min_len: MIN_RADIX_2_NS_LEN / 2,
                log_radix: 2,
            })
        );
        assert_eq!(
            Radix::from_u32(5),
            Ok(Radix::Any {
                radix: 5,
                min_len: 9,
            })
        );
        assert_eq!(
            Radix::from_u32(6),
            Ok(Radix::Any {
                radix: 6,
                min_len: 8,
            })
        );
        assert_eq!(
            Radix::from_u32(7),
            Ok(Radix::Any {
                radix: 7,
                min_len: 8,
            })
        );
        assert_eq!(
            Radix::from_u32(8),
            Ok(Radix::PowerTwo {
                radix: 8,
                min_len: 7,
                log_radix: 3,
            })
        );
        assert_eq!(
            Radix::from_u32(10),
            Ok(Radix::Any {
                radix: 10,
                min_len: 6,
            })
        );
        assert_eq!(
            Radix::from_u32(32768),
            Ok(Radix::PowerTwo {
                radix: 32768,
                min_len: MIN_NS_LEN,
                log_radix: 15,
            })
        );
        assert_eq!(
            Radix::from_u32(65535),
            Ok(Radix::Any {
                radix: 65535,
                min_len: MIN_NS_LEN,
            })
        );
        assert_eq!(
            Radix::from_u32(65536),
            Ok(Radix::PowerTwo {
                radix: 65536,
                min_len: MIN_NS_LEN,
                log_radix: 16,
            })
        );
        assert_eq!(Radix::from_u32(65537), Err(InvalidRadix(65537)));
    }
}
