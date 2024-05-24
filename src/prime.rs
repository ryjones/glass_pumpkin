//! Generates cryptographically secure prime numbers.

use rand_core::OsRng;

pub use crate::common::{
    gen_prime as from_rng, is_prime as check_with, is_prime_baillie_psw as strong_check_with,
};
use crate::error::Result;

/// Constructs a new prime number with a size of `bit_length` bits.
///
/// This will initialize an `OsRng` instance and call the
/// `from_rng()` function.
///
/// Note: the `bit_length` MUST be at least 128-bits.
pub fn new(bit_length: usize) -> Result {
    from_rng(bit_length, &mut OsRng)
}

/// Test if number is prime by
///
/// 1- Trial division by first 2048 primes
/// 2- Perform a Fermat Test
/// 3- Perform log2(bitlength) + 5 rounds of Miller-Rabin
///    depending on the number of bits
pub fn check(candidate: &num_bigint::BigUint) -> bool {
    check_with(candidate, &mut OsRng)
}

/// Checks if number is a prime using the Baillie-PSW test
pub fn strong_check(candidate: &num_bigint::BigUint) -> bool {
    strong_check_with(candidate, &mut OsRng)
}

#[cfg(test)]
mod tests {
    use super::{check, new, strong_check};

    #[test]
    fn tests() {
        for bits in &[128, 256, 512, 1024] {
            let n = new(*bits).unwrap();
            assert!(check(&n));
            assert!(strong_check(&n));
        }
    }
}
