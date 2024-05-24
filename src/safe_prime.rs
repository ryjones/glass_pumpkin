//! Generates cryptographically secure safe prime numbers.

use rand_core::OsRng;

pub use crate::common::{
    gen_safe_prime as from_rng, is_safe_prime as check_with,
    is_safe_prime_baillie_psw as strong_check_with,
};
use crate::error::Result;

/// Constructs a new safe prime number with a size of `bit_length` bits.
///
/// This will initialize an `OsRng` instance and call the
/// `from_rng()` function.
///
/// Note: the `bit_length` MUST be at least 128-bits.
pub fn new(bit_length: usize) -> Result {
    from_rng(bit_length, &mut OsRng)
}

/// Checks if number is a safe prime
pub fn check(candidate: &num_bigint::BigUint) -> bool {
    check_with(candidate, &mut OsRng)
}

/// Checks if number is a safe prime using the Baillie-PSW test
pub fn strong_check(candidate: &num_bigint::BigUint) -> bool {
    strong_check_with(candidate, &mut OsRng)
}

#[cfg(test)]
mod tests {
    use super::{check, new, strong_check};

    #[test]
    fn tests() {
        for bits in &[128, 256, 384] {
            let n = new(*bits).unwrap();
            assert!(check(&n));
            assert!(strong_check(&n));
        }
    }
}
