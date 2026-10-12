//! Random passwords, the same style as the extension's generator
//! (`apps/extension/lib/generate.ts`): 20 characters with at least one of
//! each class, look-alikes (l, I, O, 0, 1) left out.

use rand::seq::IndexedRandom;
use zeroize::Zeroizing;

const LOWER: &str = "abcdefghijkmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &str = "23456789";
const SYMBOLS: &str = "-_.!@#$%*+=?";
const LENGTH: usize = 20;

pub fn password() -> Zeroizing<String> {
    let classes = [LOWER, UPPER, DIGITS, SYMBOLS];
    let alphabet: Vec<char> = classes.concat().chars().collect();
    let mut rng = rand::rng();
    loop {
        let candidate: Zeroizing<String> = Zeroizing::new(
            (0..LENGTH)
                .map(|_| *alphabet.choose(&mut rng).expect("alphabet is not empty"))
                .collect(),
        );
        if classes
            .iter()
            .all(|class| candidate.chars().any(|c| class.contains(c)))
        {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_every_class_and_no_look_alikes() {
        for _ in 0..200 {
            let password = password();
            assert_eq!(password.chars().count(), LENGTH);
            for class in [LOWER, UPPER, DIGITS, SYMBOLS] {
                assert!(password.chars().any(|c| class.contains(c)), "{}", *password);
            }
            assert!(
                !password.chars().any(|c| "lIO01".contains(c)),
                "{}",
                *password
            );
        }
    }
}
