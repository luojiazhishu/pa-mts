use bls12_381::{G1Projective, Scalar};
use std::collections::BTreeMap;
use std::rc::Rc;

pub type UniverseId = [u8; 32];
/// PartyId denotes the party's unique identifier, which is typically derived from the signing pubkey.
pub type PartyId = usize;
pub type XCoord = usize;

/// Weight represents the number of weight units assigned to a party
pub type Weight = usize;

/// PartySecret is the 256-bit secret held by each party
pub type PartySecret = Scalar;

/// PartyPublicKey denotes the public component of each share held by a party
pub type PartyPublicKey = G1Projective;

/// AddressBook maps each party to its weight and vector of public keys
type AddressBook = BTreeMap<PartyId, (Weight, Rc<Vec<PartyPublicKey>>)>;

pub mod common;
pub mod mts;
pub mod multiverse_sig;
pub mod pa_mts;
pub mod pa_multiverse_sig;
pub mod pa_issue;
pub mod universe;

//lets allow dead code from "library" implementations
#[allow(dead_code)]
pub mod kzg;
#[allow(dead_code)]
mod polynomial;
#[allow(dead_code)]
mod utils;

/// Hash-to-G2 used for `H` (RFC 9380), exposed for benchmarks.
pub fn utils_hash_to_g2(msg: &[u8]) -> bls12_381::G2Projective {
    utils::hash_to_g2(msg)
}
