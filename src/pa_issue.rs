//! Issuance and tracing primitives of the current PA-MTS construction.
//!
//! This module implements the parts of `Aggr`, `Verify`, `Trace`, and `TraceVerify`
//! that are shared by the dealer-based evaluation path (`pa_multiverse_sig`) and the
//! universe-setup path (`pa_mts`):
//!
//! * the PRG `F` used by `KGen` (`pk = g_1^{F(s)}`, `sk = s`);
//! * the aggregator key pair, of which only `F(sk)[1]` and `pk[1]` are used;
//! * the tracing credential `c = Enc(tk, (Q, u))` under a fresh tracing key `tk`;
//! * the hash value `d = H(c || Q || u)` in `G_2`;
//! * the aggregator signature `tau = H(hat_sigma' || hat_sigma'_0 || hat_sigma'_1 || d)^{F(sk)[1]}`;
//! * `Trace(c, tk) = (Q, pi = u)`.
//!
//! `H` is the same hash-to-`G_2` function that hashes messages (RFC 9380,
//! `BLS12381G2_XMD:SHA-256_SSWU_RO_`), as in the manuscript, where `H` is a single
//! random oracle `{0,1}^* -> G_2`.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use bls12_381::{pairing, G1Projective, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha512};
use std::collections::BTreeSet;
use std::ops::Mul;

use crate::{utils, PartyId};

pub const SCALAR_BYTES: usize = 32;
pub const G1_COMPRESSED_BYTES: usize = 48;
pub const G2_COMPRESSED_BYTES: usize = 96;
pub const TRACE_KEY_BYTES: usize = 32;
pub const AES_GCM_TAG_BYTES: usize = 16;

/// Every tracing key encrypts exactly one plaintext (one issuance), so the
/// (key, nonce) pair never repeats and a fixed nonce is safe for AES-256-GCM.
const FIXED_NONCE: [u8; 12] = [0u8; 12];
const PRG_DOMAIN: &[u8] = b"PA-MTS-PRG-v1";

/// Size in bytes of the encoded quorum: a fixed-length |U|-bit membership vector.
pub const fn quorum_encoding_bytes(party_count: usize) -> usize {
    (party_count + 7) / 8
}

/// Size in bytes of a tracing credential for a universe with `party_count` parties.
pub const fn credential_size_for_party_count(party_count: usize) -> usize {
    quorum_encoding_bytes(party_count) + SCALAR_BYTES + AES_GCM_TAG_BYTES
}

/// The PRG `F : {0,1}^kappa -> F_p^len` of `KGen`, instantiated with SHA-512 and wide reduction.
pub fn prg_expand(seed: &[u8; 32], len: usize) -> Vec<Scalar> {
    (0..len)
        .map(|i| {
            let mut hasher = Sha512::new();
            hasher.update(PRG_DOMAIN);
            hasher.update(seed);
            hasher.update((i as u64).to_le_bytes());
            let digest: [u8; 64] = hasher.finalize().into();
            Scalar::from_bytes_wide(&digest)
        })
        .collect()
}

/// Aggregator key pair `(pk, sk) <- KGen(1^kappa)`.
///
/// `sk` is the PRG seed. `Aggr` uses only `F(sk)[1]`, and `Verify`/`TraceVerify`
/// use only `pk[1] = g_1^{F(sk)[1]}`, so only these two values are kept.
#[derive(Clone)]
pub struct AggregatorKeyPair {
    seed: [u8; 32],
    signing_scalar: Scalar,
    pub pk1: G1Projective,
}

impl AggregatorKeyPair {
    /// Generates an aggregator key pair with respect to the generator `g1` of the scheme.
    pub fn generate(g1: &G1Projective) -> Self {
        let mut seed = [0u8; 32];
        thread_rng().fill_bytes(&mut seed);
        Self::from_seed(seed, g1)
    }

    pub fn from_seed(seed: [u8; 32], g1: &G1Projective) -> Self {
        let signing_scalar = prg_expand(&seed, 1)[0];
        AggregatorKeyPair {
            seed,
            signing_scalar,
            pk1: g1.mul(signing_scalar),
        }
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// `tau = H(hat_sigma' || hat_sigma'_0 || hat_sigma'_1 || d)^{F(sk)[1]}`.
    pub fn sign_components(&self, components: &RandomizedComponents) -> G2Projective {
        utils::hash_to_g2(&components.tau_message()).mul(self.signing_scalar)
    }
}

/// The randomized MTS components together with the hash value `d`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RandomizedComponents {
    pub sigma_prime: G2Projective,
    pub sigma_0: G1Projective,
    pub sigma_1: G1Projective,
    pub d: G2Projective,
}

impl RandomizedComponents {
    /// Canonical encoding `hat_sigma' || hat_sigma'_0 || hat_sigma'_1 || d` (compressed points).
    pub fn tau_message(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 * G2_COMPRESSED_BYTES + 2 * G1_COMPRESSED_BYTES);
        out.extend_from_slice(&self.sigma_prime.to_affine().to_compressed());
        out.extend_from_slice(&self.sigma_0.to_affine().to_compressed());
        out.extend_from_slice(&self.sigma_1.to_affine().to_compressed());
        out.extend_from_slice(&self.d.to_affine().to_compressed());
        out
    }
}

/// Output of the PA-MTS-specific steps of `Aggr`.
#[derive(Clone)]
pub struct Issuance {
    pub components: RandomizedComponents,
    pub tau: G2Projective,
    pub credential: TraceCredential,
    pub trace_key: TraceKey,
}

/// Steps 6 and 7 of `Aggr`, i.e., everything that PA-MTS adds to MTS aggregation once the
/// raw MTS components are known: the common randomization with a fresh `u`, the credential
/// `c = Enc(tk, (Q, u))`, `d = H(c || Q || u)`, and `tau`. `h_m = H(m)` is passed in because
/// `Aggr` also uses it to validate partial signatures.
#[allow(clippy::too_many_arguments)]
pub fn randomize_and_issue(
    raw_sigma_prime: &G2Projective,
    raw_sigma_0: &G1Projective,
    raw_sigma_1: &G1Projective,
    h_m: &G2Projective,
    g1: &G1Projective,
    gamma: &G1Projective,
    universe_parties: &[PartyId],
    quorum: &[PartyId],
    aggregator_key: &AggregatorKeyPair,
) -> Option<Issuance> {
    let u = Scalar::random(&mut thread_rng());
    let sigma_prime = *raw_sigma_prime + h_m.mul(u);
    let sigma_0 = *raw_sigma_0 - g1.mul(u);
    let sigma_1 = *raw_sigma_1 - gamma.mul(u);
    let mask = encode_quorum(universe_parties, quorum)?;
    let (credential, trace_key) = issue_credential(&mask, &u);
    let d = hash_value(&credential, &mask, &u);
    let components = RandomizedComponents {
        sigma_prime,
        sigma_0,
        sigma_1,
        d,
    };
    let tau = aggregator_key.sign_components(&components);
    Some(Issuance {
        components,
        tau,
        credential,
        trace_key,
    })
}

/// `e(pk[1], H(hat_sigma' || hat_sigma'_0 || hat_sigma'_1 || d)) = e(g_1, tau)`, i.e., `BLS.Verify`.
pub fn verify_tau(
    g1: &G1Projective,
    pk1: &G1Projective,
    components: &RandomizedComponents,
    tau: &G2Projective,
) -> bool {
    let h = utils::hash_to_g2(&components.tau_message());
    pairing(&pk1.to_affine(), &h.to_affine()) == pairing(&g1.to_affine(), &tau.to_affine())
}

/// Tracing key `tk`: a fresh 256-bit AES key per issuance.
#[derive(Clone)]
pub struct TraceKey(pub [u8; TRACE_KEY_BYTES]);

impl TraceKey {
    pub fn generate() -> Self {
        let mut key = [0u8; TRACE_KEY_BYTES];
        thread_rng().fill_bytes(&mut key);
        TraceKey(key)
    }

    pub const fn serialized_size_bytes(&self) -> usize {
        TRACE_KEY_BYTES
    }
}

/// Tracing credential `c = Enc(tk, (Q, u))` (AES-256-GCM ciphertext and tag).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TraceCredential {
    pub ciphertext: Vec<u8>,
}

impl TraceCredential {
    pub fn serialized_size_bytes(&self) -> usize {
        self.ciphertext.len()
    }
}

/// Encodes a quorum as a |U|-bit membership vector over the canonical party order.
/// Returns `None` if the quorum contains a duplicate or a party outside the universe.
pub fn encode_quorum(universe_parties: &[PartyId], quorum: &[PartyId]) -> Option<Vec<u8>> {
    let mut seen = BTreeSet::new();
    let mut mask = vec![0u8; quorum_encoding_bytes(universe_parties.len())];
    for party in quorum {
        if !seen.insert(*party) {
            return None;
        }
        let index = universe_parties.iter().position(|p| p == party)?;
        mask[index / 8] |= 1u8 << (index % 8);
    }
    Some(mask)
}

/// Decodes a membership vector back into the quorum (in canonical order).
pub fn decode_quorum(universe_parties: &[PartyId], mask: &[u8]) -> Option<Vec<PartyId>> {
    if mask.len() != quorum_encoding_bytes(universe_parties.len()) {
        return None;
    }
    // Padding bits beyond |U| must be zero, so that the encoding is unique.
    for bit in universe_parties.len()..8 * mask.len() {
        if mask[bit / 8] & (1u8 << (bit % 8)) != 0 {
            return None;
        }
    }
    Some(
        universe_parties
            .iter()
            .enumerate()
            .filter(|(i, _)| mask[i / 8] & (1u8 << (i % 8)) != 0)
            .map(|(_, p)| *p)
            .collect(),
    )
}

/// `c = Enc(tk, (Q, u))` with a fresh `tk <- TKGen`.
pub fn issue_credential(quorum_mask: &[u8], u: &Scalar) -> (TraceCredential, TraceKey) {
    let tk = TraceKey::generate();
    let mut plaintext = Vec::with_capacity(quorum_mask.len() + SCALAR_BYTES);
    plaintext.extend_from_slice(quorum_mask);
    plaintext.extend_from_slice(&u.to_le_bytes());
    let cipher = Aes256Gcm::new_from_slice(&tk.0).expect("32-byte AES key");
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&FIXED_NONCE), plaintext.as_slice())
        .expect("AES-GCM encryption");
    (TraceCredential { ciphertext }, tk)
}

/// `d = H(c || Q || u)` with `Q` encoded as its membership vector and `u` as 32 bytes.
pub fn hash_value(credential: &TraceCredential, quorum_mask: &[u8], u: &Scalar) -> G2Projective {
    let mut input =
        Vec::with_capacity(credential.ciphertext.len() + quorum_mask.len() + SCALAR_BYTES);
    input.extend_from_slice(&credential.ciphertext);
    input.extend_from_slice(quorum_mask);
    input.extend_from_slice(&u.to_le_bytes());
    utils::hash_to_g2(&input)
}

/// `Trace(c, tk)`: decrypts `c` and outputs `(Q, pi = u)`.
pub fn trace(
    universe_parties: &[PartyId],
    credential: &TraceCredential,
    tk: &TraceKey,
) -> Option<(Vec<PartyId>, Scalar)> {
    let cipher = Aes256Gcm::new_from_slice(&tk.0).ok()?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&FIXED_NONCE), credential.ciphertext.as_slice())
        .ok()?;
    let mask_len = quorum_encoding_bytes(universe_parties.len());
    if plaintext.len() != mask_len + SCALAR_BYTES {
        return None;
    }
    let quorum = decode_quorum(universe_parties, &plaintext[..mask_len])?;
    let u_bytes: [u8; SCALAR_BYTES] = plaintext[mask_len..].try_into().ok()?;
    let u = Option::<Scalar>::from(Scalar::from_le_bytes(&u_bytes))?;
    Some((quorum, u))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;

    #[test]
    fn quorum_encoding_round_trip_and_rejections() {
        let parties: Vec<PartyId> = (1..=11).collect();
        let quorum = vec![2, 5, 11];
        let mask = encode_quorum(&parties, &quorum).unwrap();
        assert_eq!(mask.len(), 2);
        assert_eq!(decode_quorum(&parties, &mask).unwrap(), quorum);
        assert!(encode_quorum(&parties, &[2, 2]).is_none());
        assert!(encode_quorum(&parties, &[12]).is_none());
        let mut bad = mask.clone();
        bad[1] |= 0x80; // padding bit
        assert!(decode_quorum(&parties, &bad).is_none());
    }

    #[test]
    fn credential_trace_round_trip_and_wrong_key() {
        let parties: Vec<PartyId> = (1..=20).collect();
        let quorum: Vec<PartyId> = (1..=10).collect();
        let mask = encode_quorum(&parties, &quorum).unwrap();
        let u = Scalar::random(&mut thread_rng());
        let (c, tk) = issue_credential(&mask, &u);
        assert_eq!(c.serialized_size_bytes(), credential_size_for_party_count(parties.len()));
        assert_eq!(trace(&parties, &c, &tk), Some((quorum, u)));
        assert!(trace(&parties, &c, &TraceKey::generate()).is_none());
        let mut tampered = c.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(trace(&parties, &tampered, &tk).is_none());
    }

    #[test]
    fn tau_signs_the_components_under_the_aggregator_key() {
        let g1 = utils::get_generator_in_g1();
        let key = AggregatorKeyPair::generate(&g1);
        let other = AggregatorKeyPair::generate(&g1);
        let comps = RandomizedComponents {
            sigma_prime: utils::hash_to_g2(b"a"),
            sigma_0: utils::hash_to_g1(b"b"),
            sigma_1: utils::hash_to_g1(b"c"),
            d: utils::hash_to_g2(b"d"),
        };
        let tau = key.sign_components(&comps);
        assert!(verify_tau(&g1, &key.pk1, &comps, &tau));
        assert!(!verify_tau(&g1, &other.pk1, &comps, &tau));
        let mut changed = comps;
        changed.d = utils::hash_to_g2(b"e");
        assert!(!verify_tau(&g1, &key.pk1, &changed, &tau));
    }
}
