//! Dealer-based PA-MTS signature path used by the Signature and Accountability evaluation.
//!
//! As in the signature benchmark of the MTS artifact (`multiverse_sig`), a dealer samples
//! the degree-(W-1) polynomial `f`, so that the partial signatures, the public evaluations
//! `evals_0 = (g_1^{f(y)})_y`, `evals_1 = (g_1^{alpha f(y)})_y`, and `Gamma = g_1^alpha` have
//! the same form as after a real universe setup. Aggregation, verification, tracing, and
//! trace verification follow the current PA-MTS construction exactly.

use bls12_381::{pairing, G1Projective, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use rand::thread_rng;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Add, Mul, Neg, Sub};

use crate::common::sig_utils;
use crate::kzg::KZGParams;
use crate::pa_issue::{self, AggregatorKeyPair, RandomizedComponents};
use crate::polynomial::Polynomial;
use crate::utils;
use crate::{PartyId, Weight, XCoord};

pub use crate::pa_issue::{
    TraceCredential as PAMultiverseTraceCredential, TraceKey as PAMultiverseTraceKey,
};

pub type PAMultiversePartialSig = Vec<(XCoord, G2Projective)>;

#[derive(Clone)]
pub struct PAMultiversePublicParams {
    pub coms: Vec<G1Projective>,
    pub coms_exp_k: Vec<G1Projective>,
    pub gamma: G1Projective,
    pub private_shares: Vec<Scalar>,
    pub signer_public_keys: Vec<G1Projective>,
    pub public_key_s: G1Projective,
    pub public_key_k: G2Projective,
}

pub struct PAMultiverseParty {
    crs: KZGParams,
    k: Scalar,
    threshold_weight: Weight,
    total_weight: Weight,
    secret_polynomial: Polynomial,
    addr_book: BTreeMap<PartyId, Weight>,
    addr_book_ranges: BTreeMap<PartyId, (XCoord, XCoord)>,
    aggregator_key: AggregatorKeyPair,
}

/// PA-MTS signature `sigma = (hat_sigma', hat_sigma'_0, hat_sigma'_1, d, tau)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PAMultiverseSig {
    pub sigma_prime: G2Projective,
    pub sigma_0: G1Projective,
    pub sigma_1: G1Projective,
    pub d: G2Projective,
    pub tau: G2Projective,
}

impl PAMultiverseSig {
    /// `hat_sigma'`, `d`, `tau` in G2 and `hat_sigma'_0`, `hat_sigma'_1` in G1 (compressed).
    pub const fn compressed_size_bytes(&self) -> usize {
        3 * pa_issue::G2_COMPRESSED_BYTES + 2 * pa_issue::G1_COMPRESSED_BYTES
    }

    fn components(&self) -> RandomizedComponents {
        RandomizedComponents {
            sigma_prime: self.sigma_prime,
            sigma_0: self.sigma_0,
            sigma_1: self.sigma_1,
            d: self.d,
        }
    }
}

#[derive(Clone)]
pub struct PAMultiverseAggregation {
    pub signature: PAMultiverseSig,
    pub credential: PAMultiverseTraceCredential,
    pub trace_key: PAMultiverseTraceKey,
}

struct LagrangePlan {
    signer_xs: Vec<XCoord>,
    signer_coeffs: Vec<Scalar>,
    public_coeffs: Vec<Scalar>,
}

fn aggregator_xs(total_weight: Weight, threshold: Weight) -> Vec<Scalar> {
    ((total_weight + 1)..=(2 * total_weight - threshold))
        .map(|x| Scalar::from(x as u64))
        .collect()
}

fn signer_xs(total_weight: Weight) -> Vec<Scalar> {
    (1..=total_weight).map(|x| Scalar::from(x as u64)).collect()
}

impl PAMultiverseParty {
    pub fn new(
        crs: KZGParams,
        threshold_weight: usize,
        total_weight: usize,
        addr_book: &BTreeMap<PartyId, Weight>,
    ) -> PAMultiverseParty {
        assert!(total_weight > 0);
        assert!(threshold_weight > 0 && threshold_weight <= total_weight);
        assert_eq!(addr_book.values().sum::<usize>(), total_weight);

        let mut rng = thread_rng();
        let aggregator_key = AggregatorKeyPair::generate(&crs.gs[0]);
        PAMultiverseParty {
            threshold_weight,
            total_weight,
            crs,
            k: Scalar::random(&mut rng),
            secret_polynomial: sig_utils::sample_random_poly(&mut rng, total_weight - 1),
            addr_book: addr_book.clone(),
            addr_book_ranges: sig_utils::addr_book_to_private_xs_ranges(addr_book),
            aggregator_key,
        }
    }

    /// Generator `g_1` and aggregator key, exposed for the step-6/7 micro-benchmark.
    pub fn generator_g1(&self) -> G1Projective {
        self.crs.gs[0]
    }

    pub fn aggregator_key(&self) -> &AggregatorKeyPair {
        &self.aggregator_key
    }

    /// `pk[1]` of the aggregator, published together with `VK`.
    pub fn aggregator_public_key(&self) -> G1Projective {
        self.aggregator_key.pk1
    }

    fn generate_public_shares_commitments(&self) -> (Vec<G1Projective>, Vec<G1Projective>) {
        let xs = aggregator_xs(self.total_weight, self.threshold_weight);
        let ys: Vec<Scalar> = xs.iter().map(|x| self.secret_polynomial.eval(x)).collect();
        let coms = ys.iter().map(|y| self.crs.gs[0].mul(y)).collect();
        let coms_exp_k = ys
            .iter()
            .map(|y| self.crs.gs[0].mul(self.k.mul(y)))
            .collect();
        (coms, coms_exp_k)
    }

    fn generate_private_shares(&self) -> Vec<Scalar> {
        signer_xs(self.total_weight)
            .iter()
            .map(|x| self.secret_polynomial.eval(x))
            .collect()
    }

    pub fn setup(&self) -> PAMultiversePublicParams {
        let (coms, coms_exp_k) = self.generate_public_shares_commitments();
        let private_shares = self.generate_private_shares();
        let signer_public_keys = private_shares
            .iter()
            .map(|share| self.crs.gs[0].mul(share))
            .collect();
        let secret_key = self.secret_polynomial.eval(&Scalar::ZERO);

        PAMultiversePublicParams {
            coms,
            coms_exp_k,
            gamma: self.crs.gs[0].mul(self.k),
            private_shares,
            signer_public_keys,
            public_key_s: self.crs.gs[0].mul(secret_key),
            public_key_k: self.crs.hs[0].mul(self.k),
        }
    }

    pub fn sign(
        &self,
        id: PartyId,
        msg: &[u8],
        output: &PAMultiversePublicParams,
    ) -> PAMultiversePartialSig {
        let h_m = utils::hash_to_g2(msg);
        let (lo, hi) = self.addr_book_ranges.get(&id).unwrap();
        let xs: Vec<XCoord> = (*lo..=*hi).collect();
        let ys = &output.private_shares[*lo - 1..*hi];

        xs.iter()
            .zip(ys.iter())
            .map(|(x, y)| (*x, h_m.mul(y)))
            .collect()
    }

    /// `Aggr`. As in the timed aggregation path of the MTS artifact, the benchmark-generated
    /// partial signatures are assumed to be valid, so the randomized pairing check of the
    /// partial signatures (construction, step 2) is not part of this path; its cost is
    /// measured separately with `pa_mts::aggregate`.
    pub fn aggregate(
        &self,
        output: &PAMultiversePublicParams,
        partial_sigs: &[PAMultiversePartialSig],
        msg: &[u8],
    ) -> Option<PAMultiverseAggregation> {
        if output.coms.len() != self.total_weight - self.threshold_weight
            || output.coms_exp_k.len() != output.coms.len()
        {
            return None;
        }

        let mut all_sigs = BTreeMap::new();
        for partial_sig in partial_sigs {
            for (x, sig) in partial_sig {
                all_sigs.insert(*x, *sig);
            }
        }
        if all_sigs.len() < self.threshold_weight {
            return None;
        }

        // Steps 2-4: an authorized quorum and its Lagrange coefficients.
        let selected_xs: Vec<XCoord> = all_sigs
            .keys()
            .take(self.threshold_weight)
            .copied()
            .collect();
        let quorum = self.quorum_for_signer_xs(&selected_xs)?;
        let plan = self.lagrange_plan(&selected_xs)?;
        let signer_sigs: Vec<G2Projective> = selected_xs
            .iter()
            .map(|x| all_sigs.get(x).copied())
            .collect::<Option<_>>()?;

        // Step 5: raw MTS components.
        let raw_sigma_prime = utils::multi_exp_g2_fast(&signer_sigs, &plan.signer_coeffs);
        let raw_sigma_0 = utils::multi_exp_g1_fast(&output.coms, &plan.public_coeffs);
        let raw_sigma_1 = utils::multi_exp_g1_fast(&output.coms_exp_k, &plan.public_coeffs);

        // Steps 6-7: randomization, credential, hash value, and aggregator signature.
        let h_m = utils::hash_to_g2(msg);
        let universe_parties: Vec<PartyId> = self.addr_book.keys().copied().collect();
        let issued = pa_issue::randomize_and_issue(
            &raw_sigma_prime,
            &raw_sigma_0,
            &raw_sigma_1,
            &h_m,
            &self.crs.gs[0],
            &output.gamma,
            &universe_parties,
            &quorum,
            &self.aggregator_key,
        )?;

        Some(PAMultiverseAggregation {
            signature: PAMultiverseSig {
                sigma_prime: issued.components.sigma_prime,
                sigma_0: issued.components.sigma_0,
                sigma_1: issued.components.sigma_1,
                d: issued.components.d,
                tau: issued.tau,
            },
            credential: issued.credential,
            trace_key: issued.trace_key,
        })
    }

    /// `Verify(pk, VK, sigma, m)`: the aggregator signature and the two MTS equations.
    pub fn verify(
        &self,
        msg: &[u8],
        output: &PAMultiversePublicParams,
        aggregator_pk: &G1Projective,
        sig: &PAMultiverseSig,
    ) -> bool {
        if !pa_issue::verify_tau(&self.crs.gs[0], aggregator_pk, &sig.components(), &sig.tau) {
            return false;
        }
        let h_m = utils::hash_to_g2(msg);
        let check1_lhs = pairing(
            &output.public_key_s.add(sig.sigma_0.neg()).to_affine(),
            &h_m.to_affine(),
        );
        let check1_rhs = pairing(&self.crs.gs[0].to_affine(), &sig.sigma_prime.to_affine());
        let check2_lhs = pairing(&sig.sigma_1.to_affine(), &self.crs.hs[0].to_affine());
        let check2_rhs = pairing(&sig.sigma_0.to_affine(), &output.public_key_k.to_affine());

        check1_lhs == check1_rhs && check2_lhs == check2_rhs
    }

    /// `Trace(c, tk) = (Q, pi = u)`.
    pub fn trace(
        &self,
        credential: &PAMultiverseTraceCredential,
        trace_key: &PAMultiverseTraceKey,
    ) -> Option<(Vec<PartyId>, Scalar)> {
        pa_issue::trace(
            &self.addr_book.keys().copied().collect::<Vec<_>>(),
            credential,
            trace_key,
        )
    }

    /// `TraceVerify(U, pp, pk, m, sigma, c, Q, pi = u)`.
    #[allow(clippy::too_many_arguments)]
    pub fn trace_verify(
        &self,
        output: &PAMultiversePublicParams,
        aggregator_pk: &G1Projective,
        msg: &[u8],
        sig: &PAMultiverseSig,
        credential: &PAMultiverseTraceCredential,
        quorum: &[PartyId],
        u: &Scalar,
    ) -> bool {
        // Q in Lambda.
        if !self.is_authorized(quorum) {
            return false;
        }
        // d = H(c || Q || u).
        let universe_parties: Vec<PartyId> = self.addr_book.keys().copied().collect();
        let mask = match pa_issue::encode_quorum(&universe_parties, quorum) {
            Some(mask) => mask,
            None => return false,
        };
        if pa_issue::hash_value(credential, &mask, u) != sig.d {
            return false;
        }
        // tau is valid under pk[1].
        if !pa_issue::verify_tau(&self.crs.gs[0], aggregator_pk, &sig.components(), &sig.tau) {
            return false;
        }
        // Undo the randomization: public part.
        let selected_xs = match self.signer_xs_for_quorum(quorum) {
            Some(xs) => xs,
            None => return false,
        };
        let plan = match self.lagrange_plan(&selected_xs) {
            Some(plan) => plan,
            None => return false,
        };
        let lhs_0 = sig.sigma_0.add(self.crs.gs[0].mul(u));
        let lhs_1 = sig.sigma_1.add(output.gamma.mul(u));
        if lhs_0 != utils::multi_exp_g1_fast(&output.coms, &plan.public_coeffs)
            || lhs_1 != utils::multi_exp_g1_fast(&output.coms_exp_k, &plan.public_coeffs)
        {
            return false;
        }
        // Quorum part against VK_0^par, computed from the public keys of Q.
        let selected_public_keys: Vec<G1Projective> = plan
            .signer_xs
            .iter()
            .filter_map(|x| output.signer_public_keys.get(x - 1))
            .copied()
            .collect();
        if selected_public_keys.len() != plan.signer_coeffs.len() {
            return false;
        }
        let vk_0_par = utils::multi_exp_g1_fast(&selected_public_keys, &plan.signer_coeffs);
        let h_m = utils::hash_to_g2(msg);
        let raw_sigma_prime = sig.sigma_prime.sub(h_m.mul(u));

        pairing(&vk_0_par.to_affine(), &h_m.to_affine())
            == pairing(&self.crs.gs[0].to_affine(), &raw_sigma_prime.to_affine())
    }

    fn quorum_for_signer_xs(&self, signer_xs: &[XCoord]) -> Option<Vec<PartyId>> {
        let selected: BTreeSet<XCoord> = signer_xs.iter().copied().collect();
        if selected.len() != signer_xs.len() {
            return None;
        }
        let mut quorum = Vec::new();
        let mut represented = 0usize;

        for (party, (lo, hi)) in &self.addr_book_ranges {
            let selected_in_range = (*lo..=*hi).filter(|x| selected.contains(x)).count();
            if selected_in_range == 0 {
                continue;
            }
            let weight = hi - lo + 1;
            if selected_in_range != weight {
                return None;
            }
            quorum.push(*party);
            represented += weight;
        }

        if represented == signer_xs.len() && self.is_authorized(&quorum) {
            Some(quorum)
        } else {
            None
        }
    }

    fn signer_xs_for_quorum(&self, quorum: &[PartyId]) -> Option<Vec<XCoord>> {
        if !self.is_authorized(quorum) {
            return None;
        }
        let mut xs = Vec::new();
        for party in quorum {
            let (lo, hi) = self.addr_book_ranges.get(party)?;
            xs.extend(*lo..=*hi);
        }
        Some(xs)
    }

    fn is_authorized(&self, quorum: &[PartyId]) -> bool {
        let mut seen = BTreeSet::new();
        let mut weight = 0usize;
        for party in quorum {
            if !seen.insert(*party) {
                return false;
            }
            match self.addr_book.get(party) {
                Some(party_weight) => weight += *party_weight,
                None => return false,
            }
        }
        weight >= self.threshold_weight
    }

    fn lagrange_plan(&self, selected_xs: &[XCoord]) -> Option<LagrangePlan> {
        if selected_xs.len() < self.threshold_weight {
            return None;
        }
        let mut seen = BTreeSet::new();
        for x in selected_xs {
            if *x == 0 || *x > self.total_weight || !seen.insert(*x) {
                return None;
            }
        }

        let mut all_xs: Vec<Scalar> = selected_xs
            .iter()
            .map(|x| Scalar::from(*x as u64))
            .collect();
        let signer_len = all_xs.len();
        all_xs.extend(aggregator_xs(self.total_weight, self.threshold_weight));
        let coeffs = Polynomial::lagrange_coefficients(&all_xs);

        Some(LagrangePlan {
            signer_xs: selected_xs.to_vec(),
            signer_coeffs: coeffs[..signer_len].to_vec(),
            public_coeffs: coeffs[signer_len..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        dealer: PAMultiverseParty,
        output: PAMultiversePublicParams,
        partials: Vec<PAMultiversePartialSig>,
        msg: &'static [u8],
        n: usize,
    }

    fn fixture(n: usize, k: usize) -> Fixture {
        let total_weight = n * k;
        let threshold_weight = total_weight / 2;
        let mut rng = thread_rng();
        let crs = sig_utils::test_setup::<1>(&mut rng);
        let addr_book = sig_utils::create_addr_book(n, k);
        let dealer = PAMultiverseParty::new(crs, threshold_weight, total_weight, &addr_book);
        let output = dealer.setup();
        let msg: &'static [u8] = b"PA-MTS dealer path";
        let partials = addr_book
            .keys()
            .map(|id| dealer.sign(*id, msg, &output))
            .collect();
        Fixture { dealer, output, partials, msg, n }
    }

    #[test]
    fn round_trip_and_sizes() {
        let f = fixture(8, 2);
        let pk = f.dealer.aggregator_public_key();
        let first = f.dealer.aggregate(&f.output, &f.partials, f.msg).unwrap();
        let second = f.dealer.aggregate(&f.output, &f.partials, f.msg).unwrap();
        assert!(f.dealer.verify(f.msg, &f.output, &pk, &first.signature));
        assert!(f.dealer.verify(f.msg, &f.output, &pk, &second.signature));
        // Fresh u: the message-independent components differ between issuances.
        assert_ne!(first.signature.sigma_0, second.signature.sigma_0);

        let (quorum, u) = f.dealer.trace(&first.credential, &first.trace_key).unwrap();
        assert_eq!(quorum, vec![1, 2, 3, 4]);
        assert!(f.dealer.trace_verify(
            &f.output, &pk, f.msg, &first.signature, &first.credential, &quorum, &u
        ));
        assert_eq!(first.signature.compressed_size_bytes(), 384);
        assert_eq!(
            first.credential.serialized_size_bytes(),
            pa_issue::credential_size_for_party_count(f.n)
        );
    }

    #[test]
    fn verify_rejects_rerandomization_wrong_message_and_wrong_key() {
        let f = fixture(6, 1);
        let pk = f.dealer.aggregator_public_key();
        let issued = f.dealer.aggregate(&f.output, &f.partials, f.msg).unwrap();
        let sig = issued.signature;

        // Re-randomizing with the public Gamma keeps both MTS equations but breaks tau.
        let v = Scalar::random(&mut thread_rng());
        let mut rerand = sig;
        rerand.sigma_prime = sig.sigma_prime.add(utils::hash_to_g2(f.msg).mul(v));
        rerand.sigma_0 = sig.sigma_0.sub(f.dealer.crs.gs[0].mul(v));
        rerand.sigma_1 = sig.sigma_1.sub(f.output.gamma.mul(v));
        assert!(!f.dealer.verify(f.msg, &f.output, &pk, &rerand));

        assert!(!f.dealer.verify(b"other message", &f.output, &pk, &sig));
        let other = AggregatorKeyPair::generate(&f.dealer.crs.gs[0]);
        assert!(!f.dealer.verify(f.msg, &f.output, &other.pk1, &sig));
    }

    #[test]
    fn trace_verify_rejects_wrong_quorum_scalar_and_credential() {
        let f = fixture(6, 1);
        let pk = f.dealer.aggregator_public_key();
        let issued = f.dealer.aggregate(&f.output, &f.partials, f.msg).unwrap();
        let (quorum, u) = f.dealer.trace(&issued.credential, &issued.trace_key).unwrap();
        let sig = &issued.signature;
        let c = &issued.credential;
        assert!(f.dealer.trace_verify(&f.output, &pk, f.msg, sig, c, &quorum, &u));

        // Another authorized quorum.
        assert!(!f.dealer.trace_verify(&f.output, &pk, f.msg, sig, c, &[4, 5, 6], &u));
        // A superset quorum.
        assert!(!f.dealer.trace_verify(&f.output, &pk, f.msg, sig, c, &[1, 2, 3, 4], &u));
        // Unauthorized quorum.
        assert!(!f.dealer.trace_verify(&f.output, &pk, f.msg, sig, c, &[1, 2], &u));
        // Wrong scalar.
        let wrong_u = u + Scalar::ONE;
        assert!(!f.dealer.trace_verify(&f.output, &pk, f.msg, sig, c, &quorum, &wrong_u));
        // Substituted credential.
        let mut c2 = c.clone();
        c2.ciphertext[0] ^= 1;
        assert!(!f.dealer.trace_verify(&f.output, &pk, f.msg, sig, &c2, &quorum, &u));
        // Wrong message.
        assert!(!f.dealer.trace_verify(&f.output, &pk, b"x", sig, c, &quorum, &u));
    }
}
