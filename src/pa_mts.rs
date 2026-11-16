use group::Group;
use bls12_381::{pairing, G1Projective, G2Projective, Scalar};
use ff::Field;
use pairing::group::Curve;
use rand::thread_rng;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Add, Mul, Neg, Sub};

use crate::common::sig_utils;
use crate::pa_issue::{self, AggregatorKeyPair, RandomizedComponents};
use crate::polynomial::Polynomial;
use crate::universe::Universe;
use crate::utils;
use crate::{PartyId, XCoord};

pub use crate::pa_issue::{TraceCredential as PATraceCredential, TraceKey as PATraceKey};

#[derive(Clone)]
pub struct PAUniverseCreationMessage {
    pub blinded_evals: Vec<G1Projective>,
    pub beta: G2Projective,
    pub gamma: G1Projective,
}

#[derive(Clone)]
pub struct PAUniverseCreationState {
    pub vk_0: G1Projective,
    pub evals_0: Vec<G1Projective>,
}

#[derive(Clone)]
pub struct PAUniversePublicParams {
    pub evals_0: Vec<G1Projective>,
    pub evals_1: Vec<G1Projective>,
    pub gamma: G1Projective,
}

#[derive(Clone)]
pub struct PAUniverseVerificationKey {
    pub vk_0: G1Projective,
    pub vk_1: G2Projective,
}

#[derive(Clone)]
pub struct PAPartialSignature {
    pub signer_id: PartyId,
    pub sig_elements: Vec<G2Projective>,
}

impl PAPartialSignature {
    pub fn compressed_size_bytes(&self) -> usize {
        96 * self.sig_elements.len()
    }
}

/// PA-MTS signature `sigma = (hat_sigma', hat_sigma'_0, hat_sigma'_1, d, tau)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PAAggregateSignature {
    pub sigma_prime: G2Projective,
    pub sigma_0: G1Projective,
    pub sigma_1: G1Projective,
    pub d: G2Projective,
    pub tau: G2Projective,
}

impl PAAggregateSignature {
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
pub struct PAAggregationResult {
    pub signature: PAAggregateSignature,
    pub credential: PATraceCredential,
    pub trace_key: PATraceKey,
}

struct LagrangePlan {
    signer_xs: Vec<XCoord>,
    signer_coeffs: Vec<Scalar>,
    public_coeffs: Vec<Scalar>,
}

/// `KGen`: `pk = g_1^{F(s)}` for the PRG seed `s` (here encoded as a scalar).
pub fn publish_pubkeys(secret: &Scalar, num_pubkeys: usize) -> Vec<G1Projective> {
    let generator = utils::get_generator_in_g1();
    pa_issue::prg_expand(&secret.to_le_bytes(), num_pubkeys)
        .iter()
        .map(|x| generator.mul(x))
        .collect()
}

/// Aggregator key pair generated with `KGen` with respect to the scheme generator `g_1`.
pub fn aggregator_kgen() -> AggregatorKeyPair {
    AggregatorKeyPair::generate(&utils::get_generator_in_g1())
}

pub fn publish_universe_setup_msg(
    universe: &Universe,
) -> (PAUniverseCreationState, PAUniverseCreationMessage) {
    let (vk_0, evals_0) = compute_universe_public_points(universe);
    let mut rng = thread_rng();
    let k = Scalar::random(&mut rng);

    // Mirror the upstream MTS UGen_on operations for the common work.
    // PA-MTS adds only gamma = g_1^k.
    let blinded_evals = evals_0
        .iter()
        .map(|point| utils::commit_in_g1(point, &k))
        .collect();
    let beta = utils::commit_in_g2(&utils::get_generator_in_g2(), &k);
    let gamma = utils::commit_in_g1(&utils::get_generator_in_g1(), &k);

    (
        PAUniverseCreationState { vk_0, evals_0 },
        PAUniverseCreationMessage {
            blinded_evals,
            beta,
            gamma,
        },
    )
}

pub fn compute_universe_pp(
    universe: &Universe,
    state: &PAUniverseCreationState,
    msgs: &[PAUniverseCreationMessage],
) -> (PAUniversePublicParams, PAUniverseVerificationKey) {
    // Use the same optimized common UGen_off structure as the normalized
    // MTS baseline. PA-MTS adds only the G1 fold that derives Gamma.
    let public_point_count = universe.get_total_weight() - universe.get_threshold();
    let mut evals_1 = Vec::with_capacity(public_point_count);
    for index in 0..public_point_count {
        let combined = msgs.iter().fold(G1Projective::identity(), |sum, msg| {
            sum.add(msg.blinded_evals[index])
        });
        evals_1.push(combined);
    }
    let vk_1 = msgs
        .iter()
        .fold(G2Projective::identity(), |sum, msg| sum.add(msg.beta));
    let gamma = msgs
        .iter()
        .fold(G1Projective::identity(), |sum, msg| sum.add(msg.gamma));

    (
        PAUniversePublicParams {
            evals_0: state.evals_0.clone(),
            evals_1,
            gamma,
        },
        PAUniverseVerificationKey {
            vk_0: state.vk_0,
            vk_1,
        },
    )
}

pub fn sign(id: PartyId, secret: &Scalar, num_pubkeys: usize, msg: &[u8]) -> PAPartialSignature {
    let h_m = utils::hash_to_g2(msg);
    let sig_elements = pa_issue::prg_expand(&secret.to_le_bytes(), num_pubkeys)
        .iter()
        .map(|x| h_m.mul(x))
        .collect();

    PAPartialSignature {
        signer_id: id,
        sig_elements,
    }
}

/// Faithful PA-MTS aggregation, including the randomized batch check of partial signatures.
pub fn aggregate(
    universe: &Universe,
    pp: &PAUniversePublicParams,
    aggregator_key: &AggregatorKeyPair,
    partial_sigs: &[PAPartialSignature],
    msg: &[u8],
) -> Option<PAAggregationResult> {
    aggregate_internal(universe, pp, aggregator_key, partial_sigs, msg, true)
}

/// Aggregation path aligned with the original MTS implementation for evaluation.
/// Both paths assume that all benchmark-generated partial signatures are honest.
pub fn aggregate_assuming_valid_shares(
    universe: &Universe,
    pp: &PAUniversePublicParams,
    aggregator_key: &AggregatorKeyPair,
    partial_sigs: &[PAPartialSignature],
    msg: &[u8],
) -> Option<PAAggregationResult> {
    aggregate_internal(universe, pp, aggregator_key, partial_sigs, msg, false)
}

fn aggregate_internal(
    universe: &Universe,
    pp: &PAUniversePublicParams,
    aggregator_key: &AggregatorKeyPair,
    partial_sigs: &[PAPartialSignature],
    msg: &[u8],
    validate_shares: bool,
) -> Option<PAAggregationResult> {
    universe_shape(universe)?;
    let sigs_by_party = partial_signatures_by_party(partial_sigs)?;
    let h_m = utils::hash_to_g2(msg);
    let validation_challenge = validate_shares.then(|| {
        let max_weight = universe
            .address_book
            .values()
            .map(|(weight, _)| *weight)
            .max()
            .unwrap_or_default();
        let mut rng = thread_rng();
        (0..max_weight)
            .map(|_| Scalar::random(&mut rng))
            .collect::<Vec<_>>()
    });
    let quorum = select_available_quorum(
        universe,
        &sigs_by_party,
        &h_m,
        validation_challenge.as_deref(),
    )?;
    let plan = lagrange_plan(universe, &quorum)?;

    if pp.evals_0.len() != plan.public_coeffs.len() || pp.evals_1.len() != plan.public_coeffs.len()
    {
        return None;
    }

    let ranges = sig_utils::compute_universe_private_xs_ranges(universe);
    let mut signer_sigs = Vec::with_capacity(plan.signer_coeffs.len());
    for party in &quorum {
        let sig = sigs_by_party.get(party)?;
        let (lo, hi) = ranges.get(party)?;
        let weight = hi - lo + 1;
        signer_sigs.extend_from_slice(sig.sig_elements.get(..weight)?);
    }
    if signer_sigs.len() != plan.signer_coeffs.len() {
        return None;
    }

    let raw_sigma_prime = utils::multi_exp_g2_fast(&signer_sigs, &plan.signer_coeffs);
    let raw_sigma_0 = utils::multi_exp_g1_fast(&pp.evals_0, &plan.public_coeffs);
    let raw_sigma_1 = utils::multi_exp_g1_fast(&pp.evals_1, &plan.public_coeffs);

    // Steps 6-7: randomization, credential, hash value, and aggregator signature.
    let universe_parties = universe.get_parties_in_canonical_ordering();
    let issued = pa_issue::randomize_and_issue(
        &raw_sigma_prime,
        &raw_sigma_0,
        &raw_sigma_1,
        &h_m,
        &utils::get_generator_in_g1(),
        &pp.gamma,
        &universe_parties,
        &quorum,
        aggregator_key,
    )?;
    let signature = PAAggregateSignature {
        sigma_prime: issued.components.sigma_prime,
        sigma_0: issued.components.sigma_0,
        sigma_1: issued.components.sigma_1,
        d: issued.components.d,
        tau: issued.tau,
    };
    let (credential, trace_key) = (issued.credential, issued.trace_key);

    Some(PAAggregationResult {
        signature,
        credential,
        trace_key,
    })
}

/// `Verify(pk, VK, sigma, m)`: the aggregator signature and the two MTS equations.
pub fn verify(
    msg: &[u8],
    vk: &PAUniverseVerificationKey,
    aggregator_pk: &G1Projective,
    sig: &PAAggregateSignature,
) -> bool {
    if !pa_issue::verify_tau(
        &utils::get_generator_in_g1(),
        aggregator_pk,
        &sig.components(),
        &sig.tau,
    ) {
        return false;
    }
    let h_m = utils::hash_to_g2(msg);
    let check1_lhs = pairing(
        &vk.vk_0.add(sig.sigma_0.neg()).to_affine(),
        &h_m.to_affine(),
    );
    let check1_rhs = pairing(
        &utils::get_generator_in_g1().to_affine(),
        &sig.sigma_prime.to_affine(),
    );
    let check2_lhs = pairing(
        &sig.sigma_1.to_affine(),
        &utils::get_generator_in_g2().to_affine(),
    );
    let check2_rhs = pairing(&sig.sigma_0.to_affine(), &vk.vk_1.to_affine());

    check1_lhs == check1_rhs && check2_lhs == check2_rhs
}

/// `Trace(c, tk) = (Q, pi = u)`.
pub fn trace(
    universe: &Universe,
    credential: &PATraceCredential,
    trace_key: &PATraceKey,
) -> Option<(Vec<PartyId>, Scalar)> {
    pa_issue::trace(
        &universe.get_parties_in_canonical_ordering(),
        credential,
        trace_key,
    )
}

/// `TraceVerify(U, pp, pk, m, sigma, c, Q, pi = u)`.
#[allow(clippy::too_many_arguments)]
pub fn trace_verify(
    universe: &Universe,
    pp: &PAUniversePublicParams,
    aggregator_pk: &G1Projective,
    msg: &[u8],
    sig: &PAAggregateSignature,
    credential: &PATraceCredential,
    quorum: &[PartyId],
    u: &Scalar,
) -> bool {
    // Q in Lambda.
    if !is_authorized(universe, quorum) {
        return false;
    }
    // d = H(c || Q || u).
    let universe_parties = universe.get_parties_in_canonical_ordering();
    let mask = match pa_issue::encode_quorum(&universe_parties, quorum) {
        Some(mask) => mask,
        None => return false,
    };
    if pa_issue::hash_value(credential, &mask, u) != sig.d {
        return false;
    }
    // tau is valid under pk[1].
    if !pa_issue::verify_tau(
        &utils::get_generator_in_g1(),
        aggregator_pk,
        &sig.components(),
        &sig.tau,
    ) {
        return false;
    }

    let plan = match lagrange_plan(universe, quorum) {
        Some(plan) => plan,
        None => return false,
    };
    if pp.evals_0.len() != plan.public_coeffs.len() || pp.evals_1.len() != plan.public_coeffs.len()
    {
        return false;
    }

    let expected_sigma_0 = utils::multi_exp_g1_fast(&pp.evals_0, &plan.public_coeffs)
        .sub(utils::get_generator_in_g1().mul(u));
    let expected_sigma_1 =
        utils::multi_exp_g1_fast(&pp.evals_1, &plan.public_coeffs).sub(pp.gamma.mul(u));
    if sig.sigma_0 != expected_sigma_0 || sig.sigma_1 != expected_sigma_1 {
        return false;
    }

    let selected_pubkeys = selected_public_keys(universe, &plan.signer_xs);
    if selected_pubkeys.len() != plan.signer_coeffs.len() {
        return false;
    }
    let vk_0_partial = utils::multi_exp_g1_fast(&selected_pubkeys, &plan.signer_coeffs);
    let h_m = utils::hash_to_g2(msg);
    let raw_sigma_prime = sig.sigma_prime.sub(h_m.mul(u));

    pairing(&vk_0_partial.to_affine(), &h_m.to_affine())
        == pairing(
            &utils::get_generator_in_g1().to_affine(),
            &raw_sigma_prime.to_affine(),
        )
}

fn compute_universe_public_points(universe: &Universe) -> (G1Projective, Vec<G1Projective>) {
    // Match the upstream MTS interpolation and allocation structure.
    // active_universe_public_keys() retains PA-MTS's prefix-by-weight semantics.
    let w = universe.get_total_weight();
    let t = universe.get_threshold();

    let signer_x_coords: Vec<XCoord> = (1..w + 1).collect();
    let signer_xs: Vec<Scalar> = signer_x_coords
        .iter()
        .map(|&x| Scalar::from(x as u64))
        .collect();

    let public_x_coords: Vec<XCoord> = ((w + 1)..(2 * w - t + 1)).collect();
    let public_xs: Vec<Scalar> = public_x_coords
        .iter()
        .map(|&x| Scalar::from(x as u64))
        .collect();

    let public_keys = active_universe_public_keys(universe);
    let mut evals_0: Vec<G1Projective> = Vec::new();
    for x in public_xs {
        let coeffs = Polynomial::lagrange_coefficients_naive(signer_xs.as_slice(), &x);
        let point = utils::multi_exp_g1_fast(public_keys.as_slice(), coeffs.as_slice());
        evals_0.push(point);
    }

    let zero_coeffs =
        Polynomial::lagrange_coefficients_naive(signer_xs.as_slice(), &Scalar::from(0u64));
    let vk_0 = utils::multi_exp_g1_fast(public_keys.as_slice(), zero_coeffs.as_slice());

    (vk_0, evals_0)
}

fn partial_signatures_by_party(
    partial_sigs: &[PAPartialSignature],
) -> Option<BTreeMap<PartyId, &PAPartialSignature>> {
    let mut by_party = BTreeMap::new();
    for sig in partial_sigs {
        if by_party.insert(sig.signer_id, sig).is_some() {
            return None;
        }
    }
    Some(by_party)
}

fn select_available_quorum(
    universe: &Universe,
    sigs_by_party: &BTreeMap<PartyId, &PAPartialSignature>,
    h_m: &G2Projective,
    validation_challenge: Option<&[Scalar]>,
) -> Option<Vec<PartyId>> {
    let mut quorum = Vec::new();
    let mut total_weight = 0usize;

    for party in universe.get_parties_in_canonical_ordering() {
        let sig = match sigs_by_party.get(&party) {
            Some(sig) => *sig,
            None => continue,
        };
        let weight = universe.get_weight(&party);
        if sig.sig_elements.len() < weight {
            continue;
        }
        if let Some(challenge) = validation_challenge {
            if !partial_signature_is_valid(universe, sig, h_m, &challenge[..weight]) {
                continue;
            }
        }

        quorum.push(party);
        total_weight += weight;
        if total_weight >= universe.get_threshold() {
            return Some(quorum);
        }
    }

    None
}

fn partial_signature_is_valid(
    universe: &Universe,
    sig: &PAPartialSignature,
    h_m: &G2Projective,
    challenge: &[Scalar],
) -> bool {
    let weight = universe.get_weight(&sig.signer_id);
    if challenge.len() != weight || sig.sig_elements.len() < weight {
        return false;
    }
    let pubkeys = universe.get_pub_keys(&sig.signer_id);
    if pubkeys.len() < weight {
        return false;
    }

    let combined_pk = utils::multi_exp_g1_fast(&pubkeys[..weight], challenge);
    let combined_sig = utils::multi_exp_g2_fast(&sig.sig_elements[..weight], challenge);
    pairing(&combined_pk.to_affine(), &h_m.to_affine())
        == pairing(
            &utils::get_generator_in_g1().to_affine(),
            &combined_sig.to_affine(),
        )
}

fn lagrange_plan(universe: &Universe, quorum: &[PartyId]) -> Option<LagrangePlan> {
    if !is_authorized(universe, quorum) {
        return None;
    }
    let ranges = sig_utils::compute_universe_private_xs_ranges(universe);
    let mut signer_xs = Vec::new();
    for party in quorum {
        let (lo, hi) = ranges.get(party)?;
        signer_xs.extend(*lo..=*hi);
    }

    let mut all_xs: Vec<Scalar> = signer_xs.iter().map(|x| Scalar::from(*x as u64)).collect();
    let signer_len = all_xs.len();
    all_xs.extend(sig_utils::compute_universe_public_xs(universe));
    let coeffs = Polynomial::lagrange_coefficients(&all_xs);

    Some(LagrangePlan {
        signer_xs,
        signer_coeffs: coeffs[..signer_len].to_vec(),
        public_coeffs: coeffs[signer_len..].to_vec(),
    })
}

fn is_authorized(universe: &Universe, quorum: &[PartyId]) -> bool {
    let (_, threshold, _) = match universe_shape(universe) {
        Some(shape) => shape,
        None => return false,
    };
    let mut seen = BTreeSet::new();
    let mut total_weight = 0usize;
    for party in quorum {
        if !seen.insert(*party) || !universe.address_book.contains_key(party) {
            return false;
        }
        total_weight += universe.get_weight(party);
    }
    total_weight >= threshold
}

fn selected_public_keys(universe: &Universe, signer_xs: &[XCoord]) -> Vec<G1Projective> {
    let all_pubkeys = active_universe_public_keys(universe);
    signer_xs
        .iter()
        .filter_map(|x| x.checked_sub(1).and_then(|index| all_pubkeys.get(index)))
        .copied()
        .collect()
}

fn active_universe_public_keys(universe: &Universe) -> Vec<G1Projective> {
    // Use the same push-based collection style as the upstream MTS helper,
    // while retaining only the active W_i-prefix required by PA-MTS.
    let mut public_keys = Vec::new();
    for party in universe.get_parties_in_canonical_ordering().iter() {
        let weight = universe.get_weight(party);
        for party_key in universe.get_pub_keys(party).iter().take(weight) {
            public_keys.push(party_key.clone());
        }
    }
    public_keys
}

fn universe_shape(universe: &Universe) -> Option<(usize, usize, usize)> {
    let total_weight = universe.get_total_weight();
    let threshold = universe.get_threshold();
    if total_weight == 0 || threshold == 0 || threshold > total_weight {
        return None;
    }
    Some((total_weight, threshold, total_weight - threshold))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    struct Fixture {
        universe: Universe,
        pp: PAUniversePublicParams,
        vk: PAUniverseVerificationKey,
        agg: AggregatorKeyPair,
        secrets: BTreeMap<PartyId, Scalar>,
        partials: Vec<PAPartialSignature>,
        msg: &'static [u8],
    }

    fn fixture(weights: &[usize], threshold: usize) -> Fixture {
        let mut rng = thread_rng();
        let b = *weights.iter().max().unwrap();
        let mut universe = Universe::new();
        let mut secrets = BTreeMap::new();
        for (i, w) in weights.iter().enumerate() {
            let party = i + 1;
            let secret = Scalar::random(&mut rng);
            universe.add_party(party, *w, Rc::new(publish_pubkeys(&secret, b)));
            secrets.insert(party, secret);
        }
        universe.set_threshold(threshold);
        let mut setup_state = None;
        let mut setup_msgs = Vec::new();
        for _ in 0..weights.len() {
            let (state, setup_msg) = publish_universe_setup_msg(&universe);
            setup_state = Some(state);
            setup_msgs.push(setup_msg);
        }
        let (pp, vk) = compute_universe_pp(&universe, &setup_state.unwrap(), &setup_msgs);
        let msg: &'static [u8] = b"PA-MTS universe path";
        let partials = secrets
            .iter()
            .map(|(party, secret)| sign(*party, secret, b, msg))
            .collect();
        Fixture { universe, pp, vk, agg: aggregator_kgen(), secrets, partials, msg }
    }

    #[test]
    fn correctness_trace_and_fresh_randomization() {
        let f = fixture(&[2, 2, 2, 2, 2, 2], 6);
        let first = aggregate(&f.universe, &f.pp, &f.agg, &f.partials, f.msg).unwrap();
        let second = aggregate(&f.universe, &f.pp, &f.agg, &f.partials, f.msg).unwrap();
        assert!(verify(f.msg, &f.vk, &f.agg.pk1, &first.signature));
        assert!(verify(f.msg, &f.vk, &f.agg.pk1, &second.signature));
        assert_ne!(first.signature.sigma_0, second.signature.sigma_0);
        assert_ne!(first.signature.sigma_1, second.signature.sigma_1);

        let (quorum, u) = trace(&f.universe, &first.credential, &first.trace_key).unwrap();
        assert_eq!(quorum, vec![1, 2, 3]);
        assert!(trace_verify(
            &f.universe, &f.pp, &f.agg.pk1, f.msg, &first.signature, &first.credential, &quorum, &u
        ));
        assert_eq!(first.signature.compressed_size_bytes(), 384);
    }

    #[test]
    fn invalid_partial_signature_is_excluded() {
        let mut f = fixture(&[1, 1, 1, 1], 2);
        // Corrupt party 1's partial signature: Aggr must skip it and use parties 2 and 3.
        f.partials[0].sig_elements[0] = utils::hash_to_g2(b"garbage");
        let issued = aggregate(&f.universe, &f.pp, &f.agg, &f.partials, f.msg).unwrap();
        let (quorum, u) = trace(&f.universe, &issued.credential, &issued.trace_key).unwrap();
        assert_eq!(quorum, vec![2, 3]);
        assert!(verify(f.msg, &f.vk, &f.agg.pk1, &issued.signature));
        assert!(trace_verify(
            &f.universe, &f.pp, &f.agg.pk1, f.msg, &issued.signature, &issued.credential, &quorum, &u
        ));
    }

    #[test]
    fn rerandomized_and_self_aggregated_signatures_are_rejected() {
        let f = fixture(&[1, 1, 1, 1], 2);
        let issued = aggregate(&f.universe, &f.pp, &f.agg, &f.partials, f.msg).unwrap();
        let sig = issued.signature;
        let v = Scalar::random(&mut thread_rng());
        let mut rerand = sig;
        rerand.sigma_prime = sig.sigma_prime.add(utils::hash_to_g2(f.msg).mul(v));
        rerand.sigma_0 = sig.sigma_0.sub(utils::get_generator_in_g1().mul(v));
        rerand.sigma_1 = sig.sigma_1.sub(f.pp.gamma.mul(v));
        assert!(!verify(f.msg, &f.vk, &f.agg.pk1, &rerand));

        // A coalition that aggregates with its own key is not accepted under the aggregator key.
        let coalition_key = aggregator_kgen();
        let own = aggregate(&f.universe, &f.pp, &coalition_key, &f.partials, f.msg).unwrap();
        assert!(verify(f.msg, &f.vk, &coalition_key.pk1, &own.signature));
        assert!(!verify(f.msg, &f.vk, &f.agg.pk1, &own.signature));
    }

    #[test]
    fn trace_verify_rejects_other_quorum_scalar_credential_and_key() {
        let f = fixture(&[1, 1, 1, 1, 1], 2);
        let issued = aggregate(&f.universe, &f.pp, &f.agg, &f.partials, f.msg).unwrap();
        let (quorum, u) = trace(&f.universe, &issued.credential, &issued.trace_key).unwrap();
        let (sig, c, pk) = (&issued.signature, &issued.credential, &f.agg.pk1);
        assert!(trace_verify(&f.universe, &f.pp, pk, f.msg, sig, c, &quorum, &u));
        assert!(!trace_verify(&f.universe, &f.pp, pk, f.msg, sig, c, &[3, 4], &u));
        assert!(!trace_verify(&f.universe, &f.pp, pk, f.msg, sig, c, &[1, 2, 3], &u));
        assert!(!trace_verify(&f.universe, &f.pp, pk, f.msg, sig, c, &[1], &u));
        let wrong_u = u + Scalar::ONE;
        assert!(!trace_verify(&f.universe, &f.pp, pk, f.msg, sig, c, &quorum, &wrong_u));
        let mut c2 = c.clone();
        c2.ciphertext[0] ^= 1;
        assert!(!trace_verify(&f.universe, &f.pp, pk, f.msg, sig, &c2, &quorum, &u));
        let other = aggregator_kgen();
        assert!(!trace_verify(&f.universe, &f.pp, &other.pk1, f.msg, sig, c, &quorum, &u));
    }

    #[test]
    fn heterogeneous_weights_and_reuse_across_universes() {
        // Universe 1: weights (3, 1, 2, 2), threshold 4.
        let f = fixture(&[3, 1, 2, 2], 4);
        let issued = aggregate(&f.universe, &f.pp, &f.agg, &f.partials, f.msg).unwrap();
        let (quorum, u) = trace(&f.universe, &issued.credential, &issued.trace_key).unwrap();
        assert_eq!(quorum, vec![1, 2]);
        assert!(verify(f.msg, &f.vk, &f.agg.pk1, &issued.signature));
        assert!(trace_verify(
            &f.universe, &f.pp, &f.agg.pk1, f.msg, &issued.signature, &issued.credential, &quorum, &u
        ));

        // Universe 2 over parties 2..4 with different weights reuses the same keys
        // and the same partial signatures.
        let b = 3;
        let mut u2 = Universe::new();
        for (party, w) in [(2usize, 1usize), (3, 3), (4, 1)] {
            let secret = f.secrets[&party];
            u2.add_party(party, w, Rc::new(publish_pubkeys(&secret, b)));
        }
        u2.set_threshold(4);
        let (state, m1) = publish_universe_setup_msg(&u2);
        let (_, m2) = publish_universe_setup_msg(&u2);
        let (pp2, vk2) = compute_universe_pp(&u2, &state, &[m1, m2]);
        let agg2 = aggregator_kgen();
        let reused: Vec<PAPartialSignature> =
            f.partials.iter().filter(|p| p.signer_id != 1).cloned().collect();
        let issued2 = aggregate(&u2, &pp2, &agg2, &reused, f.msg).unwrap();
        assert!(verify(f.msg, &vk2, &agg2.pk1, &issued2.signature));
        let (q2, u2s) = trace(&u2, &issued2.credential, &issued2.trace_key).unwrap();
        assert_eq!(q2, vec![2, 3]);
        assert!(trace_verify(&u2, &pp2, &agg2.pk1, f.msg, &issued2.signature, &issued2.credential, &q2, &u2s));
    }
}
