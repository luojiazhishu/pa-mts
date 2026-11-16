use bls12_381::Scalar;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ff::Field;
use pa_mts::{
    common::sig_utils,
    kzg::KZGParams,
    mts,
    multiverse_sig::{MultiversePartialSig, MultiverseParty},
    pa_mts as pa,
    pa_multiverse_sig::{PAMultiversePartialSig, PAMultiverseParty},
    universe::Universe,
    PartyId, PartySecret,
};
use rand::thread_rng;
use std::{collections::BTreeMap, rc::Rc};

fn small_crs() -> KZGParams {
    let mut rng = thread_rng();
    sig_utils::test_setup::<1>(&mut rng)
}

fn smoke_multiverse() {
    let n = 8usize;
    let k = 2usize;
    let total_weight = n * k;
    let threshold_weight = total_weight / 2;
    let addr_book = sig_utils::create_addr_book(n, k);
    let dealer = MultiverseParty::new(small_crs(), threshold_weight, total_weight, &addr_book);
    let output = dealer.setup();
    let msg = b"PA-MTS smoke multiverse";

    let partials: Vec<MultiversePartialSig> = addr_book
        .keys()
        .copied()
        .map(|id| dealer.sign(id, msg, &output))
        .collect();
    let sig = dealer.aggregate(&output, &partials).unwrap();
    assert!(dealer.verify(msg, &output, &sig));
}

fn smoke_pa_multiverse() {
    let n = 8usize;
    let k = 2usize;
    let total_weight = n * k;
    let threshold_weight = total_weight / 2;
    let addr_book = sig_utils::create_addr_book(n, k);
    let dealer = PAMultiverseParty::new(small_crs(), threshold_weight, total_weight, &addr_book);
    let output = dealer.setup();
    let msg = b"PA-MTS smoke multiverse";

    let partials: Vec<PAMultiversePartialSig> = addr_book
        .keys()
        .copied()
        .map(|id| dealer.sign(id, msg, &output))
        .collect();
    let issued = dealer.aggregate(&output, &partials, msg).unwrap();
    let pk = dealer.aggregator_public_key();
    assert!(dealer.verify(msg, &output, &pk, &issued.signature));

    let (quorum, u) = dealer.trace(&issued.credential, &issued.trace_key).unwrap();
    assert!(dealer.trace_verify(
        &output,
        &pk,
        msg,
        &issued.signature,
        &issued.credential,
        &quorum,
        &u,
    ));
}

fn build_universe_for_mts(n: usize, k: usize) -> (Universe, BTreeMap<PartyId, PartySecret>) {
    let mut rng = thread_rng();
    let mut universe = Universe::new();
    let mut secrets = BTreeMap::new();

    for party in 1..=n {
        let secret = Scalar::random(&mut rng);
        let pubkeys = mts::publish_pubkeys(&secret, k);
        universe.add_party(party, k, Rc::new(pubkeys));
        secrets.insert(party, secret);
    }
    universe.set_threshold((n * k) / 2);

    (universe, secrets)
}

fn build_universe_for_pa(n: usize, k: usize) -> (Universe, BTreeMap<PartyId, PartySecret>) {
    let mut rng = thread_rng();
    let mut universe = Universe::new();
    let mut secrets = BTreeMap::new();

    for party in 1..=n {
        let secret = Scalar::random(&mut rng);
        let pubkeys = pa::publish_pubkeys(&secret, k);
        universe.add_party(party, k, Rc::new(pubkeys));
        secrets.insert(party, secret);
    }
    universe.set_threshold((n * k) / 2);

    (universe, secrets)
}

fn smoke_mts_ugen() {
    let n = 8usize;
    let k = 1usize;
    let (universe, _) = build_universe_for_mts(n, k);
    let mut setup_state = None;
    let mut setup_msgs = Vec::with_capacity(n);

    for _ in 0..n {
        let (state, msg) = mts::publish_universe_setup_msg(&universe);
        setup_state = Some(state);
        setup_msgs.push(msg);
    }

    let (pp, _) = mts::compute_universe_pp(&universe, &setup_state.unwrap(), &setup_msgs);
    assert_eq!(
        pp.evals.len(),
        universe.get_total_weight() - universe.get_threshold()
    );
    assert_eq!(
        pp.blinded_evals.len(),
        universe.get_total_weight() - universe.get_threshold()
    );
}

fn smoke_pa_mts_ugen() {
    let n = 8usize;
    let k = 1usize;
    let (universe, _) = build_universe_for_pa(n, k);
    let mut setup_state = None;
    let mut setup_msgs = Vec::with_capacity(n);

    for _ in 0..n {
        let (state, msg) = pa::publish_universe_setup_msg(&universe);
        setup_state = Some(state);
        setup_msgs.push(msg);
    }

    let (pp, _) = pa::compute_universe_pp(&universe, &setup_state.unwrap(), &setup_msgs);
    assert_eq!(
        pp.evals_0.len(),
        universe.get_total_weight() - universe.get_threshold()
    );
    assert_eq!(
        pp.evals_1.len(),
        universe.get_total_weight() - universe.get_threshold()
    );
}

fn smoke_pa_mts_end_to_end() {
    let n = 4usize;
    let k = 1usize;
    let (universe, secrets) = build_universe_for_pa(n, k);
    let msg = b"PA-MTS smoke full construction";
    let mut setup_state = None;
    let mut setup_msgs = Vec::with_capacity(n);
    for _ in 0..n {
        let (state, setup_msg) = pa::publish_universe_setup_msg(&universe);
        setup_state = Some(state);
        setup_msgs.push(setup_msg);
    }
    let (pp, vk) = pa::compute_universe_pp(&universe, &setup_state.unwrap(), &setup_msgs);
    let partials: Vec<_> = secrets
        .iter()
        .map(|(party, secret)| pa::sign(*party, secret, k, msg))
        .collect();
    let agg = pa::aggregator_kgen();
    let issued = pa::aggregate(&universe, &pp, &agg, &partials, msg).unwrap();
    assert!(pa::verify(msg, &vk, &agg.pk1, &issued.signature));
    let (quorum, u) = pa::trace(&universe, &issued.credential, &issued.trace_key).unwrap();
    assert!(pa::trace_verify(
        &universe,
        &pp,
        &agg.pk1,
        msg,
        &issued.signature,
        &issued.credential,
        &quorum,
        &u,
    ));
}

fn bench_smoke(c: &mut Criterion) {
    c.bench_function("smoke_multiverse_sig", |b| {
        b.iter(smoke_multiverse);
    });
    c.bench_function("smoke_pa_multiverse_sig", |b| {
        b.iter(smoke_pa_multiverse);
    });
    c.bench_function("smoke_mts_ugen", |b| {
        b.iter(smoke_mts_ugen);
    });
    c.bench_function("smoke_pa_mts_ugen", |b| {
        b.iter(smoke_pa_mts_ugen);
    });
    c.bench_function("smoke_pa_mts_end_to_end", |b| {
        b.iter(smoke_pa_mts_end_to_end);
    });

    black_box(());
}

mod perf;

criterion_group!(
    name = smoke;
    config = Criterion::default()
        .with_profiler(perf::FlamegraphProfiler::new(200))
        .sample_size(10);
    targets = bench_smoke,
);

criterion_main!(smoke);
