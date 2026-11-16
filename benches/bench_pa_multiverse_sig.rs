use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pa_mts::{
    common::sig_utils,
    pa_issue,
    kzg::KZGParams,
    pa_multiverse_sig::{
        PAMultiverseAggregation, PAMultiversePartialSig, PAMultiverseParty,
        PAMultiversePublicParams,
    },
    PartyId,
};
use bls12_381::{G1Projective, Scalar};
use rand::thread_rng;

fn compute_crs() -> KZGParams {
    let mut rng = thread_rng();
    // Keep untimed fixture construction identical to the MTS benchmark.
    sig_utils::test_setup::<1>(&mut rng)
}

struct PAMultiverseFixture {
    dealer: PAMultiverseParty,
    output: PAMultiversePublicParams,
    partials: Vec<PAMultiversePartialSig>,
    aggregation: PAMultiverseAggregation,
    traced_quorum: Vec<PartyId>,
    trace_proof: Scalar,
    aggregator_pk: G1Projective,
    first_party: PartyId,
    msg: &'static [u8],
}

fn build_fixture(n: usize, k: usize) -> PAMultiverseFixture {
    assert!(n > 0 && k > 0);
    let total_weight = n * k;
    let threshold_weight = total_weight / 2;
    assert!(threshold_weight > 0);

    let crs = compute_crs();
    let addr_book = sig_utils::create_addr_book(n, k);
    let dealer = PAMultiverseParty::new(crs, threshold_weight, total_weight, &addr_book);
    let output = dealer.setup();
    let msg = b"Hello Multiverse" as &'static [u8];

    let partials: Vec<PAMultiversePartialSig> = addr_book
        .keys()
        .copied()
        .map(|id| dealer.sign(id, msg, &output))
        .collect();
    let aggregation = dealer.aggregate(&output, &partials, msg).unwrap();
    let aggregator_pk = dealer.aggregator_public_key();
    assert!(dealer.verify(msg, &output, &aggregator_pk, &aggregation.signature));
    let (traced_quorum, trace_proof) = dealer
        .trace(&aggregation.credential, &aggregation.trace_key)
        .unwrap();
    assert!(dealer.trace_verify(
        &output,
        &aggregator_pk,
        msg,
        &aggregation.signature,
        &aggregation.credential,
        &traced_quorum,
        &trace_proof,
    ));

    PAMultiverseFixture {
        dealer,
        output,
        partials,
        aggregation,
        traced_quorum,
        trace_proof,
        aggregator_pk,
        first_party: *addr_book.keys().next().unwrap(),
        msg,
    }
}

fn bench_pa_multiverse_sig(c: &mut Criterion) {
    for (n, k) in benchmark_params::signature_accountability_params() {
        let fixture = build_fixture(n, k);

        c.bench_function(
            format!("pa_multiverse_sign [N={}, K={}]", n, k).as_str(),
            |b| {
                b.iter(|| {
                    fixture.dealer.sign(
                        black_box(fixture.first_party),
                        black_box(fixture.msg),
                        black_box(&fixture.output),
                    )
                });
            },
        );

        c.bench_function(
            format!("pa_multiverse_aggregate [N={}, K={}]", n, k).as_str(),
            |b| {
                b.iter(|| {
                    fixture.dealer.aggregate(
                        black_box(&fixture.output),
                        black_box(&fixture.partials),
                        black_box(fixture.msg),
                    )
                });
            },
        );

        // The PA-MTS-specific steps of Aggr (H(m), randomization with u, credential, d, tau),
        // measured in isolation; their cost does not depend on W.
        let universe_parties: Vec<PartyId> = (1..=n).collect();
        let sig = fixture.aggregation.signature;
        c.bench_function(
            format!("pa_multiverse_aggregate_extra [N={}, K={}]", n, k).as_str(),
            |b| {
                b.iter(|| {
                    let h_m = pa_mts::utils_hash_to_g2(black_box(fixture.msg));
                    pa_issue::randomize_and_issue(
                        black_box(&sig.sigma_prime),
                        black_box(&sig.sigma_0),
                        black_box(&sig.sigma_1),
                        &h_m,
                        &fixture.dealer.generator_g1(),
                        &fixture.output.gamma,
                        black_box(&universe_parties),
                        black_box(&fixture.traced_quorum),
                        fixture.dealer.aggregator_key(),
                    )
                });
            },
        );

        c.bench_function(
            format!("pa_multiverse_verify [N={}, K={}]", n, k).as_str(),
            |b| {
                b.iter(|| {
                    fixture.dealer.verify(
                        black_box(fixture.msg),
                        black_box(&fixture.output),
                        black_box(&fixture.aggregator_pk),
                        black_box(&fixture.aggregation.signature),
                    )
                });
            },
        );

        c.bench_function(
            format!("pa_multiverse_trace [N={}, K={}]", n, k).as_str(),
            |b| {
                b.iter(|| {
                    fixture.dealer.trace(
                        black_box(&fixture.aggregation.credential),
                        black_box(&fixture.aggregation.trace_key),
                    )
                });
            },
        );

        c.bench_function(
            format!("pa_multiverse_trace_verify [N={}, K={}]", n, k).as_str(),
            |b| {
                b.iter(|| {
                    fixture.dealer.trace_verify(
                        black_box(&fixture.output),
                        black_box(&fixture.aggregator_pk),
                        black_box(fixture.msg),
                        black_box(&fixture.aggregation.signature),
                        black_box(&fixture.aggregation.credential),
                        black_box(&fixture.traced_quorum),
                        black_box(&fixture.trace_proof),
                    )
                });
            },
        );
    }
}

mod benchmark_params;
mod perf;

criterion_group!(
    name = pa_multiverse_sig;
    config = Criterion::default()
        .with_profiler(perf::FlamegraphProfiler::new(200))
        .sample_size(10);
    targets = bench_pa_multiverse_sig,
);

criterion_main!(pa_multiverse_sig);
