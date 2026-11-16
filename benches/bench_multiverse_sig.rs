use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pa_mts::{
    common::sig_utils,
    kzg::KZGParams,
    multiverse_sig::{
        MultiversePartialSig, MultiverseParty, MultiversePublicParams, MultiverseSig,
    },
};
use rand::thread_rng;

fn compute_crs() -> KZGParams {
    let mut rng = thread_rng();
    // This benchmark only reads the two base generators from the KZG container.
    sig_utils::test_setup::<1>(&mut rng)
}

struct MultiverseFixture {
    dealer: MultiverseParty,
    output: MultiversePublicParams,
    partials: Vec<MultiversePartialSig>,
    aggregate: MultiverseSig,
    first_party: pa_mts::PartyId,
    msg: &'static [u8],
}

fn build_fixture(n: usize, k: usize) -> MultiverseFixture {
    assert!(n > 0 && k > 0);
    let total_weight = n * k;
    let threshold_weight = total_weight / 2;
    assert!(threshold_weight > 0);

    let crs = compute_crs();
    let addr_book = sig_utils::create_addr_book(n, k);
    let dealer = MultiverseParty::new(crs, threshold_weight, total_weight, &addr_book);
    let output = dealer.setup();
    let msg = b"Hello Multiverse" as &'static [u8];

    let partials: Vec<MultiversePartialSig> = addr_book
        .keys()
        .copied()
        .map(|id| dealer.sign(id, msg, &output))
        .collect();
    let aggregate = dealer.aggregate(&output, &partials).unwrap();
    assert!(dealer.verify(msg, &output, &aggregate));

    MultiverseFixture {
        dealer,
        output,
        partials,
        aggregate,
        first_party: *addr_book.keys().next().unwrap(),
        msg,
    }
}

fn bench_multiverse_sig(c: &mut Criterion) {
    for (n, k) in benchmark_params::signature_accountability_params() {
        let fixture = build_fixture(n, k);

        c.bench_function(
            format!("multiverse_sign [N={}, K={}]", n, k).as_str(),
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
            format!("multiverse_aggregate [N={}, K={}]", n, k).as_str(),
            |b| {
                b.iter(|| {
                    fixture
                        .dealer
                        .aggregate(black_box(&fixture.output), black_box(&fixture.partials))
                });
            },
        );

        c.bench_function(
            format!("multiverse_verify [N={}, K={}]", n, k).as_str(),
            |b| {
                b.iter(|| {
                    fixture.dealer.verify(
                        black_box(fixture.msg),
                        black_box(&fixture.output),
                        black_box(&fixture.aggregate),
                    )
                });
            },
        );
    }
}

mod benchmark_params;
mod perf;

criterion_group!(
    name = multiverse_sig;
    config = Criterion::default()
        .with_profiler(perf::FlamegraphProfiler::new(200))
        .sample_size(10);
    targets = bench_multiverse_sig,
);

criterion_main!(multiverse_sig);
