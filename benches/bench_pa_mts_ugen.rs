use group::Group;
use bls12_381::{G1Projective, G2Projective, Scalar};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ff::Field;
use pa_mts::{pa_mts as pa, universe::Universe, PartySecret};
use rand::thread_rng;
use std::rc::Rc;

struct PAUGenFixture {
    universe: Universe,
    setup_state: pa::PAUniverseCreationState,
    setup_msgs: Vec<pa::PAUniverseCreationMessage>,
}

fn build_honest_setup_messages(
    state: &pa::PAUniverseCreationState,
    count: usize,
) -> Vec<pa::PAUniverseCreationMessage> {
    let mut rng = thread_rng();
    (0..count)
        .map(|_| {
            let k = Scalar::random(&mut rng);
            pa::PAUniverseCreationMessage {
                blinded_evals: state.evals_0.iter().map(|point| *point * k).collect(),
                beta: G2Projective::generator() * k,
                gamma: G1Projective::generator() * k,
            }
        })
        .collect()
}

fn build_fixture(n: usize, k: usize) -> PAUGenFixture {
    assert!(n > 0 && k > 0);
    let total_weight = n * k;
    let threshold = total_weight / 2;
    assert!(threshold > 0);

    let mut rng = thread_rng();
    let mut universe = Universe::new();
    for party in 1..=n {
        let secret = PartySecret::random(&mut rng);
        let pubkeys = pa::publish_pubkeys(&secret, k);
        universe.add_party(party, k, Rc::new(pubkeys));
    }
    universe.set_threshold(threshold);

    let (setup_state, _) = pa::publish_universe_setup_msg(&universe);
    let setup_msgs = build_honest_setup_messages(&setup_state, n);

    PAUGenFixture {
        universe,
        setup_state,
        setup_msgs,
    }
}

fn bench_pa_mts_ugen(c: &mut Criterion) {
    for (n, k) in benchmark_params::universe_setup_params() {
        let fixture = build_fixture(n, k);

        c.bench_function(format!("pa_mts_ugen_on [N={}, K={}]", n, k).as_str(), |b| {
            b.iter(|| pa::publish_universe_setup_msg(black_box(&fixture.universe)));
        });

        c.bench_function(
            format!("pa_mts_ugen_off [N={}, K={}]", n, k).as_str(),
            |b| {
                b.iter(|| {
                    pa::compute_universe_pp(
                        black_box(&fixture.universe),
                        black_box(&fixture.setup_state),
                        black_box(&fixture.setup_msgs),
                    )
                });
            },
        );
    }
}

mod perf;
mod benchmark_params;

criterion_group!(
    name = pa_mts_ugen;
    config = Criterion::default()
        .with_profiler(perf::FlamegraphProfiler::new(200))
        .sample_size(10);
    targets = bench_pa_mts_ugen,
);

criterion_main!(pa_mts_ugen);
