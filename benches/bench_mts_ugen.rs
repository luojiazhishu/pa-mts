use group::Group;
use bls12_381::{G2Projective, Scalar};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ff::Field;
use pa_mts::{mts, universe::Universe, PartySecret};
use rand::thread_rng;
use std::rc::Rc;

struct MTSUGenFixture {
    universe: Universe,
    setup_state: mts::MTSUniverseCreationState,
    setup_msgs: Vec<mts::MTSUniverseCreationMessage>,
}

fn build_honest_setup_messages(
    state: &mts::MTSUniverseCreationState,
    count: usize,
) -> Vec<mts::MTSUniverseCreationMessage> {
    let mut rng = thread_rng();
    (0..count)
        .map(|_| {
            let k = Scalar::random(&mut rng);
            mts::MTSUniverseCreationMessage {
                blinded_evals: state.evals.iter().map(|point| *point * k).collect(),
                blind_commitment: G2Projective::generator() * k,
            }
        })
        .collect()
}

fn build_fixture(n: usize, k: usize) -> MTSUGenFixture {
    assert!(n > 0 && k > 0);
    let total_weight = n * k;
    let threshold = total_weight / 2;
    assert!(threshold > 0);

    let mut rng = thread_rng();
    let mut universe = Universe::new();
    for party in 1..=n {
        let secret = PartySecret::random(&mut rng);
        let pubkeys = mts::publish_pubkeys(&secret, k);
        universe.add_party(party, k, Rc::new(pubkeys));
    }
    universe.set_threshold(threshold);

    let (setup_state, _) = mts::publish_universe_setup_msg(&universe);
    let setup_msgs = build_honest_setup_messages(&setup_state, n);

    MTSUGenFixture {
        universe,
        setup_state,
        setup_msgs,
    }
}

fn bench_mts_ugen(c: &mut Criterion) {
    for (n, k) in benchmark_params::universe_setup_params() {
        let fixture = build_fixture(n, k);

        c.bench_function(format!("mts_ugen_on [N={}, K={}]", n, k).as_str(), |b| {
            b.iter(|| mts::publish_universe_setup_msg(black_box(&fixture.universe)));
        });

        c.bench_function(format!("mts_ugen_off [N={}, K={}]", n, k).as_str(), |b| {
            b.iter(|| {
                mts::compute_universe_pp(
                    black_box(&fixture.universe),
                    black_box(&fixture.setup_state),
                    black_box(&fixture.setup_msgs),
                )
            });
        });
    }
}

mod perf;
mod benchmark_params;

criterion_group!(
    name = mts_ugen;
    config = Criterion::default()
        .with_profiler(perf::FlamegraphProfiler::new(200))
        .sample_size(10);
    targets = bench_mts_ugen,
);

criterion_main!(mts_ugen);
