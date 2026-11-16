/// Single source of truth for the evaluation parameter grids.
///
/// Each tuple is `(N, K)`, where `N` is the number of parties and `K`
/// is the uniform weight assigned to each party. Thus `W = N * K`, the
/// maximum party weight is `B = K`, and `T = floor(W / 2)`.

fn validate_params(name: &str, params: &[(usize, usize)]) {
    assert!(!params.is_empty(), "{name} benchmark parameter grid must not be empty");

    for (index, &(n, k)) in params.iter().enumerate() {
        assert!(n > 0, "{name} benchmark requires N > 0");
        assert!(k > 0, "{name} benchmark requires K > 0");
        assert!(
            !params[..index].contains(&(n, k)),
            "duplicate {name} benchmark setting: (N={n}, K={k})"
        );
    }
}

/// Parameters for the Signature and Accountability Performance evaluation.
///
/// These settings benchmark Sign, Aggr, Verify, Trace, and TraceVerify.
/// The timed aggregation paths use the first N/2 parties as an
/// exact-threshold quorum under uniform weights.
pub fn signature_accountability_params() -> Vec<(usize, usize)> {
    let params = vec![
        (100, 1),
        (300, 1),
        (500, 1),
        (100, 3),
        (300, 3),
        (500, 3),
        (100, 5),
        (300, 5),
        (500, 5),
    ];

    validate_params("signature and accountability", &params);
    for &(n, _) in &params {
        assert!(
            n % 2 == 0,
            "signature and accountability benchmark requires even N so the exact-threshold quorum consists of whole parties"
        );
    }
    params
}

/// Parameters for the Universe Setup Performance evaluation.
///
/// These settings benchmark UGenOn and UGenOff, with all N parties
/// contributing universe setup messages.
pub fn universe_setup_params() -> Vec<(usize, usize)> {
    let params = vec![
        (10, 1),
        (30, 1),
        (50, 1),
        (10, 3),
        (30, 3),
        (50, 3),
        (10, 5),
        (30, 5),
        (50, 5),
    ];

    validate_params("universe setup", &params);
    params
}

/// Parameters for the Communication and Storage Costs evaluation.
///
/// The concrete size report uses the same `(N, K)` settings as the signature
/// and accountability evaluation, keeping the reported configurations aligned.
pub fn communication_storage_params() -> Vec<(usize, usize)> {
    signature_accountability_params()
}
