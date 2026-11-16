use pa_mts::pa_issue;

fn main() {
    println!("# Serialized communication and storage costs in bytes");
    println!("# G1=48, G2=96, scalar=32, AES-256-GCM authentication tag=16 (fixed nonce: one encryption per tracing key)");
    println!("# Universe setup message sizes exclude NIZK proofs, matching the evaluation scope");
    println!(
        "N,K,W,T,partial_sig,mts_signature,pa_signature,pa_credential,pa_published_pair,mts_vk,pa_vk,aggregator_pk,mts_pp,pa_pp,mts_ugen_message,pa_ugen_message,trace_key,trace_proof,disclosed_quorum,trace_output"
    );

    for (n, k) in benchmark_params::communication_storage_params() {
        let total_weight = n * k;
        let threshold = total_weight / 2;
        let public_points = total_weight - threshold;
        let partial_signature = 96 * k;
        let mts_signature = 96 + 48 + 48;
        // (hat_sigma', hat_sigma'_0, hat_sigma'_1) plus d in G2 and tau in G2.
        let pa_signature = mts_signature + 96 + 96;
        let pa_credential = pa_issue::credential_size_for_party_count(n);
        let pa_published_pair = pa_signature + pa_credential;
        let mts_vk = 48 + 96;
        let pa_vk = mts_vk;
        // Only pk[1] of the aggregator key is used by Verify and TraceVerify.
        let aggregator_pk = pa_issue::G1_COMPRESSED_BYTES;
        let mts_pp = 2 * public_points * 48;
        let pa_pp = mts_pp + 48;
        let mts_ugen_message = public_points * 48 + 96;
        let pa_ugen_message = mts_ugen_message + 48;
        let trace_key = pa_issue::TRACE_KEY_BYTES;
        let trace_proof = pa_issue::SCALAR_BYTES; // pi = u
        let disclosed_quorum = pa_issue::quorum_encoding_bytes(n);
        let trace_output = trace_proof + disclosed_quorum;

        println!(
            "{n},{k},{total_weight},{threshold},{partial_signature},{mts_signature},{pa_signature},{pa_credential},{pa_published_pair},{mts_vk},{pa_vk},{aggregator_pk},{mts_pp},{pa_pp},{mts_ugen_message},{pa_ugen_message},{trace_key},{trace_proof},{disclosed_quorum},{trace_output}"
        );
    }
}

mod benchmark_params;
