//! Static test vectors of the ring proof. Users of the scheme depend on its
//! encoding and on its values, so `process_vectors` must keep passing.
//!
//! The KZG setup is built from the trapdoor `srs_tau` with the standard BLS12-381
//! generators, and the prover runs over a domain without blinding. No RNG is
//! involved, so every proof is reproducible.

use ark_bls12_381::{Bls12_381, G1Projective, G2Projective};
use ark_ec::PrimeGroup;
use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, EdwardsAffine, Fq, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{test_rng, UniformRand};
use serde_json::{json, Value};
use w3f_ring_proof::pcs::kzg::urs::URS;
use w3f_ring_proof::pcs::kzg::KZG;
use w3f_ring_proof::piop::params::ZK_ROWS;
use w3f_ring_proof::ring_prover::RingProver;
use w3f_ring_proof::ring_verifier::RingVerifier;
use w3f_ring_proof::{index, ArkTranscript, Domain, PiopParams, RingProof};

const VECTORS_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/data/vectors.json");
const TRANSCRIPT_LABEL: &str = "w3f-ring-proof-vectors";

type Kzg = KZG<Bls12_381>;

struct Inputs {
    transcript_label: String,
    domain_size: usize,
    srs_tau: Fq,
    h: EdwardsAffine,
    seed: EdwardsAffine,
    padding: EdwardsAffine,
    ring: Vec<EdwardsAffine>,
    prover_index: usize,
    blinding: Fr,
}

impl Inputs {
    fn transcript(&self) -> ArkTranscript {
        ArkTranscript::new(self.transcript_label.clone().leak().as_bytes())
    }

    fn piop_params(&self) -> PiopParams<EdwardsAffine> {
        let domain = Domain::with_zk_rows(self.domain_size, ZK_ROWS).without_blinding();
        PiopParams::setup(domain, self.h, self.seed, self.padding)
    }

    fn to_json(&self) -> Value {
        json!({
            "transcript_label": self.transcript_label,
            "domain_size": self.domain_size,
            "srs_tau": encode(&self.srs_tau),
            "h": encode(&self.h),
            "seed": encode(&self.seed),
            "padding": encode(&self.padding),
            "ring": self.ring.iter().map(encode).collect::<Vec<_>>(),
            "prover_index": self.prover_index,
            "blinding": encode(&self.blinding),
        })
    }

    fn from_json(json: &Value) -> Self {
        Self {
            transcript_label: json["transcript_label"].as_str().unwrap().to_string(),
            domain_size: json["domain_size"].as_u64().unwrap() as usize,
            srs_tau: decode(&json["srs_tau"]),
            h: decode(&json["h"]),
            seed: decode(&json["seed"]),
            padding: decode(&json["padding"]),
            ring: json["ring"]
                .as_array()
                .unwrap()
                .iter()
                .map(decode)
                .collect(),
            prover_index: json["prover_index"].as_u64().unwrap() as usize,
            blinding: decode(&json["blinding"]),
        }
    }
}

fn encode(value: &impl CanonicalSerialize) -> Value {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes).unwrap();
    Value::String(hex::encode(bytes))
}

fn decode<T: CanonicalDeserialize>(json: &Value) -> T {
    let bytes = hex::decode(json.as_str().unwrap()).unwrap();
    let mut reader = &bytes[..];
    let value = T::deserialize_compressed(&mut reader).unwrap();
    assert!(reader.is_empty(), "trailing bytes");
    value
}

fn prove(inputs: &Inputs) -> Value {
    let max_degree = 3 * inputs.domain_size;
    let pcs_params = URS::<Bls12_381>::from_trapdoor(
        inputs.srs_tau,
        max_degree + 1,
        2,
        G1Projective::generator(),
        G2Projective::generator(),
    );
    let piop_params = inputs.piop_params();
    let (prover_key, verifier_key) = index::<_, Kzg, _>(&pcs_params, &piop_params, &inputs.ring);
    let k = inputs.prover_index;
    let result = piop_params.blind_pk(inputs.ring[k], inputs.blinding);
    let prover = RingProver::init(prover_key, piop_params, k, inputs.transcript());
    let proof = prover.prove(inputs.blinding);
    json!({
        "verifier_key": encode(&verifier_key),
        "result": encode(&result),
        "proof": encode(&proof),
    })
}

#[test]
fn process_vectors() {
    let vectors: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(VECTORS_FILE).unwrap()).unwrap();
    assert!(!vectors.is_empty());
    for vector in &vectors {
        let comment = vector["comment"].as_str().unwrap();
        let inputs = Inputs::from_json(&vector["inputs"]);
        let expected = &vector["outputs"];

        let outputs = prove(&inputs);
        for field in ["verifier_key", "result", "proof"] {
            assert_eq!(outputs[field], expected[field], "{comment}: {field}");
        }

        let verifier = RingVerifier::<_, _, BandersnatchConfig>::init(
            decode(&expected["verifier_key"]),
            inputs.piop_params(),
            inputs.transcript(),
        );
        let result: EdwardsAffine = decode(&expected["result"]);
        let proof: RingProof<Fq, Kzg> = decode(&expected["proof"]);
        assert!(verifier.verify(proof.clone(), result), "{comment}");
        assert!(
            verifier.verify_batch_kzg(vec![proof], vec![result]),
            "{comment}"
        );
    }
}

// Regenerate with `cargo test --release -p w3f-ring-proof --test vectors -- --ignored`.
// The inputs come from a seeded RNG only here; the file then freezes them.
#[test]
#[ignore]
fn generate_vectors() {
    let rng = &mut test_rng();
    let full_ring = |domain_size| {
        let domain = Domain::<Fq>::with_zk_rows(domain_size, ZK_ROWS);
        let point = EdwardsAffine::default();
        PiopParams::setup(domain, point, point, point).keyset_part_size
    };
    let cases = [
        (
            "Full ring, prover at the first position",
            512,
            full_ring(512),
            0,
        ),
        (
            "Full ring, prover at the last position",
            512,
            full_ring(512),
            full_ring(512) - 1,
        ),
        ("Ring with padding", 512, 100, 42),
        ("Ring with one key", 512, 1, 0),
        ("Larger domain", 1024, 300, 299),
    ];
    let vectors: Vec<Value> = cases
        .into_iter()
        .map(|(comment, domain_size, ring_size, prover_index)| {
            let inputs = Inputs {
                transcript_label: TRANSCRIPT_LABEL.to_string(),
                domain_size,
                srs_tau: Fq::rand(rng),
                h: EdwardsAffine::rand(rng),
                seed: EdwardsAffine::rand(rng),
                padding: EdwardsAffine::rand(rng),
                ring: (0..ring_size).map(|_| EdwardsAffine::rand(rng)).collect(),
                prover_index,
                blinding: Fr::rand(rng),
            };
            json!({
                "comment": comment,
                "inputs": inputs.to_json(),
                "outputs": prove(&inputs),
            })
        })
        .collect();
    let file = std::path::Path::new(VECTORS_FILE);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    let text = serde_json::to_string_pretty(&vectors).unwrap() + "\n";
    std::fs::write(file, text).unwrap();
}
