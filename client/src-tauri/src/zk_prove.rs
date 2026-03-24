//! Client-side Groth16 proof generation for ZK settlement.
//!
//! Loads a compiled circom circuit (R1CS + WASM witness generator) and
//! a trusted setup zkey, then generates a proof from the client's private
//! receipt data. The proof + public signals are submitted to ZKSettlement.sol.

use std::path::Path;

use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_groth16::Groth16;
use ark_std::rand::thread_rng;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};

/// Paths to the compiled circuit artifacts.
pub struct CircuitArtifacts {
    pub wasm_path: String,
    pub r1cs_path: String,
    pub zkey_path: String,
}

/// Private inputs for the bandwidth receipt proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptWitness {
    pub session_id: String,
    pub cumulative_bytes: String,
    pub timestamp: String,
    pub price_per_byte: String,
    pub deposit: String,
    pub receipt_typehash: String,

    pub client_address: String,
    pub entry_address: String,
    pub relay_address: String,
    pub exit_address: String,

    // ECDSA pubkeys as 4x64-bit limbs [[x0,x1,x2,x3],[y0,y1,y2,y3]]
    pub client_pubkey: Vec<Vec<String>>,
    pub client_r: Vec<String>,
    pub client_s: Vec<String>,

    pub node_pubkey: Vec<Vec<String>>,
    pub node_r: Vec<String>,
    pub node_s: Vec<String>,

    // Merkle proof for node registry
    pub node_merkle_proof: Vec<String>,
    pub node_merkle_index: String,
}

/// Public inputs for the proof (must match circuit's public signal order).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicInputs {
    pub domain_separator: String,
    pub total_payment: String,
    pub entry_commitment: String,
    pub relay_commitment: String,
    pub exit_commitment: String,
    pub refund_commitment: String,
    pub registry_root: String,
}

/// A generated Groth16 proof ready for on-chain submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProof {
    /// Proof point A [x, y] (G1)
    pub pi_a: [String; 2],
    /// Proof point B [[x0, x1], [y0, y1]] (G2)
    pub pi_b: [[String; 2]; 2],
    /// Proof point C [x, y] (G1)
    pub pi_c: [String; 2],
    /// Public signals (7 values matching circuit public inputs)
    pub public_signals: Vec<String>,
}

/// Generate a Groth16 proof for the bandwidth receipt circuit.
pub fn generate_proof(
    artifacts: &CircuitArtifacts,
    witness: &ReceiptWitness,
    public: &PublicInputs,
) -> Result<ZkProof, String> {
    // 1. Load circuit configuration.
    let cfg = CircomConfig::<Fr>::new(&artifacts.wasm_path, &artifacts.r1cs_path)
        .map_err(|e| format!("failed to load circuit config: {e}"))?;

    // 2. Build witness with all inputs.
    let mut builder = CircomBuilder::new(cfg);
    populate_inputs(&mut builder, witness, public)?;

    // 3. Build the circuit with witness.
    let circom = builder
        .build()
        .map_err(|e| format!("failed to build circuit witness: {e}"))?;

    let inputs = circom
        .get_public_inputs()
        .ok_or_else(|| "failed to get public inputs from witness".to_string())?;

    // 4. Load the proving key from zkey file.
    let zkey_file = std::fs::File::open(&artifacts.zkey_path)
        .map_err(|e| format!("failed to open zkey: {e}"))?;
    let mut zkey_reader = std::io::BufReader::new(zkey_file);
    let (pk, _matrices) =
        ark_circom::read_zkey(&mut zkey_reader).map_err(|e| format!("failed to read zkey: {e}"))?;

    // 5. Generate the proof.
    let mut rng = thread_rng();
    let proof =
        Groth16::<Bn254, CircomReduction>::create_random_proof_with_reduction(circom, &pk, &mut rng)
            .map_err(|e| format!("proof generation failed: {e}"))?;

    // 6. Format proof for Solidity.
    Ok(format_proof_for_solidity(&proof, &inputs))
}

/// Check if circuit artifacts exist at the expected paths.
pub fn artifacts_exist(artifacts: &CircuitArtifacts) -> bool {
    Path::new(&artifacts.wasm_path).exists()
        && Path::new(&artifacts.r1cs_path).exists()
        && Path::new(&artifacts.zkey_path).exists()
}

// ── input population ──────────────────────────────────────────────────

fn populate_inputs(
    builder: &mut CircomBuilder<Fr>,
    witness: &ReceiptWitness,
    public: &PublicInputs,
) -> Result<(), String> {
    // Public inputs
    push_input(builder, "domainSeparator", &public.domain_separator)?;
    push_input(builder, "totalPaymentPub", &public.total_payment)?;
    push_input(builder, "entryCommitmentPub", &public.entry_commitment)?;
    push_input(builder, "relayCommitmentPub", &public.relay_commitment)?;
    push_input(builder, "exitCommitmentPub", &public.exit_commitment)?;
    push_input(builder, "refundCommitmentPub", &public.refund_commitment)?;
    push_input(builder, "registryRoot", &public.registry_root)?;

    // Private inputs — receipt data
    push_input(builder, "sessionId", &witness.session_id)?;
    push_input(builder, "cumulativeBytes", &witness.cumulative_bytes)?;
    push_input(builder, "timestamp", &witness.timestamp)?;
    push_input(builder, "pricePerByte", &witness.price_per_byte)?;
    push_input(builder, "deposit", &witness.deposit)?;
    push_input(builder, "receiptTypehash", &witness.receipt_typehash)?;

    // Private inputs — addresses
    push_input(builder, "clientAddress", &witness.client_address)?;
    push_input(builder, "entryAddress", &witness.entry_address)?;
    push_input(builder, "relayAddress", &witness.relay_address)?;
    push_input(builder, "exitAddress", &witness.exit_address)?;

    // Private inputs — ECDSA signatures (4x64-bit limbs)
    push_limb_array(builder, "clientPubkey", &witness.client_pubkey)?;
    push_limbs(builder, "clientR", &witness.client_r)?;
    push_limbs(builder, "clientS", &witness.client_s)?;
    push_limb_array(builder, "nodePubkey", &witness.node_pubkey)?;
    push_limbs(builder, "nodeR", &witness.node_r)?;
    push_limbs(builder, "nodeS", &witness.node_s)?;

    // Private inputs — Merkle proof
    push_limbs(builder, "nodeMerkleProof", &witness.node_merkle_proof)?;
    push_input(builder, "nodeMerkleIndex", &witness.node_merkle_index)?;

    Ok(())
}

fn push_input(builder: &mut CircomBuilder<Fr>, name: &str, value: &str) -> Result<(), String> {
    let bigint: BigInt = value
        .parse()
        .map_err(|e| format!("invalid input '{name}': {e}"))?;
    builder.push_input(name, bigint);
    Ok(())
}

fn push_limbs(builder: &mut CircomBuilder<Fr>, name: &str, vals: &[String]) -> Result<(), String> {
    for (i, val) in vals.iter().enumerate() {
        push_input(builder, &format!("{name}[{i}]"), val)?;
    }
    Ok(())
}

fn push_limb_array(
    builder: &mut CircomBuilder<Fr>,
    name: &str,
    vals: &[Vec<String>],
) -> Result<(), String> {
    for (dim, limbs) in vals.iter().enumerate() {
        for (i, val) in limbs.iter().enumerate() {
            push_input(builder, &format!("{name}[{dim}][{i}]"), val)?;
        }
    }
    Ok(())
}

// ── proof formatting ──────────────────────────────────────────────────

fn format_proof_for_solidity(
    proof: &ark_groth16::Proof<Bn254>,
    public_inputs: &[Fr],
) -> ZkProof {
    use ark_serialize::CanonicalSerialize;

    let a = g1_to_strings(&proof.a);
    let b = g2_to_strings(&proof.b);
    let c = g1_to_strings(&proof.c);

    let signals: Vec<String> = public_inputs
        .iter()
        .map(|f| {
            let mut bytes = Vec::new();
            f.serialize_uncompressed(&mut bytes).unwrap();
            BigInt::from_bytes_le(num_bigint::Sign::Plus, &bytes).to_string()
        })
        .collect();

    ZkProof {
        pi_a: a,
        pi_b: b,
        pi_c: c,
        public_signals: signals,
    }
}

fn g1_to_strings(point: &ark_bn254::G1Affine) -> [String; 2] {
    use ark_serialize::CanonicalSerialize;
    let mut x_bytes = Vec::new();
    let mut y_bytes = Vec::new();
    point.x.serialize_uncompressed(&mut x_bytes).unwrap();
    point.y.serialize_uncompressed(&mut y_bytes).unwrap();
    [
        BigInt::from_bytes_le(num_bigint::Sign::Plus, &x_bytes).to_string(),
        BigInt::from_bytes_le(num_bigint::Sign::Plus, &y_bytes).to_string(),
    ]
}

fn g2_to_strings(point: &ark_bn254::G2Affine) -> [[String; 2]; 2] {
    use ark_serialize::CanonicalSerialize;
    let mut x0 = Vec::new();
    let mut x1 = Vec::new();
    let mut y0 = Vec::new();
    let mut y1 = Vec::new();
    point.x.c0.serialize_uncompressed(&mut x0).unwrap();
    point.x.c1.serialize_uncompressed(&mut x1).unwrap();
    point.y.c0.serialize_uncompressed(&mut y0).unwrap();
    point.y.c1.serialize_uncompressed(&mut y1).unwrap();
    [
        [
            BigInt::from_bytes_le(num_bigint::Sign::Plus, &x0).to_string(),
            BigInt::from_bytes_le(num_bigint::Sign::Plus, &x1).to_string(),
        ],
        [
            BigInt::from_bytes_le(num_bigint::Sign::Plus, &y0).to_string(),
            BigInt::from_bytes_le(num_bigint::Sign::Plus, &y1).to_string(),
        ],
    ]
}
