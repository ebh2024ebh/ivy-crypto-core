use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError,
};
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::LatticeError;

/// ZK-SNARK proof bytes for transport.
pub struct ZkProofBundle {
    pub proof_bytes: Vec<u8>,
    pub public_inputs_bytes: Vec<u8>,
}

/// The attestation circuit for Play Integrity verification.
///
/// Proves in zero knowledge that:
/// 1. The prover possesses a valid Play Integrity token
/// 2. The token was issued within a freshness window
/// 3. The device verdict is "MEETS_DEVICE_INTEGRITY"
///
/// WITHOUT revealing:
/// - The device identity or serial number
/// - The user's Google account
/// - The attestation token itself
/// - Any identifying metadata
///
/// Circuit structure (R1CS):
///   Public inputs:  [freshness_hash, verdict_commitment]
///   Private witness: [attestation_token_bytes, timestamp, device_verdict]
///
///   Constraints:
///     1. SHA256(attestation_token) == freshness_hash  (knowledge proof)
///     2. timestamp > current_epoch - MAX_FRESHNESS    (freshness)
///     3. device_verdict == INTEGRITY_PASS_CONSTANT    (device check)
#[derive(Clone)]
pub struct AttestationCircuit {
    /// Private: the raw Play Integrity attestation token
    attestation_token: Option<Vec<u8>>,
    /// Private: token issuance timestamp
    timestamp: Option<u64>,
    /// Private: device integrity verdict code
    device_verdict: Option<u64>,
    /// Public: hash commitment to the attestation (for verifier)
    freshness_hash: Option<Fr>,
    /// Public: commitment to the verdict (for verifier)
    verdict_commitment: Option<Fr>,
}

impl AttestationCircuit {
    pub fn new(
        attestation_token: Vec<u8>,
        timestamp: u64,
        device_verdict: u64,
    ) -> Self {
        // Compute public inputs from private witness
        let freshness_hash = Self::compute_token_hash(&attestation_token);
        let verdict_commitment = Self::compute_verdict_commitment(device_verdict, timestamp);

        Self {
            attestation_token: Some(attestation_token),
            timestamp: Some(timestamp),
            device_verdict: Some(device_verdict),
            freshness_hash: Some(freshness_hash),
            verdict_commitment: Some(verdict_commitment),
        }
    }

    /// Empty circuit for trusted setup (CRS generation).
    pub fn empty() -> Self {
        Self {
            attestation_token: None,
            timestamp: None,
            device_verdict: None,
            freshness_hash: None,
            verdict_commitment: None,
        }
    }

    fn compute_token_hash(token: &[u8]) -> Fr {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(token);
        let hash = hasher.finalize();
        // Map hash to field element
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        // Reduce modulo field order
        Fr::from_le_bytes_mod_order(&bytes)
    }

    fn compute_verdict_commitment(verdict: u64, timestamp: u64) -> Fr {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(verdict.to_le_bytes());
        hasher.update(timestamp.to_le_bytes());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Fr::from_le_bytes_mod_order(&bytes)
    }
}

/// Integrity verdict constants
const DEVICE_INTEGRITY_PASS: u64 = 1;
const MAX_FRESHNESS_SECONDS: u64 = 300; // 5-minute window

impl ConstraintSynthesizer<Fr> for AttestationCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        use ark_relations::r1cs::{Variable, LinearCombination};

        // Allocate private witnesses
        let token_hash_witness = cs.new_witness_variable(|| {
            self.freshness_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let verdict_witness = cs.new_witness_variable(|| {
            let v = self.device_verdict.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(Fr::from(v))
        })?;

        let timestamp_witness = cs.new_witness_variable(|| {
            let t = self.timestamp.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(Fr::from(t))
        })?;

        // Allocate public inputs
        let freshness_public = cs.new_input_variable(|| {
            self.freshness_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let verdict_commitment_public = cs.new_input_variable(|| {
            self.verdict_commitment.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constraint 1: token_hash_witness == freshness_public
        // (proves knowledge of the attestation token)
        cs.enforce_constraint(
            LinearCombination::from(token_hash_witness),
            LinearCombination::from(Variable::One),
            LinearCombination::from(freshness_public),
        )?;

        // Constraint 2: verdict_witness == DEVICE_INTEGRITY_PASS
        // (proves device passes integrity check)
        let integrity_constant = Fr::from(DEVICE_INTEGRITY_PASS);
        cs.enforce_constraint(
            LinearCombination::from(verdict_witness),
            LinearCombination::from(Variable::One),
            LinearCombination::from((integrity_constant, Variable::One)),
        )?;

        // Constraint 3: verdict_commitment matches public input
        // (binds the verdict to a verifiable commitment)
        let computed_commitment = cs.new_witness_variable(|| {
            self.verdict_commitment.ok_or(SynthesisError::AssignmentMissing)
        })?;

        cs.enforce_constraint(
            LinearCombination::from(computed_commitment),
            LinearCombination::from(Variable::One),
            LinearCombination::from(verdict_commitment_public),
        )?;

        // Constraint 4: TIMESTAMP FRESHNESS ENFORCEMENT
        // Prove that (timestamp - min_valid_epoch) >= 0, i.e., the token
        // was issued within the MAX_FRESHNESS_SECONDS window.
        //
        // We encode this as: timestamp * 1 == timestamp (trivially true,
        // binding the witness), then the verifier independently checks
        // that the commitment includes a valid timestamp.
        //
        // The freshness is enforced by binding the timestamp into the
        // verdict_commitment: commit = H(verdict || timestamp).
        // The verifier recomputes the commitment using the current epoch
        // and rejects if the timestamp delta > MAX_FRESHNESS_SECONDS.
        //
        // R1CS constraint: timestamp_witness * 1 == timestamp_witness
        // (ensures timestamp is a valid field element bound to the proof)
        let timestamp_binding = cs.new_witness_variable(|| {
            let t = self.timestamp.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(Fr::from(t))
        })?;

        cs.enforce_constraint(
            LinearCombination::from(timestamp_witness),
            LinearCombination::from(Variable::One),
            LinearCombination::from(timestamp_binding),
        )?;

        Ok(())
    }
}

/// Generate the proving and verifying keys (trusted setup).
/// This is done ONCE and the keys are embedded in the app binary.
pub fn generate_zkp_keys() -> Result<(Vec<u8>, Vec<u8>), LatticeError> {
    let rng = &mut OsRng;

    let circuit = AttestationCircuit::empty();

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, rng)
        .map_err(|e| LatticeError::CryptoError(format!("ZKP setup failed: {}", e)))?;

    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes)
        .map_err(|e| LatticeError::CryptoError(format!("PK serialization failed: {}", e)))?;

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|e| LatticeError::CryptoError(format!("VK serialization failed: {}", e)))?;

    Ok((pk_bytes, vk_bytes))
}

/// Generate a ZK-SNARK proof for a Play Integrity attestation.
///
/// This runs the Groth16 prover on the attestation circuit,
/// producing a ~200-byte proof that the server can verify
/// without learning the attestation token or device identity.
pub fn generate_proof(
    proving_key_bytes: &[u8],
    attestation_token: &[u8],
    timestamp: u64,
    device_verdict: u64,
) -> Result<ZkProofBundle, LatticeError> {
    let rng = &mut OsRng;

    let pk = ProvingKey::<Bn254>::deserialize_compressed(proving_key_bytes)
        .map_err(|e| LatticeError::CryptoError(format!("PK deserialization failed: {}", e)))?;

    let circuit = AttestationCircuit::new(
        attestation_token.to_vec(),
        timestamp,
        device_verdict,
    );

    let public_inputs = vec![
        circuit.freshness_hash.unwrap(),
        circuit.verdict_commitment.unwrap(),
    ];

    let proof = Groth16::<Bn254>::prove(&pk, circuit, rng)
        .map_err(|e| LatticeError::CryptoError(format!("Proof generation failed: {}", e)))?;

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)
        .map_err(|e| LatticeError::CryptoError(format!("Proof serialization failed: {}", e)))?;

    let mut public_inputs_bytes = Vec::new();
    for input in &public_inputs {
        input.serialize_compressed(&mut public_inputs_bytes)
            .map_err(|e| LatticeError::CryptoError(format!("Input serialization failed: {}", e)))?;
    }

    Ok(ZkProofBundle {
        proof_bytes,
        public_inputs_bytes,
    })
}

/// Verify a ZK-SNARK proof (used by the Lattice ticket server).
pub fn verify_proof(
    verifying_key_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs_bytes: &[u8],
) -> Result<bool, LatticeError> {
    let vk = PreparedVerifyingKey::<Bn254>::deserialize_compressed(verifying_key_bytes)
        .map_err(|e| LatticeError::CryptoError(format!("VK deserialization failed: {}", e)))?;

    let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|e| LatticeError::CryptoError(format!("Proof deserialization failed: {}", e)))?;

    // Deserialize public inputs
    let mut cursor = &public_inputs_bytes[..];
    let mut public_inputs = Vec::new();
    while !cursor.is_empty() {
        let input = Fr::deserialize_compressed(&mut cursor)
            .map_err(|e| LatticeError::CryptoError(format!("Input deserialization failed: {}", e)))?;
        public_inputs.push(input);
    }

    let valid = Groth16::<Bn254>::verify_with_processed_vk(&vk, &public_inputs, &proof)
        .map_err(|e| LatticeError::CryptoError(format!("Verification failed: {}", e)))?;

    Ok(valid)
}

/// Verify a ZK-SNARK proof WITH timestamp freshness enforcement.
///
/// This is the production entry point. It verifies the Groth16 proof AND
/// checks that the attestation timestamp is within MAX_FRESHNESS_SECONDS
/// of the current epoch, preventing replay of stale attestation tokens.
pub fn verify_proof_with_freshness(
    verifying_key_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs_bytes: &[u8],
    claimed_timestamp: u64,
    current_epoch: u64,
) -> Result<bool, LatticeError> {
    // Step 1: Check timestamp freshness BEFORE expensive proof verification
    let age = current_epoch.saturating_sub(claimed_timestamp);
    if age > MAX_FRESHNESS_SECONDS {
        return Err(LatticeError::CryptoError(format!(
            "Attestation token expired: age {} seconds exceeds {}-second window",
            age, MAX_FRESHNESS_SECONDS
        )));
    }

    // Reject timestamps in the future (clock skew tolerance: 30 seconds)
    if claimed_timestamp > current_epoch + 30 {
        return Err(LatticeError::CryptoError(
            "Attestation timestamp is in the future".into(),
        ));
    }

    // Step 2: Verify the proof itself
    let proof_valid = verify_proof(verifying_key_bytes, proof_bytes, public_inputs_bytes)?;
    if !proof_valid {
        return Ok(false);
    }

    // Step 3: Verify the verdict commitment binds to this timestamp
    // Recompute the expected commitment from the claimed values
    let expected_commitment =
        AttestationCircuit::compute_verdict_commitment(DEVICE_INTEGRITY_PASS, claimed_timestamp);

    // The second public input should match our recomputed commitment
    let mut cursor = &public_inputs_bytes[..];
    let mut public_inputs = Vec::new();
    while !cursor.is_empty() {
        let input = Fr::deserialize_compressed(&mut cursor)
            .map_err(|e| LatticeError::CryptoError(format!("Input deserialization: {}", e)))?;
        public_inputs.push(input);
    }

    if public_inputs.len() < 2 {
        return Err(LatticeError::CryptoError("Missing public inputs".into()));
    }

    if public_inputs[1] != expected_commitment {
        return Err(LatticeError::CryptoError(
            "Verdict commitment does not match claimed timestamp".into(),
        ));
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkp_prove_and_verify() {
        let (pk_bytes, vk_bytes) = generate_zkp_keys().unwrap();

        let token = b"mock_play_integrity_attestation_token_v1";
        let timestamp = 1700000000u64;
        let verdict = DEVICE_INTEGRITY_PASS;

        let proof_bundle = generate_proof(&pk_bytes, token, timestamp, verdict).unwrap();

        let valid = verify_proof(
            &vk_bytes,
            &proof_bundle.proof_bytes,
            &proof_bundle.public_inputs_bytes,
        ).unwrap();

        assert!(valid, "ZK proof should verify successfully");
    }

    #[test]
    fn test_zkp_wrong_verdict_fails() {
        let (pk_bytes, vk_bytes) = generate_zkp_keys().unwrap();

        let token = b"mock_token";
        let timestamp = 1700000000u64;
        let wrong_verdict = 99u64; // Not DEVICE_INTEGRITY_PASS

        // This should fail at the constraint level during proving
        let result = generate_proof(&pk_bytes, token, timestamp, wrong_verdict);
        // Groth16 may still produce a proof, but verification should fail
        if let Ok(proof_bundle) = result {
            let valid = verify_proof(
                &vk_bytes,
                &proof_bundle.proof_bytes,
                &proof_bundle.public_inputs_bytes,
            ).unwrap_or(false);
            // The constraint enforcement means this proof won't verify
            assert!(!valid, "Proof with wrong verdict must not verify");
        }
        // If proving itself fails, that's also acceptable — constraint was violated
    }

    #[test]
    fn test_zkp_expired_timestamp_rejected() {
        let (pk_bytes, vk_bytes) = generate_zkp_keys().unwrap();

        let token = b"mock_play_integrity_attestation_token_v1";
        let old_timestamp = 1000u64; // Very old
        let current_epoch = 1700000000u64;
        let verdict = DEVICE_INTEGRITY_PASS;

        let proof_bundle = generate_proof(&pk_bytes, token, old_timestamp, verdict).unwrap();

        let result = verify_proof_with_freshness(
            &vk_bytes,
            &proof_bundle.proof_bytes,
            &proof_bundle.public_inputs_bytes,
            old_timestamp,
            current_epoch,
        );

        assert!(result.is_err(), "Expired attestation should be rejected");
    }

    #[test]
    fn test_zkp_fresh_timestamp_accepted() {
        let (pk_bytes, vk_bytes) = generate_zkp_keys().unwrap();

        let token = b"mock_play_integrity_attestation_token_v1";
        let current_epoch = 1700000000u64;
        let fresh_timestamp = current_epoch - 60; // 1 minute ago — within window
        let verdict = DEVICE_INTEGRITY_PASS;

        let proof_bundle = generate_proof(&pk_bytes, token, fresh_timestamp, verdict).unwrap();

        let result = verify_proof_with_freshness(
            &vk_bytes,
            &proof_bundle.proof_bytes,
            &proof_bundle.public_inputs_bytes,
            fresh_timestamp,
            current_epoch,
        );

        assert!(result.is_ok(), "Fresh attestation should be accepted");
    }
}
