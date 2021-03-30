use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use bellman::{
    bn256::{Bn256 as Engine, Fr},
    kate_commitment::{Crs, CrsForMonomialForm},
    plonk::{
        better_cs::{
            adaptor::TranspilationVariant,
            cs::PlonkCsWidth4WithNextStepParams,
            keys::{Proof, SetupPolynomials, VerificationKey},
        },
        commitments::transcript::keccak_transcript::RollingKeccakTranscript,
        make_verification_key, prove_by_steps, setup, transpile, verify,
    },
    Circuit,
};
use lazy_static::lazy_static;

use crate::primitives::{serialize_fe_for_ethereum, serialize_g1_for_ethereum};

use super::fs_utils;

pub const SETUP_MIN_POW2: u32 = 20;
pub const SETUP_MAX_POW2: u32 = 26;

pub struct PlonkVerificationKey(pub VerificationKey<Engine, PlonkCsWidth4WithNextStepParams>);

impl PlonkVerificationKey {
    //This function creates the verification key from setup
    pub fn generate_verification_key_from_setup(
        setup_for_prover: &SetupForStepByStepProver,
    ) -> Result<Self, failure::Error> {
        let verification_key = make_verification_key(
            &setup_for_prover.setup_polynomials,
            &setup_for_prover
                .key_monomial_form
                .as_ref()
                .expect("Setup should have universal setup struct"),
        )
        .expect("failed to create verification key");
        Ok(Self(verification_key))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EncodedProofPlonk {
    pub inputs: Vec<[u8; 32]>,
    pub proof: Vec<[u8; 32]>,
}

impl Default for EncodedProofPlonk {
    fn default() -> Self {
        Self {
            inputs: vec![[0u8; 32]; 1],
            proof: vec![[0u8; 32]; 33],
        }
    }
}

pub struct SetupForStepByStepProver {
    setup_polynomials: SetupPolynomials<Engine, PlonkCsWidth4WithNextStepParams>,
    hints: Vec<(usize, TranspilationVariant)>,
    setup_power_of_two: u32,
    key_monomial_form: Option<Crs<Engine, CrsForMonomialForm>>,
}

impl SetupForStepByStepProver {
    pub fn prepare_setup_for_step_by_step_prover<C: Circuit<Engine> + Clone>(
        circuit: C,
    ) -> Result<Self, failure::Error> {
        let hints = transpile(circuit.clone())?;
        let setup_polynomials = setup(circuit, &hints)?;
        let size = setup_polynomials.n.next_power_of_two().trailing_zeros();
        let setup_power_of_two = std::cmp::max(size, SETUP_MIN_POW2); // for exit circuit
        let key_monomial_form = Some(get_universal_setup_monomial_form(setup_power_of_two)?);
        Ok(SetupForStepByStepProver {
            setup_polynomials,
            hints,
            setup_power_of_two,
            key_monomial_form,
        })
    }

    pub fn gen_step_by_step_proof_using_prepared_setup<C: Circuit<Engine> + Clone>(
        &self,
        circuit: C,
        vk: &PlonkVerificationKey,
    ) -> Result<EncodedProofPlonk, failure::Error> {
        let proof = prove_by_steps::<_, _, RollingKeccakTranscript<Fr>>(
            circuit,
            &self.hints,
            &self.setup_polynomials,
            None,
            self.key_monomial_form
                .as_ref()
                .expect("Setup should have universal setup struct"),
        )?;

        let valid = verify::<_, RollingKeccakTranscript<Fr>>(&proof, &vk.0)?;
        failure::ensure!(valid, "proof for block is invalid");
        Ok(serialize_proof(&proof))
    }
}

impl Drop for SetupForStepByStepProver {
    fn drop(&mut self) {
        let setup = self
            .key_monomial_form
            .take()
            .expect("Setup should have universal setup struct");
        UNIVERSAL_SETUP_CACHE.put_setup_struct(self.setup_power_of_two, setup);
    }
}

pub fn serialize_proof(
    proof: &Proof<Engine, PlonkCsWidth4WithNextStepParams>,
) -> EncodedProofPlonk {
    let mut inputs = vec![];
    for input in proof.input_values.iter() {
        let ser = serialize_fe_for_ethereum(input);
        inputs.push(ser);
    }
    let mut serialized_proof = vec![];

    for c in proof.wire_commitments.iter() {
        let (x, y) = serialize_g1_for_ethereum(c);
        serialized_proof.push(x);
        serialized_proof.push(y);
    }

    let (x, y) = serialize_g1_for_ethereum(&proof.grand_product_commitment);
    serialized_proof.push(x);
    serialized_proof.push(y);

    for c in proof.quotient_poly_commitments.iter() {
        let (x, y) = serialize_g1_for_ethereum(c);
        serialized_proof.push(x);
        serialized_proof.push(y);
    }

    for c in proof.wire_values_at_z.iter() {
        serialized_proof.push(serialize_fe_for_ethereum(c));
    }

    for c in proof.wire_values_at_z_omega.iter() {
        serialized_proof.push(serialize_fe_for_ethereum(c));
    }

    serialized_proof.push(serialize_fe_for_ethereum(&proof.grand_product_at_z_omega));
    serialized_proof.push(serialize_fe_for_ethereum(&proof.quotient_polynomial_at_z));
    serialized_proof.push(serialize_fe_for_ethereum(
        &proof.linearization_polynomial_at_z,
    ));

    for c in proof.permutation_polynomials_at_z.iter() {
        serialized_proof.push(serialize_fe_for_ethereum(c));
    }

    let (x, y) = serialize_g1_for_ethereum(&proof.opening_at_z_proof);
    serialized_proof.push(x);
    serialized_proof.push(y);

    let (x, y) = serialize_g1_for_ethereum(&proof.opening_at_z_omega_proof);
    serialized_proof.push(x);
    serialized_proof.push(y);

    EncodedProofPlonk {
        inputs,
        proof: serialized_proof,
    }
}

/// Reads universal setup from disk or downloads from network.
pub fn get_universal_setup_monomial_form(
    power_of_two: u32,
) -> Result<Crs<Engine, CrsForMonomialForm>, failure::Error> {
    if let Some(cached_setup) = UNIVERSAL_SETUP_CACHE.take_setup_struct(power_of_two) {
        Ok(cached_setup)
    } else {
        fs_utils::get_universal_setup_monomial_form(power_of_two)
    }
}

/// Plonk prover may need to change keys on the fly to prove block of the smaller size
/// cache is used to avoid downloading/loading from disk same files over and over again.
///
/// Note: Keeping all the key files at the same time in memory is not a huge overhead
/// (around 4GB, compared to 135GB that are used to generate proof)
struct UniversalSetupCache {
    data: Arc<Mutex<HashMap<u32, Crs<Engine, CrsForMonomialForm>>>>,
}

impl UniversalSetupCache {
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn take_setup_struct(&self, setup_power: u32) -> Option<Crs<Engine, CrsForMonomialForm>> {
        self.data
            .lock()
            .expect("SetupPolynomialsCache lock")
            .remove(&setup_power)
    }

    pub fn put_setup_struct(&self, setup_power: u32, setup: Crs<Engine, CrsForMonomialForm>) {
        self.data
            .lock()
            .expect("SetupPolynomialsCache lock")
            .insert(setup_power, setup);
    }
}

lazy_static! {
    static ref UNIVERSAL_SETUP_CACHE: UniversalSetupCache = UniversalSetupCache::new();
}
