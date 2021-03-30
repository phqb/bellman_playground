use bellman::{
    bn256::Bn256,
    plonk::{
        better_cs::cs::PlonkCsWidth4WithNextStepParams, make_verification_key, setup,
        transpile_with_gates_count, Proof, VerificationKey,
    },
};
use fs_utils::get_universal_setup_monomial_form;

use crate::{
    circuit::XorCircuit,
    prover::prover_utils::{PlonkVerificationKey, SetupForStepByStepProver},
};

pub mod fs_utils;
pub mod prover_utils;

pub fn prove(circuit: XorCircuit) -> Proof<Bn256, PlonkCsWidth4WithNextStepParams> {
    let setup = SetupForStepByStepProver::prepare_setup_for_step_by_step_prover(circuit.clone())
        .map_err(|e| {
            log::error!("Failed to prepare setup: {}", e);
            e
        })
        .unwrap();

    let vk = PlonkVerificationKey::generate_verification_key_from_setup(&setup)
        .map_err(|e| {
            log::error!("Failed to generate vk: {}", e);
            e
        })
        .unwrap();

    let mut vk_bytes: Vec<u8> = vec![];
    vk.0.write(&mut vk_bytes).unwrap();

    log::debug!("vk {}", hex::encode(&vk_bytes));

    setup
        .gen_step_by_step_proof_using_prepared_setup(circuit, &vk)
        .map_err(|e| {
            log::error!("Failed to prove: {}", e);
            e
        })
        .unwrap()
}

pub fn generate_vk() -> VerificationKey<Bn256, PlonkCsWidth4WithNextStepParams> {
    let circuit = XorCircuit {
        a: None,
        b: None,
        c: None,
    };

    log::info!("Transpiling circuit");

    let (gates_count, transpilation_hints) =
        transpile_with_gates_count::<Bn256, XorCircuit>(circuit.clone())
            .expect("failed to transpile");

    println!("gates_count = {}", gates_count);

    let size_log2 = gates_count.next_power_of_two().trailing_zeros();
    assert!(
        size_log2 <= 26,
        "power of two too big {}, max: 26",
        size_log2
    );

    let size_log2 = std::cmp::max(20, size_log2);
    log::info!(
        "Reading setup file, gates_count: {}, pow2: {}",
        gates_count,
        size_log2
    );

    let key_monomial_form =
        get_universal_setup_monomial_form(size_log2).expect("Failed to read setup file.");

    log::info!("Generating setup");
    let setup = setup(circuit, &transpilation_hints).expect("failed to make setup");

    log::info!("Generating verification key");
    make_verification_key(&setup, &key_monomial_form).expect("failed to create verification key")
}

#[cfg(test)]
mod tests {
    use bellman::{
        bn256::Fr,
        plonk::{commitments::transcript::keccak_transcript::RollingKeccakTranscript, verify},
    };
    use simple_logger::SimpleLogger;

    use crate::{
        circuit::XorCircuit,
        prover::{prove, prover_utils::serialize_proof},
    };

    use super::generate_vk;

    #[test]
    fn test_proving_and_verify_proof() {
        SimpleLogger::new().init().unwrap();

        let circuit = XorCircuit {
            a: Some(true),
            b: Some(true),
            c: Some(false),
        };

        let proof = prove(circuit);
        let serialized_proof = serialize_proof(&proof);

        println!("inputs");
        for i in serialized_proof.inputs.iter() {
            println!("{}", hex::encode(&i));
        }
        println!("proof");
        for p in serialized_proof.proof.iter() {
            println!("{}", hex::encode(&p));
        }

        let vk = generate_vk();

        let valid = verify::<_, RollingKeccakTranscript<Fr>>(&proof, &vk).expect("must verify");
        println!("proof valid = {}", valid);
    }

    #[test]
    fn test_generate_vk() {
        SimpleLogger::new().init().unwrap();

        let vk = generate_vk();
        let mut vk_bytes: Vec<u8> = vec![];
        vk.write(&mut vk_bytes).unwrap();

        log::debug!("vk {}", hex::encode(&vk_bytes));
    }
}
