use crate::{
    circuit::XorCircuit,
    prover::prover_utils::{EncodedProofPlonk, PlonkVerificationKey, SetupForStepByStepProver},
};

pub mod fs_utils;
pub mod prover_utils;

pub fn prove(circuit: XorCircuit) -> EncodedProofPlonk {
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

#[cfg(test)]
mod tests {
    use simple_logger::SimpleLogger;

    use crate::{circuit::XorCircuit, prover::prove};

    #[test]
    fn test_proving() {
        SimpleLogger::new().init().unwrap();

        let circuit = XorCircuit {
            a: true,
            b: true,
            c: false,
        };

        let proof = prove(circuit);

        println!("inputs");
        for i in proof.inputs.iter() {
            println!("{}", hex::encode(&i));
        }
        println!("proof");
        for p in proof.proof.iter() {
            println!("{}", hex::encode(&p));
        }
    }
}
