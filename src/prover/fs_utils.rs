use std::{fs::File, io::BufReader, path::PathBuf};

use bellman::{
    bn256::Bn256 as Engine,
    kate_commitment::{Crs, CrsForMonomialForm},
};
use failure::format_err;

use crate::prover::prover_utils::{SETUP_MAX_POW2, SETUP_MIN_POW2};

fn base_universal_setup_dir() -> Result<PathBuf, failure::Error> {
    let mut dir = PathBuf::new();

    if let Ok(setup_dir) = std::env::var("SETUP_DIR") {
        dir.push(setup_dir);
    } else {
        dir.push("keys");
        dir.push("setup");
    }

    failure::ensure!(dir.exists(), "Universal setup dir does not exits");

    Ok(dir)
}

fn get_universal_setup_file_buff_reader(
    setup_file_name: &str,
) -> Result<BufReader<File>, failure::Error> {
    let mut path = base_universal_setup_dir()?;
    path.push(&setup_file_name);

    let setup_file = File::open(path).map_err(|e| {
        format_err!(
            "Failed to open universal setup file {}, err: {}",
            setup_file_name,
            e
        )
    })?;

    Ok(BufReader::with_capacity(1 << 29, setup_file))
}

/// Returns universal setup in the monomial form of the given power of two (range: SETUP_MIN_POW2..=SETUP_MAX_POW2). Checks if file exists
pub fn get_universal_setup_monomial_form(
    power_of_two: u32,
) -> Result<Crs<Engine, CrsForMonomialForm>, failure::Error> {
    failure::ensure!(
        (SETUP_MIN_POW2..=SETUP_MAX_POW2).contains(&power_of_two),
        "setup power of two is not in the correct range"
    );

    let setup_file_name = format!("setup_2^{}.key", power_of_two);

    let mut buf_reader = get_universal_setup_file_buff_reader(&setup_file_name)?;

    Crs::<Engine, CrsForMonomialForm>::read(&mut buf_reader)
        .map_err(|e| format_err!("Failed to read Crs from setup file: {}", e))
}
