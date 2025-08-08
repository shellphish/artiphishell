// Nautilus
// Copyright (C) 2024  Daniel Teuchert, Cornelius Aschermann, Sergej Schumilo

#[macro_use]
extern crate clap;
extern crate grammartec;
extern crate pyo3;
extern crate ron;
extern crate serde_json;

mod python_grammar_loader;
use grammartec::context::Context;
use grammartec::seed_serialization::SerializedSeed;
use grammartec::tree::TreeLike;

use clap::{App, Arg};
use ron::ser::PrettyConfig;
use std::fs;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path,PathBuf};


fn process_new_ron(
    ron_path: &PathBuf,
    output_path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    if !ron_path.is_file() {
        return Ok(());
    }

    let ron_file_name = ron_path
        .file_name()
        .ok_or("Failed to get ron filename")?
        .to_string_lossy()
        .to_string();

    let ron_text = fs::read_to_string(ron_path).expect("cannot read ron file");

    let ron: SerializedSeed = ron::de::from_str(&ron_text)?;

    let mut ctx = python_grammar_loader::load_python_grammar_from_str(&ron.grammar_string);
    ctx.initialize(ron.generation_depth);

    let bytes = ron.tree.unparse_to_vec(&ctx);

    eprintln!("bytes: {:?}", bytes);

    std::fs::write(output_path, &bytes)?;

    Ok(())
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    pyo3::prepare_freethreaded_python();
    //Parse parameters
    let matches = App::new("ron_to_bytes")
        .about("Generate strings using a grammar. This can also be used to generate a corpus")
        .arg(Arg::with_name("ron_path")
             .required(true)
             .help("Path to RON file to serialize"))
        .arg(Arg::with_name("output")
             .required(false)
             .help("Store output to files. This will create a folder containing one file for each generated tree."))
        .get_matches();

    let ron_path = matches
        .value_of("ron_path")
        .expect("ron_path is a required parameter")
        .to_string();

    if !Path::new(&ron_path).exists() {
        eprintln!("The specified RON file does not exist: {}", ron_path);
        std::process::exit(1);
    }
    // Get the output path, defaulting to the ron name + ".bytes" if not specified
    let output = matches
        .value_of("output")
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            let file_name = Path::new(&ron_path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("output");
            format!("{}.bytes", file_name)
        });


    process_new_ron(&PathBuf::from(ron_path), &PathBuf::from(output))
        .unwrap_or_else(|err| {
            eprintln!("Error processing RON file: {}", err);
            std::process::exit(1);
        });
}
