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
use std::path::Path;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    pyo3::prepare_freethreaded_python();
    //Parse parameters
    let matches = App::new("generator")
        .about("Generate strings using a grammar. This can also be used to generate a corpus")
        .arg(Arg::with_name("grammar_path")
             .short("g")
             .value_name("GRAMMAR")
             .takes_value(true)
             .required(true)
             .help("Path to grammar"))
        .arg(Arg::with_name("tree_depth")
             .short("t")
             .value_name("DEPTH")
             .takes_value(true)
             .required(true)
             .help("Size of trees that are generated"))
        .arg(Arg::with_name("number_of_trees")
             .short("n")
             .value_name("NUMBER")
             .takes_value(true)
             .help("Number of trees to generate [default: 1]"))
        .arg(Arg::with_name("store")
             .short("s")
             .help("Store output to files. This will create a folder containing one file for each generated tree."))
        .arg(Arg::with_name("ron_dir")
             .short("r")
             .value_name("DIR")
             .takes_value(true)
             .help("Output directory to store the serialized trees. Will store one file for each generated tree in this directory. [default=rons]"))
        .arg(Arg::with_name("corpus_dir")
             .short("c")
             .value_name("DIR")
             .takes_value(true)
             .help("Output directory to store the raw inputs. Will store one file for each generated tree in this directory. [default=corpus]"))
        .arg(Arg::with_name("verbose")
             .short("v")
             .help("Be verbose"))
        .get_matches();

    let grammar_path = matches
        .value_of("grammar_path")
        .expect("grammar_path is a required parameter")
        .to_string();
    let tree_depth =
        value_t!(matches, "tree_depth", usize).expect("tree_depth is a requried parameter");
    let number_of_trees = value_t!(matches, "number_of_trees", usize).unwrap_or(1);
    let store = matches.is_present("store");
    let ron_store = matches
        .value_of("ron_dir")
        .map(|s| s.to_string())
        .unwrap_or("".to_string());
    let corpus_store = matches
        .value_of("corpus_dir")
        .map(|s| s.to_string())
        .unwrap_or("".to_string());
    let verbose = matches.is_present("verbose");

    let mut ctx = Context::new();

    let grammar_text = fs::read_to_string(&grammar_path).expect("cannot read grammar file");
    //Create new Context and saved it
    if grammar_path.ends_with(".json") {
        let gf = File::open(&grammar_path).expect("cannot read grammar file");
        let rules: Vec<Vec<String>> =
            serde_json::from_reader(&gf).expect("cannot parse grammar file");
        assert!(rules.len() > 0, "rule file didn_t include any rules");
        let root = "{".to_string() + &rules[0][0] + "}";
        ctx.add_rule("START", root.as_bytes());
        for rule in rules {
            ctx.add_rule(&rule[0], rule[1].as_bytes());
        }
    } else if grammar_path.ends_with(".py") {
        ctx = python_grammar_loader::load_python_grammar(&grammar_path);
    } else {
        panic!("Unknown grammar type");
    }

    ctx.initialize(tree_depth);
    ctx = ctx.take_no_anyrule_ctx().unwrap();

    //Generate Tree
    if store {
        if corpus_store != "" && !Path::new(&corpus_store).exists() {
            fs::create_dir(&corpus_store).expect("Could not create corpus directory");
        }
        if ron_store != "" && !Path::new(&ron_store).exists() {
            fs::create_dir(&ron_store).expect("Could not create ron directory");
        }
    }
    for i in 0..number_of_trees {
        let nonterm = ctx.nt_id("START");
        let len = ctx.get_random_len_for_nt(&nonterm);
        let generated_tree = ctx.generate_tree_from_nt(nonterm, len); //1 is the index of the "START" Node
        if verbose {
            println!("Generating tree {} from {}", i + 1, number_of_trees);
        }
        if store {
            if corpus_store != "" {
                let mut output = File::create(&format!("{}/{}", &corpus_store, i + 1))
                    .expect("cannot create output file");
                // generated_tree.unparse_to(&ctx, &mut output);
                let data = generated_tree.unparse_to_vec(&ctx);
                output.write_all(&data).expect("cannot write to output file");
            }
            if ron_store != "" {
                let mut output_serialized: File =
                    File::create(&format!("{}/{}.ron", ron_store, i + 1,))
                        .expect("cannot create serialized output file");
                output_serialized
                    .write_all(
                        ron::ser::to_string_pretty(
                            &SerializedSeed {
                                seed: None,
                                tree: generated_tree.clone(),
                                generation_index: i,
                                generation_depth: tree_depth,
                                grammar_string: grammar_text.clone(),
                                grammar_hash: format!("{:x}", md5::compute(&grammar_text)),
                            },
                            PrettyConfig::new()
                                .depth_limit(3)
                                .new_line("\n".to_string())
                                .indentor(" ".to_string())
                        )
                        .expect("Serialization of tree failed!")
                        .as_bytes(),
                    )
                    .expect("Writing to tree file failed");
            }
        } else {
            let stdout = io::stdout();
            let mut stdout_handle = stdout.lock();
            // generated_tree.unparse_to(&ctx, &mut stdout_handle);
            let data = generated_tree.unparse_to_vec(&ctx);
            stdout_handle.write_all(&data).expect("cannot write to stdout");
        }
    }
}
