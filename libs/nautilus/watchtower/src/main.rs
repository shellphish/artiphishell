#[macro_use]
extern crate clap;
extern crate grammartec;
extern crate pyo3;
extern crate rand;
extern crate ron;
extern crate serde_json;

use fuzzer::python_grammar_loader;
use grammartec::context::Context;
use grammartec::seed_serialization::SerializedSeed;
use crate::grammartec::tree::TreeLike;

use clap::Parser;
use notify::{Config, Watcher, PollWatcher, RecursiveMode};
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use lazy_static::lazy_static;
use std::sync::Mutex;

const TREE_GEN_DEPTH: usize = 200;
const POLL_FREQUENCY_SECS: u64 = 30;

#[derive(Parser)]
struct CmdArgs {
    #[clap(subcommand)]
    commands: Commands
}

#[derive(Subcommand)]
enum Commands {
    /// Read grammars from grammar explorer and produce inputs for revolver
    SyncGrammars {
        /// Path to grammars
        #[clap(short = 'i')]
        grammar_watch_dir: String,

        /// Path to output/sync directory
        #[clap(short = 'o')]
        output_dir: String,

        /// Number of corpus inputs to generate per new grammar
        #[clap(short = 'n', default_value="50")]
        corpus_gen_amt: usize,
    },
    /// Convert ron inputs produced by revolver to bytes and sync to other fuzzers
    SyncOutputs {
        /// Path to ron inputs
        #[clap(short = 'i')]
        rons_watch_dir: String,

        /// Path to output/sync directory
        #[clap(short = 'o')]
        output_dir: String,
    },
}

lazy_static! {
    static ref INPUT_COUNTER: Mutex<u32> = Mutex::new(0);
}

fn watch_directory(
    input_dir: &String,
    mut closure: impl FnMut(&PathBuf)
) -> Result<(), Box<dyn std::error::Error>> {
    // Create a channel to receive the events
    let (tx, rx) = std::sync::mpsc::channel();

    // Create a watcher object with default config
    let mut watcher = PollWatcher::new(
        tx,
        Config::default()
            .with_poll_interval(Duration::from_secs(POLL_FREQUENCY_SECS))
            .with_compare_contents(true),
    )?;

    // Add a path to be watched
    watcher.watch(Path::new(input_dir.as_str()), RecursiveMode::Recursive)?;

    println!("Watching directory {}!", input_dir);

    // Loop forever waiting for events
    for res in rx {
        match res {
            Ok(event) => {
                // Process create and modify events
                if event.kind.is_create() || event.kind.is_modify() {
                    for path in event.paths {
                        closure(&path);
                    }
                }
            }
            Err(error) => println!("Error: {}", error),
        }
    }

    Ok(())
}

fn process_new_grammar(
    grammar_path: &PathBuf,
    output_dir: &PathBuf,
    corpus_gen_amt: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    // Skip if not a file
    if !grammar_path.is_file() {
        return Ok(());
    }

    // Create output file path
    let grammar_file_name = grammar_path
        .file_name()
        .ok_or("Failed to get grammar filename")?
        .to_string_lossy()
        .to_string();

    // Generate inputs
    let mut ctx = Context::new();

    let absolute_grammar_path = fs::canonicalize(grammar_path)?;
    let absolute_grammar_path_str = absolute_grammar_path.as_os_str().to_str().unwrap();
    let grammar_text = fs::read_to_string(grammar_path)?;
    if grammar_file_name.ends_with(".json") {
        let gf = File::open(&grammar_path)?;
        let rules: Vec<Vec<String>> =
            serde_json::from_reader(&gf)?;
        assert!(rules.len() > 0, "rule file didnt include any rules");
        let root = "{".to_string() + &rules[0][0] + "}";
        ctx.add_rule("START", root.as_bytes());
        for rule in rules {
            ctx.add_rule(&rule[0], rule[1].as_bytes());
        }
    } else if grammar_file_name.ends_with(".py") {
        ctx = python_grammar_loader::load_python_grammar(absolute_grammar_path_str);
    } else {
        return Err(format!("Unknown grammar type for {}", grammar_file_name).into());
    }

    ctx.initialize(TREE_GEN_DEPTH);

    for i in 0..corpus_gen_amt {
        let generated_tree = if let Some(no_any_ctx) = ctx.get_no_anyrule_ctx() {
            let nonterm = no_any_ctx.nt_id("START");
            let len = no_any_ctx.get_random_len_for_nt(&nonterm);
            no_any_ctx.generate_tree_from_nt(nonterm, len)
        } else {
            let nonterm = ctx.nt_id("START");
            let len = ctx.get_random_len_for_nt(&nonterm);
            ctx.generate_tree_from_nt(nonterm, len)
        };
                                                                      // generated_tree.unparse_to(&ctx, &mut output);
        let mut output_serialized: File = File::create(&format!(
            "{}/id:{:06}",
            output_dir.clone().into_os_string().into_string().unwrap(),
            *INPUT_COUNTER.lock().unwrap()
        ))?;
        *INPUT_COUNTER.lock().unwrap() += 1;
        output_serialized.write_all(
            ron::ser::to_string(&SerializedSeed {
                seed: None,
                tree: generated_tree.clone(),
                generation_index: i,
                generation_depth: TREE_GEN_DEPTH.into(),
                grammar_string: grammar_text.clone(),
                grammar_hash: format!("{:x}", md5::compute(&grammar_text)),
            })?
            .as_bytes(),
        )?;
    }

    Ok(())
}

fn generate_initial_corpus(
    input_grammar_dir: &String,
    output_corpus_dir: &String,
    corpus_gen_amt: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create output directory if it doesn't exist
    let _ = fs::create_dir_all(output_corpus_dir.as_str());
    println!("Checking for initial grammars in {}...", input_grammar_dir);
    // Iterate through files and generate inputs for each
    let input_path = Path::new(input_grammar_dir.as_str());
    for entry in fs::read_dir(input_path)? {
        let entry = entry?;
        let file_path = entry.path();

        // Check if it's a file (not a subdirectory)
        if !file_path.is_file() {
            continue;
        }

        // Generate inputs
        match process_new_grammar(
            &file_path,
            &PathBuf::from(output_corpus_dir.clone()),
            corpus_gen_amt,
        ) {
            Ok(_) => {
                println!(
                    "Processed initial grammar: {}",
                    file_path.file_name().unwrap().to_string_lossy()
                )
            }
            Err(error) => println!("Error while processing initial grammar: {}", error),
        }
    }

    Ok(())
}

fn process_new_ron(
    ron_path: &PathBuf,
    output_dir: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    if !ron_path.is_file() {
        return Ok(());
    }

    let ron_file_name = ron_path
        .file_name()
        .ok_or("Failed to get ron filename")?
        .to_string_lossy()
        .to_string();

    if let Ok(ron_text) = fs::read_to_string(ron_path) {
        let ron: SerializedSeed = ron::de::from_str(&ron_text)?;

        let mut ctx = python_grammar_loader::load_python_grammar_from_str(&ron.grammar_string);
        ctx.initialize(TREE_GEN_DEPTH);

        let bytes = ron.tree.unparse_to_vec(&ctx);

        let output_path = output_dir.clone().join(ron_file_name);
        std::fs::write(output_path, &bytes)?;
    } else {
        eprintln!("Error loading grammar to string: {:?}", ron_path);
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start Python interpreter
    pyo3::prepare_freethreaded_python();

    let args = CmdArgs::parse();

    match args.commands {
        Commands::SyncGrammars { grammar_watch_dir, output_dir, corpus_gen_amt } => {
            // Create watch directory if it doesn't exist
            let _ = fs::create_dir_all(grammar_watch_dir.as_str());

            // Create output directory if it doesn't exist
            let _ = fs::create_dir_all(output_dir.as_str());

            // Generate initial corpus
            if let Err(e) = generate_initial_corpus(&grammar_watch_dir, &output_dir, corpus_gen_amt) {
                println!("Error in generate_initial_corpus: {}", e.to_string());
            }

            // Start watching grammar dir for changes
            watch_directory(
                &grammar_watch_dir,
                |path| {
                    match process_new_grammar(
                        &path,
                        &PathBuf::from(output_dir.clone()),
                        corpus_gen_amt,
                    ) {
                        Ok(_) => {
                            println!(
                                "Processed new grammar: {}",
                                path.file_name().unwrap().to_string_lossy()
                            )
                        }
                        Err(error) => println!("Error while processing grammar: {}", error),
                    }
                }
            )?;
        },
        Commands::SyncOutputs { rons_watch_dir, output_dir } => {
            // Create watch directory if it doesn't exist
            let _ = fs::create_dir_all(rons_watch_dir.as_str());

            // Create output directory if it doesn't exist
            let _ = fs::create_dir_all(output_dir.as_str());

            // Start watching rons dir for changes
            watch_directory(
                &rons_watch_dir,
                |path| {
                    match process_new_ron(
                        &path,
                        &PathBuf::from(output_dir.clone()),
                    ) {
                        Ok(_) => {
                            println!(
                                "Synced byte outputs for grammar {}",
                                path.file_name().unwrap().to_string_lossy()
                            )
                        }
                        Err(error) => println!("Error while syncing byte inputs: {}", error),
                    }
                }
            )?;
        }
    }

    Ok(())
}
