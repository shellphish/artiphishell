use std::path::PathBuf;
use std::time::Instant;

use z3::ast::Bool;
use z3::Context;

// use smt_sampler::generic::SmtSampler;
use smt_sampler::symcc::{SymCCSampler, SymCCModel, SymCCInputVars};

#[cfg(feature = "z3jit_support")]
use z3jit::jit_constraint::JitContext;

const TIMEOUT: u64 = 500_000;

fn parse_smtlib(path: PathBuf) {
    // println!("Supposedly enabling z3 logging!");
    // z3::logging::toggle_warning_messages(true);
    // z3::logging::open_log("z3.log");
    // z3::logging::append_log("hi");

    let mut config = z3::Config::new();
    config.set_model_generation(true);
    // config.set_proof_generation(true);
    config.set_unsat_core_generation(true);
    config.set_timeout_msec(TIMEOUT);

    let ctx = z3::Context::new(&config);
    let csts = ctx.parse_file(path.to_str().unwrap()).unwrap();
    let csts: Vec<Bool> = csts.into_iter().map(|x| x.try_into().unwrap()).collect();
    let symcc_input_vars = SymCCInputVars::from_constraints(&ctx, csts.clone());

    let start = Instant::now();
    let samples = sample(&ctx, symcc_input_vars.byte_vars.len(), csts);
    let time_taken = start.elapsed();
    println!("Got {} solutions in {:?}", samples.len(), time_taken);
    // for model in samples {
    //     println!("{:?}", model);
    // }
}

#[cfg(feature = "z3jit_support")]
fn sample<'z3_ctx>(z3_ctx: &'z3_ctx Context, num_byte_vars: usize, csts: Vec<Bool<'z3_ctx>>) -> Vec<SymCCModel<'z3_ctx>> {
    let jit_context = JitContext::create();
    let mut sampler = SymCCSampler::new(&z3_ctx, &jit_context);
    log::info!("Making sure that the {num_byte_vars} variables exist!");
    sampler.ensure_byte_vars_exist_upto(num_byte_vars);
    let mut samples = vec![];
    for cst in csts {
        sampler.push_constraint(cst).expect("Should not be unsat!");
        samples.extend(sampler.quick_sample(100).into_iter());
    }
    println!("Sampler stats: {:?}", sampler.stats());
    samples
}

#[cfg(not(feature = "z3jit_support"))]
fn sample<'z3_ctx>(z3_ctx: &'z3_ctx Context, vars: Vec<BV<'z3_ctx>>, csts: Vec<Bool<'z3_ctx>>) -> Vec<SymCCModel<'z3_ctx>> {
    let mut sampler = SymCCSampler::new(&z3_ctx, vars, csts).expect("Could not create SymCCSampler");
    let samples = sampler.quick_sample(100);
    samples
}

fn main() {
    env_logger::init();
    let app = clap::Command::new("sample_smtlib")
        .bin_name("sample_smtlib")
        .arg(clap::Arg::new("path").required(true));
    let matches = app.get_matches();
    let path = matches
        .value_of("path")
        .map(std::path::PathBuf::from)
        .unwrap();
    println!("path: {:?}", path);
    parse_smtlib(path);
}
