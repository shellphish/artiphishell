//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for `stb_image`.

#![feature(option_get_or_insert_default)]

use clap::Parser;

use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use serde::{Deserialize, Serialize};
use symcts::util::hash_bytes;

use libafl_bolts::{
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider}
};
use libafl::prelude::{*, tui::{TuiMonitor, ui::TuiUI}};

// parse cmdline args with clap
#[derive(Parser, Serialize, Deserialize, Debug, Clone)]
#[clap(version = "0.1", author = "Lukas Dresel", about = "A concolic-execution based fuzzer with constraint sampling")]
pub struct SyMCTSArgs {
    // the broker port
    #[clap(short, long, default_value = "1337")]
    pub broker_port: u16,
}

pub fn main() -> Result<(), Error> {

    env_logger::init();

    let args = SyMCTSArgs::parse();

    let monitor = TuiMonitor::new(TuiUI::new("symcts_fuzz".to_string(), true));

    type Input = BytesInput;
    type Corpus = InMemoryCorpus<Input>;
    type State = StdState<Input, Corpus, StdRand, Corpus>;

    RestartingMgr::<_, State, _>::builder()
        .shmem_provider(StdShMemProvider::new()?)
        .monitor(Some(monitor))
        .broker_port(args.broker_port)
        .configuration(libafl::prelude::EventConfig::FromName { name_hash: hash_bytes("broker".as_bytes()) })
        .serialize_state(true)
        .build()
        .launch()
        .expect("Could not start manager");

    panic!("There appears to already be a broker running?")
}