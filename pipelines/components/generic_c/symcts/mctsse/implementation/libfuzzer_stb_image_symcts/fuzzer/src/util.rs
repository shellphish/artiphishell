use std::{hash::{BuildHasher, Hasher}, path::Path};

use libafl::{prelude::{Corpus, Input, CorpusId, HasBytesVec}, state::HasCorpus};
use libafl_bolts::AsSlice;

pub fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut hasher = ahash::RandomState::with_seeds(0, 0, 0, 0).build_hasher();
    hasher.write(bytes);
    let hash = hasher.finish();
    hash
}
pub fn hash_target_bytes_input<I: HasBytesVec>(input: &I) -> u64 {
    let input_bytes = input.bytes();
    hash_bytes(&input_bytes.as_slice())
}
pub fn hash_corpus_entry<I: Input + HasBytesVec, S: HasCorpus<Input = I>>(state: &mut S, id: CorpusId) -> Result<u64, libafl::Error> {
    let corpus = state.corpus_mut();
    let mut input = corpus.get(id)?.borrow_mut();
    let input = input.load_input(corpus)?;
    Ok(hash_target_bytes_input(input))
}

pub fn ensure_baseline_inputs_exist(dir: &Path) -> Result<(), std::io::Error> {
    log::info!("Creating baseline inputs in {:?}", dir);
    let baseline_dir = dir.join("symcts_baseline_inputs");
    std::fs::create_dir_all(&baseline_dir).unwrap();
    std::fs::write(
        baseline_dir.join("1024"),
        vec![69; 1024],
    ).unwrap();
    std::fs::write(
        baseline_dir.join("256"),
        vec![69; 256],
    ).unwrap();
    std::fs::write(
        baseline_dir.join("64"),
        vec![69; 64],
    ).unwrap();
    std::fs::write(
        baseline_dir.join("32"),
        vec![69; 32],
    ).unwrap();
    std::fs::write(
        baseline_dir.join("16"),
        vec![69; 16],
    ).unwrap();
    std::fs::write(
        baseline_dir.join("4"),
        vec![69; 64],
    ).unwrap();
    Ok(())
}