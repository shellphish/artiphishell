use libafl::{prelude::{CorpusId, Corpus, HasTargetBytes, EventFirer, CustomBufEventResult, UsesInput, HasBytesVec}, state::{UsesState, HasCorpus, HasMetadata, BetterStateTrait}};
use libafl_bolts::Error;

use crate::{util::hash_corpus_entry, metadata::global::{SyMCTSGlobalMetadata, register_symbolic_mutation_scheduling_of_testcase}};

pub fn send_concolic_execution_event<S, E, EM>(manager: &mut EM, state: &mut S, corpus_idx: CorpusId) -> Result<(), Error>
where
    S: HasCorpus + UsesInput + HasMetadata,
    <S as UsesInput>::Input: HasBytesVec,
    E: UsesState<State = S>,
    EM: UsesState<State = S> + EventFirer,
{
    let hash = hash_corpus_entry(state, corpus_idx)?;

    state
        .metadata_mut::<SyMCTSGlobalMetadata>()
        .unwrap()
        .register_traced_by_us(hash);

    let payload = hash.to_le_bytes().to_vec();
    log::info!("Sending concolic execution event for input with hash {:x}", hash);
    // panic!("Sending concolic execution event for input with hash {:x}", hash);
    manager.fire(state, libafl::prelude::Event::CustomBuf {
        tag: "symmut".to_string(),
        buf: payload,
    })?;
    Ok(())
}
pub fn handle_concolic_execution_event<S: HasCorpus + HasMetadata + BetterStateTrait>(state: &mut S, tag: &str, buf: &[u8]) -> CustomBufEventResult {
    if tag != "symmut" {
        log::warn!("Received custom buffer event with tag {}, but expected symmut", tag);
        return CustomBufEventResult::Next;
    }

    assert!(buf.len() == std::mem::size_of::<u64>());
    let data: &[u8; std::mem::size_of::<u64>()] = buf
        .try_into()
        .expect(&format!("Could not parse custom buffer {:?} into the testcase hash", buf));

    let input_hash: u64 = u64::from_le_bytes(*data);

    let global_meta = state.metadata_mut::<SyMCTSGlobalMetadata>().unwrap();
    global_meta.register_traced_by_others(input_hash);
    global_meta.total_num_times_sampled += 1;

    let corpus_id = if let Ok(global_metadata) = state.metadata::<SyMCTSGlobalMetadata>() {
        // usuall
        if let Some(corpus_id) = global_metadata.hash_to_corpus_id.get(&input_hash) {
            log::info!("Received concolic execution event for input with hash {:x} and corpus id {:?}", input_hash, corpus_id);
            *corpus_id
        }
        else {
            // this is a valid event, but the traced input is not in our corpus.
            // this can happen, e.g. if we already had an input with overlapping
            // coverage in our corpus and don't add it instead.
            log::warn!("Received concolic execution event for input with hash {:x}, but this input is not in our corpus", input_hash);
            return CustomBufEventResult::Handled;
        }
    }
    else {
        panic!("Could not find global metadata???");
    };

    log::info!("Received concolic execution event for input with hash {:x} which corresponds to our corpus id {:?}", input_hash, corpus_id);
    // we have this input in our corpus, mark that another fuzzer has mutated it already
    register_symbolic_mutation_scheduling_of_testcase(
        state,
        corpus_id,
        false); // mutated by another process, don't update local sampling counts

    CustomBufEventResult::Handled
}