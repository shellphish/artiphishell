//! The [`SyncFromAFLStage`] is a stage that imports inputs from disk for e.g. sync with AFL

use core::marker::PhantomData;
use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use libafl::{ExecuteInputResult, prelude::{HasTargetBytes, HasBytesVec}};
use libafl_bolts::impl_serdeany;
use serde::{Deserialize, Serialize};

use libafl_bolts::{current_time, shmem::ShMemProvider};
use libafl::{
    corpus::{Corpus, CorpusId},
    events::{llmp::LlmpEventConverter, Event, EventConfig, EventFirer},
    executors::{Executor, ExitKind, HasObservers},
    fuzzer::{Evaluator, EvaluatorObservers, ExecutionProcessor},
    inputs::{Input, InputConverter, UsesInput},
    stages::Stage,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasMetadata, HasRand, UsesState},
    Error,
};

use crate::{metadata::global::SyMCTSGlobalMetadata, util::hash_target_bytes_input};

/// Metadata used to store information about disk sync time
#[derive(Serialize, Deserialize, Debug)]
pub struct SyncFromDiskMetadata {
    /// The last time the sync was done
    pub last_time: SystemTime,
}

impl_serdeany!(SyncFromDiskMetadata);

impl SyncFromDiskMetadata {
    /// Create a new [`struct@SyncFromDiskMetadata`]
    #[must_use]
    pub fn new(last_time: SystemTime) -> Self {
        Self { last_time }
    }
}

/// A stage that loads testcases from disk to sync with other fuzzers such as AFL++
#[derive(Debug)]
pub struct SyncFromAFLStage<CB, E, EM, Z> {
    sync_dir: PathBuf,
    load_callback: CB,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<CB, E, EM, Z> UsesState for SyncFromAFLStage<CB, E, EM, Z>
where
    E: UsesState,
{
    type State = E::State;
}

impl<CB, E, EM, Z> Stage<E, EM, Z> for SyncFromAFLStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut Z::State, &Path) -> Result<<Z::State as UsesInput>::Input, Error>,
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasMetadata,
    <Z::State as UsesInput>::Input: HasBytesVec,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        _corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        let global_meta = state.metadata_mut::<SyMCTSGlobalMetadata>().unwrap();
        #[cfg(feature = "sync_only_when_stuck")]
        if !global_meta.seems_stuck() {
            return Ok(());
        }
        global_meta.reset_stuck_counter(); // reset the stuck counter to not immediately sync again

        let last_synced_time = state
            .metadata::<SyncFromDiskMetadata>()
            .ok()
            .map(|m| m.last_time);

        let now = SystemTime::now();
        if let Some(l) = last_synced_time {
            if now.duration_since(l).unwrap().as_secs() < 120 {
                return Ok(());
            }
        }
        let path = self.sync_dir.clone();
        if let Some(max_time) =
            self.load_from_directory(&path, &last_synced_time, fuzzer, executor, state, manager)?
        {
            if last_synced_time.is_none() {
                state
                    .add_metadata(SyncFromDiskMetadata::new(max_time));
            } else {
                state
                    .metadata_mut::<SyncFromDiskMetadata>()
                    .unwrap()
                    .last_time = max_time;
            }
        }

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        Ok(())
    }
}

impl<CB, E, EM, Z> SyncFromAFLStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut Z::State, &Path) -> Result<<Z::State as UsesInput>::Input, Error>,
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasMetadata,
    <Z::State as UsesInput>::Input: HasBytesVec,
{
    /// Creates a new [`SyncFromAFLStage`]
    #[must_use]
    pub fn new(sync_dir: PathBuf, load_callback: CB) -> Self {
        Self {
            sync_dir,
            load_callback,
            phantom: PhantomData,
        }
    }

    fn load_from_directory(
        &mut self,
        in_dir: &Path,
        last: &Option<SystemTime>,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
    ) -> Result<Option<SystemTime>, Error> {
        let mut max_time = None;
        log::info!(target: "sync_from_afl_stage", "Loading from directory: {:?}", in_dir);
        let my_sync_dir = state.metadata::<SyMCTSGlobalMetadata>().unwrap().sync_dir.canonicalize()?;
        for entry in fs::read_dir(in_dir)?.collect::<Vec<_>>().into_iter() {
            let entry = entry?;
            let path = match entry.path().canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    log::warn!(target: "sync_from_afl_stage", "Failed to canonicalize path: {:?}: {:?}", entry.path(), e);
                    continue;
                }
            };
            log::debug!(target: "sync_from_afl_stage", "Found path: {:?} => {:?}", path, entry);

            if path.file_name().unwrap().to_str().unwrap().starts_with(".") {
                continue;
            }

            let attributes = fs::metadata(&path);

            if attributes.is_err() {
                continue;
            }

            let attr = attributes?;

            if attr.is_file() && attr.len() > 0 {
                if let Ok(time) = attr.modified() {
                    log::debug!(target: "sync_from_afl_stage", "Checking time: {:?} > {:?}", time, last);
                    if let Some(l) = last {
                        if time.duration_since(*l).is_err() {
                            continue;
                        }
                    }

                    // if it doesn't start with 'id:', it's not a testcase, so skip it
                    if !path.file_name().unwrap().to_str().unwrap().starts_with("id:") {
                        continue;
                    }

                    log::info!(target: "sync_from_afl_stage", "Loading: {:?}", path);
                    max_time = Some(max_time.map_or(time, |t: SystemTime| t.max(time)));
                    let input = (self.load_callback)(fuzzer, state, &path)?;
                    let hash = hash_target_bytes_input(&input);
                    if state.metadata::<SyMCTSGlobalMetadata>().unwrap().hash_to_corpus_id.contains_key(&hash) {
                        log::warn!(target: "sync_from_afl_stage", "Skipping input with duplicate hash: {:?}", path);
                        continue;
                    }
                    else {
                        if let (ExecuteInputResult::Corpus, Some(corpus_id)) = fuzzer.evaluate_input(state, executor, manager, input)? {
                            let global_meta = state.metadata_mut::<SyMCTSGlobalMetadata>().unwrap();
                            global_meta.synced_inputs_queue.push(corpus_id);
                            global_meta.hash_to_corpus_id.insert(hash, corpus_id);
                        }
                    }
                }
            } else if attr.is_dir() {
                // if the name is symcts_latest, skip it
                if path.file_name().unwrap().to_str().unwrap() == "symcts_latest" {
                    continue;
                }
                // if it's my_sync_dir, skip it
                if path.starts_with(&my_sync_dir) {
                    continue;
                }
                let dir_max_time =
                    self.load_from_directory(&path, last, fuzzer, executor, state, manager)?;
                if let Some(time) = dir_max_time {
                    max_time = Some(max_time.map_or(time, |t: SystemTime| t.max(time)));
                }
            }
        }

        Ok(max_time)
    }
}

/// Function type when the callback in `SyncFromAFLStage` is not a lambda
pub type SyncFromDiskFunction<S, Z> =
    fn(&mut Z, &mut S, &Path) -> Result<<S as UsesInput>::Input, Error>;

impl<E, EM, Z> SyncFromAFLStage<SyncFromDiskFunction<Z::State, Z>, E, EM, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasMetadata,
{
    /// Creates a new [`SyncFromAFLStage`] invoking `Input::from_file` to load inputs
    #[must_use]
    pub fn with_from_file(sync_dir: PathBuf) -> Self {
        fn load_callback<S: UsesInput, Z>(
            _: &mut Z,
            _: &mut S,
            p: &Path,
        ) -> Result<S::Input, Error> {
            Input::from_file(p)
        }
        Self {
            sync_dir,
            load_callback: load_callback::<_, _>,
            phantom: PhantomData,
        }
    }
}

/// Metadata used to store information about the last sent testcase with `SyncFromBrokerStage`
#[derive(Serialize, Deserialize, Debug)]
pub struct SyncFromBrokerMetadata {
    /// The `CorpusId` of the last sent testcase
    pub last_id: Option<CorpusId>,
}

impl_serdeany!(SyncFromBrokerMetadata);

impl SyncFromBrokerMetadata {
    /// Create a new [`struct@SyncFromBrokerMetadata`]
    #[must_use]
    pub fn new(last_id: Option<CorpusId>) -> Self {
        Self { last_id }
    }
}

/// A stage that loads testcases from disk to sync with other fuzzers such as AFL++
#[derive(Debug)]
pub struct SyncFromBrokerStage<IC, ICB, DI, S, SP>
where
    SP: ShMemProvider + 'static,
    S: UsesInput,
    IC: InputConverter<From = S::Input, To = DI>,
    ICB: InputConverter<From = DI, To = S::Input>,
    DI: Input,
{
    client: LlmpEventConverter<IC, ICB, DI, S, SP>,
}

impl<IC, ICB, DI, S, SP> UsesState for SyncFromBrokerStage<IC, ICB, DI, S, SP>
where
    SP: ShMemProvider + 'static,
    S: UsesInput,
    IC: InputConverter<From = S::Input, To = DI>,
    ICB: InputConverter<From = DI, To = S::Input>,
    DI: Input,
{
    type State = S;
}

impl<E, EM, IC, ICB, DI, S, SP, Z> Stage<E, EM, Z> for SyncFromBrokerStage<IC, ICB, DI, S, SP>
where
    EM: UsesState<State = S> + EventFirer,
    S: UsesInput + HasClientPerfMonitor + HasExecutions + HasCorpus + HasRand + HasMetadata,
    SP: ShMemProvider,
    E: HasObservers<State = S> + Executor<EM, Z>,
    for<'a> E::Observers: Deserialize<'a>,
    Z: EvaluatorObservers<E::Observers, State = S> + ExecutionProcessor<E::Observers, State = S>,
    IC: InputConverter<From = S::Input, To = DI>,
    ICB: InputConverter<From = DI, To = S::Input>,
    DI: Input,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        _corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        if self.client.can_convert() {
            let last_id = state
                .metadata::<SyncFromBrokerMetadata>()
                .ok()
                .and_then(|m| m.last_id);

            let mut cur_id =
                last_id.map_or_else(|| state.corpus().first(), |id| state.corpus().next(id));

            while let Some(id) = cur_id {
                let input = state.corpus().get(id)?.borrow_mut().load_input(state.corpus())?.clone();

                self.client.fire(
                    state,
                    Event::NewTestcase {
                        input,
                        observers_buf: None,
                        exit_kind: ExitKind::Ok,
                        corpus_size: 0, // TODO choose if sending 0 or the actual real value
                        client_config: EventConfig::AlwaysUnique,
                        time: current_time(),
                        executions: 0,
                        forward_id: None,
                    },
                )?;

                cur_id = state.corpus().next(id);
            }

            let last = state.corpus().last();
            if last_id.is_none() {
                state
                    .add_metadata(SyncFromBrokerMetadata::new(last));
            } else {
                state
                    .metadata_mut::<SyncFromBrokerMetadata>()
                    .unwrap()
                    .last_id = last;
            }
        }

        self.client.process(fuzzer, state, executor, manager)?;
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();
        Ok(())
    }
}

impl<IC, ICB, DI, S, SP> SyncFromBrokerStage<IC, ICB, DI, S, SP>
where
    SP: ShMemProvider + 'static,
    S: UsesInput,
    IC: InputConverter<From = S::Input, To = DI>,
    ICB: InputConverter<From = DI, To = S::Input>,
    DI: Input,
{
    /// Creates a new [`SyncFromBrokerStage`]
    #[must_use]
    pub fn new(client: LlmpEventConverter<IC, ICB, DI, S, SP>) -> Self {
        Self { client }
    }
}
