use std::{path::{PathBuf, Path}, fs::OpenOptions, io::{Write, Read}};

use libafl::observers::concolic::{serialization_format::MessageFileReader, SymExpr, SymExprRef, ConcolicMetadata};
use libafl_bolts::impl_serdeany;
use serde::{Deserialize, Serialize};
use flate2::{Compression, write::GzEncoder, read::GzDecoder};
use sha2::{Sha256, Digest};

/// A metadata holding a buffer of a concolic trace.
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct DiskBackedConcolicMetadata {
    /// Constraints data
    pub path: PathBuf,
}

pub trait ToDiskBackedConcolicMetadata {
    fn to_disk_backed_metadata(self, sync_dir: &Path, prefix: &str) -> DiskBackedConcolicMetadata;
}
impl ToDiskBackedConcolicMetadata for ConcolicMetadata {
    fn to_disk_backed_metadata(self, sync_dir: &Path, prefix: &str) -> DiskBackedConcolicMetadata {
        let trace_dir = sync_dir.join(".concolic_traces");
        std::fs::create_dir_all(&trace_dir).expect("Could not create concolic trace directory");

        let fname = format!("{}_{:x}", prefix, Sha256::digest(&self.buffer));
        let trace_file_path = trace_dir.join(fname);

        DiskBackedConcolicMetadata::create(PathBuf::from(trace_file_path), &self.buffer)
    }
}



impl DiskBackedConcolicMetadata {
    /// Iterates over all messages in the buffer. Does not consume the buffer.
    pub fn iter_messages(&self) -> impl Iterator<Item = (SymExprRef, SymExpr)> + '_ {
        // mmap file for fast access
        // let file = File::
        let f = OpenOptions::new()
            .read(true)
            .create(false)
            .append(false)
            .truncate(false)
            .open(&self.path)
            .expect(&format!("Concolic trace file backing does not exist?? {:?}", self.path));

        let mut parser = MessageFileReader::from_reader(GzDecoder::new(f));
        std::iter::from_fn(move || parser.next_message()).flatten()
    }

    pub(crate) fn create(path: PathBuf, data: &[u8]) -> Self {
        let mut trace_file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&path)
            .expect("Could not create concolic trace file on disk");
        GzEncoder::new(&mut trace_file, Compression::default())
            .write_all(data)
            .expect("Could not write trace to disk");
        trace_file.flush().expect("Could not flush concolic trace file??");
        drop(trace_file); // should write and close the file so it's in a consistent state
        Self { path }
    }
    pub fn for_path(path: PathBuf) -> Self {
        Self { path }
    }
}

impl_serdeany!(DiskBackedConcolicMetadata);
