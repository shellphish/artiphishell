#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use anyhow::Result;

use snapchange::addrs::{Cr3, VirtAddr};
use snapchange::fuzzer::{Breakpoint, BreakpointLookup, BreakpointType, Fuzzer};
use snapchange::fuzzvm::FuzzVm;
use snapchange::Execution;
use snapchange::fuzz_input::InputType;
use snapchange::FuzzInput;

// [   26.505214] rc.local[195]: >>> SNAPSHOT Data buffer: 0x55555559c4e0


REPLACEMECOMMENTS

const CR3: Cr3 = Cr3(REPLACEMECR3);
const KCOV_PAGE_ADDRESS: u64 = REPLACEMEKCOV;
const COVERAGE_START:u64 = REPLACEMESTART;
const COVERAGE_STOP:u64 = REPLACEMESTOP;

#[derive(Default)]
pub struct Example1Fuzzer {
    // Fuzzer specific data could go in here
    file_offset: usize,

}

impl Fuzzer for Example1Fuzzer {
    type Input = InputType;
    const START_ADDRESS: u64 = REPLACEMERIP;
    const MAX_INPUT_LENGTH: usize = 1024;
    const MAX_MUTATIONS: u64 = 2;

    fn reset_fuzzer_state(&mut self) {
        // Reset the file offset
        self.file_offset = 0;
    }

    fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        // Write the mutated input

        let mut input_bytes: Vec<u8> = vec![];
        input.to_bytes(&mut input_bytes);
        fuzzvm.write_bytes_dirty(VirtAddr(REPLACEMEDATABUFFER), CR3, &input_bytes)?;

        Ok(())
    }

    fn get_kcov_coverage(&mut self, fuzzvm: &mut FuzzVm<Self>) -> Result<Vec<u64>> {
        // Read the kcov coverage
        fuzzvm.read_kcov_array(VirtAddr(KCOV_PAGE_ADDRESS), CR3)
    }

    fn get_sanitizer_coverage(&mut self, fuzzvm: &mut FuzzVm<Self>) -> Result<Vec<u8>> {
        // Read the 8 bit sanitizer coverage
        fuzzvm.read_sanitizer_array(VirtAddr(COVERAGE_START), VirtAddr(COVERAGE_STOP), CR3)
    }

    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        Some(&[
            Breakpoint {
                lookup: BreakpointLookup::SymbolOffset("libc.so.6!__GI___getpid", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer| {
                    // Set the return value to 0xdeadbeef
                    fuzzvm.set_rax(0xdead_beef);

                    // Fake an immediate return from the function by setting RIP to the
                    // value popped from the stack (this assumes the function was entered
                    // via a `call`)
                    fuzzvm.fake_immediate_return()?;

                    // Continue execution
                    Ok(Execution::Continue)
                },
            },
        ])
    }
}

