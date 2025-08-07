#![feature(lazy_cell)]
//! This is a basic SymCC runtime.
//! It traces the execution to the shared memory region that should be passed through the environment by the fuzzer process.
//! Additionally, it concretizes all floating point operations for simplicity.
//! Refer to the `symcc_runtime` crate documentation for building your own runtime.
use std::{collections::{HashMap, binary_heap}, io::{stderr, stdout, Seek, Write}, num::NonZeroUsize, ops::{BitAnd, BitOr, BitXor, Mul}, path::{Path, PathBuf}};
use libafl::observers::concolic::{serialization_format::{Result, BinaryMessageWriter, MessageWriter}, SymExpr as ConcSymExpr, SymExprRef};
use libafl_bolts::shmem::{ShMemProvider, ShMemCursor, StdShMemProvider};
use z3::ast::{Ast, Dynamic, BV, Bool};

use concolic_trace_interpretation::{Z3TraceInterpreter, ConcolicTraceInterpreter};

use symcc_runtime::{
    export_runtime,
    filter::{CallStackCoverage, NoFloat, NoMem},
    tracing::{self, StdShMemBinaryMessageWriter, TracingRuntime},
    Runtime, mem_model::ApproximateMemoryModel,
};

#[export_name = "__SECRET_MY_Z3_ENV"]
pub static mut __SECRET_MY_Z3_ENV: Option<(z3::Config, z3::Context)> = None;

pub struct Z3ApproximateMemoryModel<'z3_ctx> {
    z3_trace_interp: Z3TraceInterpreter<'z3_ctx>,
    opt: z3::Optimize<'z3_ctx>,
}
impl<'z3_ctx> Z3ApproximateMemoryModel<'z3_ctx> {
    fn new(z3_ctx: &'z3_ctx z3::Context) -> Self {
        let opt = z3::Optimize::new(z3_ctx);
        Self {
            z3_trace_interp: Z3TraceInterpreter::new(z3_ctx),
            opt,
        }
    }
}
impl<'z3_ctx> ApproximateMemoryModel for Z3ApproximateMemoryModel<'z3_ctx> {
    fn register_new_expr(&mut self, id: RSymExpr, expr: libafl::observers::concolic::SymExpr) {
        let csts_before = self.z3_trace_interp.constraints_for_mutation().len();
        self.z3_trace_interp.interpret_message(id, expr);
        let csts_after = self.z3_trace_interp.constraints_for_mutation().len();
        for i in csts_before..csts_after {
            let cst = &self.z3_trace_interp.constraints_for_mutation()[i];
            if !cst.is_divergent {
                self.opt.assert(&cst.constraint);
            }
        }
    }
    fn get_exact_pointer_range(&self, expr: RSymExpr) -> Option<(usize, usize)> {
        let bv_expr = self.z3_trace_interp.as_bv(expr);
        assert!(bv_expr.get_size() == 64, "pointer size is not 64 bits??");

        self.opt.push();
        self.opt.maximize(&bv_expr);
        let max_sat = self.opt.check(&[]);
        assert!(max_sat == z3::SatResult::Sat, "maximization failed");
        let model = self.opt.get_model().expect("maximization failed: model retrieval");
        let max = model
                    .eval(&bv_expr, true)
                    .expect("maximization failed: evaluation")
                    .as_u64()
                    .expect("maximization failed: evaluation to u64");
        self.opt.pop();

        self.opt.push();
        self.opt.minimize(&bv_expr);
        let min_sat = self.opt.check(&[]);
        assert!(min_sat == z3::SatResult::Sat, "minimization failed");
        let model = self.opt.get_model().expect("minimization failed: model retrieval");
        let min = model
                    .eval(&bv_expr, true)
                    .expect("minimization failed: evaluation")
                    .as_u64()
                    .expect("minimization failed: evaluation to u64");
        self.opt.pop();
        return Some((min as usize, max as usize));
    }

    fn get_under_approximate_pointer_range(&self, id: RSymExpr) -> Option<(usize, usize)> {
        return None;
    }

    fn get_over_approximate_pointer_range(&self, id: RSymExpr) -> Option<(usize, usize)> {
        return None;
    }
}


#[derive(Debug)]
enum MultiplexMessageWriter {
    File {
        file_writer: BinaryMessageWriter<std::fs::File>,
        num_messages_written: usize,
    },
    Stdout {
        pos: usize,
        num_bytes_written: usize,
        num_messages_written: usize,
    },
    Stderr {
        pos: usize,
        num_bytes_written: usize,
        num_messages_written: usize,
    },
    ShMem {
        shmem: StdShMemBinaryMessageWriter,
        num_messages_written: usize,
    },
    None {
        pos: usize,
        num_bytes_written: usize,
        num_messages_written: usize,
    }
}
impl MultiplexMessageWriter {
    fn for_file_path(path: &Path) -> Self {
        MultiplexMessageWriter::File {
            file_writer: BinaryMessageWriter::from_writer(
                std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(path)
                    .expect(&format!("Could not open MultiplexMessageWriter file path: {:?}", path))
                ).expect(&format!("Could not create BinaryMessageWriter for file stream for {:?}", path)),
            num_messages_written: 0
        }
    }
    fn for_stdout() -> Self {
        MultiplexMessageWriter::Stdout {
            num_bytes_written: 0,
            num_messages_written: 0,
            pos: 0
        }
    }
    fn for_stderr() -> Self {
        MultiplexMessageWriter::Stderr {
            num_bytes_written: 0,
            num_messages_written: 0,
            pos: 0
        }
    }
    fn for_shmem(env_var_name: Option<&str>) -> Self {
        // if env_var_name is given, use that one, otherwise use the default
        MultiplexMessageWriter::ShMem {
            num_messages_written: 0,
            shmem: if let Some(var) = env_var_name {
                StdShMemBinaryMessageWriter::from_stdshmem_env_with_name(var)
            }
            else {
                StdShMemBinaryMessageWriter::from_stdshmem_default_env()
            }
            .unwrap_or_else(|err| {
                eprintln!("unable to construct tracing runtime writer. (missing env?) reason={}", err);
                eprintln!("If you want to disable writing to shared memory (e.g. when running testcases during compilation where shared memory is unavailable), you can set the environment variable SYMCC_DISABLE_WRITING to allow this.");
                panic!("unable to construct tracing runtime writer");
            })
        }
    }
    fn for_none() -> Self {
        MultiplexMessageWriter::None {
            num_bytes_written: 0,
            num_messages_written: 0,
            pos: 0
        }
    }
}

impl MessageWriter for MultiplexMessageWriter {
    fn write_message(&mut self, message: ConcSymExpr) -> Result<SymExprRef> {
        let is_expression = message.is_expression();
        let (res, num_written) = match self {
            MultiplexMessageWriter::File { file_writer, num_messages_written } => {
                (file_writer.write_message(message), num_messages_written)
            },
            MultiplexMessageWriter::Stderr { pos, num_bytes_written, num_messages_written } => {
                let msg = format!("{:x?}: {:?}\n", *num_messages_written+1, &message);

                stderr()
                    .write_all(msg.as_bytes())
                    .expect(&format!("Could not write message {:?} to stderr", message));
                *num_bytes_written += msg.as_bytes().len();
                *pos += msg.as_bytes().len();
                (Ok(NonZeroUsize::try_from(*num_messages_written+1).unwrap()), num_messages_written)
            }
            MultiplexMessageWriter::Stdout { pos, num_bytes_written, num_messages_written } => {
                let msg = format!("{:x?}: {:?}\n", *num_messages_written+1, &message);
                stdout()
                    .write_all(msg.as_bytes())
                    .expect(&format!("Could not write message {:?} to stdout", message));
                *num_bytes_written += msg.as_bytes().len();
                *pos += msg.as_bytes().len();
                (Ok(NonZeroUsize::try_from(*num_messages_written+1).unwrap()), num_messages_written)
            },
            MultiplexMessageWriter::ShMem { shmem, num_messages_written } => {
                (shmem.write_message(message), num_messages_written)
            },
            MultiplexMessageWriter::None { pos, num_bytes_written, num_messages_written } => {
                let msg = format!("{:x?}: {:?}\n", *num_messages_written+1, &message);
                *num_bytes_written += msg.as_bytes().len();
                *pos += msg.as_bytes().len();
                (Ok(NonZeroUsize::try_from(*num_messages_written+1).unwrap()), num_messages_written)
            }
        };
        assert!(res.as_ref().map(|x| x.get() == *num_written+1).unwrap_or(true), "MessageWriter {:?} did not write the correct number of messages", self);
        if is_expression {
            *num_written += 1;
        }
        res
    }
    fn write_trace_size(&mut self) -> std::io::Result<()> {
        match self {
            MultiplexMessageWriter::ShMem { shmem, .. } => shmem.write_trace_size(),
            MultiplexMessageWriter::File { file_writer, .. } => file_writer.write_trace_size(),
            MultiplexMessageWriter::Stderr {..} | MultiplexMessageWriter::Stdout{..} => Ok(()), // do nothing
            MultiplexMessageWriter::None {..} => Ok(()), // do nothing
        }
    }
}

type SymCCRuntime<'z3_ctx> = TracingRuntime<MultiplexMessageWriter, Z3ApproximateMemoryModel<'z3_ctx>, 0x1000>;

fn multiplex_writer_for_trace_output_from_env() -> MultiplexMessageWriter {
    let config = std::env::var("SYMCC_TRACE_OUTPUT").unwrap_or("none".to_string());

    let (message_type, arg) = config
        .split_once("=")
        .map(|(x,y)| (x, Some(y)))
        .unwrap_or((&config, None));
    match message_type {
        "stdout" => MultiplexMessageWriter::for_stdout(),
        "stderr" => MultiplexMessageWriter::for_stderr(),
        "file" => MultiplexMessageWriter::for_file_path(&PathBuf::from(arg.unwrap_or("/tmp/symcc_trace"))),
        "shmem" => MultiplexMessageWriter::for_shmem(arg),
        "none" => MultiplexMessageWriter::for_none(),
        _ => panic!("Unknown message output type: {:?}", message_type),
    }
}

fn parse_bool_env(env_name: &str, default_val: bool) -> bool {
    std::env::var(env_name).map(|x| x.parse::<bool>().unwrap_or(default_val)).unwrap_or(default_val)
}

struct EnvRuntimeConfiguration {
    with_symbolic_input: bool, // should symbolic input be used?
    trace_locations: bool, // whether the trace should contain location information (e.g. BasicBlock, Call, etc.)
    trace_before_symbolic_input: bool, // if false, the trace will only start logging messages once the first symbolic input is encountered
    print_msgs_to_stdout: bool,
    writer: MultiplexMessageWriter,
}
impl EnvRuntimeConfiguration {
    fn from_env() -> Self {
        Self {
            with_symbolic_input: !parse_bool_env("SYMCC_NO_SYMBOLIC_INPUT", false),
            trace_locations: parse_bool_env("SYMCC_TRACE_LOCATIONS", false),
            trace_before_symbolic_input: parse_bool_env("SYMCC_TRACE_BEFORE_SYMBOLIC", false),
            print_msgs_to_stdout: parse_bool_env("SYMCC_PRINT_STDOUT", false),
            writer: multiplex_writer_for_trace_output_from_env()
        }
    }
    fn build_runtime<'z3_ctx>(self, z3_ctx: &'z3_ctx z3::Context) -> SymCCRuntime<'z3_ctx> {
        let z3_approx_mem_model = Z3ApproximateMemoryModel::new(z3_ctx);
        SymCCRuntime::new(
            z3_approx_mem_model,
            if self.with_symbolic_input { Some(self.writer) } else { None },
            self.trace_locations,
            self.print_msgs_to_stdout,
            self.trace_before_symbolic_input,
        )
    }
}
export_runtime!(
    NoFloat => NoFloat;
    NoMem => NoMem;
    CallStackCoverage::default() => CallStackCoverage; // QSym-style expression pruning
    {
        let z3_config = z3::Config::new();
        let z3_ctx = z3::Context::new(&z3_config);
        unsafe {
            __SECRET_MY_Z3_ENV = Some((z3_config, z3_ctx));
        }
        let (_, z3_ctx) = __SECRET_MY_Z3_ENV.as_ref().expect("The constructor should have been called before this function");
        EnvRuntimeConfiguration::from_env().build_runtime(z3_ctx)
    } => SymCCRuntime
);
