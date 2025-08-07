use libafl::observers::concolic::{SymExprRef, SymExpr, Location};
use libafl_bolts::os::{fork, ForkResult};


pub type ConstraintId = usize;
pub type ConstraintKey = (ConstraintId, usize);

pub mod z3_trace_interpreter;

pub use z3_trace_interpreter::Z3TraceInterpreter;
// pub mod interval_trace_interpretation; // range analysis or strided intervals?


#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConstraintMutationSource {
    ConcretizePointer { expr: SymExprRef, value: usize, location: Location },
    ConcretizeSize { expr: SymExprRef, value: usize, location: Location },
    PathConstraint { expr: SymExprRef, taken: bool, location: Location },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConstraintToMutate<BoolType> {

    pub is_divergent: bool,

    // the source of the constraint + how many other constraints originated from this exact place previously
    // (e.g. for concretization it's 0 for the < constraint, 1 for the >, and 2 for the == constraint)
    pub source: (ConstraintMutationSource, usize),

    pub constraint: BoolType,
    pub constraint_guard: BoolType,
    pub location: Location,
    pub key: ConstraintKey,
}

pub trait ConcolicTraceInterpreter {
    type BoolType;
    type BVType;

    fn as_bool(&self, op: SymExprRef) -> Self::BoolType;

    fn as_bv(&self, op: SymExprRef) -> Self::BVType;

    fn unique_constraints_iter(&self) -> impl Iterator<Item = &ConstraintToMutate<Self::BoolType>>;

    fn interpret_message(&mut self, id: SymExprRef, msg: SymExpr);

    fn interpret_messages(&mut self, msgs: Vec<(SymExprRef, SymExpr)>) {
        for (id, msg) in msgs {
            self.interpret_message(id, msg);
        }
    }

    fn interpret_messages_crash_resistant(&mut self, msgs: Vec<(SymExprRef, SymExpr)>) -> Result<(), String> {
        // fork a canary child process that tells us whether or not this will succeed
        match unsafe { fork() } {
            Ok(ForkResult::Parent(child_handle)) => {
                if child_handle.status() == 0 {
                    Ok(self.interpret_messages(msgs))
                } else {
                    Err(format!("forked child crashed with status {}", child_handle.status()))
                }
            },
            Ok(ForkResult::Child) => {
                self.interpret_messages(msgs);
                std::process::exit(0);
            },
            Err(e) => {
                return Err(format!("fork failed: {}", e));
            }
        }
    }
}

