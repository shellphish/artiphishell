use z3::SatResult;
use z3::ast::Bool;
use std::time::Instant;

pub trait TimedSolver<'ctx> {
    fn timed_check_assumptions(&self, assumptions: &[&Bool<'ctx>]) -> SatResult;
}

impl<'ctx> TimedSolver<'ctx> for z3::Solver<'ctx> {
    fn timed_check_assumptions(&self, assumptions: &[&Bool<'ctx>]) -> SatResult {
        println!("Calling Solver.check([{} assumptions])", assumptions.len());
        let start = Instant::now();
        let res = self.check_assumptions(assumptions);
        let duration = start.elapsed();
        println!("Solver.check([{} assumptions]) = {:?} took {:?}", assumptions.len(), res, duration);
        res
    }
}

// global variable counting the number of times the solver is called
// static mut SOLVER_CALLS: u64 = 0;

impl<'ctx> TimedSolver<'ctx> for z3::Optimize<'ctx> {
    fn timed_check_assumptions(&self, assumptions: &[&Bool<'ctx>]) -> SatResult {
        // println!("Calling Optimize.check([{} assumptions])", assumptions.len());
        // let now = SystemTime::now();
        // let start = Instant::now();
        let res = self.check(assumptions);
        // let duration = start.elapsed();
        // log::info!("Optimize.check([{} assumptions]) = {:?} took {:?}", assumptions.len(), res, duration);
        // let solver_string = self.to_string();

        // let dir = "solver_states_new";

        // let mut file = std::fs::File::create(format!("{}/{}_{:?}.smt2", dir, unsafe { &SOLVER_CALLS }, res)).unwrap();
        // unsafe { SOLVER_CALLS += 1; }
        // file.write_all(solver_string.as_bytes()).unwrap();

        // if res == SatResult::Unsat {
        //     println!("Unsat core: {:?}", self.get_unsat_core());
        // }
        res
    }
}
