use std::process::Command;

use sancov_collection::ptrace_coverage_collection::collect_sancov_ptrace;

fn main() {
    let dir = std::path::PathBuf::from("/home/honululu/lukas/research/mctsse/sancov");
    let mut cmd = Command::new(dir.join("test/test_inline_8bit"));
    cmd
        .current_dir(&dir)
        .arg(dir.join("test/input_crash"))
        .env("LD_LIBRARY_PATH", dir.join("target/debug"))
        // .env("LD_PRELOAD", dir.join(""))
        ;
    let cov = collect_sancov_ptrace(cmd, move |_child| {}).expect("error");
    println!("Result: {:#?}", cov);
}
