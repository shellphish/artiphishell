// build.rs

use std::{
    env,
    io::Write,
    path::PathBuf,
    fs::OpenOptions,
};

use which::which;

fn dump_build_details() {
    // get MANIFEST_DIR to locate the root
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // panic!("manifest_dir: {:?}", manifest_dir);

    // make sure it's the current directory
    env::set_current_dir(&manifest_dir).unwrap();

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let features = env::vars()
        .into_iter()
        .filter_map(|(key, _)| {
            if key.starts_with("CARGO_FEATURE_") {
                Some(key.trim_start_matches("CARGO_FEATURE_").to_string())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    // dump it to features.rs
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(out_dir.join("features.rs"))
        .unwrap()
        .write_all(format!("&[{:?}]", features.join(", ")).as_bytes())
        .unwrap();


    // run git status, git log and git diff and log them as well
    let git_path = which("git")
        .expect("Could not find git??");

    let git_status_out = std::process::Command::new(&git_path)
        .arg("status")
        .output()
        .unwrap();
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(out_dir.join("git_status.rs"))
        .unwrap()
        .write_all(&git_status_out.stdout)
        .unwrap();

    let git_log_out = std::process::Command::new(&git_path)
        .arg("log")
        .args(&["-n", "1"])
        .output()
        .unwrap();
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(out_dir.join("git_log.rs"))
        .unwrap()
        .write_all(&git_log_out.stdout)
        .unwrap();

    let git_diff_out = std::process::Command::new(&git_path)
        .arg("diff")
        .output()
        .unwrap();
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(out_dir.join("git_diff.rs"))
        .unwrap()
        .write_all(&git_diff_out.stdout)
        .unwrap();
}

fn main() {
    // make sure this script always gets rerun
    println!("cargo:rerun-if-changed=build.rs");

    // dump the features
    dump_build_details();
}
