use std::{path::{PathBuf, Path}, io::Write, process::Command};

use regex::Regex;

pub fn features() -> &'static [&'static str] {
    include!(concat!(env!("OUT_DIR"), "/features.rs"))
}

pub fn git_status() -> &'static str {
    include_str!(concat!(env!("OUT_DIR"), "/git_status.rs"))
}
pub fn git_log() -> &'static str {
    include_str!(concat!(env!("OUT_DIR"), "/git_log.rs"))
}
pub fn git_diff() -> &'static str {
    include_str!(concat!(env!("OUT_DIR"), "/git_diff.rs"))
}

pub fn dump_build_details(out_dir: &PathBuf) {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(out_dir.join(".cargo_features"))
        .unwrap()
        .write_all(features().join("\n").as_bytes())
        .unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(out_dir.join(".git_status"))
        .unwrap()
        .write_all(git_status().as_bytes())
        .unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(out_dir.join(".git_log"))
        .unwrap()
        .write_all(git_log().as_bytes())
        .unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(out_dir.join(".git_diff"))
        .unwrap()
        .write_all(git_diff().as_bytes())
        .unwrap();

}

pub fn dump_binary_and_deps(out_dir: &Path, binary: &Path) {
    // first look up any library dependencies this has
    std::fs::create_dir_all(out_dir).unwrap();
    let mut deps = vec![];
    let mut cmd = Command::new("ldd");
    cmd.arg(binary);
    let output = cmd.output().unwrap();
    let output = String::from_utf8(output.stdout).unwrap();

    // line_regex for lines like:
    // libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007f7f8b7f5000)
    let ldd_line_regex = Regex::new(r"^\s*(?P<lib>.*) => (?P<path>.*) \(0x[0-9a-f]+\)$").unwrap();
    let ldd_line_regex_v2 = Regex::new(r"^\s*(?P<path>.*) \(0x[0-9a-f]+\)$").unwrap();

    for line in output.lines() {
        let line = line.trim_start().trim_end();
        let (lib, lib_path) = match ldd_line_regex.captures(line) {
            Some(caps) => (caps.name("lib").unwrap().as_str(), caps.name("path").unwrap().as_str()),
            None => {
                match ldd_line_regex_v2.captures(line) {
                    Some(caps) => {
                        let path = caps.name("path").unwrap().as_str();
                        let lib = Path::new(path).file_name().unwrap().to_str().unwrap();
                        if lib.starts_with("linux-vdso.so") {
                            continue;
                        }
                        (lib, path)
                    },
                    None => {
                        log::warn!("Could not match string {:?}", line);
                        continue;
                    }
                }
            }
        };

        deps.push((lib.to_string(), lib_path.to_string()));
    }
    log::info!(target: "build_details", "Found dependencies for binary: {:?}: {:?}", binary, deps);

    // copy dependencies to out_dir
    for (libname, libpath) in deps {
        if let Err(e) = std::fs::copy(&libpath, out_dir.join(&libname)) {
            log::warn!("Could not copy library {} @ {:?} to {:?}: {:?}", libname, libpath, out_dir, e);
        }
    }
    // copy binary to out_dir
    std::fs::copy(binary, out_dir.join(binary.file_name().unwrap())).unwrap();
}