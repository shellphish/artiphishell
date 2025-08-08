// Nautilus
// Copyright (C) 2024  Daniel Teuchert, Cornelius Aschermann, Sergej Schumilo

use nix;
use std;

quick_error! {
    #[derive(Debug, Clone)]
    pub enum SpawnError {
        Fork(err: nix::Error) {
            from()
            description("execve failed")
            display("execve error: {}", err)
            cause(err)
        }
        Path(desc: String){
            description("Invalid Path")
            display("Problem with binary path: {}", desc)
        }

        Exec(desc: String){
            description("Execution Failed")
            display("Execution failed: {}", desc)
        }

        FFINull(err: std::ffi::NulError) {
            from()
            description("argument/path contained Null byte")
            display("Null error: {}", err)
            cause(err)
        }
        DevNull(desc: String){
            description("failed to open /dev/null")
            display("failed to open /dev/null: {}", desc)
        }
    }
}

pub fn path_err<T>(desc: &str) -> Result<T, SpawnError> {
    return Err(SpawnError::Path(desc.into()));
}

quick_error! {
    #[derive(Debug)]
    pub enum SubprocessError {
        Spawn(err: SpawnError) {
            from()
            description("spawning failed")
            display("spawning failed: {}", err)
            cause(err)
        }
        Unspecific(desc: String){
            description("Subprocess Failed")
            display("Subprocess failed: {}", desc)
        }
        Io(err: std::io::Error){
            from()
            cause(err)
        }
        Unix(err: nix::Error){
            from()
            cause(err)
        }
    }
}

pub fn descr_err<T>(desc: &str) -> Result<T, SubprocessError> {
    return Err(SubprocessError::Unspecific(desc.into()));
}
