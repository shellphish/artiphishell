// Nautilus
// Copyright (C) 2024  Daniel Teuchert, Cornelius Aschermann, Sergej Schumilo

use nix::sys::wait::WaitStatus;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExitReason {
    Normal(i32),
    Timeouted,
    Signaled(i32),
    Stopped(i32),
}

impl ExitReason {
    pub fn from_wait_status(status: WaitStatus) -> ExitReason {
        return match status {
            WaitStatus::Exited(_, return_value) => ExitReason::Normal(return_value),
            WaitStatus::Signaled(_, signal, _) => ExitReason::Signaled(signal as i32),
            WaitStatus::Stopped(_, signal) => ExitReason::Stopped(signal as i32),
            _ => panic!("Unknown WaitStatus: {:?}", status),
        };
    }
}
