//! Worker lifecycle backed by the vendored Codex Linux helpers.
use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[path = "../third_party/codex/codex-rs/process-hardening/src/lib.rs"]
mod hardening;
#[path = "../third_party/codex/codex-rs/utils/pty/src/linux_fds.rs"]
mod linux_fds;
#[path = "../third_party/codex/codex-rs/utils/pty/src/process_group.rs"]
mod process_group;

pub fn spawn(cmd: &mut Command) -> io::Result<Child> {
    let parent = std::process::id() as libc::pid_t;
    cmd.stdin(Stdio::null());
    // Only allocation-free child operations between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            process_group::set_process_group()?;
            process_group::set_parent_death_signal(parent)?;
            hardening::set_core_file_size_limit_to_zero()?;
            hardening::disable_process_dumping()?;
            linux_fds::close_inherited_fds_except(&[])?;
            Ok(())
        });
    }
    cmd.spawn()
}

pub fn terminate(pid: u32) {
    let _ = process_group::terminate_process_group(pid);
}

pub struct Completion {
    pub status: ExitStatus,
    pub state: &'static str,
}

/// Wait-loop states. Terminal states refuse all further events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Running,
    StoppingTimeout,
    StoppingCancel,
    Done,
    TimedOut,
    Cancelled,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Poll,
    Deadline,
    Cancel,
    Exit,
    GraceElapsed,
    IoError,
}
pub fn transition(state: &mut State, event: Event) -> Result<(), &'static str> {
    use Event::*;
    use State::*;
    let next = match (*state, event) {
        (Running, Poll) => Running,
        (Running, Deadline) => StoppingTimeout,
        (Running, Cancel) => StoppingCancel,
        (Running, Exit) => Done,
        (Running | StoppingTimeout | StoppingCancel, IoError) => Failed,
        (StoppingTimeout, Poll) => StoppingTimeout,
        (StoppingCancel, Poll) => StoppingCancel,
        (StoppingTimeout, Exit | GraceElapsed) => TimedOut,
        (StoppingCancel, Exit | GraceElapsed) => Cancelled,
        _ => return Err(crate::error_catalog::ILLEGAL_TRANSITION),
    };
    *state = next;
    Ok(())
}

#[cfg(test)]
mod run37_state_tests {
    use super::{transition, Event, State};

    #[test]
    fn run37_w1_exhaustive_transition_table() {
        use Event::{Cancel, Deadline, Exit, GraceElapsed, IoError, Poll};
        use State::{Cancelled, Done, Failed, Running, StoppingCancel, StoppingTimeout, TimedOut};
        let events = [Poll, Deadline, Cancel, Exit, GraceElapsed, IoError];
        let rows = [
            (
                Running,
                [
                    Some(Running),
                    Some(StoppingTimeout),
                    Some(StoppingCancel),
                    Some(Done),
                    None,
                    Some(Failed),
                ],
            ),
            (
                StoppingTimeout,
                [
                    Some(StoppingTimeout),
                    None,
                    None,
                    Some(TimedOut),
                    Some(TimedOut),
                    Some(Failed),
                ],
            ),
            (
                StoppingCancel,
                [
                    Some(StoppingCancel),
                    None,
                    None,
                    Some(Cancelled),
                    Some(Cancelled),
                    Some(Failed),
                ],
            ),
            (Done, [None; 6]),
            (TimedOut, [None; 6]),
            (Cancelled, [None; 6]),
            (Failed, [None; 6]),
        ];
        assert_eq!(rows.len() * events.len(), 42);
        let mut checked = 0;
        for (initial, expected) in rows {
            for (event, next) in events.into_iter().zip(expected) {
                let mut actual = initial;
                let result = transition(&mut actual, event);
                match next {
                    Some(next) => {
                        assert_eq!(result, Ok(()), "{initial:?}/{event:?}");
                        assert_eq!(actual, next, "{initial:?}/{event:?}");
                    }
                    None => {
                        assert_eq!(
                            result,
                            Err(crate::error_catalog::ILLEGAL_TRANSITION),
                            "{initial:?}/{event:?}"
                        );
                        assert_eq!(actual, initial, "refusal changed {initial:?}/{event:?}");
                        assert_eq!(
                            crate::error_catalog::lookup(None, result.unwrap_err())
                                .unwrap()
                                .code,
                            crate::error_catalog::ILLEGAL_TRANSITION
                        );
                    }
                }
                checked += 1;
            }
        }
        assert_eq!(checked, 42);
    }
}
fn completion_state(state: State) -> &'static str {
    match state {
        State::Done => "done",
        State::TimedOut => "timed_out",
        State::Cancelled => "cancelled",
        _ => unreachable!("completion requires a terminal success state"),
    }
}

pub fn wait(
    child: &mut Child,
    deadline: Instant,
    grace: Duration,
    mut cancelled: impl FnMut() -> bool,
) -> io::Result<Completion> {
    let pid = child.id();
    let mut term_at = None;
    let mut state = State::Running;
    loop {
        // Check the deadline even if the leader just exited. Remaining group
        // members must never outlive this worker attempt.
        if term_at.is_none() && (Instant::now() >= deadline || cancelled()) {
            let event = if Instant::now() >= deadline {
                Event::Deadline
            } else {
                Event::Cancel
            };
            transition(&mut state, event).expect("active worker");
            terminate(pid);
            term_at = Some(Instant::now());
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let _ = process_group::kill_process_group(pid);
                transition(&mut state, Event::Exit).expect("active worker");
                return Ok(Completion {
                    status,
                    state: completion_state(state),
                });
            }
            Err(err) => {
                transition(&mut state, Event::IoError).expect("active worker");
                let _ = process_group::kill_process_group(pid);
                let _ = child.wait();
                return Err(err);
            }
            Ok(None) => {
                transition(&mut state, Event::Poll).expect("active worker");
            }
        }
        if term_at.is_some_and(|at| Instant::now().duration_since(at) >= grace) {
            if let Err(err) = process_group::kill_process_group(pid) {
                transition(&mut state, Event::IoError).expect("active worker");
                let _ = child.kill();
                let _ = child.wait();
                return Err(err);
            }
            let status = child.wait().inspect_err(|_| {
                transition(&mut state, Event::IoError).expect("active worker");
            })?;
            transition(&mut state, Event::GraceElapsed).expect("stopping worker");
            return Ok(Completion {
                status,
                state: completion_state(state),
            });
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests;
