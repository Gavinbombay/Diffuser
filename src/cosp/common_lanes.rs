#[path = "common.rs"]
mod core;
pub use core::{args, emit, fail, hash, opt, qc_gate_path, read, Failure, Result};
#[path = "common_io.rs"]
mod io;
pub use io::value;
#[path = "common_ack.rs"]
mod ack;
pub use ack::ack_at;
#[path = "common_contains.rs"]
mod contains;
pub use contains::contains_banned_name;

#[path = "common_ack_wrapper.rs"]
mod ack_wrapper;
pub use ack_wrapper::ack;

#[cfg(test)]
#[path = "common_tests.rs"]
mod tests;
