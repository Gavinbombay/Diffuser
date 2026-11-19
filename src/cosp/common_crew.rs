#[path = "common.rs"]
mod core;
pub use core::{args, emit, fail, hash, now, opt, read, Failure, Result};
#[path = "common_io.rs"]
mod io;
pub use io::value;
#[path = "common_time.rs"]
mod time;
pub use time::timestamp;
#[path = "common_storage.rs"]
mod storage;
pub use storage::{atomic, client, db, http};
#[path = "common_bridge.rs"]
mod bridge;
pub use bridge::{config, home, protected};
#[path = "common_ack.rs"]
mod ack;
use ack::ack_at;

#[path = "common_ack_wrapper.rs"]
mod ack_wrapper;
pub use ack_wrapper::ack;

#[cfg(test)]
#[path = "common_tests.rs"]
mod tests;
