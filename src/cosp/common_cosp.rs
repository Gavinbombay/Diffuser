#[path = "common.rs"]
mod core;
pub use core::{args, emit, fail, hash, now, opt, read, Failure, Result};
#[path = "common_time.rs"]
mod time;
pub use time::timestamp;
#[path = "common_storage.rs"]
mod storage;
pub use storage::{atomic, db, http};
#[path = "common_contains.rs"]
mod contains;
pub use contains::contains_banned_name;

#[cfg(test)]
#[path = "common_ack.rs"]
mod ack;
#[cfg(test)]
use ack::ack_at;

#[cfg(test)]
#[path = "common_tests.rs"]
mod tests;
