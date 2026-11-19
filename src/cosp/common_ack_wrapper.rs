use super::{ack_at, Result};
use std::path::Path;

pub fn ack() -> Result<()> {
    if let Some(r) = std::env::var_os("LANE_JOB_ROOT") {
        ack_at(Path::new(&r), false)?;
    }
    Ok(())
}
