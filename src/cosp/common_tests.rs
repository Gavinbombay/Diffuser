use super::*;
use std::path::Path;
#[test]
fn sha_is_content_addressed() {
    assert_eq!(
        hash(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
#[test]
fn absent_ack_fails_closed() {
    assert_eq!(
        ack_at(Path::new("/nonexistent/cosp"), false).unwrap_err().0,
        62
    );
}
