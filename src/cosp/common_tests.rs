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
#[test]
fn ack_requires_staged_rules_and_precedes_work() {
    let root = std::env::temp_dir().join(format!(
        "diffuser-ack-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let staged = root.join("stage/INPUTS/rules");
    std::fs::create_dir_all(&staged).unwrap();
    std::fs::create_dir_all(root.join("out/evidence")).unwrap();
    let rules = b"# Rules\nVersion 1\n";
    let connect = b"# Connect\n";
    std::fs::write(staged.join("RULES.md"), rules).unwrap();
    std::fs::write(staged.join("CONNECT.md"), connect).unwrap();
    std::fs::write(root.join("out/early.txt"), b"work").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    let ack = format!("{}\n{}\nVersion 1\n", hash(rules), hash(connect));
    std::fs::write(root.join("out/evidence/ACK.md"), ack).unwrap();
    assert_eq!(ack_at(&root, false).unwrap()["ack_verified"], true);
    assert_eq!(ack_at(&root, true).unwrap_err().1, "ack_written_after_work");
    std::fs::remove_dir_all(&root).unwrap();
}
