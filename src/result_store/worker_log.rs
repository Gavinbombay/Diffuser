//! Bounded stdout/stderr capture. No unbounded worker output reaches disk.
use std::io::{self, Read};
use std::path::Path;
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

#[path = "../../third_party/codex/codex-rs/utils/head-tail-buffer/src/lib.rs"]
mod head_tail;
use head_tail::HeadTailBuffer;

pub fn read(input: impl Read, cap: usize) -> io::Result<Vec<u8>> {
    let buffer = Arc::new(Mutex::new(HeadTailBuffer::new(cap)));
    drain(input, buffer.clone())?;
    let data = buffer.lock().unwrap().to_bytes_with_omission_marker();
    Ok(data)
}
pub fn bounded(input: &str, cap: usize) -> String {
    String::from_utf8_lossy(&read(input.as_bytes(), cap).expect("memory log read")).into_owned()
}
/// Bound and redact controller evidence through the same drain as worker logs.
pub fn emit(writer: &mut impl io::Write, input: &[u8], cap: usize) -> io::Result<()> {
    writer.write_all(&read(input, cap)?)
}
pub fn write(path: &Path, input: &[u8], cap: usize) -> io::Result<()> {
    std::fs::write(path, read(input, cap)?)
}
pub fn append(path: &Path, input: &str, cap: usize) -> io::Result<()> {
    static LOG_WRITE: Mutex<()> = Mutex::new(());
    let _guard = LOG_WRITE.lock().unwrap();
    let mut data = match std::fs::File::open(path) {
        Ok(file) => read(file, cap)?,
        Err(err) if err.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(err),
    };
    data.extend_from_slice(input.as_bytes());
    write(path, &data, cap)
}
pub fn document(input: &serde_json::Value, cap: usize) -> serde_json::Value {
    fn visit(value: &mut serde_json::Value, log_field: bool, cap: usize) {
        match value {
            serde_json::Value::String(text) if log_field => *text = bounded(text, cap),
            serde_json::Value::Array(values) => {
                values.iter_mut().for_each(|v| visit(v, log_field, cap))
            }
            serde_json::Value::Object(values) => {
                for (field, value) in values {
                    let inline = log_field
                        || ((field.contains("log")
                            || ["stdout", "stderr"].contains(&field.as_str()))
                            && !["device_log", "adapter_log"].contains(&field.as_str()));
                    visit(value, inline, cap);
                }
            }
            _ => {}
        }
    }
    let mut output = input.clone();
    visit(&mut output, false, cap);
    output
}
pub fn status(input: &serde_json::Value, cap: usize) -> serde_json::Value {
    let mut output = document(input, cap);
    if let (Some(root), Some(chunks)) = (input["out"].as_str(), input["chunks"].as_array()) {
        if let Ok(root) = std::fs::canonicalize(root) {
            let mut tails = Vec::new();
            for chunk in chunks {
                if let Some(name) = chunk["adapter_log"].as_str() {
                    if let Ok(path) = std::fs::canonicalize(root.join(name)) {
                        if path.starts_with(&root) && path.is_file() {
                            if let Ok(data) = std::fs::File::open(path).and_then(|f| read(f, cap)) {
                                tails.push(serde_json::Value::String(
                                    String::from_utf8_lossy(&data).into_owned(),
                                ));
                            }
                        }
                    }
                }
            }
            if !tails.is_empty() {
                output["log_tail"] = serde_json::Value::Array(tails);
            }
        }
    }
    output
}

pub struct Capture {
    buffers: [Arc<Mutex<HeadTailBuffer>>; 2],
    cap: usize,
    readers: Vec<JoinHandle<io::Result<()>>>,
}
fn drain(mut input: impl Read, buffer: Arc<Mutex<HeadTailBuffer>>) -> io::Result<()> {
    // Bound individual lines as well as retained output. Keep a complete line
    // until sanitization so a read boundary cannot bisect a sensitive value.
    const LINE_MAX: usize = 65536;
    let mut chunk = [0; 8192];
    let mut line = Vec::new();
    let mut oversized = false;
    let flush = |line: &[u8], oversized: bool| {
        let text = if oversized {
            "[R: oversized log line omitted]\n".to_owned()
        } else {
            crate::log_redaction::line(&String::from_utf8_lossy(line))
        };
        buffer.lock().unwrap().push_chunk(text.as_bytes());
    };
    loop {
        let n = match input.read(&mut chunk) {
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if n == 0 {
            if oversized || !line.is_empty() {
                flush(&line, oversized);
            }
            return Ok(());
        }
        for &byte in &chunk[..n] {
            if !oversized {
                if line.len() == LINE_MAX {
                    oversized = true;
                    line.clear();
                } else {
                    line.push(byte);
                }
            }
            if byte == b'\n' {
                flush(&line, oversized);
                line.clear();
                oversized = false;
            }
        }
    }
}
impl Capture {
    pub fn start(child: &mut Child, cap: usize) -> Self {
        let buffers = [
            Arc::new(Mutex::new(HeadTailBuffer::new(cap))),
            Arc::new(Mutex::new(HeadTailBuffer::new(cap))),
        ];
        let stdout = child.stdout.take().expect("piped worker stdout");
        let stderr = child.stderr.take().expect("piped worker stderr");
        let first = buffers[0].clone();
        let second = buffers[1].clone();
        Self {
            buffers,
            cap,
            readers: vec![
                thread::spawn(move || drain(stdout, first)),
                thread::spawn(move || drain(stderr, second)),
            ],
        }
    }
    pub fn finish(self, path: &Path) -> io::Result<()> {
        let mut failure = None;
        for reader in self.readers {
            if let Err(err) = reader
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("worker log reader panicked")))
            {
                failure = Some(err);
            }
        }
        if let Some(err) = failure {
            return Err(err);
        }
        // Each pipe is drained and redacted concurrently within its own cap.
        // Fixed stdout then stderr ordering removes reader scheduling from logs.
        let first = self.buffers[0]
            .lock()
            .unwrap()
            .to_bytes_with_omission_marker();
        let second = self.buffers[1]
            .lock()
            .unwrap()
            .to_bytes_with_omission_marker();
        if first.is_empty() {
            return write_captured(path, &second);
        }
        if second.is_empty() {
            return write_captured(path, &first);
        }
        let mut combined = HeadTailBuffer::new(self.cap);
        combined.push_chunk(&first);
        combined.push_chunk(&second);
        write_captured(path, &combined.to_bytes_with_omission_marker())
    }
}

fn write_captured(path: &Path, data: &[u8]) -> io::Result<()> {
    std::fs::write(path, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn captured(body: &str, cap: usize) -> Vec<u8> {
        let root = std::env::temp_dir().join(format!(
            "run22-log-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let script = root.join("child.py");
        fs::write(&script, body).unwrap();
        let mut cmd = Command::new("python3");
        cmd.arg(script)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = crate::worker_process::spawn(&mut cmd).unwrap();
        let capture = Capture::start(&mut child, cap);
        let done = crate::worker_process::wait(
            &mut child,
            Instant::now() + Duration::from_secs(5),
            Duration::ZERO,
            || false,
        )
        .unwrap();
        assert!(done.status.success());
        let path = root.join("worker.log");
        capture.finish(&path).unwrap();
        let data = fs::read(path).unwrap();
        fs::remove_dir_all(root).unwrap();
        data
    }
    #[test]
    fn under_cap_kept_whole() {
        let data = captured(
            "import sys\nsys.stdout.write('first line\\n')\nsys.stderr.write('second line\\n')\n",
            100,
        );
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("first line\n"));
        assert!(text.contains("second line\n"));
        assert_eq!(text.len(), 23);
    }
    #[test]
    fn over_cap_keeps_head_and_tail_with_marker() {
        let data = captured(
            "import sys\nsys.stdout.write('HEAD1234 middle omitted content TAIL5678')\n",
            16,
        );
        assert_eq!(
            String::from_utf8(data).unwrap(),
            "HEAD1234\n... 24 bytes omitted ...\nTAIL5678"
        );
    }
    #[test]
    fn cap_default_read() {
        let cfg = super::super::Config::from_value(&serde_json::json!({}));
        assert_eq!(cfg.worker_log_max, 65536);
        let custom = super::super::Config::from_value(
            &serde_json::json!({"result_storage":{"worker_log_max_bytes":17}}),
        );
        assert_eq!(custom.worker_log_max, 17);
    }

    #[test]
    fn assignment_value_redacted() {
        let data = captured("print('api_key = placeholdervalue')\n", 100);
        assert_eq!(
            String::from_utf8(data).unwrap(),
            "api_key = [REDACTED_SECRET]\n"
        );
        // Exercise the event disk path too, including nested strings.
        let root = std::env::temp_dir().join(format!(
            "run22-event-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let store = super::super::Store::new(&root, super::super::Config::default());
        store
            .write_device(
                "tts",
                "job-1",
                1,
                &serde_json::json!({"events":[{"reason":"api_key = placeholdervalue"}]}),
            )
            .unwrap();
        let data =
            fs::read_to_string(root.join("lanes/tts/jobs/job-1/attempts/1/device.json")).unwrap();
        assert!(data.contains("api_key = [REDACTED_SECRET]"));
        assert!(!data.contains("placeholdervalue"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bearer_value_redacted() {
        let data = captured("print('Bearer placeholderwordsabc')\n", 100);
        assert_eq!(
            String::from_utf8(data).unwrap(),
            "Bearer [REDACTED_SECRET]\n"
        );
        let bounded = captured("print('Bearer placeholderwordsabc')\n", 8);
        assert_eq!(
            String::from_utf8(bounded).unwrap(),
            "Bear\n... 17 bytes omitted ...\nET]\n"
        );
    }

    #[test]
    fn clean_line_unchanged() {
        let data = captured("print('worker finished cleanly')\n", 100);
        assert_eq!(data, b"worker finished cleanly\n");
    }
}

#[cfg(test)]
mod run36_v5 {
    use super::super::{Config, Store};
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    fn inventory(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn walk(root: &Path, folder: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(folder).unwrap() {
                let entry = entry.unwrap();
                assert!(!entry.file_type().unwrap().is_symlink());
                if entry.file_type().unwrap().is_dir() {
                    walk(root, &entry.path(), files);
                } else {
                    files.insert(
                        entry.path().strip_prefix(root).unwrap().to_owned(),
                        fs::read(entry.path()).unwrap(),
                    );
                }
            }
        }
        let mut files = BTreeMap::new();
        walk(root, root, &mut files);
        files
    }

    #[test]
    fn run36_v5_worker_log_store_refusals_preserve_good_results() {
        let modules: std::collections::BTreeSet<_> =
            fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/result_store"))
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
        assert_eq!(
            modules,
            std::collections::BTreeSet::from(["worker_log.rs".to_owned()])
        );
        let root = std::env::temp_dir().join(format!(
            "run36-results-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("outside-store"), b"[R] untouched\n").unwrap();
        let store_root = root.join("results");
        let store = Store::new(&store_root, Config::default());
        let good = read(b"[R] good result\n".as_slice(), 128).unwrap();
        let sha = store
            .put_named_artifact("tts", Path::new("speech.wav"), &good, None)
            .unwrap();
        let good_log = store_root.join("good.log");
        write(&good_log, &good, 128).unwrap();
        store
            .write_device(
                "tts",
                "good",
                1,
                &serde_json::json!({"log":bounded("[R] completed\n", 128)}),
            )
            .unwrap();
        let disk = inventory(&root);
        let other = super::super::digest(b"[R] other result\n");
        for (row, code) in [
            (0, crate::error_catalog::PATH_UNSAFE),
            (1, crate::error_catalog::BAD_DIGEST),
            (2, crate::error_catalog::STORAGE_UNAVAILABLE),
        ] {
            let reason = match row {
                0 => store
                    .put_named_artifact("tts", Path::new("../outside-store"), &good, None)
                    .map(|_| ()),
                1 => store
                    .put_named_artifact("tts", Path::new("speech.wav"), &good, Some(&other))
                    .map(|_| ()),
                // Simulate a partial worker-log write to the staged file before
                // the actual atomic publish rehash, entirely inside this root.
                2 => store.atomic_hook(&good_log, b"[R] replacement log\n", |path| {
                    write(path, b"[R] partial", 128).unwrap()
                }),
                _ => unreachable!(),
            }
            .unwrap_err();
            assert_eq!(reason, code);
            assert_eq!(
                crate::error_catalog::lookup(None, reason).unwrap().code,
                code
            );
            assert_eq!(store.get_artifact("tts", &sha).unwrap(), good);
            assert_eq!(read(fs::File::open(&good_log).unwrap(), 128).unwrap(), good);
            assert_eq!(
                inventory(&root),
                disk,
                "refusal changed an existing result or escaped the store: row {row}"
            );
            assert_eq!(fs::read_dir(store_root.join("tmp")).unwrap().count(), 0);
        }
        fs::remove_dir_all(root).unwrap();
    }
}
