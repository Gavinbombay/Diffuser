use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
};

const HEADER: &str = "ts,job_id,segment,event,balance,delta,floor,gpu_class,reason\n";

pub(crate) struct Entry<'a> {
    pub ts: &'a str,
    pub job_id: &'a str,
    pub segment: u64,
    pub event: &'a str,
    pub balance: f64,
    pub delta: f64,
    pub floor: f64,
    pub gpu_class: &'a str,
    pub reason: &'a str,
}

fn csv(value: &str) -> String {
    format!(
        "\"{}\"",
        crate::log_redaction::line(value).replace('"', "\"\"")
    )
}

pub(crate) fn append(root: &Path, entry: &Entry<'_>) -> io::Result<()> {
    let id = entry.job_id;
    if !(3..=96).contains(&id.len())
        || !id.as_bytes()[0].is_ascii_lowercase() && !id.as_bytes()[0].is_ascii_digit()
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        || !entry.balance.is_finite()
        || !entry.delta.is_finite()
        || !entry.floor.is_finite()
        || entry.floor < 0.0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid ledger entry",
        ));
    }
    if entry.balance < 0.0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            crate::error_catalog::CU_FLOOR,
        ));
    }
    let row = format!(
        "{},{},{},{},{},{},{},{},{}",
        csv(entry.ts),
        csv(id),
        entry.segment,
        csv(entry.event),
        entry.balance,
        entry.delta,
        entry.floor,
        csv(entry.gpu_class),
        csv(entry.reason)
    );
    let dir = root.join(id);
    fs::create_dir_all(&dir)?;
    let path = dir.join("cu.csv");
    // Callers serialize each job. Identity is the complete sanitized CSV row,
    // so distinct balance observations in the same second remain valid.
    match fs::read_to_string(&path) {
        Ok(content) if content.lines().skip(1).any(|line| line == row) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                crate::error_catalog::INVALID_REPORT,
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    if file.metadata()?.len() == 0 {
        file.write_all(HEADER.as_bytes())?;
    }
    writeln!(file, "{row}")?;
    file.sync_data()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry<'a>(id: &'a str) -> Entry<'a> {
        Entry {
            ts: "2026-10-31T12:00:00Z",
            job_id: id,
            segment: 0,
            event: "admit",
            balance: 12.5,
            delta: 0.0,
            floor: 5.0,
            gpu_class: "l4",
            reason: "",
        }
    }
    fn root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ledger-{}-{:?}",
            std::process::id(),
            (
                std::thread::current().id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )
        ))
    }
    #[test]
    fn admission_row_and_column_order() {
        let root = root();
        append(&root, &entry("job-123")).unwrap();
        let content = fs::read_to_string(root.join("job-123/cu.csv")).unwrap();
        assert_eq!(
            content,
            format!(
                "{HEADER}\"2026-10-31T12:00:00Z\",\"job-123\",0,\"admit\",12.5,0,5,\"l4\",\"\"\n"
            )
        );
    }
    #[test]
    fn subsequent_events_append_without_another_header() {
        let root = root();
        append(&root, &entry("job-234")).unwrap();
        let mut e = entry("job-234");
        e.event = "resume";
        e.reason = "exit, \"75\"";
        append(&root, &e).unwrap();
        let content = fs::read_to_string(root.join("job-234/cu.csv")).unwrap();
        assert_eq!(content.matches(HEADER).count(), 1);
        assert!(content.contains("\"exit, \"\"75\"\"\""));
    }
    #[test]
    fn rejects_unsafe_identifiers() {
        assert!(append(&root(), &entry("../bad")).is_err());
    }
    #[test]
    fn write_failure_is_returned() {
        let root = root();
        fs::write(&root, b"file").unwrap();
        assert!(append(&root, &entry("job-345")).is_err());
    }
    #[test]
    fn rejects_invalid_balance() {
        let mut e = entry("job-456");
        e.balance = f64::NAN;
        assert!(append(&root(), &e).is_err());
    }
    #[test]
    fn run30_replay_has_byte_identical_totals() {
        let root = root();
        let mut events = vec![
            entry("job-replay"),
            entry("job-replay"),
            entry("job-replay"),
        ];
        events[1].event = "poll";
        events[1].balance = 9.0;
        events[1].delta = -3.5;
        events[2].event = "done";
        events[2].balance = 0.0;
        events[2].delta = -9.0;
        for event in &events {
            append(&root, event).unwrap();
        }
        let before = fs::read(root.join("job-replay/cu.csv")).unwrap();
        let totals = |bytes: &[u8]| {
            let content = std::str::from_utf8(bytes).unwrap();
            let mut balance = 0.0_f64;
            let mut delta = 0.0_f64;
            for line in content.lines().skip(1) {
                let fields: Vec<_> = line.split(',').collect();
                balance = fields[4].parse().unwrap();
                delta += fields[5].parse::<f64>().unwrap();
                assert!(balance >= 0.0);
            }
            serde_json::to_vec(&serde_json::json!({"balance":balance,"delta":delta})).unwrap()
        };
        assert_eq!(totals(&before), br#"{"balance":0.0,"delta":-12.5}"#);
        for event in &events {
            assert_eq!(
                append(&root, event).unwrap_err().to_string(),
                crate::error_catalog::INVALID_REPORT
            );
        }
        let after = fs::read(root.join("job-replay/cu.csv")).unwrap();
        assert_eq!(totals(&before), totals(&after));
        assert_eq!(before, after);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn run30_duplicate_event_refused_without_write() {
        let root = root();
        let e = entry("job-duplicate");
        append(&root, &e).unwrap();
        let before = fs::read(root.join("job-duplicate/cu.csv")).unwrap();
        let error = append(&root, &e).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), crate::error_catalog::INVALID_REPORT);
        assert_eq!(fs::read(root.join("job-duplicate/cu.csv")).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn run30_totals_never_below_zero() {
        let root = root();
        let mut e = entry("job-nonnegative");
        for balance in [12.5, 1.0, 0.0] {
            e.balance = balance;
            append(&root, &e).unwrap();
        }
        let before = fs::read(root.join("job-nonnegative/cu.csv")).unwrap();
        for balance in [-0.01, -f64::MAX] {
            e.balance = balance;
            assert_eq!(
                append(&root, &e).unwrap_err().to_string(),
                crate::error_catalog::CU_FLOOR
            );
            assert_eq!(
                fs::read(root.join("job-nonnegative/cu.csv")).unwrap(),
                before
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod run37_csv_tests {
    use super::*;
    use std::path::PathBuf;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "run37-csv-{}-{:?}-{}",
                std::process::id(),
                std::thread::current().id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    // Independent record reader: quoted fields may contain delimiters, escaped
    // quotes and physical newlines. Reject malformed field endings and quotes.
    fn records(input: &str) -> Vec<Vec<String>> {
        let mut rows = Vec::new();
        let mut row = Vec::new();
        let mut field = String::new();
        let mut quoted = false;
        let mut closed = false;
        let mut chars = input.chars().peekable();
        while let Some(ch) = chars.next() {
            if quoted {
                if ch == '"' {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        field.push('"');
                    } else {
                        quoted = false;
                        closed = true;
                    }
                } else {
                    field.push(ch);
                }
            } else {
                match ch {
                    '"' => {
                        assert!(field.is_empty() && !closed);
                        quoted = true;
                    }
                    ',' => {
                        row.push(std::mem::take(&mut field));
                        closed = false;
                    }
                    '\n' => {
                        row.push(std::mem::take(&mut field));
                        rows.push(std::mem::take(&mut row));
                        closed = false;
                    }
                    _ => {
                        assert!(!closed, "characters after closing quote");
                        field.push(ch);
                    }
                }
            }
        }
        assert!(
            !quoted && !closed && field.is_empty() && row.is_empty(),
            "unfinished CSV record"
        );
        rows
    }

    fn entry(reason: &str, segment: u64) -> Entry<'_> {
        Entry {
            ts: "2026-11-02T12:00:00Z",
            job_id: "job-csv",
            segment,
            event: "poll",
            balance: 12.5,
            delta: -1.0,
            floor: 5.0,
            gpu_class: "l4",
            reason,
        }
    }

    fn inventory(root: &Path) -> Vec<String> {
        fn visit(root: &Path, path: &Path, found: &mut Vec<String>) {
            for child in fs::read_dir(path).unwrap() {
                let child = child.unwrap().path();
                assert!(!child.is_symlink());
                assert!(child
                    .canonicalize()
                    .unwrap()
                    .starts_with(root.canonicalize().unwrap()));
                found.push(
                    child
                        .strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                );
                if child.is_dir() {
                    visit(root, &child, found);
                }
            }
        }
        let mut found = Vec::new();
        visit(root, root, &mut found);
        found.sort();
        found
    }

    #[test]
    fn run37_w3_reason_fields_round_trip() {
        let scratch = Scratch::new();
        let cases = [
            ("comma, value", "comma, value"),
            ("quoted \"value\"", "quoted \"value\""),
            ("first\nsecond", "first\nsecond"),
            ("[R]", "[REDACTED_SECRET]"),
        ];
        assert_eq!(cases.len(), 4);
        for (index, (reason, _)) in cases.iter().enumerate() {
            append(&scratch.0, &entry(reason, index as u64)).unwrap();
        }
        let content = fs::read_to_string(scratch.0.join("job-csv/cu.csv")).unwrap();
        let rows = records(&content);
        assert_eq!(rows.len(), 5);
        for (index, (_, expected)) in cases.iter().enumerate() {
            assert_eq!(rows[index + 1].len(), 9);
            assert_eq!(
                rows[index + 1],
                vec![
                    "2026-11-02T12:00:00Z".to_owned(),
                    "job-csv".to_owned(),
                    index.to_string(),
                    "poll".to_owned(),
                    "12.5".to_owned(),
                    "-1".to_owned(),
                    "5".to_owned(),
                    "l4".to_owned(),
                    expected.to_string()
                ]
            );
        }
        assert!(!content.contains("[R]"));
        assert_eq!(inventory(&scratch.0), ["job-csv", "job-csv/cu.csv"]);
    }

    #[test]
    fn run37_w3_header_written_once_across_appends() {
        let scratch = Scratch::new();
        let mut previous = String::new();
        for index in 0..4 {
            append(&scratch.0, &entry("ordinary", index)).unwrap();
            let content = fs::read_to_string(scratch.0.join("job-csv/cu.csv")).unwrap();
            assert!(content.starts_with(&previous));
            assert!(content
                .starts_with("ts,job_id,segment,event,balance,delta,floor,gpu_class,reason\n"));
            assert_eq!(
                content
                    .matches("ts,job_id,segment,event,balance,delta,floor,gpu_class,reason\n")
                    .count(),
                1
            );
            assert_eq!(records(&content).len(), index as usize + 2);
            assert_eq!(
                records(&content)[0],
                [
                    "ts",
                    "job_id",
                    "segment",
                    "event",
                    "balance",
                    "delta",
                    "floor",
                    "gpu_class",
                    "reason"
                ]
            );
            previous = content;
        }
        assert_eq!(inventory(&scratch.0), ["job-csv", "job-csv/cu.csv"]);
    }
}
