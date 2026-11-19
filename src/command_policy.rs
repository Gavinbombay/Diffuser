//! Lane-scoped exact-program policy, validated and frozen before dispatch startup.
use crate::*;
pub fn load(options: &Value) -> Result<Value, &'static str> {
    load_with_writer(options, &mut std::io::stderr().lock())
}
fn load_with_writer(
    options: &Value,
    writer: &mut impl std::io::Write,
) -> Result<Value, &'static str> {
    let explicit = options["command_policy_path"]
        .as_str()
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("LANE_COMMAND_POLICY").map(PathBuf::from));
    let raw = if let Some(path) = explicit {
        read_policy(path).map_err(|_| error_catalog::WORKER_REFUSED)?
    } else {
        match read_policy(base_dir().join("command-policy.json")) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                include_bytes!("../docs/command-policy.json").to_vec()
            }
            Err(_) => return Err(error_catalog::WORKER_REFUSED),
        }
    };
    if raw.len() > POLICY_MAX {
        return Err(error_catalog::reason(error_catalog::REQUEST_TOO_LARGE));
    }
    let policy = lane_gate::parse(&raw).map_err(|_| error_catalog::WORKER_REFUSED)?;
    let lanes = policy.as_object().ok_or(error_catalog::WORKER_REFUSED)?;
    for (lane, commands) in lanes {
        if !LANES.contains(&lane.as_str()) {
            return Err(error_catalog::reason(
                error_catalog::COMMAND_POLICY_UNKNOWN_LANE,
            ));
        }
        let commands = commands
            .as_array()
            .ok_or_else(|| error_catalog::reason(error_catalog::COMMAND_POLICY_NOT_ARRAY))?;
        let mut seen = HashSet::new();
        for command in commands {
            let command = command
                .as_str()
                .filter(|s| !s.trim().is_empty() && !s.contains(['*', '?', '\n', '\r']))
                .ok_or_else(|| {
                    error_catalog::reason(error_catalog::COMMAND_POLICY_INVALID_PROGRAM)
                })?;
            if !seen.insert(command) {
                return Err(error_catalog::reason(
                    error_catalog::COMMAND_POLICY_DUPLICATE_PROGRAM,
                ));
            }
        }
    }
    let evidence = format!(
        "policy_sha256={} lane_count={}\n",
        hex::encode(Sha256::digest(&raw)),
        lanes.len()
    );
    result_store::worker_log::emit(writer, evidence.as_bytes(), 128)
        .map_err(|_| error_catalog::STORAGE_UNAVAILABLE)?;
    Ok(policy)
}
#[derive(Default)]
struct Policies {
    values: HashMap<PathBuf, Value>,
    frozen: bool,
}
impl Policies {
    fn resolve(options: &Value) -> PathBuf {
        options["command_policy_path"]
            .as_str()
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("LANE_COMMAND_POLICY").map(PathBuf::from))
            .unwrap_or_else(|| base_dir().join("command-policy.json"))
    }
    fn get(&mut self, options: &Value) -> Result<&Value, &'static str> {
        let path = Self::resolve(options);
        if !self.values.contains_key(&path) {
            if self.frozen {
                return Err(error_catalog::WORKER_REFUSED);
            }
            self.values.insert(path.clone(), load(options)?);
        }
        Ok(&self.values[&path])
    }
    fn freeze(&mut self, options: &[Value]) -> Result<(), &'static str> {
        for value in options {
            self.get(value)?;
        }
        self.frozen = true;
        Ok(())
    }
}
static POLICIES: std::sync::LazyLock<Mutex<Policies>> =
    std::sync::LazyLock::new(|| Mutex::new(Policies::default()));

/// Called before any runtime, signal thread, listener or job is created.
pub fn startup() -> Result<(), &'static str> {
    let workers = load_registry().map_err(|_| error_catalog::WORKER_REFUSED)?;
    // Validate explicit worker paths before the missing-default fallback can
    // occupy the same path in the cache. Missing explicit files must refuse.
    let mut options: Vec<Value> = workers.into_iter().map(|worker| worker.dispatch).collect();
    options.sort_by_key(|value| !value["command_policy_path"].is_string());
    options.push(json!({}));
    POLICIES.lock().unwrap().freeze(&options)
}

// The cap includes argv[0] and one terminating byte per element.
const ARGV_MAX_BYTES: usize = 65536;
fn argv_shape(command: &Command) -> Result<(), &'static str> {
    let mut bytes = 0usize;
    for argument in std::iter::once(command.get_program()).chain(command.get_args()) {
        let text = argument
            .to_str()
            .ok_or_else(|| error_catalog::reason(error_catalog::WORKER_REFUSED))?;
        if text.contains([';', '|', '&', '<', '>', '`', '\n', '\r'])
            || text.contains("$(")
            || text.contains("${")
        {
            return Err(error_catalog::reason(error_catalog::WORKER_REFUSED));
        }
        bytes = bytes.saturating_add(text.len()).saturating_add(1);
    }
    if command.get_program().is_empty() || bytes > ARGV_MAX_BYTES {
        return Err(error_catalog::reason(error_catalog::WORKER_REFUSED));
    }
    Ok(())
}

pub fn authorize(lane: &str, command: &Command, options: &Value) -> Result<(), &'static str> {
    argv_shape(command)?;
    let mut policies = POLICIES.lock().unwrap();
    let policy = policies.get(options)?;
    let program = command
        .get_program()
        .to_str()
        .ok_or(error_catalog::WORKER_REFUSED)?;
    if !LANES.contains(&lane)
        || !policy[lane]
            .as_array()
            .is_some_and(|commands| commands.iter().any(|allowed| allowed == program))
    {
        return Err(error_catalog::WORKER_REFUSED);
    }
    Ok(())
}

/// Startup-only validation. This path creates no runtime, listener or worker.
pub fn check_cli(args: &[String]) -> i32 {
    if args.len() != 1 {
        eprintln!("{}", error_catalog::USAGE);
        return 2;
    }
    match load(&json!({"command_policy_path":args[0]})) {
        Ok(_) => {
            println!("policy valid");
            0
        }
        Err(code) => {
            eprintln!("{code}");
            1
        }
    }
}

#[cfg(test)]
pub fn fixture_allow(path: &Path) {
    let policy_path = path.parent().unwrap().join("commands.json");
    let mut policy: Value = fs::read(&policy_path)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or(json!({}));
    let program = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().unwrap().join(path)
    };
    for lane in LANES {
        if !policy[*lane].is_array() {
            policy[*lane] = json!([]);
        }
        if !policy[*lane].as_array().unwrap().contains(&json!(program)) {
            policy[*lane].as_array_mut().unwrap().push(json!(program));
        }
    }
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    std::env::set_var("LANE_COMMAND_POLICY", policy_path);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy(name: &str, value: Value) -> (PathBuf, Value) {
        let root = std::env::temp_dir().join(format!("run23-policy-{}-{name}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("commands.json");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        (root, json!({"command_policy_path":path}))
    }
    #[test]
    fn allow() {
        let (root, options) = policy("allow", json!({"tts":["/bin/true"]}));
        let mut command = Command::new("/bin/true");
        authorize("tts", &command, &options).unwrap();
        let mut child = worker_process::spawn(&mut command).unwrap();
        assert!(child.wait().unwrap().success());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn deny() {
        let (root, options) = policy("deny", json!({"tts":["/bin/true"]}));
        for program in ["/bin/false", "/bin/true-extra", "true"] {
            assert_eq!(
                authorize("tts", &Command::new(program), &options),
                Err(error_catalog::WORKER_REFUSED)
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn unknown_denied() {
        let (root, options) = policy("unknown", json!({"tts":["/bin/true"]}));
        for lane in ["unknown", "stt"] {
            assert!(authorize(lane, &Command::new("/bin/true"), &options).is_err());
        }
        fs::write(root.join("commands.json"), "{").unwrap();
        assert!(load(&options).is_err());
        assert!(load(&json!({"command_policy_path":root.join("missing")})).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn per_lane_policy_loads() {
        let (root, options) = policy("lanes", json!({"tts":["/bin/true"],"stt":["/bin/false"]}));
        assert_eq!(load(&options).unwrap()["stt"], json!(["/bin/false"]));
        assert!(authorize("stt", &Command::new("/bin/false"), &options).is_ok());
        assert!(authorize("tts", &Command::new("/bin/false"), &options).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn load_rejects_unknown_lane() {
        let (root, options) = policy("unknown-lane", json!({"unknown":[]}));
        assert_eq!(
            load(&options),
            Err(error_catalog::COMMAND_POLICY_UNKNOWN_LANE)
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn load_rejects_non_array() {
        for (n, value) in [Value::Null, json!({}), json!("program"), json!(1)]
            .into_iter()
            .enumerate()
        {
            let (root, options) = policy(&format!("non-array-{n}"), json!({"tts":value}));
            assert_eq!(load(&options), Err(error_catalog::COMMAND_POLICY_NOT_ARRAY));
            fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn load_rejects_empty_or_invalid_program() {
        for (n, value) in [
            json!(""),
            json!("   "),
            json!(1),
            json!("*"),
            json!("line\nfeed"),
        ]
        .into_iter()
        .enumerate()
        {
            let (root, options) = policy(&format!("invalid-program-{n}"), json!({"tts":[value]}));
            assert_eq!(
                load(&options),
                Err(error_catalog::COMMAND_POLICY_INVALID_PROGRAM)
            );
            fs::remove_dir_all(root).unwrap();
        }
        let shipped: Value =
            serde_json::from_str(include_str!("../docs/command-policy.json")).unwrap();
        assert_eq!(shipped.as_object().unwrap().len(), LANES.len());
        for lane in LANES {
            assert_eq!(shipped[*lane], json!([]));
        }
    }
    #[test]
    fn load_rejects_duplicate_program() {
        let (root, options) = policy("duplicate-program", json!({"tts":["[R]","[R]"]}));
        assert_eq!(
            load(&options),
            Err(error_catalog::COMMAND_POLICY_DUPLICATE_PROGRAM)
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod check_tests {
    use super::*;
    fn check(name: &str, raw: &[u8]) -> i32 {
        let root = std::env::temp_dir().join(format!("run26-check-{}-{name}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("policy.json");
        fs::write(&path, raw).unwrap();
        let result = check_cli(&[path.to_str().unwrap().to_owned()]);
        fs::remove_dir_all(root).unwrap();
        result
    }
    #[test]
    fn check_policy_valid_deny_all() {
        assert_eq!(
            check("valid", include_bytes!("../docs/command-policy.json")),
            0
        );
    }
    #[test]
    fn check_policy_invalid_and_missing_fail() {
        assert_eq!(check("invalid", br#"{"unknown":[]}"#), 1);
        assert_eq!(check("malformed", b"{"), 1);
        assert_eq!(
            check_cli(&[std::env::temp_dir()
                .join(format!("run26-absent-{}", std::process::id()))
                .to_str()
                .unwrap()
                .to_owned()]),
            1
        );
    }
    #[test]
    fn check_policy_requires_exactly_one_path() {
        assert_eq!(check_cli(&[]), 2);
        assert_eq!(check_cli(&["[R]".into(), "[R]".into()]), 2);
    }
}

/// The read budget also bounds allocations before JSON shape validation.
const POLICY_MAX: usize = 65536;
fn read_policy(path: PathBuf) -> std::io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    fs::File::open(path)?
        .take((POLICY_MAX + 1) as u64)
        .read_to_end(&mut raw)?;
    Ok(raw)
}

#[cfg(test)]
mod fuzz_table_tests {
    use super::*;
    #[test]
    fn policy_edge_shapes_have_bounded_reads_and_catalog_refusals() {
        let root = std::env::temp_dir().join(format!("run26-policy-fuzz-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("policy.json");
        let mut cases: Vec<(&str, Vec<u8>, &str)> = vec![
            ("empty", b"".to_vec(), error_catalog::WORKER_REFUSED),
            (
                "whitespace",
                b" \n\t".to_vec(),
                error_catalog::WORKER_REFUSED,
            ),
            ("null", b"null".to_vec(), error_catalog::WORKER_REFUSED),
            ("scalar", b"true".to_vec(), error_catalog::WORKER_REFUSED),
            ("root-array", b"[]".to_vec(), error_catalog::WORKER_REFUSED),
            (
                "duplicate-lane",
                br#"{"tts":[],"tts":[]}"#.to_vec(),
                error_catalog::WORKER_REFUSED,
            ),
            (
                "number-program",
                br#"{"tts":[1]}"#.to_vec(),
                error_catalog::COMMAND_POLICY_INVALID_PROGRAM,
            ),
            (
                "bool-program",
                br#"{"tts":[false]}"#.to_vec(),
                error_catalog::COMMAND_POLICY_INVALID_PROGRAM,
            ),
            (
                "null-program",
                br#"{"tts":[null]}"#.to_vec(),
                error_catalog::COMMAND_POLICY_INVALID_PROGRAM,
            ),
            (
                "object-program",
                br#"{"tts":[{}]}"#.to_vec(),
                error_catalog::COMMAND_POLICY_INVALID_PROGRAM,
            ),
            (
                "array-program",
                br#"{"tts":[[]]}"#.to_vec(),
                error_catalog::COMMAND_POLICY_INVALID_PROGRAM,
            ),
            (
                "empty-program",
                br#"{"tts":[""]}"#.to_vec(),
                error_catalog::COMMAND_POLICY_INVALID_PROGRAM,
            ),
            (
                "non-array",
                br#"{"tts":{}}"#.to_vec(),
                error_catalog::COMMAND_POLICY_NOT_ARRAY,
            ),
            (
                "unknown-lane",
                br#"{"unknown":[]}"#.to_vec(),
                error_catalog::COMMAND_POLICY_UNKNOWN_LANE,
            ),
            (
                "duplicate-program",
                br#"{"tts":["[R]","[R]"]}"#.to_vec(),
                error_catalog::COMMAND_POLICY_DUPLICATE_PROGRAM,
            ),
        ];
        cases.push((
            "deep-nesting",
            format!("{}0{}", "[".repeat(256), "]".repeat(256)).into_bytes(),
            error_catalog::WORKER_REFUSED,
        ));
        cases.push((
            "huge-array",
            format!("{{\"tts\":[{}0]}}", "0,".repeat(POLICY_MAX)).into_bytes(),
            error_catalog::REQUEST_TOO_LARGE,
        ));
        cases.push((
            "oversize-whitespace",
            vec![b' '; POLICY_MAX + 1],
            error_catalog::REQUEST_TOO_LARGE,
        ));
        assert!(cases.len() >= 12);
        for (name, raw, expected) in cases {
            fs::write(&path, &raw).unwrap();
            assert!(
                read_policy(path.clone()).unwrap().len() <= POLICY_MAX + 1,
                "unbounded read: {name}"
            );
            let code = load(&json!({"command_policy_path":path})).expect_err(name);
            assert_eq!(code, expected, "{name}");
            assert!(
                error_catalog::lookup(None, code).is_some(),
                "{name}: {code}"
            );
        }
        // A sparse large file proves the loader does not allocate its file size.
        let file = fs::File::create(&path).unwrap();
        file.set_len(64 * 1024 * 1024).unwrap();
        drop(file);
        assert_eq!(read_policy(path.clone()).unwrap().len(), POLICY_MAX + 1);
        assert_eq!(
            load(&json!({"command_policy_path":path})),
            Err(error_catalog::REQUEST_TOO_LARGE)
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod evidence_tests {
    use super::*;
    fn capture(name: &str, bytes: &[u8]) -> (Result<Value, &'static str>, Vec<u8>) {
        let root = std::env::temp_dir().join(format!(
            "run27-policy-evidence-{}-{name}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("policy.json");
        fs::write(&path, bytes).unwrap();
        let mut output = Vec::new();
        let result = load_with_writer(&json!({"command_policy_path":path}), &mut output);
        fs::remove_dir_all(root).unwrap();
        (result, output)
    }
    #[test]
    fn policy_load_evidence_one_line_with_digest_and_lane_count() {
        for (name, bytes, count) in [
            ("empty", b"{}".as_slice(), 0),
            ("two", br#"{"tts":[],"stt":[]}"#.as_slice(), 2),
        ] {
            let (result, output) = capture(name, bytes);
            assert!(result.is_ok());
            assert_eq!(
                output,
                format!(
                    "policy_sha256={} lane_count={count}\n",
                    hex::encode(Sha256::digest(bytes))
                )
                .as_bytes()
            );
            assert_eq!(output.iter().filter(|b| **b == b'\n').count(), 1);
        }
    }
    #[test]
    fn policy_load_evidence_bounded_redacted_and_never_lists_programs() {
        let bytes = serde_json::to_vec(&json!({"tts":["[R]".repeat(10000)]})).unwrap();
        let (result, output) = capture("large", &bytes);
        assert!(result.is_ok());
        assert!(output.len() <= 128);
        assert_eq!(output.iter().filter(|b| **b == b'\n').count(), 1);
        assert!(!String::from_utf8(output.clone()).unwrap().contains("[R]"));
        assert_eq!(
            crate::log_redaction::line(std::str::from_utf8(&output).unwrap()).as_bytes(),
            output
        );
        let (result, output) = capture("invalid", br#"{"tts":[false]}"#);
        assert_eq!(result, Err(error_catalog::COMMAND_POLICY_INVALID_PROGRAM));
        assert!(
            output.is_empty(),
            "a refused policy must not claim a successful load"
        );
    }
}

#[cfg(test)]
mod startup_tests {
    use super::*;
    #[test]
    fn startup_policy_path_order_table() {
        let cases = [
            ("explicit-present", "worker", "valid", true, None),
            (
                "explicit-missing-default-present",
                "worker",
                "missing",
                true,
                Some(error_catalog::WORKER_REFUSED),
            ),
            (
                "explicit-invalid",
                "worker",
                "invalid",
                true,
                Some(error_catalog::COMMAND_POLICY_UNKNOWN_LANE),
            ),
            ("default-only", "none", "missing", true, None),
            ("neither", "none", "missing", false, None),
            ("environment-present", "environment", "valid", true, None),
            (
                "environment-missing-default-present",
                "environment",
                "missing",
                true,
                Some(error_catalog::WORKER_REFUSED),
            ),
            (
                "explicit-default-alias-missing",
                "alias",
                "missing",
                false,
                Some(error_catalog::WORKER_REFUSED),
            ),
        ];
        let selected = std::env::var("RUN29_POLICY_ROW").ok();
        if selected.is_none() {
            for (name, ..) in cases {
                let status = crate::test_process::command()
                    .args([
                        "--exact",
                        "command_policy::startup_tests::startup_policy_path_order_table",
                    ])
                    .env("RUN29_POLICY_ROW", name)
                    .env_remove("LANE_COMMAND_POLICY")
                    .status()
                    .unwrap();
                assert!(status.success(), "startup table row {name}");
            }
            return;
        }
        let (name, source, state, default_present, refusal) = cases
            .into_iter()
            .find(|row| Some(row.0) == selected.as_deref())
            .unwrap();
        let root = std::env::temp_dir().join(format!("run29-policy-{}-{name}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let default_path = root.join("command-policy.json");
        let explicit_path = if source == "alias" {
            default_path.clone()
        } else {
            root.join("explicit.json")
        };
        if default_present {
            fs::write(&default_path, br#"{"tts":["[R]"]}"#).unwrap();
        }
        match state {
            "valid" => fs::write(&explicit_path, br#"{"stt":["[R]"]}"#).unwrap(),
            "invalid" => fs::write(&explicit_path, br#"{"unknown":[]}"#).unwrap(),
            _ => (),
        }
        let options = if source == "worker" || source == "alias" {
            json!({"command_policy_path":explicit_path})
        } else {
            json!({})
        };
        let registry = root.join("workers.cfg");
        // Put the default first to pin the N8 explicit-path-before-fallback fix.
        fs::write(&registry, serde_json::to_vec(&json!({"workers":[
            {"id":"default","lanes":["tts"],"kind":"exec","exec":"[R]","dispatch":{},"seats":1,"enabled":true},
            {"id":"configured","lanes":["stt"],"kind":"exec","exec":"[R]","dispatch":options,"seats":1,"enabled":true}
        ]})).unwrap()).unwrap();
        std::env::set_var("LANE_ROUTER_HOME", &root);
        std::env::set_var("LANE_REGISTRY", registry);
        std::env::remove_var("LANE_COMMAND_POLICY");
        if source == "environment" {
            std::env::set_var("LANE_COMMAND_POLICY", &explicit_path);
        }
        assert_eq!(startup(), refusal.map_or(Ok(()), Err), "{name}");
        let mut policies = POLICIES.lock().unwrap();
        assert_eq!(policies.frozen, refusal.is_none(), "{name}");
        if refusal.is_none() {
            let expected = if source == "worker" || source == "environment" {
                json!({"stt":["[R]"]})
            } else if default_present {
                json!({"tts":["[R]"]})
            } else {
                serde_json::from_slice(include_bytes!("../docs/command-policy.json")).unwrap()
            };
            assert_eq!(policies.get(&options).unwrap(), &expected, "{name}");
        }
        fs::remove_dir_all(root).unwrap();
    }

    fn fixture(name: &str) -> (PathBuf, Value) {
        let root = std::env::temp_dir().join(format!("run28-policy-{}-{name}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("policy.json");
        fs::write(&path, br#"{"tts":["[R]"]}"#).unwrap();
        (root, json!({"command_policy_path":path}))
    }
    #[test]
    fn startup_snapshot_survives_edit_and_removal() {
        let (root, options) = fixture("snapshot");
        let mut policies = Policies::default();
        policies.freeze(std::slice::from_ref(&options)).unwrap();
        let original = policies.get(&options).unwrap().clone();
        fs::write(root.join("policy.json"), b"{").unwrap();
        assert_eq!(policies.get(&options).unwrap(), &original);
        fs::remove_file(root.join("policy.json")).unwrap();
        assert_eq!(policies.get(&options).unwrap(), &original);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn startup_invalid_policy_preserves_catalog_reason() {
        let (root, options) = fixture("invalid");
        fs::write(root.join("policy.json"), br#"{"unknown":[]}"#).unwrap();
        let mut policies = Policies::default();
        assert_eq!(
            policies.freeze(&[options]),
            Err(error_catalog::COMMAND_POLICY_UNKNOWN_LANE)
        );
        assert!(!policies.frozen);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn startup_frozen_paths_deny_new_configuration() {
        let (root, options) = fixture("frozen");
        let mut policies = Policies::default();
        policies.freeze(std::slice::from_ref(&options)).unwrap();
        assert_eq!(policies.values.len(), 1);
        let other = json!({"command_policy_path":root.join("unloaded.json")});
        assert_eq!(policies.get(&other), Err(error_catalog::WORKER_REFUSED));
        assert_eq!(policies.values.len(), 1);
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod run33_policy_tests {
    use super::*;
    #[test]
    fn run33_s3_command_refusal_table() {
        let root = std::env::temp_dir().join(format!("run33-policy-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("commands.json");
        let allowed = json!({"render-blender":["/bin/true"]});
        fs::write(&path, serde_json::to_vec(&allowed).unwrap()).unwrap();
        let options = json!({"command_policy_path":path});
        let mut rows = vec![
            ("unknown program", Command::new("unknown-program")),
            ("absolute unlisted", Command::new("/unlisted/worker")),
            ("empty argv", Command::new("")),
        ];
        for text in [
            ";",
            "|",
            "&",
            "<",
            ">",
            "`",
            "$(fixture)",
            "${fixture}",
            "\n",
            "\r",
        ] {
            let mut command = Command::new("/bin/true");
            command.arg(text);
            rows.push(("shell metacharacter", command));
        }
        let mut long = Command::new("/bin/true");
        long.arg("x".repeat(ARGV_MAX_BYTES));
        rows.push(("over-long argv", long));
        assert!(rows.len() >= 5);
        for (shape, command) in rows {
            assert_eq!(
                authorize("render-blender", &command, &options),
                Err(error_catalog::WORKER_REFUSED),
                "{shape}"
            );
            assert_eq!(
                error_catalog::canonical_code(error_catalog::WORKER_REFUSED),
                error_catalog::WORKER_REFUSED
            );
        }
        // Equality is permitted. Refusing an empty argv does not forbid zero arguments.
        let mut boundary = Command::new("/bin/true");
        boundary.arg("x".repeat(ARGV_MAX_BYTES - "/bin/true".len() - 2));
        assert!(authorize("render-blender", &boundary, &options).is_ok());
        assert!(authorize("render-blender", &Command::new("/bin/true"), &options).is_ok());
        assert_eq!(
            fs::read(&path).unwrap(),
            serde_json::to_vec(&allowed).unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
