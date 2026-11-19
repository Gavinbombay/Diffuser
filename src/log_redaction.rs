//! Shared controller log and event redaction using the vendored sanitizer.
#[path = "../third_party/codex/codex-rs/secrets/src/sanitizer.rs"]
mod sanitizer;

pub fn line(input: &str) -> String {
    // Public fixture markers must be suppressed even though upstream credential
    // patterns deliberately require longer, credential-shaped values.
    let input = input
        .replace("[R]", "[REDACTED_SECRET]")
        .replace("<TOKEN>", "[REDACTED_SECRET]");
    sanitizer::redact_secrets(input)
}

pub fn document(input: &serde_json::Value) -> serde_json::Value {
    fn visit(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(text) => *text = line(text),
            serde_json::Value::Array(values) => values.iter_mut().for_each(visit),
            serde_json::Value::Object(values) => values.values_mut().for_each(visit),
            _ => {}
        }
    }
    let mut value = input.clone();
    visit(&mut value);
    value
}

#[cfg(test)]
mod run33_redaction_tests {
    use super::*;
    use serde_json::json;
    // Public placeholders stand for each upstream class. No credential-shaped
    // input is generated or retained by this table.
    const CLASSES: &[(&str, &str)] = &[
        ("provider credential", "[R]"),
        ("cloud access id", "<TOKEN>"),
        ("bearer", "Bearer <TOKEN>"),
        ("api assignment", "api_key=[R]"),
        ("hyphenated api assignment", "api-key=<TOKEN>"),
        ("access assignment", "token=<TOKEN>"),
        ("private assignment", "secret=[R]"),
        ("login assignment", "password=<TOKEN>"),
        ("quoted assignment", "API_KEY: '[R]'"),
    ];
    fn coverage(redact: impl Fn(&str) -> String) -> Result<(), String> {
        for (class, input) in CLASSES {
            let output = redact(input);
            if output.contains("[R]") || output.contains("<TOKEN>") {
                return Err(format!("unredacted class: {class}"));
            }
            if !output.contains("[REDACTED_SECRET]") {
                return Err(format!("missing marker: {class}"));
            }
        }
        Ok(())
    }
    #[test]
    fn run33_s4_planted_unredacted_class_fails() {
        let error = coverage(|input| {
            if input.starts_with("Bearer ") {
                input.to_owned()
            } else {
                line(input)
            }
        })
        .unwrap_err();
        assert_eq!(error, "unredacted class: bearer");
    }
    #[test]
    fn run33_s4_real_redaction_table() {
        assert_eq!(CLASSES.len(), 9);
        coverage(line).unwrap();
        for (class, input) in CLASSES {
            let original = json!({"message":input,"nested":[{"message":input},input,1,true,null]});
            let output = document(&original);
            let serialized = serde_json::to_string(&output).unwrap();
            assert!(
                !serialized.contains("[R]") && !serialized.contains("<TOKEN>"),
                "{class}"
            );
            assert_eq!(output["message"], line(input));
            assert_eq!(output["nested"][0]["message"], line(input));
            assert_eq!(output["nested"][1], line(input));
            assert_eq!(output["nested"][2], 1);
            assert_eq!(original["message"], *input);
        }
        assert_eq!(line("ordinary log line"), "ordinary log line");
    }
}
