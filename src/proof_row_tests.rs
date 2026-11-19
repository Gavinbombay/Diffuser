use super::*;

#[test]
fn proof_source_on_rows() {
    for (id, bytes) in [
        (
            "warp-2070",
            &include_bytes!("../tests/fixtures/card-state/warp-2070.json")[..],
        ),
        (
            "echo-3060",
            &include_bytes!("../tests/fixtures/card-state/echo-3060-self-probe-fresh.json")[..],
        ),
        (
            "colab-l4",
            &include_bytes!("../tests/fixtures/card-state/colab-l4-state.json")[..],
        ),
    ] {
        let mut state: Value = serde_json::from_slice(bytes).unwrap();
        let now = state["epoch"].as_u64().unwrap();
        state["stale"] = json!(false);
        let probe = if id == "colab-l4" {
            json!({"epoch":now})
        } else {
            json!({"epoch":now,"util":state["util"],"watts":state["watts"]})
        };
        let worker = Worker {
            id: id.into(),
            lanes: vec!["tts".into()],
            kind: "agent-push".into(),
            exec: String::new(),
            dispatch: Value::Null,
            seats: 1,
            enabled: true,
            note: String::new(),
        };
        let row = card_worker_view(
            &worker,
            "tts",
            &HashMap::new(),
            &state,
            now,
            Some(&probe),
            Some(5.0),
        );
        assert_eq!(row["proved"], true);
        assert_eq!(
            row["proof_source"],
            if id == "echo-3060" {
                "self-probe"
            } else {
                "router-probe"
            }
        );
        assert_eq!(row["accepting"], id != "colab-l4");
        let refused = card_worker_view(
            &worker,
            "tts",
            &HashMap::new(),
            &state,
            now + 121,
            Some(&probe),
            Some(5.0),
        );
        assert_eq!(refused["accepting"], false);
    }
}

#[test]
fn router_source_has_no_ssh() {
    for source in [
        include_str!("main.rs"),
        include_str!("engine.rs"),
        include_str!("routes/common.rs"),
        include_str!("routes/pull.rs"),
        include_str!("routes/compat.rs"),
        include_str!("routes/jobs.rs"),
        include_str!("routes/queue.rs"),
        include_str!("routes/server.rs"),
        include_str!("card_state.rs"),
        include_str!("agent_pull.rs"),
    ] {
        assert!(!source.contains(concat!("Command::new(\"", "ssh", "\")")));
    }
}
