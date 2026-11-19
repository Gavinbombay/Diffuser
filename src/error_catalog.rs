//! Error and refusal inventory. Wire messages and statuses remain unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub status: Option<u16>,
    pub code: &'static str,
    pub reason: &'static str,
    pub source: &'static str,
}
pub const MESSAGES_REQUIRED: &str = "MESSAGES_REQUIRED";
pub const PROMPT_REQUIRED: &str = "PROMPT_REQUIRED";
pub const ADAPTER_DRY_RUN_UNSUPPORTED: &str = "adapter-dry-run-unsupported";
pub const ADAPTER_ENTRY_UNSET: &str = "adapter-entry-unset";
pub const APPROVAL_MISSING: &str = "approval-missing";
pub const ARTIFACT_COUNT_EXCEEDED: &str = "artifact-count-exceeded";
pub const ARTIFACT_MISMATCH: &str = "artifact-mismatch";
pub const ARTIFACT_TOO_LARGE: &str = "artifact-too-large";
pub const AUDIT_UNWRITABLE: &str = "audit-unwritable";
pub const BAD_CATALOG: &str = "bad-catalog";
pub const BAD_DIGEST: &str = "bad-digest";
pub const BAD_JSON: &str = "bad-json";
pub const BAD_PINS: &str = "bad-pins";
pub const BAD_SPEC: &str = "bad-spec";
pub const CARTRIDGE_ID_EXISTS: &str = "cartridge-id-exists";
pub const CARTRIDGE_PLACEHOLDER: &str = "cartridge-placeholder";
pub const CEILING_UNKNOWN: &str = "ceiling-unknown";
pub const CLOCK_UNAVAILABLE: &str = "clock-unavailable";
pub const CU_FLOOR: &str = "cu-floor";
pub const DEADLINE_EXCEEDED: &str = "deadline-exceeded";
pub const DIGEST_CONFLICT: &str = "digest-conflict";
pub const DOC_TOO_LARGE: &str = "doc-too-large";
pub const DRAINING: &str = "draining";
pub const DUPLICATE_ARTIFACT: &str = "duplicate-artifact";
pub const FRAME_COUNT_INCONSISTENT: &str = "frame-count-inconsistent";
pub const FRAME_COUNT_UNKNOWABLE: &str = "frame-count-unknowable";
pub const HASH_MISMATCH: &str = "hash-mismatch";
pub const ILLEGAL_TRANSITION: &str = "illegal-transition";
pub const INVALID_REPORT: &str = "invalid-report";
pub const INVALID_REQUEST: &str = "invalid-request";
pub const JOB_FROZEN: &str = "job-frozen";
pub const JOB_ID_EXISTS: &str = "job-id-exists";
pub const LANE_DISABLED: &str = "lane-disabled";
pub const LANE_MISMATCH: &str = "lane-mismatch";
pub const LANE_NOT_GATED: &str = "lane-not-gated";
pub const MANIFEST_MISMATCH: &str = "manifest-mismatch";
pub const MAX_SEGS_EXCEEDED: &str = "max-segs-exceeded";
pub const METHOD_NOT_ALLOWED: &str = "method-not-allowed";
pub const MODEL_UNRESOLVED: &str = "model-unresolved";
pub const UNKNOWN_ROUTE: &str = "unknown-route";
pub const MODEL_NOT_FOUND: &str = "model_not_found";
pub const NO_SUCH_ARTIFACT: &str = "no-such-artifact";
pub const NO_SUCH_DOCUMENT: &str = "no-such-document";
pub const NO_SUCH_JOB: &str = "no-such-job";
pub const NO_WORKER: &str = "no-worker";
pub const OUTPUT_EMPTY: &str = "output-empty";
pub const OUTPUT_MISSING: &str = "output-missing";
pub const OUTPUT_OVER_CEILING: &str = "output-over-ceiling";
pub const OUTPUT_TRUNCATED: &str = "output-truncated";
pub const OUTPUT_UNREADABLE: &str = "output-unreadable";
pub const PATH_UNSAFE: &str = "path-unsafe";
pub const PIN_INCOMPATIBLE: &str = "pin-incompatible";
pub const PIN_UNSET: &str = "pin-unset";
pub const PINS_UNREADABLE: &str = "pins-unreadable";
pub const PROBE_MISMATCH: &str = "probe-mismatch";
pub const PROBE_MISSING: &str = "probe-missing";
pub const QUEUE_FULL: &str = "queue-full";
pub const REQUEST_TOO_LARGE: &str = "request-too-large";
pub const RETRY_EXHAUSTED: &str = "retry-exhausted";
pub const SAMPLE_RATE_MISMATCH: &str = "sample-rate-mismatch";
pub const SEAT_HELD: &str = "seat-held";
pub const SEATS_FULL: &str = "seats-full";
pub const SEGMENT_FAILED: &str = "segment-failed";
pub const SELF_PROBE_MISSING: &str = "self-probe-missing";
pub const SELF_PROBE_WORKER_MISMATCH: &str = "self-probe-worker-mismatch";
pub const SESSION_LIVE: &str = "session-live";
pub const STALE_STATE: &str = "stale-state";
pub const STATE_CORRUPT: &str = "state-corrupt";
pub const STATE_UNREADABLE: &str = "state-unreadable";
pub const STATE_UNWRITABLE: &str = "state-unwritable";
pub const STORAGE_UNAVAILABLE: &str = "storage-unavailable";
pub const UNKNOWN_CARTRIDGE: &str = "unknown-cartridge";
pub const UNKNOWN_LANE: &str = "unknown-lane";
pub const UNKNOWN_WORKER: &str = "unknown-worker";
pub const UNREGISTERED_WORKER: &str = "unregistered-worker";
pub const UNSUPPORTED_MEDIA_TYPE: &str = "unsupported-media-type";
pub const UNSUPPORTED_PARAMETERS: &str = "unsupported-parameters";
pub const UNSUPPORTED_ENCODING_FORMAT: &str = "unsupported_encoding_format";
pub const USAGE: &str = "usage";
pub const WORKER_DRAINING: &str = "worker-draining";
pub const WORKER_ID_EXISTS: &str = "worker-id-exists";
pub const WORKER_MISMATCH: &str = "worker-mismatch";
pub const WORKER_NOT_READY: &str = "worker-not-ready";
pub const WORKER_REFUSED: &str = "worker-refused";
pub const WORKER_STALE: &str = "worker-stale";

pub const COMMAND_POLICY_UNKNOWN_LANE: &str = "command-policy-unknown-lane";
pub const COMMAND_POLICY_NOT_ARRAY: &str = "command-policy-not-array";
pub const COMMAND_POLICY_INVALID_PROGRAM: &str = "command-policy-invalid-program";
pub const COMMAND_POLICY_DUPLICATE_PROGRAM: &str = "command-policy-duplicate-program";
pub const WATCHDOG_IDLE_WAIT: &str = "watchdog-idle-wait";
pub const WATCHDOG_IDLE_READY: &str = "watchdog-idle-ready";
pub const WATCHDOG_GAP_RESET: &str = "watchdog-gap-reset";
pub const WATCHDOG_GAP_CONTINUE: &str = "watchdog-gap-continue";
pub const WATCHDOG_ALERT_SUPPRESSED: &str = "watchdog-alert-suppressed";
pub const WATCHDOG_ALERT_READY: &str = "watchdog-alert-ready";
pub const TABLE: &[Entry] = &[
    Entry {
        status: None,
        code: ADAPTER_DRY_RUN_UNSUPPORTED,
        reason: "adapter-dry-run-unsupported",
        source: "src/dispatch_kinds.rs:167",
    },
    Entry {
        status: None,
        code: ADAPTER_ENTRY_UNSET,
        reason: "adapter-entry-unset",
        source: "src/dispatch_kinds.rs:174",
    },
    Entry {
        status: None,
        code: APPROVAL_MISSING,
        reason: "approval-missing",
        source: "src/lane_gate.rs:192",
    },
    Entry {
        status: None,
        code: ARTIFACT_COUNT_EXCEEDED,
        reason: "artifact-count-exceeded",
        source: "src/runtime_limits.rs:175",
    },
    Entry {
        status: None,
        code: ARTIFACT_MISMATCH,
        reason: "artifact-mismatch",
        source: "src/dispatch_kinds.rs:328",
    },
    Entry {
        status: None,
        code: ARTIFACT_TOO_LARGE,
        reason: "artifact-too-large",
        source: "src/result_store.rs:209",
    },
    Entry {
        status: None,
        code: AUDIT_UNWRITABLE,
        reason: "audit-unwritable",
        source: "src/lane_gate.rs:369",
    },
    Entry {
        status: None,
        code: BAD_CATALOG,
        reason: "bad-catalog",
        source: "src/cartridge_registry.rs:12",
    },
    Entry {
        status: None,
        code: BAD_DIGEST,
        reason: "bad-digest",
        source: "src/result_store.rs:158",
    },
    Entry {
        status: None,
        code: BAD_JSON,
        reason: "bad-json",
        source: "src/render_admission.rs:57",
    },
    Entry {
        status: None,
        code: BAD_PINS,
        reason: "bad-pins",
        source: "src/lane_gate.rs:105",
    },
    Entry {
        status: None,
        code: BAD_SPEC,
        reason: "bad-spec",
        source: "src/render_admission.rs:49",
    },
    Entry {
        status: None,
        code: CARTRIDGE_ID_EXISTS,
        reason: "cartridge-id-exists",
        source: "src/cartridge_registry.rs:80",
    },
    Entry {
        status: None,
        code: CARTRIDGE_PLACEHOLDER,
        reason: "cartridge-placeholder",
        source: "src/lane_gate.rs:189",
    },
    Entry {
        status: None,
        code: CEILING_UNKNOWN,
        reason: "ceiling-unknown",
        source: "src/runtime_limits.rs:69",
    },
    Entry {
        status: None,
        code: CLOCK_UNAVAILABLE,
        reason: "clock-unavailable",
        source: "src/lane_gate.rs:375",
    },
    Entry {
        status: None,
        code: CU_FLOOR,
        reason: "cu-floor",
        source: "src/segment_lifecycle.rs:34",
    },
    Entry {
        status: None,
        code: DEADLINE_EXCEEDED,
        reason: "deadline-exceeded",
        source: "src/deadline.rs:224",
    },
    Entry {
        status: None,
        code: DIGEST_CONFLICT,
        reason: "digest-conflict",
        source: "src/result_store.rs:221",
    },
    Entry {
        status: None,
        code: DOC_TOO_LARGE,
        reason: "doc-too-large",
        source: "src/result_store.rs:367",
    },
    Entry {
        status: None,
        code: DRAINING,
        reason: "draining",
        source: "src/worker_registry.rs:286",
    },
    Entry {
        status: None,
        code: DUPLICATE_ARTIFACT,
        reason: "duplicate-artifact",
        source: "src/runtime_limits.rs:181",
    },
    Entry {
        status: None,
        code: FRAME_COUNT_INCONSISTENT,
        reason: "frame-count-inconsistent",
        source: "src/runtime_limits.rs:244",
    },
    Entry {
        status: None,
        code: FRAME_COUNT_UNKNOWABLE,
        reason: "frame-count-unknowable",
        source: "src/runtime_limits.rs:237",
    },
    Entry {
        status: None,
        code: HASH_MISMATCH,
        reason: "hash-mismatch",
        source: "src/runtime_limits.rs:260",
    },
    Entry {
        status: None,
        code: ILLEGAL_TRANSITION,
        reason: "illegal-transition",
        source: "src/deadline.rs:94",
    },
    Entry {
        status: None,
        code: INVALID_REPORT,
        reason: "invalid-report",
        source: "src/engine.rs:264",
    },
    Entry {
        status: None,
        code: INVALID_REQUEST,
        reason: "invalid-request",
        source: "src/engine.rs:261",
    },
    Entry {
        status: None,
        code: JOB_FROZEN,
        reason: "job-frozen",
        source: "src/result_store.rs:399",
    },
    Entry {
        status: None,
        code: JOB_ID_EXISTS,
        reason: "job-id-exists",
        source: "src/queue_policy.rs:93",
    },
    Entry {
        status: None,
        code: LANE_DISABLED,
        reason: "lane-disabled",
        source: "src/render_admission.rs:186",
    },
    Entry {
        status: None,
        code: LANE_MISMATCH,
        reason: "lane-mismatch",
        source: "src/render_admission.rs:51",
    },
    Entry {
        status: None,
        code: LANE_NOT_GATED,
        reason: "lane-not-gated",
        source: "src/lane_gate.rs:200",
    },
    Entry {
        status: None,
        code: MANIFEST_MISMATCH,
        reason: "manifest-mismatch",
        source: "src/artifact_routes.rs:97",
    },
    Entry {
        status: None,
        code: MAX_SEGS_EXCEEDED,
        reason: "max-segs-exceeded",
        source: "src/segment_lifecycle.rs:39",
    },
    Entry {
        status: None,
        code: METHOD_NOT_ALLOWED,
        reason: "method-not-allowed",
        source: "src/routes/jobs.rs:160",
    },
    Entry {
        status: None,
        code: MODEL_UNRESOLVED,
        reason: "model-unresolved",
        source: "src/lane_gate.rs:182",
    },
    Entry {
        status: None,
        code: MODEL_NOT_FOUND,
        reason: "model_not_found",
        source: "src/routes/compat.rs:214",
    },
    Entry {
        status: None,
        code: NO_SUCH_ARTIFACT,
        reason: "no-such-artifact",
        source: "src/result_store.rs:230",
    },
    Entry {
        status: None,
        code: NO_SUCH_DOCUMENT,
        reason: "no-such-document",
        source: "src/artifact_routes.rs:93",
    },
    Entry {
        status: None,
        code: NO_SUCH_JOB,
        reason: "no-such-job",
        source: "src/result_store.rs:150",
    },
    Entry {
        status: None,
        code: NO_WORKER,
        reason: "no-worker",
        source: "src/deadline.rs:305",
    },
    Entry {
        status: None,
        code: OUTPUT_EMPTY,
        reason: "output-empty",
        source: "src/runtime_limits.rs:142",
    },
    Entry {
        status: None,
        code: OUTPUT_MISSING,
        reason: "output-missing",
        source: "src/runtime_limits.rs:170",
    },
    Entry {
        status: None,
        code: OUTPUT_OVER_CEILING,
        reason: "output-over-ceiling",
        source: "src/runtime_limits.rs:148",
    },
    Entry {
        status: None,
        code: OUTPUT_TRUNCATED,
        reason: "output-truncated",
        source: "src/runtime_limits.rs:138",
    },
    Entry {
        status: None,
        code: OUTPUT_UNREADABLE,
        reason: "output-unreadable",
        source: "src/runtime_limits.rs:91",
    },
    Entry {
        status: None,
        code: PATH_UNSAFE,
        reason: "path-unsafe",
        source: "src/result_store.rs:126",
    },
    Entry {
        status: None,
        code: PIN_INCOMPATIBLE,
        reason: "pin-incompatible",
        source: "src/render_admission.rs:193",
    },
    Entry {
        status: None,
        code: PIN_UNSET,
        reason: "pin-unset",
        source: "src/render_admission.rs:190",
    },
    Entry {
        status: None,
        code: PINS_UNREADABLE,
        reason: "pins-unreadable",
        source: "src/lane_gate.rs:220",
    },
    Entry {
        status: None,
        code: PROBE_MISMATCH,
        reason: "probe-mismatch",
        source: "src/card_state.rs:35",
    },
    Entry {
        status: None,
        code: PROBE_MISSING,
        reason: "probe-missing",
        source: "src/card_state.rs:29",
    },
    Entry {
        status: None,
        code: REQUEST_TOO_LARGE,
        reason: "request-too-large",
        source: "src/lane_bodies.rs:280",
    },
    Entry {
        status: None,
        code: RETRY_EXHAUSTED,
        reason: "retry-exhausted",
        source: "src/deadline.rs:303",
    },
    Entry {
        status: None,
        code: SAMPLE_RATE_MISMATCH,
        reason: "sample-rate-mismatch",
        source: "src/runtime_limits.rs:60",
    },
    Entry {
        status: None,
        code: SEAT_HELD,
        reason: "seat-held",
        source: "src/agent_pull.rs:13",
    },
    Entry {
        status: None,
        code: SEATS_FULL,
        reason: "seats-full",
        source: "src/worker_registry.rs:236",
    },
    Entry {
        status: None,
        code: SEGMENT_FAILED,
        reason: "segment-failed",
        source: "src/segment_lifecycle.rs:65",
    },
    Entry {
        status: None,
        code: SELF_PROBE_MISSING,
        reason: "self-probe-missing",
        source: "src/card_state.rs:18",
    },
    Entry {
        status: None,
        code: SELF_PROBE_WORKER_MISMATCH,
        reason: "self-probe-worker-mismatch",
        source: "src/card_state.rs:19",
    },
    Entry {
        status: None,
        code: SESSION_LIVE,
        reason: "session-live",
        source: "src/agent_pull.rs:15",
    },
    Entry {
        status: None,
        code: STALE_STATE,
        reason: "stale-state",
        source: "src/agent_pull.rs:11",
    },
    Entry {
        status: None,
        code: STATE_CORRUPT,
        reason: "state-corrupt",
        source: "src/lane_gate.rs:282",
    },
    Entry {
        status: None,
        code: STATE_UNREADABLE,
        reason: "state-unreadable",
        source: "src/lane_gate.rs:280",
    },
    Entry {
        status: None,
        code: STATE_UNWRITABLE,
        reason: "state-unwritable",
        source: "src/lane_gate.rs:334",
    },
    Entry {
        status: None,
        code: STORAGE_UNAVAILABLE,
        reason: "storage-unavailable",
        source: "src/worker_registry.rs:365",
    },
    Entry {
        status: None,
        code: UNKNOWN_CARTRIDGE,
        reason: "unknown-cartridge",
        source: "src/cartridge_registry.rs:282",
    },
    Entry {
        status: None,
        code: UNKNOWN_LANE,
        reason: "unknown-lane",
        source: "src/lane_bodies.rs:55",
    },
    Entry {
        status: None,
        code: UNKNOWN_WORKER,
        reason: "unknown-worker",
        source: "src/worker_registry.rs:110",
    },
    Entry {
        status: None,
        code: UNREGISTERED_WORKER,
        reason: "unregistered-worker",
        source: "src/card_state.rs:22",
    },
    Entry {
        status: None,
        code: UNSUPPORTED_MEDIA_TYPE,
        reason: "unsupported-media-type",
        source: "src/render_admission.rs:215",
    },
    Entry {
        status: None,
        code: UNSUPPORTED_PARAMETERS,
        reason: "unsupported-parameters",
        source: "src/lane_bodies.rs:207",
    },
    Entry {
        status: None,
        code: UNSUPPORTED_ENCODING_FORMAT,
        reason: "unsupported_encoding_format",
        source: "src/routes/compat.rs:33",
    },
    Entry {
        status: None,
        code: USAGE,
        reason: "usage",
        source: "src/lane_gate.rs:306",
    },
    Entry {
        status: None,
        code: WORKER_DRAINING,
        reason: "worker-draining",
        source: "src/worker_registry.rs:228",
    },
    Entry {
        status: None,
        code: WORKER_ID_EXISTS,
        reason: "worker-id-exists",
        source: "src/worker_registry.rs:121",
    },
    Entry {
        status: None,
        code: WORKER_MISMATCH,
        reason: "worker-mismatch",
        source: "src/card_state.rs:54",
    },
    Entry {
        status: None,
        code: WORKER_NOT_READY,
        reason: "worker-not-ready",
        source: "src/worker_registry.rs:226",
    },
    Entry {
        status: None,
        code: WORKER_REFUSED,
        reason: "worker-refused",
        source: "src/deadline.rs:287",
    },
    Entry {
        status: None,
        code: WORKER_STALE,
        reason: "worker-stale",
        source: "src/worker_registry.rs:227",
    },
    Entry {
        status: Some(400),
        code: "",
        reason: "Axum path or body extractor rejection with dynamic detail",
        source: "src/http_routes.rs:8",
    },
    Entry {
        status: Some(400),
        code: "",
        reason:
            "Dynamic detail from validation, registry, planning, cartridge storage or publication",
        source: "src/routes/common.rs:13",
    },
    Entry {
        status: Some(400),
        code: "",
        reason: "invalid JSON",
        source: "src/routes/compat.rs:29",
    },
    Entry {
        status: Some(400),
        code: "",
        reason: "invalid request",
        source: "src/routes/pull.rs:3",
    },
    Entry {
        status: Some(400),
        code: "",
        reason: "request must be an object",
        source: "src/routes/compat.rs:117",
    },
    Entry {
        status: Some(400),
        code: "",
        reason: "stream must be a boolean",
        source: "src/routes/compat.rs:124",
    },
    Entry {
        status: Some(400),
        code: MESSAGES_REQUIRED,
        reason: "messages must be a nonempty array",
        source: "src/routes/compat.rs:119",
    },
    Entry {
        status: Some(400),
        code: PROMPT_REQUIRED,
        reason: "a substantive user message is required",
        source: "src/routes/compat.rs:122",
    },
    Entry {
        status: Some(400),
        code: BAD_SPEC,
        reason: "bad-spec",
        source: "src/render_admission.rs:49",
    },
    Entry {
        status: Some(400),
        code: UNSUPPORTED_ENCODING_FORMAT,
        reason: "unsupported encoding_format",
        source: "src/routes/compat.rs:33",
    },
    Entry {
        status: Some(401),
        code: "",
        reason: "bad token",
        source: "src/routes/common.rs:24",
    },
    Entry {
        status: Some(404),
        code: "",
        reason: "no such job",
        source: "src/routes/jobs.rs:157",
    },
    Entry {
        status: Some(404),
        code: "",
        reason: "not_found; path is the requested URI",
        source: "src/routes/compat.rs:166",
    },
    Entry {
        status: Some(404),
        code: "",
        reason: "unknown lane",
        source: "src/routes/common.rs:18",
    },
    Entry {
        status: Some(404),
        code: MODEL_NOT_FOUND,
        reason: "Model not found",
        source: "src/routes/compat.rs:214",
    },
    Entry {
        status: Some(404),
        code: NO_SUCH_JOB,
        reason: "no-such-job",
        source: "src/result_store.rs:150",
    },
    Entry {
        status: Some(404),
        code: UNKNOWN_LANE,
        reason: "unknown-lane",
        source: "src/lane_bodies.rs:55",
    },
    Entry {
        status: Some(405),
        code: "",
        reason: "method not allowed; method is the requested HTTP method",
        source: "src/routes/compat.rs:170",
    },
    Entry {
        status: Some(405),
        code: METHOD_NOT_ALLOWED,
        reason: "method-not-allowed",
        source: "src/routes/jobs.rs:160",
    },
    Entry {
        status: Some(409),
        code: "",
        reason: "CU balance below floor",
        source: "src/job_spec.rs:34",
    },
    Entry {
        status: Some(409),
        code: "",
        reason: "CU balance or floor unavailable",
        source: "src/job_spec.rs:32",
    },
    Entry {
        status: Some(409),
        code: "",
        reason:
            "Dynamic detail from validation, registry, planning, cartridge storage or publication",
        source: "src/routes/common.rs:13",
    },
    Entry {
        status: Some(409),
        code: "",
        reason: "estimated CU exceeds cap",
        source: "src/job_spec.rs:27",
    },
    Entry {
        status: Some(409),
        code: "",
        reason: "invalid report",
        source: "src/routes/pull.rs:35",
    },
    Entry {
        status: Some(409),
        code: "",
        reason: "job_id exists",
        source: "src/routes/compat.rs:175",
    },
    Entry {
        status: Some(409),
        code: "",
        reason: "lane disabled",
        source: "src/routes/compat.rs:25",
    },
    Entry {
        status: Some(409),
        code: "",
        reason: "no accepting compatibility worker",
        source: "src/routes/compat.rs:106",
    },
    Entry {
        status: Some(409),
        code: "",
        reason: "no accepting worker meets GPU and cartridge VRAM requirements",
        source: "src/job_spec.rs:57",
    },
    Entry {
        status: Some(409),
        code: "",
        reason: "requested cartridge is not active",
        source: "src/routes/jobs.rs:66",
    },
    Entry {
        status: Some(409),
        code: DIGEST_CONFLICT,
        reason: "digest-conflict",
        source: "src/result_store.rs:221",
    },
    Entry {
        status: Some(409),
        code: MANIFEST_MISMATCH,
        reason: "manifest-mismatch",
        source: "src/artifact_routes.rs:97",
    },
    Entry {
        status: Some(409),
        code: PATH_UNSAFE,
        reason: "path-unsafe",
        source: "src/result_store.rs:126",
    },
    Entry {
        status: Some(410),
        code: NO_SUCH_ARTIFACT,
        reason: "no-such-artifact",
        source: "src/result_store.rs:230",
    },
    Entry {
        status: Some(413),
        code: "",
        reason: "Axum request body limit exceeded",
        source: "src/http_routes.rs:8",
    },
    Entry {
        status: Some(413),
        code: REQUEST_TOO_LARGE,
        reason: "request-too-large",
        source: "src/lane_bodies.rs:280",
    },
    Entry {
        status: Some(422),
        code: "",
        reason:
            "Dynamic detail from validation, registry, planning, cartridge storage or publication",
        source: "src/routes/common.rs:13",
    },
    Entry {
        status: Some(422),
        code: "",
        reason: "input must contain nonempty text",
        source: "src/routes/compat.rs:30",
    },
    Entry {
        status: Some(422),
        code: "",
        reason: "invalid JSON",
        source: "src/routes/compat.rs:29",
    },
    Entry {
        status: Some(422),
        code: "",
        reason: "invalid job-spec/v1 or lane mismatch",
        source: "src/job_spec.rs:23",
    },
    Entry {
        status: Some(422),
        code: "",
        reason: "prompt must be a nonempty string",
        source: "src/routes/compat.rs:153",
    },
    Entry {
        status: Some(422),
        code: "",
        reason: "request must be an object",
        source: "src/routes/compat.rs:117",
    },
    Entry {
        status: Some(422),
        code: "",
        reason: "spec must be an object",
        source: "src/routes/jobs.rs:50",
    },
    Entry {
        status: Some(429),
        code: QUEUE_FULL,
        reason: "queue-full",
        source: "src/artifact_routes.rs:9",
    },
    Entry {
        status: Some(501),
        code: "",
        reason: "streaming is not supported",
        source: "src/routes/compat.rs:125",
    },
    Entry {
        status: Some(502),
        code: "",
        reason: "compatibility worker failed",
        source: "src/routes/compat.rs:104",
    },
    Entry {
        status: Some(502),
        code: "",
        reason: "invalid chat worker response",
        source: "src/routes/compat.rs:138",
    },
    Entry {
        status: Some(502),
        code: "",
        reason: "invalid embedding worker response",
        source: "src/routes/compat.rs:45",
    },
    Entry {
        status: Some(502),
        code: "",
        reason: "status:error; job carries the failed generation result",
        source: "src/routes/compat.rs:128",
    },
    Entry {
        status: Some(503),
        code: "",
        reason: "CU balance unavailable",
        source: "src/routes/pull.rs:24",
    },
    Entry {
        status: Some(503),
        code: "",
        reason: "CU floor unavailable",
        source: "src/routes/pull.rs:23",
    },
    Entry {
        status: Some(503),
        code: "",
        reason: "CU ledger data unavailable",
        source: "src/routes/jobs.rs:100",
    },
    Entry {
        status: Some(503),
        code: "",
        reason: "CU ledger write failed",
        source: "src/routes/jobs.rs:103",
    },
    Entry {
        status: Some(503),
        code: "",
        reason:
            "Dynamic detail from validation, registry, planning, cartridge storage or publication",
        source: "src/routes/common.rs:13",
    },
    Entry {
        status: Some(503),
        code: "",
        reason: "admission check failed",
        source: "src/routes/compat.rs:168",
    },
    Entry {
        status: Some(503),
        code: "",
        reason: "card proof unavailable",
        source: "src/routes/pull.rs:20",
    },
    Entry {
        status: Some(503),
        code: "",
        reason: "chat dispatch failed",
        source: "src/routes/compat.rs:140",
    },
    Entry {
        status: Some(503),
        code: "",
        reason: "clock unavailable",
        source: "src/routes/pull.rs:25",
    },
    Entry {
        status: Some(503),
        code: "",
        reason: "embedding dispatch failed",
        source: "src/routes/compat.rs:63",
    },
    Entry {
        status: Some(503),
        code: "",
        reason: "generation failed",
        source: "src/routes/compat.rs:191",
    },
    Entry {
        status: Some(503),
        code: "",
        reason: "lane_token_unset: [owner] has not approved a token for this lane; use the CLI",
        source: "src/routes/common.rs:21",
    },
    Entry {
        status: Some(503),
        code: "",
        reason: "ledger write failed",
        source: "src/routes/pull.rs:34",
    },
    Entry {
        status: Some(503),
        code: "",
        reason: "worker registry unavailable",
        source: "src/routes/compat.rs:71",
    },
    Entry {
        status: Some(503),
        code: STORAGE_UNAVAILABLE,
        reason: "storage-unavailable",
        source: "src/worker_registry.rs:365",
    },
    Entry {
        status: None,
        code: COMMAND_POLICY_UNKNOWN_LANE,
        reason: "command-policy-unknown-lane",
        source: "src/command_policy.rs:19",
    },
    Entry {
        status: None,
        code: COMMAND_POLICY_NOT_ARRAY,
        reason: "command-policy-not-array",
        source: "src/command_policy.rs:20",
    },
    Entry {
        status: None,
        code: COMMAND_POLICY_INVALID_PROGRAM,
        reason: "command-policy-invalid-program",
        source: "src/command_policy.rs:24",
    },
    Entry {
        status: None,
        code: COMMAND_POLICY_DUPLICATE_PROGRAM,
        reason: "command-policy-duplicate-program",
        source: "src/command_policy.rs:25",
    },
    Entry {
        status: None,
        code: WATCHDOG_IDLE_WAIT,
        reason: "watchdog-idle-wait",
        source: "src/watchdog.rs:72",
    },
    Entry {
        status: None,
        code: WATCHDOG_IDLE_READY,
        reason: "watchdog-idle-ready",
        source: "src/watchdog.rs:72",
    },
    Entry {
        status: None,
        code: WATCHDOG_GAP_RESET,
        reason: "watchdog-gap-reset",
        source: "src/watchdog.rs:72",
    },
    Entry {
        status: None,
        code: WATCHDOG_GAP_CONTINUE,
        reason: "watchdog-gap-continue",
        source: "src/watchdog.rs:72",
    },
    Entry {
        status: None,
        code: WATCHDOG_ALERT_SUPPRESSED,
        reason: "watchdog-alert-suppressed",
        source: "src/watchdog.rs:72",
    },
    Entry {
        status: None,
        code: WATCHDOG_ALERT_READY,
        reason: "watchdog-alert-ready",
        source: "src/watchdog.rs:72",
    },
    Entry {
        status: Some(404),
        code: UNKNOWN_ROUTE,
        reason: "not_found",
        source: "src/routes/compat.rs:229",
    },
];
pub fn lookup(status: Option<u16>, message: &str) -> Option<&'static Entry> {
    TABLE.iter().find(|entry| {
        (status.is_none() || entry.status == status || entry.status.is_none())
            && (entry.reason == message || (!entry.code.is_empty() && entry.code == message))
    })
}
/// Canonical refusal association for legacy messages whose native catalog row
/// deliberately has no machine-code field. Wire lookup remains unchanged.
pub fn refusal_entry(status: Option<u16>, message: &str) -> Option<&'static Entry> {
    match (status, message) {
        (None | Some(400), "invalid request") => lookup(None, INVALID_REQUEST),
        (None | Some(404), "unknown lane") => lookup(None, UNKNOWN_LANE),
        (None | Some(404), "no such job") => lookup(None, NO_SUCH_JOB),
        (None | Some(409), "no accepting worker meets GPU and cartridge VRAM requirements") => {
            lookup(None, WORKER_NOT_READY)
        }
        (None | Some(409), detail)
            if detail.starts_with("cartridge ")
                && detail.ends_with(" lacks a commercial licence") =>
        {
            lookup(None, APPROVAL_MISSING)
        }
        _ => lookup(status, message),
    }
}
pub fn observe(status: Option<u16>, message: &str) {
    let found = refusal_entry(status, message);
    if let Some(entry) = found {
        debug_assert!(!entry.source.is_empty());
    }
    #[cfg(test)]
    if let Some(root) = std::env::var_os("FOLD_CATALOG_CAPTURE") {
        use std::io::Write;
        static CAPTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = CAPTURE_LOCK.lock().unwrap();
        let code = found
            .map(|entry| entry.code)
            .filter(|code| !code.is_empty())
            .unwrap_or("_message");
        let path = std::path::PathBuf::from(root).join(format!("{}.tsv", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("catalog capture");
        writeln!(
            file,
            "{}\t{}",
            code,
            std::thread::current().name().unwrap_or("process")
        )
        .expect("catalog capture write");
    }
}
pub fn canonical_code(value: &str) -> &'static str {
    TABLE
        .iter()
        .find(|entry| !entry.code.is_empty() && entry.code == value)
        .map_or(ARTIFACT_MISMATCH, |entry| entry.code)
}
pub fn reason(value: &'static str) -> &'static str {
    let code = canonical_code(value);
    observe(None, code);
    code
}
/// Closed machine-code fields emitted by each HTTP operation. Native message-only
/// responses have no machine-code field and retain their wire shape.
pub fn route_codes(path: &str) -> &'static [&'static str] {
    if path.contains("chat/completions") {
        &[MESSAGES_REQUIRED, PROMPT_REQUIRED]
    } else if path.contains("embed") {
        &[UNSUPPORTED_ENCODING_FORMAT]
    } else if path.contains("models/") {
        &[MODEL_NOT_FOUND]
    } else if path.contains("/artifacts") {
        &[
            DIGEST_CONFLICT,
            MANIFEST_MISMATCH,
            NO_SUCH_ARTIFACT,
            NO_SUCH_DOCUMENT,
            NO_SUCH_JOB,
            PATH_UNSAFE,
            STORAGE_UNAVAILABLE,
            UNKNOWN_LANE,
        ]
    } else if ["/v1/lanes/{lane}/jobs", "/v1/generate"].contains(&path) {
        &[QUEUE_FULL]
    } else {
        &[]
    }
}

#[cfg(test)]
#[path = "../tests/error_catalog.rs"]
pub(crate) mod tests;
