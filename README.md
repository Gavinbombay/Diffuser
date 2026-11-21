# lane-router (service-lane/v1)

Rust/Axum router for shared service lanes. This development build is not ready
for deployment; see the repoint checklist in `FOLD-NOTES.md`.

Build with `cargo build`. Start a local instance with
`lane-router serve --bind 127.0.0.1:17500`. HTTP job and compatibility POST
routes use the existing lane credential; replace `<TOKEN>` below with the
credential for the lane selected by the route. Health and catalog routes do
not require authentication. `/v1/lanes` uses the render-blender credential.

`compat-routes.json` in the router home contains a `lanes` map of lane names to
booleans and a `routes` map from each compatibility path to its lane. Use
`/v1/models/{id}` as the model-detail mapping. A missing mapping or unknown
lane returns 404; a disabled lane returns 409. Configuration is loaded at
startup. All six job lanes are disabled unless enabled in this map. Render also
requires the resolved render_pin described below. Diffusion-video discovery
remains accepting:false. An enabled lane still needs an
accepting, proof-passing compatible worker, a verified cartridge, and resolved lane pins with an approval record. Chat and
embedding routes require a configured lane and <!-- worker-cli -->a worker supporting `--chat` or
`--embed` respectively<!-- /worker-cli -->. Catalog entries come from enabled lanes with readable
active cartridge manifests. See `CONTRACT-5820.md` for response shapes and
reference limitations.

For `job-spec/v1` admission, `require_commercial` in `compat-routes.json`
defaults to true. Set it to false to allow internal jobs to use cartridges
without commercial approval. A job with `"use":"public"` always requires
the active cartridge manifest to declare `license_commercial: true`.

## HTTP examples

Examples use local paths and model IDs as placeholders. Supply an existing
absolute `.blend` file for render, an absolute empty output directory for each
job, and an active compatible cartridge or explicit cartridge manifest and
directory. Choose a fresh `job_id` for each submission. The lane job endpoint
returns 202 and a job ID; poll status or request cancellation using that ID.
The lane bodies require nonempty `prompt` (diffusion-image and music-sfx),
`text` (tts), or a relative `audio` reference (stt). Reference video dimensions
are multiples of 64; the retained flat legacy profile uses multiples of 16.
The video example describes the isolated fixture path, with public discovery
still accepting:false. Adapter command contracts and full bounds appear below.

```sh
curl http://127.0.0.1:17500/v1/health
curl -H 'Authorization: Bearer <TOKEN>' http://127.0.0.1:17500/v1/lanes
curl -H 'Authorization: Bearer <TOKEN>' http://127.0.0.1:17500/v1/lanes/render-blender/workers
curl -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{"blend":"/path/scene.blend","frames":"1-10","out":"/path/render-out","job_id":"render-example"}' http://127.0.0.1:17500/v1/lanes/render-blender/jobs
curl -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{"text":"Hello","out":"/path/tts-out","job_id":"tts-example"}' http://127.0.0.1:17500/v1/lanes/tts/jobs
curl -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{"audio":"store/audio/input.wav","out":"/path/stt-out","job_id":"stt-example"}' http://127.0.0.1:17500/v1/lanes/stt/jobs
curl -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{"prompt":"A landscape","out":"/path/image-out","job_id":"image-example"}' http://127.0.0.1:17500/v1/lanes/diffusion-image/jobs
curl -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{"width":832,"height":480,"loop":true,"out":"/path/video-out","job_id":"video-example"}' http://127.0.0.1:17500/v1/lanes/diffusion-video/jobs
curl -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{"prompt":"A bell","duration_seconds":30,"out":"/path/music-out","job_id":"music-example"}' http://127.0.0.1:17500/v1/lanes/music-sfx/jobs
curl -H 'Authorization: Bearer <TOKEN>' http://127.0.0.1:17500/v1/lanes/render-blender/jobs/render-example
curl -X POST -H 'Authorization: Bearer <TOKEN>' http://127.0.0.1:17500/v1/lanes/render-blender/jobs/render-example/cancel
```

Compatibility generation waits for completion and returns the job and verified
artifact digests. This example assumes `/v1/generate` maps to diffusion-image.
Chat streaming is refused with JSON 501; embedding input may be one string or a
batch of up to 32 strings. The model identifier below is illustrative.

```sh
curl -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{"prompt":"A landscape","out":"/path/generate-out","job_id":"generate-example"}' http://127.0.0.1:17500/v1/generate
curl -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{"model":"example-model","messages":[{"role":"user","content":"Hello"}]}' http://127.0.0.1:17500/v1/chat/completions
curl -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{"model":"example-model","messages":[{"role":"user","content":"Hello"}]}' http://127.0.0.1:17500/openai/v1/chat/completions
curl -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{"model":"example-model","input":["one","two"]}' http://127.0.0.1:17500/v1/embeddings
curl -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{"model":"example-model","input":"one"}' http://127.0.0.1:17500/openai/v1/embeddings
curl -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{"input":"one"}' http://127.0.0.1:17500/v1/embed
curl -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{"input":["one","two"]}' http://127.0.0.1:17500/embed
curl http://127.0.0.1:17500/v1/models
curl http://127.0.0.1:17500/openai/v1/models
curl http://127.0.0.1:17500/models
curl http://127.0.0.1:17500/api/v1/models
curl http://127.0.0.1:17500/api/models
curl http://127.0.0.1:17500/api/tags
curl http://127.0.0.1:17500/v1/models/example-model
```

The CLI also supports `workers --lane <lane>`, `submit --spec job.json
[--dry-run]`, `status <job_id>`, `cancel <job_id>` and `reap`. Output includes
job state and artifact SHA-256 manifests. Run `python3 tools/test-suite.py` for the full test suite. The harness serializes full runs and test execution, counts both the main suite and isolated subprocess checks, verifies b5 and b6 execution and reports their 172 and 350 case totals, rejects empty or failed groups, and writes target/suite.log and target/suite.json. Subprocess tests run private helper copies in temporary directories, so removing a build output cannot unlink their executable.

## Cartridge guard status

This development build is incomplete and must not be deployed. The cartridge
store is under `LANE_ROUTER_HOME/cartridges` (or the router's default state
directory). `versions/<manifest-sha256>/manifest.json` and `files/` hold a
staged, verified copy; `active/<lane>` holds the selected manifest digest.
Install and swap are local CLI operations:

```sh
lane-router cartridge-install --manifest /path/manifest.json --directory /path/files
lane-router cartridge-swap --lane render-blender --manifest-sha256 <MANIFEST_SHA256>
```

Install prints the SHA-256 of the manifest bytes. Swap verifies the installed
copy before atomically replacing the pointer. Jobs without explicit manifest and directory select the active pointer. HTTP
submission selects and verifies the manifest before queueing; the CLI selects it
before planning. The selected digest is rechecked for each attempt, as are worker
health and compatibility. Bake dispatch also rechecks the advertised job type.
HTTP returns 422 for manifest selection or verification errors, 409 when the
admission check finds no accepting compatible worker, and 503 for registry
access errors. Admission does not reserve capacity; dispatch checks again and
can still fail if capacity changes. The files remain mutable between verification
and use, so this is not complete in-flight pinning.

The optional in-router GPU watchdog is enabled by a `watchdog` object in
`compat-routes.json` with a `directory` containing `backlog.json` and optional
`standing.tsv`. It writes `events.csv`, `alerts.log`, and
`standing.dispatched.log` in that directory. `card_state_dir` selects pushed
card state. The watchdog checks proof before considering a card, samples every
120 seconds by default, and requires ten minutes below 10% utilization with
no live job. The `sample_seconds` (maximum 120), `idle_seconds`, and
`util_threshold` settings can change those values. Set `watchdog.off` to true
or create the configured `off_file` (default `/etc/lanes/GPU-WATCHDOG-OFF`)
to stop filling while health remains available. `clock_file` optionally supplies
an epoch for controlled tests. The watchdog submits through the router's normal
in-process admission path and does not need an HTTP credential.

The router service account must own `card_state_dir`, the watchdog directory,
and their input subdirectories with mode `0700`. Publish regular input files
with mode `0600` by atomic rename from the same directory. Watchdog job specs
and the optional clock file must be inside the watchdog directory. Paths may
be absolute within that directory or relative to it.

Remote fleet worker and controller URLs require HTTPS. Local HTTP URLs may use
`localhost` or a loopback address. Update controllers and workers together so
workers can re-enroll with the signed RPC session protocol. The ready queue is
available to the service account or root on the Unix control socket used by
`lanes-ctl`.

## Router policies E1 to E6

The native job and generation handlers share admission and result policies.
The `queue` object in `compat-routes.json` accepts `per_lane_limit` (default
128), `global_limit` (512), and `seats` (1). Caps count live jobs, including
running and cancelling jobs. Full queues return 429 with
`{"error":"queue-full","code":"queue-full","retryable":true}` and a
`Retry-After` hint from 1 to 5 seconds. Dispatch rotates across eligible
lanes, then selects owner priority before standard priority and FIFO within
each class. `submitter` defaults to `standard`. Worker seats and proof checks
still apply independently. Pull jobs share the caps and held-seat accounting.

Runtime output checks run before a job can finish successfully. TTS defaults
to 24000 Hz and an admitted 300 second ceiling. `runtime_limits.tts_seconds`
can select the ceiling for newly admitted TTS jobs. Music requires an integer
`duration_seconds` from 1 to 300. Every WAV, including music stems, must have
a consistent header and sufficient data. Exact sample comparisons accept the
ceiling and reject one sample over. FLAC stems fail closed until measurement
is supported. Video defaults to 48 admitted frames, within 2 to 480, and
requires a produced count from the worker manifest or numbered frame files.
The two produced signals must agree. A merge allows at most 8 distinct
artifacts and rechecks every declared digest and byte count.

An enabled lane also needs `pins` in the config, or `pins_path` naming a
strict JSON catalog. The catalog has `kind: cartridge-catalog/v1`, a
`cartridges` array, and six `lane_pins` records. Render keeps its existing
id-list pin and additionally requires the resolved render_pin below. Each other record supplies lane, resolved model, cartridge,
matching Pin, and a plain `owner_approval` record naming `[owner]`.
Placeholders, duplicate fields or cartridge ids, mismatched pins, and requests
outside the configured pin bounds refuse admission. No approval credential is
stored in this catalog. Use the offline gate with explicit paths:

```sh
lane-router lane-gate check --pins /path/pins.json --state-dir /path/gate-state
lane-router lane-gate enable tts --pins /path/pins.json --state-dir /path/gate-state
lane-router lane-gate disable tts --pins /path/pins.json --state-dir /path/gate-state
```

`lane_gate_state_dir` in the config adds the persisted enabled set to the
allowlist check. Missing state means disabled. Corrupt state fails closed.
Each valid gate call fsyncs one audit record; snapshots use atomic rename.
Usage errors exit 2 without a traceback. Gate commands do not change a running
router's startup configuration.

Results default to `<router-home>/results`; `result_store_dir` selects a
separate result root. The layout is `lanes/<lane>/jobs/<job_id>/` for the
closed result envelope, metadata, manifest, sidecar, and attempt device logs.
Artifacts are lane-local blobs under `lanes/<lane>/blobs/<prefix>/<sha256>`.
Writes rehash the temporary file before atomic rename, reads verify digests,
and terminal documents freeze. Native authenticated downloads use
`GET /v1/lanes/{lane}/jobs/{id}/artifacts/{path}` for a referenced artifact,
`manifest.json`, or `SHA256SUMS`. Existing legacy artifact names remain valid
through the bridge; the direct storage contract uses lane-fixed names.

| Lane | Artifact retention | Document retention |
| --- | --- | --- |
| render-blender | 30 days | 90 days |
| tts, stt, diffusion-image, music-sfx | 14 days | 45 days |
| diffusion-video | 7 days | 30 days |

GC is an explicit offline command. `lane-router results-gc --root
/path/results` reports a dry run; add `--apply` to collect expired results and
orphans. Live jobs remain. Malformed metadata is reported and keeps uncertain
blobs. Temporary writes have a default 86400 second grace. The maximum
artifact is 64 MiB, job document 64 KiB, and metadata 4 KiB.

A job's absolute deadline is fixed at admission and includes queue time.
Expiry is inclusive and settles before cancellation or a worker completion.
The default timeout is 45 minutes; bake jobs retain their existing sum of step
budgets and staging allowance. Attempts have the six result-contract fields,
a cap of two, and device event documents. Existing retry decisions are
unchanged. Internal worker refusal projects to a failed result with a refused
attempt, keeping the stored envelope valid.

Registry `kind` values are `exec`, `adapter-tts`, `adapter-diffusion`,
`adapter-music-sfx`, `adapter-render-blender`, and `adapter-stt`.
An adapter worker adds `dispatch.entry`, the absolute adapter entry path.
Python entries use `dispatch.interpreter`, default `/usr/bin/python3`;
executable entries run directly. `dispatch.grace_seconds` defaults to 5 for
termination escalation. `exec` remains the underlying worker executable and
must satisfy the existing health, proof, and resource checks. The router
passes each adapter its declared spec/job, output, worker, identity and budget
flags. Adapter dry runs refuse unless using the existing exec dry-run path.
Adapter delivery requires part sidecars and a device log. The router checks
part bytes and the job sidecar, then resolves evidence from process return
code, device log, and terminal result document in that order of increasing
precedence. Timeouts and cancellation enforced by the router take priority.
Unknown kinds retain their existing refusal message. The accepted reference
citations and deliberate legacy differences are recorded in `FOLD-NOTES.md`.

## RUN20 admission and result contracts

The router includes the accepted artifact, render, registry and lane-body
references. The b5-06 corpus is stored byte for byte under
`tests/fixtures/b5-06`, with its manifest and SHA256SUMS. Its four named tests
check all 172 cases and the 18 admission, 63 dispatch and 91 limits counts.
The conformance test is compiled inside the binary crate to exercise the
production functions directly. Additional named tests cover the 175 admission
edge cases and 45 per-lane fixtures. Reference differences and case citations
are recorded under F1 to F5 in `FOLD-NOTES.md`.

Authenticated reads use the existing lane credential:

- `GET /v1/lanes/{lane}/jobs/{id}/artifacts` lists artifact triples.
- `GET /v1/lanes/{lane}/jobs/{id}/artifacts/manifest.json` serves the stored
  manifest bytes.
- `GET /v1/lanes/{lane}/jobs/{id}/artifacts/{path}` serves a named artifact.

Reads check identifiers and containment, refuse symlinks, require a done job,
and verify manifest identity, sorted artifact metadata, hashes and byte sizes.
Successful responses include Content-Type, Content-Length and a strong SHA256
ETag. Unknown jobs and names are 404. Missing or expired retained artifact
bytes are 410. Integrity conflicts are 409; storage failures are 503. Read
failures use the three-field error envelope, while authentication keeps its
existing behavior. Cleanup state does not gate reads. The existing authenticated
SHA256SUMS download remains available. Artifact routes accept GET only.

Render bodies now reject unknown fields, invalid steps and misplaced floats.
The render arm uses the existing frame parser; the bake arm accepts ranges,
comma lists, arrays and omitted frames. Steps are one to three distinct values
from script, bake and render. Script-only bake jobs still require an absolute
empty output path and the existing blend-file guard. Timeout defaults to 45
minutes with a 1..=360 band. Bake step timeouts are in (0,720]; render step
fields permit 0..=720. Fractional values are supported in those three minute
fields. Script text is bounded at 4096 characters.

Render admission defaults disabled. Enablement requires
`lanes.render-blender: true` and an eight-field `render_pin` containing id,
sha256, voices, rates, max_width, max_height, max_steps and max_text_chars.
Its id must be `blender-4.5.14-cycles`; its digest must match the selected
cartridge manifest. Existing cartridge-byte, resource and worker guards still
apply. The native gate keeps its established 409 refusal status.

Worker configuration is parsed as strict JSON with validated ids, unique lanes,
unique worker ids and seats in 1..=16, default 1. Existing exec/adapter entries
and card-only records remain supported. Optional `worker_state_path` points to
an offline heartbeat registry. Registering, stale, draining, gone and full
records cannot enable a static worker; advertised lanes and remaining seats
constrain selection. Defaults are heartbeat 30 seconds, stale after age greater
than 90 seconds, and gone after age greater than 180 seconds. A stale worker
keeps held jobs; a sweep reports reassignment evidence without changing retry
policy. State saves use a synced temporary file and atomic rename.

The offline CLI supports:

```text
lane-router worker-registry register --state state.json --record worker.json
lane-router worker-registry heartbeat --state state.json --id worker-id
lane-router worker-registry drain --state state.json --id worker-id
lane-router worker-registry sweep --state state.json
lane-router worker-registry candidates --state state.json --lane stt
lane-router catalog-resolve --catalog catalog.json --lane stt --job job.json
```

The registry CLI also supports view, claim and release. Catalog resolution
validates metadata, pin shapes and bounds, lane schema pointers, unique ids
and at most one default per lane. Render catalogs may omit a pin. A non-string
job lane refuses cleanly. Optional `cartridge_catalog_path` or an inline
`cartridge_catalog` adds this resolution to native submission, generation and
CLI submission. Catalog metadata does not replace physical cartridge integrity
or enable a lane by itself.

STT, video and music bodies now validate their field tables and bounds. STT
uses a relative audio reference of at most 1024 characters, the wav/flac/ogg/mp3/
m4a format enum, full-string language syntax, bounded hints and alternatives,
and a 3600-second serviceability ceiling. Video validates prompt, negative,
steps, seed, size, fps, frames and mp4 format; reference size dimensions are
256..=1536 and multiples of 64. Music validates text, duration 1..=300,
bpm 20..=300, musical tonality, seed, stems and wav format. Text bounds are
4096 characters and seeds are unsigned 32-bit values. Explicit nulls refuse.
Diffusion-video remains `accepting:false` in lane and worker discovery.

The native legacy `out` profile retains acceptance of omitted api/format fields,
resolved cartridge ids, flat video dimensions and loop-only video jobs. Its
existing HTTP refusal assertions and two-field queued response remain intact.
Reference-shaped bodies use the strict required field table. Header replay is
not introduced; reused job ids retain the existing conflict policy. Submitted
fingerprints exclude injected defaults. S1a and S1b remain unfinished; this
work does not deploy or replace a running binary.

## RUN21 conformance and HTTP documentation

The b6-04w2 corpus extends the checked fixture set to 350 cases: 114 admission,
63 dispatch, 82 gate and 91 limits. Each case has a named Rust test that calls
the production components in process. Corpus files and MANIFEST are byte
identical to the accepted source, with source-derived SHA256SUMS. There are
187 reference matches and 163 exact, documented native differences. See
`docs/CONFORMANCE-B6.md` and `tests/b6_differences.json`.

`docs/openapi.json` documents all 29 explicitly registered path and method
pairs. A shared declaration in src/http_routes.rs:3 builds the real handler
and its route inventory. Tests compare the complete route sets, validate
one live loopback response per path, and reject missing routes or required
fields. The document uses native wire shapes and resolving source anchors.
Implicit HEAD follows Axum GET behavior; artifact paths refuse HEAD.

D1 to D6 remain open for [owner]. `docs/DECISIONS-FIT.md` and six named tests
pin the existing behavior. No recommendation has been adopted by this run.
`docs/ERRORS.md` and src/error_catalog.rs:9 expose the same 148 catalog rows,
including native message families, structured codes and internal reasons.
An isolated suite replay captures actual emissions and requires every listed
code to be exercised. The source scan rejects unlisted production codes.

The cite checker validates local file and line ranges in README.md,
CONTRACT-5820.md and FOLD-NOTES.md. Available A references are checked too;
unavailable A references are counted and skipped. `SHA256SUMS.run21` records
the RUN21 files. Check it from the repository root with
`sha256sum -c SHA256SUMS.run21`. No deployment or live service change is made.

RUN22 vendors worker helpers from openai/codex@8801b9a, Apache-2.0. See third_party/codex/LICENSE, NOTICE and CHANGES.md.

Dispatch workers use their own Linux process groups, closed stdin, a zero core dump limit, and close-on-exec cleanup of all inherited descriptors above stdio. Cleanup failure prevents exec. Timeout and cancellation signal the group, escalate to group KILL after the configured grace, and reap the worker. The terminal manifest is published after result storage.

Worker dispatch config accepts `result_storage.worker_log_max_bytes`, default 65536 and range 1 through 16777216. This bounds retained stdout and stderr payload bytes across both streams; an omission notice adds at most 64 bytes. Logs retain a stable head and recent tail. Complete lines are redacted before truncation and disk writes. Lines exceeding 65536 bytes are wholly omitted with a public marker. Device events, ledger and audit output, watchdog events and cleanup messages share the sanitizer. The upstream regex sanitizer is best effort and recognizes its documented assignment and bearer patterns.

H4 retry backoff is deferred because the latest retry/quota QC did not pass. H5 command allowlisting is deferred because its parser needs packages outside Cargo.lock. Existing retry, quota and admission policy remains in use. FOLD-NOTES.md contains H1 to H5 provenance and decisions. third_party/codex/CHANGES.md records every vendored adaptation. Verify RUN22 files using `sha256sum -c SHA256SUMS.run22` from this root. The new code uses only packages already present in Cargo.lock.


## RUN23 enforced contracts

The OpenAPI response matrix exercises all 29 registered operations and 139
operation/status pairs on ephemeral 127.0.0.1 listeners. Six new tests validate
required fields, types and enums, reject undeclared statuses, and prove that the
document walker names any missing exercising case. Artifact lists now include
api, lane and job_id alongside artifacts, as the existing schema requires.
Unreachable operation statuses were removed from the document and artifact-name
400 was added. Explorer is unavailable in this sandbox; these document/handler
discrepancies are recorded in CONT_REPORT.md.

src/error_catalog.rs owns machine-code constants, canonical code resolution and
route code sets. Native message-only bodies retain their wire shape; machine-code
enums are closed per route. Unknown device diagnostics remain attempt reasons
and cannot introduce new router error codes. Three new tests enforce bare-code
scanning, route enum equality and recursive source coverage. docs/ERRORS.md still
has 148 rows matching the catalog.

The 350 b6 cases retain 187 matches and 163 classified differences: 162 deliberate
native contracts and one reference bug for duplicate artifact paths. Every entry
has a REF file:line and reason. No fold bug was identified. Two new classification
tests pass. D1 to D6 are unchanged and I7/I8 remain held.

Real worker supervision checks absolute deadlines and cancellation during wait,
uses H1 group termination, and records raw OS exit evidence only after reaping.
Retained result snapshots still project exactly the six contract attempt fields;
runtime manifests retain the OS evidence. Four new real-child tests cover group
expiry, cancellation, reaped exit settlement and the two-attempt cap.

The shared H2/H3 log writer bounds and redacts watchdog CSV and standing/alert
logs, inline manifest log fields and HTTP status log tails. Four new checks cover
these surfaces and reject direct log-write bypasses with file:line diagnostics.
Retained head/tail payload is capped; the omission notice adds at most 64 bytes.
Device_log and adapter_log file references retain their paths.

H5 was deferred, so docs/ALLOWLIST-PLAN.md defines our strict JSON exact-program
policy. docs/command-policy.json ships empty grants for every lane. Dispatch
requires explicit administrative grants for each executable, interpreter and
adapter entry. Missing or malformed policy denies. Four new tests cover allow,
deny, unknown denied and per-lane policy loading. No crates or vendored files
were added. No deployment, live process change, retry or quota port was performed.

Verify current files and evidence with sha256sum -c SHA256SUMS.run28 from this
root. CONT_REPORT.md records the final consecutive suites and inaccessible note
updates.

RUN23 final validation: three consecutive serial suites each passed 1195 main tests plus 42 isolated checks, reported total 1237. This adds 23 distinct main tests to RUN22, exceeding its required reported minimum of 1226. Earlier run manifests describe their historical snapshots; SHA256SUMS.run28 verifies the current tree.

## RUN24 native QC, deadlines and structure

The QC sweep in docs/QC-MINORS.md records 65 findings with status and both
accepted-verdict and fold citations. Four native regressions and a table guard
were added. Python signed verification, adapter and delivery-only findings are
identified as absent from this fold. Explicit unknown lanes precede body size
and parsing at the native request boundary.

The 350 b6 cases still have 187 matching and 163 listed results. Twelve additional
family tests pin eleven deliberate families and the duplicate-path reference
bug. All 162 deliberate entries remain listed; family counts sum to 163.

Real queue waiting expires jobs without workers, attributes the timeout to the
router and publishes result/device files. Adapter commands use H1 supervision,
with terminal/expired jobs refused before spawn. Four new checks cover waiting,
seat release, adapter supervision and terminal stability after real child exits.

The shipped six-lane command policy still grants no programs. Four new tests
pin distinct catalog errors for unknown lanes, non-array values, invalid programs
and duplicate entries. The error catalog has 148 rows; OpenAPI includes the
canonical codes in optional job error details. I2 route enum equality still holds.

src/main.rs has 217 lines. Shared execution is in src/engine.rs; handlers are in
src/routes/{common,pull,compat,jobs,queue,server}.rs. The root test declarations
and embedded script bytes were preserved. Citation checks include docs Markdown
and enforce the root size bound. The OpenAPI matrix remains 29 operations and
139 method/status pairs.

Run `python3 tools/test-suite.py` for one offline full-suite command. Test
subprocesses hold private executable copies in temporary directories, including
a regression that removes the source path. The harness runs suites and tests
serially, checks unchanged inputs and reports the main and isolated checks as
one total. RUN24 adds 26 main tests to RUN23: 1221 main plus 45 isolated is 1266.
Final serial evidence is recorded in CONT_REPORT.md. Verify current deliverables
with `sha256sum -c SHA256SUMS.run28`. Earlier manifests describe historical trees.
I7/I8, S1a/S1b and item 16 retain their existing gates. No crates or vendored files were added. No retry/quota policy, deployment or
live process change was introduced.

## RUN25 QC and regression guards

All 65 QC rows have a resolved disposition. Three real-child deadline tests
compare persisted files, snapshots and journals using an injected clock, including
a delayed replay. Fixed fixture job identifiers preserve the existing native
identifier policy.

Every route module has body-size and content-type refusal coverage using catalog
codes. POST bodies above 65536 bytes and explicit unsupported media types receive
413 and 415 JSON refusals before handler extraction and authentication. Missing
content-type headers retain the existing legacy behavior. The OpenAPI matrix
covers all 29 operations and 157 method/status pairs.

Policy reload is DEFERRED because there is no existing reload admin route or
SIGHUP handler. docs/ALLOWLIST-PLAN.md records the restart-only administrative
procedure. RUN28 N1 closes the load discrepancy: startup validates and retains
each configured policy path, and invalid startup policy refuses with its catalog
reason. Authorization uses the retained snapshot until restart.

The b6 guard compares all 350 case rows with their exact class and reason in
docs/CONFORMANCE-B6.md and names any drifting entry. Its mutation regression
checks that the matching row must change. Run `python3 tools/test-suite.py` for
the offline serial harness, which requires successful b5 and b6 execution and
reports 172 b5 cases (159 matches, 13 listed) and 350 b6 cases (187 matches,
163 listed). RUN25 adds 14 main tests and three isolated checks to RUN24:
1235 main plus 48 isolated checks gives 1283. Final serial evidence is recorded
in CONT_REPORT.md. Verify deliverables with `sha256sum -c SHA256SUMS.run28`.
I7/K6 and I8 retain their gates; S1a/S1b stay held and item 16 stays flagged.

## RUN26 policy validation

Run `lane-router --check-policy docs/command-policy.json` before startup. The
command validates the named policy and exits without a listener. Invalid policy
prints the catalog reason and exits 1; incorrect arguments exit 2 with usage.
RUN28 loads and validates policy before dispatch startup and retains it until
restart. There is no reload route or signal.

## RUN26 request, coverage and worker guards

`lane-router --check-policy FILE` validates the policy before startup and exits
without a listener. The command uses the dispatch loader and prints a catalog
reason on refusal. Reads stop at 65537 bytes; policies above 65536 bytes refuse
with request-too-large before parsing. The shipped policy still grants nothing.

Every registered HTTP method has the documented 65536-byte body cap. Invalid
UTF-8 path parameters return 400 path-unsafe. Unknown JSON fields return 400
invalid-request where a request schema has additionalProperties false, including
the nested pull report. Open request schemas retain their declared extensions.
The OpenAPI matrix now exercises 29 operations and 186 method/status pairs.

The full harness command remains `python3 tools/test-suite.py`. It clears old
coverage artifacts before each run and rejects unexercised operations, statuses
and error codes, undeclared exercised statuses and catalog codes without a route
declaration or explicit internal-only scope in docs/ERRORS.md. Internal codes
still require real emission evidence. Each run writes its coverage report beside
its suite log and JSON report in target/.

QC row guards require status, both positive file:line citations and an existing
fold target within line bounds. Four real-worker fault tests cover ignored TERM,
forked descendants, early stdout closure and output above the H2 cap. Each checks
reaped OS status, one terminal settlement and bounded redacted logs. The policy
edge table has 18 refusal rows plus a sparse large-file read-budget check.

RUN26 adds 33 main tests and four isolated checks to RUN25. The final inventory is
1268 main plus 52 isolated checks, total 1320. CONT_REPORT.md records three serial
full-suite runs, offline build, Clippy and name-scan evidence. Verify current
deliverables with `sha256sum -c SHA256SUMS.run28`. Historical manifests describe
their own snapshots. L7/I7 and I8 retain their gates; S1a/S1b stay held and item 16
stays flagged.

## RUN27 harness timing

`python3 tools/test-suite.py` writes `target/suite-timing.json` with the pass
count and wall time for every libtest group, including isolated checks, plus
the total cargo wall time. Groups use their completion order as stable report
identifiers. Empty, failed, ignored or missing timing groups fail the harness.
Each labeled run also retains `target/<label>-timing.json`.

## RUN27 route, example and settlement evidence

Six per-module fuzz tables exercise truncated JSON, wrong top-level types,
oversized strings, deep nesting and duplicate fields. Each response must have
its exact status, catalog entry and declared OpenAPI schema. Native legacy
message-only catalog entries retain their existing wire shape.

Every one of the 186 OpenAPI operation/status pairs has a response example.
`docs/openapi-response-source.json` preserves the real HTTP response corpus
used to populate those examples. Rust validates every example and checks its
provenance. The coverage gate requires fresh validation evidence matching the
OpenAPI file SHA256 and fails with the affected pair for invalid examples.

Four real fault workers each run twice under the same injected clock. Their
settlement records, logs and manifests must match byte for byte, with exactly
one terminal event. Capture drains both pipes concurrently within bounded
buffers and emits stdout before stderr so reader scheduling cannot change the
result. Combined output retains the configured head/tail cap and omission
markers. Existing redaction and descendant cleanup checks remain enforced.

Each successful policy load, including `--check-policy FILE`, writes one
redacted line through the shared bounded writer to stderr. The line contains
only `policy_sha256` for the exact input bytes and `lane_count`. Refused loads
retain their catalog error and never claim a successful load. Policy program
lists are not logged. Policy activation remains restart-only.

The QC table has seven closed-in-fold rows, four completed fixed-now rows and
54 not-in-fold rows. There are no open fold findings or additional M5 fixes.
RUN27 adds 16 main tests and ten isolated checks to RUN26, for 1284 main plus
62 isolated checks, total 1346. Three final serial suite reports retain their
per-group timing reports alongside the final `target/suite-timing.json`.

The historical shared-note ledger is [docs/NOTES-TO-UPDATE.md](docs/NOTES-TO-UPDATE.md). It preserves source notes from RUN23 onward and their affected sections.

Close-outs use `python3 tools/name-scan.py` with relative file or directory roots.
The tool silently reads the prescribed reference and prints one matching-file
count per root, in argument order. It never prints patterns, matches or paths.
Directory scans skip target and protected or excluded trees; list evidence files
as explicit roots when checking close-out artifacts. A scan error exits nonzero.

The full harness also writes `target/suite-timing-delta.json`, comparing each
group's wall time and pass count with the last saved `target/suite-timing.json`.
It names groups missing from either run and records unavailable prior timing.
`target/suite-timing-previous.json` preserves that input. Labeled copies retain
each run's current timing, previous timing and delta. This is a report only;
it adds no timing or count-change failure threshold.

## RUN28 policy and maintenance guards

Submit and serve load and validate the default and configured worker policy
paths before creating a runtime or job. Each path is loaded once. Invalid
startup policy exits with its catalog reason; later edits or removal leave
the retained grants unchanged. New policy paths require restart. The
standalone --check-policy command remains validation only. Load evidence
appears once per path; authorization emits no additional load line.

The citation guard checks every file and line range in the three required
documents, including accepted and pinned vendor references. CLI SIGINT and
SIGTERM tests run real workers and require one cancelled settlement, reaping
before exit and one bounded redacted cancellation line. Clippy allows require
a file/lint justification in FOLD-NOTES.md. The notes ledger retains every
RUN23 to RUN27 source entry, and RUN27 carry records none for M1 to M6.

The offline command remains `python3 tools/test-suite.py`. RUN28 adds nine
main tests to the RUN27 baseline, for 1293 main plus 62 isolated checks,
total 1355. Final serial evidence is recorded in CONT_REPORT.md. Verify the
current tree with `sha256sum -c SHA256SUMS.run28`. Per-item manifests cover
the same final files and their item evidence. Earlier manifests are historical.

## RUN29 maintenance outputs

Counts-only close-outs use tools/name-scan.py. The startup policy table pins
explicit paths before default fallback and checks actual catalog refusals.
The notes ledger includes RUN28 and RUN29 follow-ups and checks every source
entry from RUN23 onward. The manifest guard checks every shipped run manifest
without opening listed paths. The timing delta is a report only and names
groups missing from either saved run. RUN28 carry is empty.

RUN29 adds seven main tests and eight isolated startup checks. The inventory
is 1300 main plus 70 isolated, total 1370. O3 was deferred after two failed
targeted runs under the loop guard; its partial changes remain. Close-out
documentation reconciliation adds the RUN24 entry named by that diagnostic.
The final serial suite reports establish the complete-tree result. O7/I7,
I8 and S1a/S1b remain held; item 16 remains flagged. No deployment or live
process change is part of this run.

## RUN30 core edge tables

Queue dispatch rotates through render-blender, tts, stt, diffusion-image, diffusion-video and music-sfx, starting after the last dispatched lane and skipping lanes without eligible queued jobs. Within a lane, owner priority precedes standard priority, then ascending admission position gives FIFO, then job id breaks ties lexically. Admission uses the injected clock for deadlines; clock equality does not change queue order.

### Router CLI flags

The maintenance test parses main.rs and its delegated command parsers and checks router flags throughout this README. The annotated worker CLI arguments above belong to workers.

| Command | Accepted flags |
| --- | --- |
| serve | `--bind` |
| workers | `--lane` |
| submit | `--spec`, `--dry-run` |
| cartridge-install | `--manifest`, `--directory` |
| cartridge-swap | `--lane`, `--manifest-sha256` |
| results-gc | `--root`, `--apply` |
| lane-gate | `--pins`, `--state-dir` |
| worker-registry | `--state`, `--id`, `--record`, `--reason`, `--job`, `--lane` |
| catalog-resolve | `--catalog`, `--lane`, `--job`, `--cartridge` |
| policy validation | `--check-policy` |

Worker registry drain accepts an optional reason. Catalog resolution accepts an optional cartridge id and job file. Status, cancel and reap take no flags.


RUN30 adds ten core regression tests over the RUN29 baseline of 1370 checks.
Deadline tables cover equality, adjacent ticks, zero timeout and maximum
saturating arithmetic; expiry settles once with deadline-exceeded. Warp
watchdog tables cover the same idle-limit boundaries with consecutive injected
observations and once-only dispatch. No wall-clock sleep is used in these tables.
CU ledger identity is the complete sanitized CSV row, with per-job access
serialized by the existing caller. Exact duplicates refuse invalid-report
without writing; negative balances refuse cu-floor. Replaying identical events
preserves ledger bytes and totals. Distinct observations in one second remain
valid. Named artifact paths refuse traversal, absolute, empty and non-UTF-8
names with path-unsafe; artifacts over the default 67108864 byte cap refuse
artifact-too-large before writes. Queue dispatch rotates through render-blender,
tts, stt, diffusion-image, diffusion-video and music-sfx, starting after the
last lane and skipping ineligible work. Within a lane it orders owner priority,
admission position, then lexical job id. CLI drift tests parse accepted router
flags and name any missing or extra README flag. RUN29 carries only O3, under
its two-failure loop guard; no O implementation work is repeated here.
The shared follow-ups remain in docs/NOTES-TO-UPDATE.md. Close-out evidence uses
three serial full-suite runs, tools/run30-audit.py and relative-path
SHA256SUMS.run30 manifests. I7/P7, I8 and S1a/S1b remain held; item 16 remains
flagged. No retry, backoff or quota rule is introduced.

The full-suite harness gives each invocation a fresh temporary directory through TMPDIR, inherited by its isolated child checks. This prevents process-id fixture collisions across sandbox launches while preserving CARGO_HOME. All three final suites use this isolation.

## RUN31 contract and tool checks

RUN31 adds cartridge registry refusal tables, render and request decoder
limit tables, tool process fixtures and bidirectional error documentation
checks. The limits and stage status meanings are in docs/RUN31-LIMITS.md.
The registry table has ten rows; render and decoder tables have 62 and 20.
Error documentation covers all 89 nonempty catalog codes. Responses without
a code remain documented as none.

Every script under tools/ accepts the clean and planted fixture modes
documented in docs/RUN31-LIMITS.md. The seven new cargo tests require clean tempdir
inputs to succeed and planted failures to exit nonzero without PASS output.
They cover coverage-gate, test-suite including the timing delta, cli-cancel,
name-scan and the RUN28, RUN29 and RUN30 audits. Existing signal and self-test
checks remain. The fixtures use no network.

Q1 is DEFERRED by the two-failure loop guard. Four retained draft tests and
serde field contracts cover the three shipped schemas, including nested
closed objects and planted field/additionalProperties drift. The wire
contracts join the existing schema validation paths. No schema file changed.
Later full-suite results report these tests without reopening the deferred
item. The build prerequisite corrected the raw Rust ref identifier.

RUN30 has no P1 to P6 carry items. Q7/I7 and I8 remain held, as do S1a/S1b;
item 16 remains flagged. RUN31 has sixteen new main tests including the four
Q1 draft tests, raising the RUN30 baseline of 1380 to 1396 checks. Run the
complete offline suite with `python3 tools/test-suite.py`.
Close-out evidence uses target/run31-final-serial-1.json through
run31-final-serial-3.json, target/run31-final-series.json,
target/run31-audit.json, seven per-item manifests and SHA256SUMS.run31.
Shared design follow-ups remain in docs/NOTES-TO-UPDATE.md.


Runtime limit defaults and admission bounds are pinned to named constants. TTS seconds can be configured for newly admitted jobs.

| Constant | Value |
|---|---|
| runtime_limits::TTS_SECONDS | 300 |
| runtime_limits::SAMPLE_RATE | 24000 |
| runtime_limits::VIDEO_FRAMES | 48 |
| runtime_limits::MAX_ARTIFACTS | 8 |
| runtime_limits::MUSIC_SECONDS_MIN | 1 |
| runtime_limits::MUSIC_SECONDS_MAX | 300 |
| runtime_limits::VIDEO_FRAMES_MIN | 2 |
| runtime_limits::VIDEO_FRAMES_MAX | 480 |
| runtime_limits::SAMPLE_RATES | [16000,22050,24000,44100,48000] |

## RUN32 transition and runtime tables

RUN32 adds a 60-pair segment boundary table, nine worker registration refusal
rows, a 32-pair pushed-card snapshot table and bidirectional runtime constant
document checks. Checked segment APIs expose catalog codes; bool callers keep
their existing behavior. Deliberately drained worker ids cannot register again;
use a fresh id. Heartbeat expiry still supports a new generation of the same id.

R3 is deferred: exec spans six lanes and adapter-diffusion spans two, while the
retained S01 unknown-kind test pins its original message. Changing those
contracts would violate the rule preserving older completed items and tests.
Card states are writer observations: idle, busy and unknown may replace each
other. Invalid snapshots fail closed as state-unreadable. docs/RUN32-TABLES.md
records the event coverage and runtime parity scope. RUN31 carry contains Q1
only, with its existing loop-guard blocker. RUN32 retains five new cargo tests
over baseline 1396; the required final total is 1401. R7/I7, I8 and S1a/S1b
remain held, and item 16 remains flagged.


## RUN33 dispatch, timeout, policy and wire tables

RUN33 adds eight Rust tests over the RUN32 final baseline of 1401. Three fixed-clock
Warp dispatch traces match worker/frame decisions and event order. Unknown lane,
job type and worker kind refuse with catalog codes before changing dispatch state.
Existing multi-lane kind mappings and kind-parser diagnostics remain intact.
Nine watchdog rows pin idle 600-second, observation-gap 150-second and alert
3600-second boundaries with action codes and no sleeps. The sampling schedule is
unchanged. These are existing observation thresholds.

Command authorization refuses unknown programs, unlisted absolute paths, an empty
executable, shell metacharacters and argv over 65536 bytes including terminating
bytes. Exact equality and a granted executable with no arguments are accepted.
docs/ALLOWLIST-PLAN.md lists the syntax. The shipped grants remain empty.
Public [R] and <TOKEN> markers are removed before the unchanged vendored sanitizer.
Nine symbolic redaction rows and recursive documents are checked; a planted bearer
bypass is detected. These cases test marker handling, not upstream credential-length
regex branches.

Six schema examples and six lane fixtures pass admission and byte-identical typed
wire round trips after JSON normalization. Unknown top-level and item fields refuse
422 bad-spec. RUN32 carry contains R3 only. docs/RUN33-TABLES.md records the scope,
and docs/RUN33-NOTES-TO-UPDATE.md records inaccessible shared design follow-ups.
The required final total is 1339 main plus 70 isolated checks, total 1409, with three
consecutive serial full suites. SHA256SUMS.run33 and seven item manifests cover the
current outputs. S7/I7, I8 and S1a/S1b remain held; item 16 remains flagged.

## RUN34 refusal and parity coverage

RUN34 adds eight Rust tests over RUN33 baseline 1409. The worker wait loop has
an explicit lifecycle tested over all 42 state/event pairs with inert children.
Artifact requests have a five-row refusal table, including invalid UTF-8 through
the real in-process guard. Five gated lane body contracts have bidirectional
parity with orphan, duplicate and missing-body detection. All 29 explicit HTTP
operations match OpenAPI. Store integrity checks refuse corrupt immutable
manifest records with catalog codes while keeping earlier versions readable
and the active pointer unchanged. RUN33 has no S1 to S6 carry items.

Details are in docs/RUN34-TABLES.md and shared design follow-ups are in
docs/RUN34-NOTES-TO-UPDATE.md, linked from docs/NOTES-TO-UPDATE.md. The full-suite
command is python3 tools/test-suite.py; three serial reports and checks under
target/run34-* form the close-out evidence. The required final total is 1417.
SHA256SUMS.run34 and seven per-item manifests cover source, docs, the local
binary and actual evidence with relative paths and conventional self-exclusion.
T7/I7, I8 and S1a/S1b remain held; item 16 remains flagged.

Final RUN34 validation: 1347 main plus 70 isolated checks, total 1417, pass in
three consecutive serial suites with 71 nonempty timing groups, zero failed or
ignored checks and green coverage. Build and all-target Clippy have no warnings.
The name scan returns 0. target/run34-final-series.json records the sequence.

RUN35 adds seven Rust tests over the RUN34 baseline of 1417 checks. The final
suite floor is 1354 main plus 70 isolated, total 1424. U1 covers agent pull
refusals and schema examples, U2 covers pinned cartridge loading, U3 covers
card-state enum and field parity, U4 covers all 20 compatibility paths, and U6
checks the empty RUN34 carry list. U5 is DEFERRED because GET pagination has no
existing contract and adding it conflicts with the retained 29-operation
RUN34 assertion. See docs/RUN35-TABLES.md and CONT_REPORT.md. Each implemented
item has a temporary-copy planted failure followed by restored green tests;
U5 has a planted blocker-consistency failure. The full-suite command remains
python3 tools/test-suite.py. SHA256SUMS.run35 and the per-item manifests use
relative paths and conventional self-exclusion.

## RUN36 route and harness coverage

RUN36 adds seven Rust tests over RUN35 baseline 1424. The required final floor
is 1361 main plus 70 isolated checks, total 1431. V1 covers six Jobs refusal
rows with catalog association and no writes. V2 checks all 29 mounted route
operations, unique handlers, common error codes, queue refusal linkage and
unmounted-handler drift. V3 checks all nine runtime-limit values and units in
both directions. V4 covers the worker-process test submodule with 24 terminal
refusals on inert child records. V5 covers the worker-log submodule through
bad-path, wrong-digest and partial-write result-store refusals. V6 carries the
unchanged U5 pagination blocker. See docs/RUN36-TABLES.md and CONT_REPORT.md.

Use python3 tools/test-suite.py for the full suite and
python3 tools/run36-check.py finalize for the close-out audit. The current
payload manifest is SHA256SUMS.run36, checked with
sha256sum -c SHA256SUMS.run36. Seven per-item manifests cover the same source,
docs, local binary and real evidence using relative paths and self-exclusion.
Earlier checksum and test-total references describe historical run snapshots.
Shared design follow-ups are in docs/RUN36-NOTES-TO-UPDATE.md. I7/V7, I8 and
S1a/S1b remain held; item 16 remains flagged. No retry policy is introduced.

RUN36 V1 also keeps unknown-ID refusals ahead of deadline processing: an
unrelated already-expired queued job remains unchanged and is not published
by a refused lookup. Successful lookups retain deadline processing.

Final RUN36 validation: three consecutive serial suites each pass 1361 main
plus 70 isolated checks, total 1431, with 71 nonempty groups and green
coverage. Name scan is 0. target/run36-final-series.json records the sequence.

## RUN37 worker and admission checks

RUN37 adds eight Rust tests over the RUN36 baseline 1431, for a required
floor of 1439 checks: 1369 main plus 70 isolated. The tests cover all 42
worker state/event pairs, request decoding and HTTP status mapping, CU CSV
escaping and single-header appends, canonical job-spec normalization for all
schema examples, and ten GPU/licence admission rows. Physical card worker views
must satisfy card_pref. Generic exec workers and anonymous helper callers retain
their existing resource-check contract. Native refusal messages keep their
wire shape and have canonical catalog associations for evidence capture.

RUN36 carry is empty; RUN35 U5 pagination remains carried. W7/I7, I8 and
S1a/S1b remain held and item 16 remains flagged. The run requires three
serial complete suites with every group nonempty, per-item temporary-copy
planted failures, preservation checks and clean scans. See
[RUN37 tables](docs/RUN37-TABLES.md), [notes to update](docs/RUN37-NOTES-TO-UPDATE.md)
and the root RUN37_REPORT.md. Reproduce with `python3 tools/run37-close.py
finalize` after generating the real evidence and manifests.
