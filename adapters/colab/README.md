# Colab fleet worker adapters

Run Diffuser jobs on Google Colab GPUs using a Linux worker and Python 3.9 or later. These adapters use only the Python standard library. Install the pinned [Google Colab CLI](https://github.com/googlecolab/google-colab-cli/tree/v0.7.5) separately. Use `google-colab-cli==0.7.5`. The adapter targets that release’s command and output formats.

## Set up a worker

Run these commands from a Diffuser checkout as the account that will run the worker and the reaper. Sign in with `colab login` if your CLI provides it. Google Colab CLI 0.7.5 starts the OAuth sign-in flow when you run `colab usage`.

```sh
export DIFFUSER_COLAB_BIN="$(command -v colab)"
export DIFFUSER_COLAB_STATE_DIR="$HOME/.local/state/diffuser-colab"
export DIFFUSER_COLAB_MAX_ACCOUNT_VMS=2
install -d -m 700 "$DIFFUSER_COLAB_STATE_DIR"
"$DIFFUSER_COLAB_BIN" usage

ctl="$PWD/adapters/colab/colab_ctl.py"
config="$HOME/.config/diffuser/fleet-worker-colab.json"
"$ctl" list-presets
"$ctl" init --config "$config" --worker-id colab-gpu-01 \
  --bind 127.0.0.1:5834 --controller http://127.0.0.1:5820
```

Edit the starter config to supply the controller's enrollment bearer and a fresh 32-byte random RPC secret encoded as 64 hex characters. Add `--from-worker /path/to/existing-worker.json` to `init` to copy its enrollment bearer. The config is written with mode `0600`. The operator owns Colab OAuth sign-in, storage, rotation and revocation. Keep Colab credential files at mode `0600` in a private directory owned by the worker account. Session metadata can also contain credentials.

Keep the fleet worker on loopback for a same-host controller. The fleet worker is the authorization boundary. The adapter trusts requests it receives on stdin and executes shell commands on the Colab guest. For a controller on another host, set `bind` and `advertise_url` for a private, access-controlled network path. The adapter relies on the OS account boundary for local files. Anyone with the worker UID can access its private state and credentials.

```sh
for gpu in T4 L4 A100 H100 G4; do
  lane="$(printf '%s' "$gpu" | tr '[:upper:]' '[:lower:]')"
  "$ctl" add-lane --config "$config" --lane "$lane" --gpus "$gpu"
done
"$ctl" add-lane --config "$config" --lane custom --gpus CUSTOM_SKU --parked
"$ctl" add-lane --config "$config" --lane training --gpus H100,G4,A100 \
  --forbid-gpus L4,T4 --max-seats 2 --max-cu 100 --max-walltime 21600 --parked
"$ctl" list-lanes --config "$config"
diffuser --fleet-worker "$config"
```

Each lane publishes `colab.<lane>.exec/v1` unless you set `--capability`. Use `add-lane` again to update the profile or `remove-lane --config "$config" --lane <id>` to remove it. The worker reads its profiles when it starts. The original `colab_l4.py` and `colab_train.py` entrypoints still accept their existing requests and retain their original defaults.

The first GPU that survives the denylist is the default. Requests can choose another allowed GPU explicitly. Each allocation requests exactly one SKU and checks the provider's reported SKU before running the guest probe. Custom names pass through to the CLI as entered and use the standard 30 CU and 5400 second limits by default. Custom SKUs require CLI and account support. For example, CLI 0.7.5 maps unknown SKUs to A100, which fails the adapter's provider SKU check. [Upstream GPU selection](https://github.com/googlecolab/google-colab-cli/blob/v0.7.5/src/colab_cli/commands/session.py#L61-L85)

## Send a request

The adapter reads one JSON object of up to 256 KiB from stdin and prints one JSON receipt. Diffuser returns the receipt in the worker response's `output` field. Check its `ok`, `error` and `cleanup_verified` fields.

For a Diffuser fleet job, put the adapter request under `input` and select the lane with `capability`. The starter config advertises zero local VRAM. Leave `min_vram_bytes` and `pin_gpu_uuid` unset and select the accelerator through the lane or `input.gpu`.

```json
{"capability":"colab.t4.exec/v1","timeout_secs":240,"input":{"action":"probe","timeout_secs":180}}
```

```json
{"action":"status"}
{"action":"probe","gpu":"T4","timeout_secs":180}
{"action":"exec","command":"python3 --version","timeout_secs":180,"max_cu":10}
```

`health` is an alias for `status`. Status and health report account balance, session count and lane state without allocating or stopping a VM. A probe reports the observed GPU model, memory and driver version. Exec runs a shell command on the verified guest and reports the exit code. Successful receipts can include bounded workload stdout. Keep secrets out of workload output, job IDs and artifact names. Failure receipts omit workload stdout and raw CLI diagnostics. The adapter caps combined CLI stdout and stderr at 256 KiB. The job ID comes from `DIFFUSER_JOB_ID`, the request's `job_id`, or a generated ID, in that order.

### Transfer artifacts

Place inputs under `$DIFFUSER_COLAB_STATE_DIR/<lane>/artifacts/` on the worker. Local paths in a request are relative to that directory, or absolute paths within it. Remote paths are relative to `/content` in the guest.

```json
{
  "action": "exec",
  "command": "mkdir -p output && cp input/data.bin output/result.bin",
  "files_in": [{"local":"data.bin","remote":"input/data.bin"}],
  "files_out": [{"remote":"output/result.bin","local":"runs/job-01/result.bin"}]
}
```

Each direction supports up to four regular files, 64 MiB per file and 128 MiB total. Use paths of up to 120 characters with letters, digits, dots, underscores and hyphens in each component. The adapter rejects traversal, symlink components and hard-linked inputs. State and artifact directories use mode `0700`. Adapter state, lock, config and published artifact files use mode `0600`. Uploads finish before the command starts. After a successful command, the adapter downloads the requested outputs before stopping the VM. It verifies their size and SHA-256 digest against the guest and publishes each verified file atomically. The receipt's `files_out` entries include `local`, `remote`, `bytes` and `sha256`. Use distinct output paths for concurrent jobs. If a later download fails, the receipt lists the files already published.

## Resource limits and recovery

- Use one private, writable state root per account, shared by all its lanes and the reaper on the same host and PID namespace. The default is `/var/lib/diffuser-colab`. The CLI path defaults to `/opt/colab-cli-venv/bin/colab`. Session metadata under the state root can contain runtime credentials.
- The account cap defaults to two reserved VMs across those lanes. Set `DIFFUSER_COLAB_MAX_ACCOUNT_VMS` for the worker or use `--max-account-vms` in a lane profile. Use the same cap throughout an account. An active reservation with a smaller cap also constrains admission. The guard counts Diffuser intents, including unresolved ones, and coordinates through `_account/account.lock`.
- Each lane defaults to one seat. `--max-seats 2` allows two in the same lane subject to the account cap. A seat keeps its lock through cleanup. During controlled shutdown the adapter sends TERM, then KILL if needed, to the CLI process group and checks that the group disappears. An undrained work group triggers quarantine. A CLI child with an inherited lock retains it until exit if the adapter is forcibly killed. The configured CLI is trusted to keep its children in its process group. Seat zero coordinates with legacy `seat.lock` and `active_intent.json` state.
- The adapter blocks `colab pay` and requires an account balance of at least 200 CU. Increase the floor with `--min-cu-floor`. The lane enforces its CU and walltime ceilings at admission. The receipt compares account balances before and after execution. Other jobs on the same account can contribute to that delta, and pinned `google-colab-cli` 0.7.5 has no mid-session billing cutoff. A running VM can incur charges beyond the requested CU budget until the provider stops it.
- The work deadline includes staging, balance checks, allocation, execution and transfers. Cleanup has separate control deadlines. The Diffuser exec worker caps the entire adapter subprocess at 300 seconds. Leave time for cleanup by using a shorter work timeout, such as 180 seconds. The longer lane ceilings apply to direct callers with longer deadlines. Set `timeout_secs` up to the lane ceiling (`21600` on the training presets) as the outer safety limit. `idle_timeout_secs` defaults to 900 seconds, clamped to `1..max_walltime_secs`, and aborts a silent `colab exec` with `idle_timeout`. Stdout or stderr from the guest keeps that clock fresh. Configure the default with `--idle-timeout` or `DIFFUSER_COLAB_IDLE_TIMEOUT_SECS`. A failed `colab new` that spent 0 CU and left no owned session is retried once after `DIFFUSER_COLAB_ALLOC_RETRY_DELAY_SECS` (default 30). The delay finishes before the retry generation is saved. Immediately after the delay, the adapter reads `colab usage` and `colab sessions` again. The retry continues only when the balance is still unchanged and at least the CU floor, no owned session is listed, and the account VM count is still below the cap. A failed recheck does not call `colab new` again. A second allocation failure still returns `allocation_failed` and stops any owned VM.
- Use `park --lane <id>` to block new allocations and `unpark --lane <id>` to resume them. A profile with `--parked` needs `OWNER-GO.json` containing `{"unparked":true}` to allocate. Park leaves in-flight jobs to finish cleanup.
- The engine writes an intent with the owner PID and exact session name before allocating. Cleanup stops only that name and verifies absence. A failed stop, ambiguous listing, or remaining owned session quarantines the lane. After investigating provider state, use `clear-quarantine --lane <id>`. The command preserves unresolved intents.

### Run the orphan reaper

```sh
"$ctl" reap --state-dir "$DIFFUSER_COLAB_STATE_DIR" --dry-run
"$ctl" reap --state-dir "$DIFFUSER_COLAB_STATE_DIR"
```

Dry runs report candidates without invoking the Colab CLI. The reaper checks the PID again under lock before stopping a session named by an owned intent. It skips live PIDs, busy seats and legacy intents without a PID. Failed cleanup retains the intent and writes `quarantine.json`. Run the reaper with the worker's account, state root and CLI path.

For recurring cleanup, save these as `~/.config/systemd/user/diffuser-colab-reap.service` and `diffuser-colab-reap.timer` in the same directory. Replace the CLI and adapter paths with absolute paths from your installation. Use your worker's state root if it differs from the setup above.

```ini
[Unit]
Description=Reconcile orphaned Diffuser Colab sessions

[Service]
Type=oneshot
Environment=DIFFUSER_COLAB_BIN=/absolute/path/to/colab
Environment=DIFFUSER_COLAB_STATE_DIR=%h/.local/state/diffuser-colab
ExecStart=/absolute/path/to/diffuser/adapters/colab/colab_ctl.py reap
```

```ini
[Unit]
Description=Run the Diffuser Colab orphan reaper

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min

[Install]
WantedBy=timers.target
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now diffuser-colab-reap.timer
```

## Offline tests

The test suite uses a fake Colab binary and a fake GPU probe.

```sh
python3 -m unittest discover -s adapters/colab/tests -v
```

## Post-audit release

After the Cloudflare security audit, the operator reviews the audit findings and repair receipt, then manually commits and releases the adapter.
