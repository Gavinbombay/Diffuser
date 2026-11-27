# Diffuser Gaming-Laptop Idle-Lane Guard

Quiet to the gamer, loud to the fleet.

This guard watches an RTX 4060 / Ryzen 9 laptop (A15, 8 GB VRAM). The moment a game or other non-Diffuser GPU load shows up, it drains that worker so the Diffuser controller stops putting new jobs on the GPU. After the machine stays continuously idle, it brings the worker back.

Python 3 standard library only. No pip packages. It runs on Linux, WSL2, and Windows.

## States

The machine is in exactly one of these states. Moving into `GAMER_ACTIVE` happens on the same poll that sees the signal. Moving back to `ACTIVE_FOR_FLEET` waits out the full cooldown.

| State | Meaning |
| --- | --- |
| `ACTIVE_FOR_FLEET` | The worker may accept Diffuser jobs. |
| `GAMER_ACTIVE` | A game or foreign GPU load is present. The worker is drained and, when configured, stopped. |
| `COOLDOWN` | Every gamer signal has cleared. The worker stays down until `idle_cooldown_secs` (default 180) of continuous idle. A new signal returns to `GAMER_ACTIVE` and the wait starts over. |

A short trip to the desktop, a loading stutter, or a GPU spike that drops for a few seconds does not hand the card back to the fleet. The idle stretch has to be continuous.

## What counts as gamer activity

Each poll (default every 3 seconds) checks two sources.

1. Process watchlist. A case-insensitive substring match against the process name and command line. The example list is `steam`, `cs2`, `cyberpunk`, `eldenring`, `baldursgate`, `valorant`, `helldivers`, `gamescope`, and `wine64-preloader`. `steam` matches `steam.exe`. `cyberpunk` matches `Cyberpunk2077.exe`.
2. Live `nvidia-smi`:
   - Any graphics or compute process that is not a Diffuser job and not on the desktop ignore list.
   - Or `utilization.gpu >= busy_util_pct` (default 25).
   - Or `memory.used >= busy_vram_mib` (default 1500 MiB).

The utilization and VRAM rules apply when no Diffuser job is running on the GPU. A Diffuser job is a GPU process whose name matches `diffuser_process_markers`, or a process that is the fleet worker or a child of it. A fleet training job can sit at high utilization without the guard treating it as a game. A game that launches beside that job still drains immediately, because the watchlist and foreign-process checks stay active.

1500 MiB is about a fifth of the 8 GB RTX 4060. An idle desktop on this laptop stays under that line. The ignore list covers the shell and the NVIDIA helper processes (`xorg`, `gnome-shell`, `dwm.exe`, `explorer.exe`, `nvcontainer`, and similar) so those always-on processes do not take the laptop out of the fleet. Add a browser or launcher name to `gpu_process_ignore` when that program should be allowed to use the GPU while the worker stays enrolled. If an idle desktop still drains, read `memory.used` from `nvidia-smi` and either raise `busy_vram_mib` or add that process name to the ignore list.

## Controller routes

Confirmed from the Diffuser fleet router (`/v1/fleet` on the controller):

- `POST /v1/fleet/workers/{worker_id}/drain` with `Authorization: Bearer <admin token>`. Sets `status` to `draining`. Success body is `{"ok": true, "worker_id": "...", "status": "draining"}`. The guard sends `{}`. The handler does not read a body.
- `POST /v1/fleet/workers/enroll` sets `status` to `active` on insert and on conflict. That is the call that puts a worker back in the scheduling set.
- `POST /v1/fleet/workers/{worker_id}/heartbeat` updates the heartbeat, live VRAM, and utilization. It does not change `status`.
- `GET /v1/fleet/workers` reports `status` and `accepting` (`accepting` is true when the worker is alive and `status` is `active`).

The router does not register an undrain path. The stock `uai-diffuser --fleet-worker` process also enrolls itself about once a minute, which would clear a drain on its own. On this laptop the guard posts drain and stops that process, so the GPU stays quiet for the whole gaming session. After the cooldown it starts the process again. The process mints its own `rpc_session` and enrolls.

`reenroll` in the config is optional and mutually exclusive with `worker_command`. When it is set, the guard itself POSTs `/v1/fleet/workers/enroll` after the cooldown. Leave it `null` on the A15. A second enroll would replace `rpc_session` out from under a worker that is already running.

While the state is `GAMER_ACTIVE` or `COOLDOWN`, every poll posts drain again. A stray enroll cannot stick for more than one poll interval.

Drain and enroll both require the fleet admin bearer. In the worker config that same secret is `enroll_bearer`.

## Security

- The bearer token is read from a regular file that is mode `0600` (owner read and write, nothing for group or other), or from the environment variable named by `token_env` when `token_file` is empty. The file wins when `token_file` is set.
- The token is not written into this repo, not placed in the example config, and not written to logs or error text.
- Prefer the file. On Linux, another process on the same machine can read an environment block.
- `controller_url` must be an origin with no user, password, path, or query. `https` is required. `http` is accepted only for `127.0.0.1`, `localhost`, and `::1`.
- Redirects are refused, so a `Location` header cannot carry the bearer token off the controller.
- `HTTP_PROXY` and `HTTPS_PROXY` are not used. The token is not sent to a proxy.
- HTTPS uses the platform certificate store. The client does not disable verification.
- HTTP timeouts are bounded (default 5 seconds, allowed range 1 to 30). `nvidia-smi` has its own timeout (default 2 seconds).
- Stop signals a pid from the pid file only when that process command line contains the worker executable name and the worker config file name. An unrelated recycled pid is left alone. The stop is `SIGTERM` to the process group, then `SIGKILL` after `stop_timeout_secs` (Windows: `taskkill /T`, then `taskkill /F /T`).

## Configure

```bash
mkdir -p /home/operator/.config/diffuser /home/operator/.local/state/diffuser
cp config.example.json /home/operator/.config/diffuser/gamer-idle.json
install -m 600 /dev/null example-admin-token.txt
# Write the fleet admin bearer into fleet.token. One line, no quotes.
```

Edit `controller_url` so it is the real controller origin, for example `https://diffuser.example.net`. Point `worker_command` at the local `uai-diffuser` binary and the fleet worker JSON (`--fleet-worker`). The example command is:

```text
/usr/local/bin/uai-diffuser --fleet-worker /home/operator/.config/diffuser/a15-worker.json
```

On Windows, set `token_file` to a user-only ACL path or leave `token_file` empty and set `token_env`. POSIX mode bits are enforced on Linux and WSL2. Windows skips that mode check because the permission model is different.

## Run

```bash
python3 gamer_idle_guard.py --config /home/operator/.config/diffuser/gamer-idle.json --check
python3 gamer_idle_guard.py --config /home/operator/.config/diffuser/gamer-idle.json
```

`--check` loads the config and the token, then exits. It prints `config ok` and does not print the token. `--once` runs a single poll.

A user systemd unit:

```ini
[Unit]
Description=Diffuser gamer idle-lane guard
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/operator/.hermes/workspaces/fleet-upgrades-20261122/job3-gamer-idle/gamer_idle_guard.py --config /home/operator/.config/diffuser/gamer-idle.json
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
```

On WSL2, `/proc` sees Linux processes, so Proton games are caught by `wine64-preloader` and `gamescope`. Windows games that never appear in `/proc` are still caught when `nvidia-smi` lists them or when utilization or VRAM crosses the threshold. Set `nvidia_smi_bin` to the Windows `nvidia-smi` if the Linux binary cannot see the GPU.

## State file

`state_file` remembers `GAMER_ACTIVE` and `COOLDOWN` across a guard restart, including how much of the idle wait has already elapsed. The file is mode `0600` and holds only the state name and a timestamp. It does not hold the token. The running process measures the wait with a monotonic clock. The file uses wall time so a later process can continue that wait.

Deleting the state file makes the next start begin in `ACTIVE_FOR_FLEET`. An idle machine with `worker_command` set will start the worker. A game that is already running drains on the first poll.

## Tests

```bash
python3 -m unittest discover -s . -p "test_*.py"
```

The tests mock `nvidia-smi`, the process list, the clock, and the HTTP controller. They cover instant drain on game launch, instant drain on a foreign GPU utilization or VRAM spike, cooldown hysteresis, re-enable after a clean cooldown, worker restart only after that cooldown, and HTTPS enforcement on remote URLs.

## Files

- `gamer_idle_guard.py` is the guard.
- `config.example.json` is the A15 / RTX 4060 config.
- `test_gamer_idle_guard.py` is the unittest suite.

## Limits

The guard sees what is true at each poll. A game that starts and exits entirely between polls can be missed. Poll default is 3 seconds.

A large step of the wall clock can shorten or lengthen one restored cooldown. The in-process wait uses a monotonic clock and does not follow NTP steps.

If the process list cannot be read, the guard drains so the laptop stays quiet until the list works again and the cooldown completes. If only `nvidia-smi` fails, the process watchlist still runs.
