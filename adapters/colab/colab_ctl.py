#!/usr/bin/env python3
"""Configure Colab fleet profiles and reconcile orphaned allocations."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import re
import sys
import time

from engine import (
    CONTROL_TIMEOUT, NUMBERED_INTENT, Engine, Refusal, account_lock, directory_entries, exists,
    intent_paths, lane_directory, locked_file, make_state_dir, seat_lock,
    state_directory, write_state,
)
from presets import (
    CU_FLOOR, PRESETS, LaneConfig, add_lane_arguments, argument_type, capability,
    lane_config, lane_id, positive_int,
)
from secure_io import JsonSizeError, directory, read_json, unlink_regular


WORKER = Path(__file__).resolve().parent / "colab_worker.py"
LEGACY_LANES = {"colab_l4.py": "colab-l4", "colab_train.py": "colab-train"}
CAPABILITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:-]{0,127}")


def read_config(path):
    config = read_json(path)
    if not isinstance(config, dict):
        raise ValueError("config must be a JSON object")
    return config


def init_config(args):
    if exists(args.config):
        raise ValueError("config already exists")
    bearer = "REPLACE_WITH_ENROLL_BEARER"
    if args.from_worker:
        bearer = read_config(args.from_worker).get("enroll_bearer")
        if not isinstance(bearer, str) or not bearer.strip():
            raise ValueError("source config has no enrollment bearer")
    write_state(args.config, {
        "worker_id": args.worker_id,
        "host": args.worker_id,
        "bind": args.bind,
        "advertise_url": f"http://{args.bind}",
        "controller_url": args.controller,
        "enroll_bearer": bearer,
        "rpc_secret_hex": "<set-64-hex>",
        "auto_detect_gpus": False,
        "profiles": [],
    }, exclusive=True)


def profile_lane(profile):
    adapter = profile.get("adapter")
    if not isinstance(adapter, dict) or adapter.get("kind") != "exec":
        return None
    command = adapter.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
        return None
    program = Path(command[0]).name
    if program in LEGACY_LANES:
        return LEGACY_LANES[program]
    if program == WORKER.name and "--lane" in command:
        index = command.index("--lane") + 1
        if index < len(command):
            try:
                return lane_id(command[index])
            except ValueError:
                pass
    return None


class ProfileArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("invalid lane command")


def describe_lane(profile, lane):
    adapter = profile["adapter"]
    name = profile.get("capability")
    timeout = adapter.get("timeout_secs")
    result = {
        "lane_id": lane,
        "capability": name if isinstance(name, str) and CAPABILITY.fullmatch(name) else None,
        "timeout_secs": timeout if type(timeout) is int else None,
    }
    command = adapter["command"]
    if Path(command[0]).name == WORKER.name:
        parser = ProfileArgumentParser(add_help=False, allow_abbrev=False)
        add_lane_arguments(parser)
        try:
            config = lane_config(parser.parse_args(command[1:]))
        except ValueError:
            return {**result, "configuration_valid": False}
    elif lane == "colab-l4":
        from colab_l4 import CONFIG as config
    else:
        from colab_train import CONFIG as config
    return {
        **result, "gpus": config.allowed_gpus, "forbid_gpus": config.forbidden_gpus,
        "min_cu_floor": config.min_cu_floor, "max_cu_per_job": config.max_cu_per_job,
        "max_walltime_secs": config.max_walltime_secs, "max_seats": config.max_seats,
        "max_account_vms": config.max_account_vms, "parked_by_default": not config.accepting,
    }


def lane_command(args):
    command = [str(WORKER), "--lane", args.lane, "--gpus", ",".join(args.gpus)]
    if args.forbid_gpus:
        command.extend(("--forbid-gpus", ",".join(args.forbid_gpus)))
    for flag, value in (
        ("--min-cu-floor", args.min_cu_floor), ("--max-cu", args.max_cu),
        ("--max-walltime", args.max_walltime), ("--max-seats", args.max_seats),
        ("--max-account-vms", args.max_account_vms), ("--idle-timeout", args.idle_timeout),
    ):
        if value is not None:
            command.extend((flag, str(value)))
    if args.parked:
        command.append("--parked")
    return command


def add_lane(args, profiles):
    lane_config(args)
    name = args.capability or capability(args.lane)
    if not CAPABILITY.fullmatch(name):
        raise ValueError("invalid capability")
    matches = [profile for profile in profiles if profile_lane(profile) == args.lane]
    if len(matches) > 1:
        raise ValueError("multiple profiles already use this lane")
    profile = matches[0] if matches else {}
    if any(other is not profile and other.get("capability") == name for other in profiles):
        raise ValueError("capability already belongs to another profile")
    profile.update(capability=name, adapter={
        **profile.get("adapter", {}), "kind": "exec", "command": lane_command(args),
        "timeout_secs": args.timeout_secs,
    })
    if not matches:
        profiles.append(profile)
    return {"lane_id": args.lane, "capability": name}


def redact_config_secrets(value, config):
    secrets = tuple(secret.casefold() for key in ("enroll_bearer", "rpc_secret_hex")
                    if isinstance(secret := config.get(key), str) and secret)

    def redact(item):
        if isinstance(item, str) and any(secret in item.casefold() for secret in secrets):
            return "[redacted]"
        if isinstance(item, dict):
            return {key: redact(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [redact(child) for child in item]
        return item

    return redact(value)


def config_profiles(config):
    profiles = config.get("profiles")
    if not isinstance(profiles, list) or not all(isinstance(profile, dict) for profile in profiles):
        raise ValueError("invalid profiles")
    return profiles


def configure(args):
    path = args.config
    action = args.action
    if action == "list-lanes":
        config = read_config(path)
        profiles = config_profiles(config)
        return redact_config_secrets([
            describe_lane(profile, lane)
            for profile in profiles if (lane := profile_lane(profile)) is not None
        ], config)

    if action == "init":
        # Existing config parents may also hold unrelated applications' files.
        with directory(path.parent, create=True):
            pass
    with locked_file(path.with_name(path.name + ".lock"), time.monotonic() + CONTROL_TIMEOUT):
        if action == "init":
            init_config(args)
            return {"created": True}
        config = read_config(path)
        profiles = config_profiles(config)
        if action == "add-lane":
            result = add_lane(args, profiles)
        else:
            config["profiles"] = [p for p in profiles if profile_lane(p) != args.lane]
            result = {"lane_id": args.lane, "removed": len(profiles) - len(config["profiles"])}
        write_state(path, config)
        return redact_config_secrets(result, config)


def change_lane_state(args, root):
    directory = root / args.lane
    make_state_dir(root)
    make_state_dir(directory)
    with account_lock(root, time.monotonic() + CONTROL_TIMEOUT):
        if args.action == "clear-quarantine":
            marker = directory / "quarantine.json"
            unlink_regular(marker, missing_ok=True)
            return {"lane_id": args.lane, "quarantined": False}
        parked = args.action == "park"
        write_state(directory / "OWNER-GO.json", {"unparked": not parked})
        return {"lane_id": args.lane, "parked": parked}


def inspect_orphan(engine):
    try:
        return {"status": "orphan", "session_name": engine.recovery_target(require_pid=True)}
    except Refusal as exc:
        return {"status": str(exc)}
    except FileNotFoundError:
        return {"status": "intent_gone"}
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return {"status": "intent_invalid"}


def reap_intent(engine, index, dry_run):
    candidate = inspect_orphan(engine)
    if dry_run or candidate["status"] != "orphan":
        return candidate
    try:
        with seat_lock(engine.state_dir, index) as engine.seat_fds:
            with engine.account_guard(time.monotonic() + 2 * CONTROL_TIMEOUT):
                candidate = inspect_orphan(engine)
                if candidate["status"] != "orphan":
                    return candidate
                session = candidate["session_name"]
                result = engine.cleanup_locked(session)
            return {
                "status": "cleaned" if result["cleanup_verified"] else "quarantined",
                "session_name": session, **result,
            }
    except Refusal as exc:
        return {"status": str(exc)}
    except OSError:
        return {"status": "state_unavailable"}
    finally:
        engine.seat_fds = ()


def reap(root, dry_run):
    summary = {"ok": True, "dry_run": dry_run, "cleaned": 0, "quarantined": 0, "intents": []}
    for name in directory_entries(root):
        try:
            lane = lane_id(name)
        except ValueError:
            continue
        if not lane_directory(root, name):
            continue
        for path in intent_paths(root / name):
            match = NUMBERED_INTENT.fullmatch(path.name)
            index = int(match[1]) if match else 0
            engine = Engine(LaneConfig(lane, ("L4",), CU_FLOOR, 30.0, 5400, False), state_root=root)
            engine.intent_path = path
            result = reap_intent(engine, index, dry_run)
            status = result["status"]
            if status in ("cleaned", "quarantined"):
                summary[status] += 1
            if status in ("quarantined", "intent_invalid", "account_lock_timeout", "state_unavailable"):
                summary["ok"] = False
            summary["intents"].append({"lane_id": lane, "intent": path.name, **result})
    return summary



class ControlArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "colab_ctl: invalid command arguments\n")


def main():
    parser = ControlArgumentParser(prog="colab_ctl", description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("list-presets")
    init = commands.add_parser("init")
    init.add_argument("--worker-id", default="colab-gpu-01")
    init.add_argument("--bind", default="127.0.0.1:5834")
    init.add_argument("--controller", default="http://127.0.0.1:5820")
    init.add_argument("--from-worker", type=Path)
    add = commands.add_parser("add-lane")
    add_lane_arguments(add)
    add.add_argument("--capability")
    add.add_argument("--timeout-secs", type=argument_type(positive_int), default=300)
    remove = commands.add_parser("remove-lane")
    listing = commands.add_parser("list-lanes")
    for command in (init, add, remove, listing):
        command.add_argument("--config", type=Path, required=True)
    remove.add_argument("--lane", type=argument_type(lane_id), required=True)
    for action in ("park", "unpark", "clear-quarantine"):
        command = commands.add_parser(action)
        command.add_argument("--lane", type=argument_type(lane_id), required=True)
        command.add_argument("--state-dir", type=Path)
    reaper = commands.add_parser("reap")
    reaper.add_argument("--state-dir", type=Path)
    reaper.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        if args.action == "list-presets":
            result = {gpu: {**asdict(preset), "capability": capability(gpu.lower())}
                      for gpu, preset in PRESETS.items()}
        elif args.action in ("init", "add-lane", "remove-lane", "list-lanes"):
            result = configure(args)
        elif args.action == "reap":
            result = reap(state_directory(args.state_dir), args.dry_run)
        else:
            result = change_lane_state(args, state_directory(args.state_dir))
    except JsonSizeError:
        parser.exit(2, "colab_ctl: JSON size limit exceeded\n")
    except (OSError, ValueError, Refusal, RecursionError):
        parser.exit(2, "colab_ctl: invalid or unavailable configuration or state\n")
    print(json.dumps(result, allow_nan=False))
    return int(isinstance(result, dict) and result.get("ok") is False)


if __name__ == "__main__":
    sys.exit(main())
