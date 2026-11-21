"""Accelerator defaults and validation shared by both Colab entrypoints."""

import argparse
from dataclasses import dataclass
from typing import Optional
import math
import os
import re


CU_FLOOR = 200.0
DEFAULT_ACCOUNT_VMS = 2
LANE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
GPU_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


@dataclass(frozen=True)
class AcceleratorPreset:
    vram_gib: int
    max_cu_per_job: float
    max_walltime_secs: int


PRESETS = {
    "T4": AcceleratorPreset(16, 30.0, 5400),
    "L4": AcceleratorPreset(24, 30.0, 5400),
    "A100": AcceleratorPreset(40, 100.0, 21600),
    "H100": AcceleratorPreset(80, 100.0, 21600),
    "G4": AcceleratorPreset(96, 100.0, 21600),
}


@dataclass(frozen=True)
class LaneConfig:
    lane_id: str
    allowed_gpus: tuple
    min_cu_floor: float
    max_cu_per_job: float
    max_walltime_secs: int
    accepting: bool
    forbidden_gpus: tuple = ()
    max_seats: int = 1
    max_account_vms: Optional[int] = None
    legacy_seat: bool = False


def lane_id(value):
    if not isinstance(value, str) or not LANE_ID.fullmatch(value):
        raise ValueError("invalid lane ID")
    return value


def capability(lane):
    return f"colab.{lane_id(lane)}.exec/v1"


def gpu_list(value):
    names = tuple(item.strip() for item in value.split(","))
    if any(not GPU_NAME.fullmatch(name) for name in names):
        raise ValueError("invalid GPU identifier")
    if len({name.upper() for name in names}) != len(names):
        raise ValueError("duplicate GPU identifier")
    return tuple(name.upper() if name.upper() in PRESETS else name for name in names)


def positive_int(value):
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("expected a positive integer") from None
    if not 1 <= number <= 2**31 - 1:
        raise ValueError("expected a positive integer")
    return number


def positive_cu(value):
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("expected a positive finite CU budget") from None
    if not math.isfinite(number) or number <= 0:
        raise ValueError("expected a positive finite CU budget")
    return number


def cu_floor(value):
    number = positive_cu(value)
    if number < CU_FLOOR:
        raise ValueError("CU floor must be at least 200")
    return number


def account_limit(override=None):
    if override is not None:
        return positive_int(override)
    return positive_int(os.environ.get("DIFFUSER_COLAB_MAX_ACCOUNT_VMS", DEFAULT_ACCOUNT_VMS))


def argument_type(convert):
    def parse(value):
        try:
            return convert(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(str(exc)) from None
    return parse


def add_lane_arguments(parser):
    parser.add_argument("--lane", required=True, type=argument_type(lane_id))
    parser.add_argument("--gpus", required=True, type=argument_type(gpu_list))
    parser.add_argument("--forbid-gpus", type=argument_type(gpu_list), default=())
    parser.add_argument("--min-cu-floor", type=argument_type(cu_floor), default=CU_FLOOR)
    parser.add_argument("--max-cu", type=argument_type(positive_cu))
    parser.add_argument("--max-walltime", type=argument_type(positive_int))
    parser.add_argument("--max-seats", type=argument_type(positive_int), default=1)
    parser.add_argument("--max-account-vms", type=argument_type(positive_int))
    parser.add_argument("--parked", action="store_true")


def lane_config(args):
    denied = {name.upper() for name in args.forbid_gpus}
    allowed = tuple(name for name in args.gpus if name.upper() not in denied)
    if not allowed:
        raise ValueError("GPU denylist excludes every allowed GPU")
    preset = PRESETS.get(allowed[0], AcceleratorPreset(0, 30.0, 5400))
    return LaneConfig(
        args.lane, allowed, args.min_cu_floor, args.max_cu or preset.max_cu_per_job,
        args.max_walltime or preset.max_walltime_secs, not args.parked,
        args.forbid_gpus, args.max_seats, args.max_account_vms,
    )
