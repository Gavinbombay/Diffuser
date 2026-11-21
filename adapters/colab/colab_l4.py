#!/usr/bin/env python3
"""Run the legacy L4 lane through the shared Colab worker."""

from colab_worker import main
from presets import LaneConfig


CONFIG = LaneConfig(
    lane_id="colab-l4",
    allowed_gpus=("L4",),
    min_cu_floor=200.0,
    max_cu_per_job=30.0,
    max_walltime_secs=5400,
    accepting=True,
    legacy_seat=True,
)


if __name__ == "__main__":
    main(CONFIG)
