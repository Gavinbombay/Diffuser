#!/usr/bin/env python3
"""Run the legacy training lane through the shared Colab worker."""

from colab_worker import main
from presets import LaneConfig


CONFIG = LaneConfig(
    lane_id="colab-train",
    allowed_gpus=("G4", "H100", "A100"),
    min_cu_floor=200.0,
    max_cu_per_job=100.0,
    max_walltime_secs=21600,
    accepting=False,
    legacy_seat=True,
    forbidden_gpus=("L4", "T4"),
)


if __name__ == "__main__":
    main(CONFIG)
