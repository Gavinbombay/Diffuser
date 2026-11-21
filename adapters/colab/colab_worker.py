#!/usr/bin/env python3
"""Run one config-driven Colab fleet request."""

import argparse

from engine import main as run_worker
from presets import account_limit, add_lane_arguments, lane_config


class WorkerArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "colab_worker: invalid lane configuration\n")


def main(config=None):
    if config is None:
        parser = WorkerArgumentParser(prog="colab_worker", description=__doc__, allow_abbrev=False)
        add_lane_arguments(parser)
        args = parser.parse_args()
        try:
            config = lane_config(args)
            account_limit(config.max_account_vms)
        except ValueError as exc:
            parser.error(str(exc))
    run_worker(config)


if __name__ == "__main__":
    main()
