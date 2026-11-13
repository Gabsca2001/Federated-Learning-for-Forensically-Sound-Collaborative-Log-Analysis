"""Conservative connection-observation bounds for start-timestamped windows."""

import math


def observation_end_upper_bound(row):
    """Allow a full window for the latest start, its max duration and one second.

    This is a conservative bound for the released timestamp/duration precision,
    not a reconstruction of packet arrival times or log-write timestamps.
    """
    duration = float(row["features"][5])
    if not math.isfinite(duration) or duration < 0:
        raise ValueError("Invalid maximum duration")
    if int(row["window_end_epoch"]) != int(row["window_start_epoch"]) + 60:
        raise ValueError("Expected one-minute window")
    return float(row["window_end_epoch"]) + duration + 1.0


def indices_observed_by(rows, deadline):
    return [index for index, row in enumerate(rows) if observation_end_upper_bound(row) <= deadline]
