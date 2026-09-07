from __future__ import annotations

from fl_forensics.discovery_stress import _episodes, _stress_summary


def test_discovery_events_are_grouped_into_independent_temporal_bursts() -> None:
    bursts, identity_to_burst = _episodes(
        [("a", 0.0), ("b", 59.0), ("c", 60.0), ("d", 121.0)],
        gap_seconds=60,
    )

    assert len(bursts) == 2
    assert bursts[0]["source_event_count"] == 3
    assert bursts[1]["source_event_count"] == 1
    assert identity_to_burst["a"] == identity_to_burst["c"]
    assert identity_to_burst["c"] != identity_to_burst["d"]


def test_stress_summary_does_not_treat_offsets_as_independent_samples() -> None:
    bursts, _ = _episodes([("a", 0.0), ("b", 121.0)], gap_seconds=60)
    offsets = [0, 5]
    records = []
    for burst in bursts:
        for offset in offsets:
            records.append(
                {
                    "alignment_offset_seconds": offset,
                    "target_burst_ids": [burst["burst_id"]],
                    "predicted_model_label": ("multi_tactic" if offset == 0 else "benign"),
                    "maximum_softmax_probability": 0.9,
                }
            )

    summary = _stress_summary(
        episodes=bursts,
        offsets=offsets,
        records=records,
        benign_label="benign",
    )

    assert summary["independent_burst_count"] == 2
    assert summary["correlated_burst_alignment_trial_count"] == 4
    assert summary["any_segment_detection_fraction"] == 0.5
    assert summary["all_segments_detection_fraction"] == 0.5
    assert "not additional samples" in summary["independence_warning"]
