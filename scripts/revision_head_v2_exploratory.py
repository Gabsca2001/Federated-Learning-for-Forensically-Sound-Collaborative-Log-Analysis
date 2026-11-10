"""Exploratory (non-confirmatory) evaluation of all head gate v2 arms.

Deviation from the frozen v2 protocol, recorded before execution: the guard
qualified only tpm_only arms (head_v2 arms failed the 80% per-round mass budget
through one borderline false positive: round 14, an honest client holding 30.7%
of the data, score 6.71 vs threshold 6.56). This phase evaluates every arm anyway
so the protection of head_v2 (alone and with clipping) can be measured. Results
are EXPLORATORY: they cannot confirm the predeclared hypotheses.

Reuses revision_head_v2_study unchanged (its source locks still hold); writes to
``<lab>/evaluation-exploratory``. Usage: revision_head_v2_exploratory.py [--workers N]
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import revision_head_v2_study as v2
from revision_study_data import read
from revision_dba_experiment import save
from fl_forensics.canonical import sha256_file

PHASE = 'evaluation-exploratory'


def tasks():
    protocol = read(v2.LAB / 'protocol-before-fitting.json'); out = []
    for cohort, seed in v2.STAGES['evaluation']:
        for arm in v2.ARMS:
            for v in list(v2.VARIANTS) + (['adaptive-headfrozen'] if arm.split('+')[0] in v2.HEADFROZEN_GATES else []):
                out.append(dict(name=f'{cohort}-s{seed}-{arm}-{v}', cohort=cohort, seed=seed, attackers=protocol['attackers'][str(seed)],
                                policy=arm, mode='adaptive' if v.startswith('adaptive') else v, variant=v))
    return out


def phase_protocol():
    folder = v2.LAB / PHASE; path = folder / 'protocol-before-training.json'
    if path.exists():
        p = read(path); v2.assert_locks(p); return p
    root = read(v2.LAB / 'protocol-before-fitting.json'); v2.assert_locks(root)
    decision_path = v2.LAB / 'guard-decision.json'
    v2.base.require(decision_path.exists(), 'Guard decision must exist (the deviation is defined relative to it)')
    folder.mkdir(); (folder / 'partitions').symlink_to(v2.LAB / 'partitions', target_is_directory=True)
    p = {**root, 'phase': PHASE, 'tasks': tasks(), 'model_sha256': sha256_file(v2.LAB / 'models/head-v2.json'),
         'guard_decision_sha256': sha256_file(decision_path), 'exploratory': True,
         'deviation': dict(recorded_at=datetime.now(timezone.utc).isoformat(), exploratory_runner_sha256=sha256_file(Path(__file__)),
             reason='head_v2 arms failed the clean guard only through the 80% per-round mass budget: one borderline false positive '
                    '(round 14, honest client with 30.7% of data, score 6.71 vs threshold 6.56). Evaluated as exploratory evidence; '
                    'thresholds, arms, seeds, attacks and metrics unchanged; no confirmatory claim for H1-H4.')}
    save(path, p); return p


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--workers', type=int, default=2)
    a = ap.parse_args()
    p = phase_protocol()
    print('EXPLORATORY ' + json.dumps(dict(cases=len(p['tasks']), protocol_sha256=sha256_file(v2.LAB / PHASE / 'protocol-before-training.json'))), flush=True)
    original = v2.phase_protocol
    v2.phase_protocol = lambda phase: p  # run_phase reads the protocol through this hook
    try:
        v2.run_phase(PHASE, a.workers)
    finally:
        v2.phase_protocol = original


if __name__ == '__main__':
    main()
