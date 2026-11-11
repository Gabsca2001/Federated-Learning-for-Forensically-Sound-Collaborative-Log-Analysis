"""Confirmatory study of head_v2 + per-tensor clipping (reduced, predeclared).

Thin wrapper around revision_head_v2_study (unchanged; its source locks hold).
* Model: the frozen head-v2 model of artifacts/revision-head-gate-v2 is reused
  byte-for-byte (copied and pinned). No new fitting, no threshold change.
* Arms: tpm_only+fedavg (reference), tpm_only+bounded, head_v2+bounded.
* Fresh assignments: guard 2 IID + 2 non-IID; evaluation 4 IID + 4 non-IID; seeds
  spaced by 1000; partitions refused if duplicated, also against all earlier gate
  studies including revision-head-gate-v2.
* Revised clean guard, declared BEFORE any confirmatory outcome and motivated by the
  exploratory study: the per-round >=80% mass rule fails any exclusion of a client
  holding >20% of data, i.e. almost any detector under Dirichlet(0.3) partitions.
  Replacement (per arm, on every guard assignment): complete 15 rounds; benign
  quarantine <=5%; pooled nominal mass >=90%; NO client excluded in two consecutive
  rounds (no persistent benign exclusion); validation macro-F1 loss vs reference
  <=2 points at rounds 10 and 15.
* Primary hypothesis C1: head_v2+bounded has lower paired worst-trigger peak harm than
  tpm_only+bounded in a majority of defined attacked comparisons. C2: head_v2+bounded
  lower than tpm_only+fedavg in effective reference controls (majority).
* Disk: after verification and test, case evidence is archived per case (tar.gz) with
  its manifest digest recorded; archives can be unpacked and re-verified.
Usage: revision_head_v2_confirm.py {prepare,guard,guard-decide,evaluation,smoke} [--workers N] [--lab P]
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import numpy as np

import revision_head_v2_study as v2
import clean_gate_calibration as cal
from revision_study_data import read
from revision_dba_experiment import save, environment
from fl_forensics.canonical import sha256_file

ROOT = v2.ROOT
LAB = ROOT / 'artifacts/revision-head-gate-v2-confirm'
SOURCE_MODEL = ROOT / 'artifacts/revision-head-gate-v2/models/head-v2.json'
ARMS = ('tpm_only+fedavg', 'tpm_only+bounded', 'head_v2+bounded')
STAGES = {
    'guard': [('iid', 2027400001), ('iid', 2027401001), ('non-iid', 2027402001), ('non-iid', 2027403001)],
    'evaluation': [('iid', 2027410001 + 1000 * k) for k in range(4)] + [('non-iid', 2027420001 + 1000 * k) for k in range(4)],
}
HYPOTHESES = [
    dict(id='C1_gate_adds_to_clipping', a='head_v2+bounded', b='tpm_only+bounded',
         variants=['distributed', 'complete-trigger', 'adaptive', 'adaptive-headfrozen'],
         text='head_v2+bounded lower paired peak harm than clipping alone (majority of defined comparisons)'),
    dict(id='C2_vs_reference', a='head_v2+bounded', b='tpm_only+fedavg',
         variants=['distributed', 'complete-trigger', 'adaptive', 'adaptive-headfrozen'], only_effective=True,
         text='head_v2+bounded lower paired peak harm than TPM-only FedAvg in effective controls (majority)'),
]
GUARD = dict(maximum_quarantine_rate=.05, minimum_nominal_mass_retention=.90, maximum_consecutive_rounds_excluded=1,
             maximum_fixed_endpoint_validation_f1_loss=.02)


def patch():
    """Point the unchanged v2 controller at this study's design (main process only)."""
    v2.LAB = LAB; v2.ARMS = ARMS; v2.STAGES = STAGES; v2.HYPOTHESES = HYPOTHESES
    v2.PRIOR_PARTITION_ROOTS = (*v2.PRIOR_PARTITION_ROOTS, 'revision-head-gate-v2')


def prepare():
    patch()
    v2.prepare()  # partitions, distinctness checks, attackers, base protocol (write-once)
    (LAB / 'models').mkdir()
    shutil.copyfile(SOURCE_MODEL, LAB / 'models/head-v2.json')
    base_protocol = read(LAB / 'protocol-before-fitting.json')
    addendum = dict(profile='head-v2-confirmatory-addendum', arms=ARMS, hypotheses=HYPOTHESES,
                    model=dict(source=str(SOURCE_MODEL.relative_to(ROOT)), sha256=sha256_file(SOURCE_MODEL), refit=False),
                    guard_rule_revised=GUARD, guard_rule_motivation=__doc__.split('* Revised clean guard,')[1].split('* Primary')[0].strip(),
                    supersedes_in_protocol=['guard.rule (80% per-round mass)', 'fitting (no new fit; frozen model reused)', 'hypotheses'],
                    base_protocol_sha256=sha256_file(LAB / 'protocol-before-fitting.json'),
                    wrapper_sha256=sha256_file(Path(__file__)), disk='case evidence archived per case after verification and test',
                    attacker_data_share=base_protocol['attacker_data_share'])
    save(LAB / 'confirmatory-addendum.json', addendum)
    print('CONFIRM_PREPARED ' + json.dumps(dict(addendum_sha256=sha256_file(LAB / 'confirmatory-addendum.json'),
                                                 model_sha256=addendum['model']['sha256'], attacker_share=addendum['attacker_data_share'])), flush=True)


def guard_decide():
    patch()
    v2.base.require((LAB / 'guard/training-complete.json').exists() and (LAB / 'guard/verified/summary.json').exists(), 'Guard closed+verified first')
    v2.base.require(not (LAB / 'guard-decision.json').exists(), 'Guard decision exists')
    closed = read(LAB / 'guard/training-complete.json'); by = {(r['task']['seed'], r['task']['policy']): r for r in closed['results']}
    details, qualified = {}, []
    for arm in ARMS:
        rows = []
        for cohort, seed in STAGES['guard']:
            res, ref = by[(seed, arm)], by[(seed, 'tpm_only+fedavg')]
            entry = dict(cohort=cohort, seed=seed, complete=bool(res['complete'] and ref['complete']), qualified=False)
            if entry['complete']:
                sizes = {r['client_id']: r['train_row_count'] for r in read(LAB / 'partitions' / str(seed) / 'manifest.json')['clients']}
                summaries, losses, excluded = [], [], []
                for n in range(1, 16):
                    row = read(LAB / 'guard/cases' / res['task']['name'] / 'evidence/rounds' / f'round-{n:03d}' / 'round.json')
                    summaries.append(dict(statuses=row['statuses'], masses=row['masses'], example_counts=sizes))
                    excluded.append({c for c, s in row['statuses'].items() if s.endswith('quarantined')})
                    if n in (10, 15):
                        other = read(LAB / 'guard/cases' / ref['task']['name'] / 'evidence/rounds' / f'round-{n:03d}' / 'round.json')
                        losses.append(other['validation']['clean']['macro_f1_all_model_classes'] - row['validation']['clean']['macro_f1_all_model_classes'])
                longest = 0
                for c in sizes:
                    run_len = 0
                    for ex in excluded:
                        run_len = run_len + 1 if c in ex else 0; longest = max(longest, run_len)
                b = cal.budget_summary(summaries)
                entry.update(budget=b, validation_losses=losses, longest_consecutive_exclusion=longest, qualified=bool(
                    b['quarantine_rate'] <= GUARD['maximum_quarantine_rate'] and b['nominal_mass_retention'] >= GUARD['minimum_nominal_mass_retention']
                    and longest <= GUARD['maximum_consecutive_rounds_excluded'] and max(losses) <= GUARD['maximum_fixed_endpoint_validation_f1_loss']))
            rows.append(entry)
        details[arm] = rows
        if all(r['qualified'] for r in rows):
            qualified.append(arm)
    decision = dict(qualified_arms=qualified, rule=GUARD, details=details, uses_attack_or_test_outcomes=False,
                    guard_closure_sha256=sha256_file(LAB / 'guard/training-complete.json'))
    save(LAB / 'guard-decision.json', decision); print('GUARD ' + json.dumps(dict(qualified_arms=qualified)), flush=True)


def smoke(folder):
    """2-round developer check of this study's three arms (writes only under ``folder``)."""
    import builtins
    patch(); folder = Path(folder); v2.base.require(not folder.exists(), 'Smoke folder must be new')
    root = read(LAB / 'protocol-before-fitting.json'); v2.assert_locks(root)
    folder.mkdir(parents=True); (folder / 'partitions').symlink_to(LAB / 'partitions', target_is_directory=True)
    cohort, seed = STAGES['evaluation'][4]
    tasks = [dict(name=f'smoke-{a}-{v}', cohort=cohort, seed=seed, attackers=root['attackers'][str(seed)], policy=a,
                  mode='adaptive' if v.startswith('adaptive') else v, variant=v)
             for a, v in (('head_v2+bounded', 'adaptive'), ('head_v2+bounded', 'adaptive-headfrozen'),
                          ('tpm_only+bounded', 'distributed'), ('tpm_only+fedavg', 'clean'))]
    save(folder / 'protocol-before-training.json', {**root, 'phase': 'smoke', 'tasks': tasks,
         'model_sha256': sha256_file(LAB / 'models/head-v2.json'), 'NOT_EVIDENCE': True})
    v2.base.range = lambda *x: builtins.range(1, 3) if x == (1, 16) else builtins.range(*x)
    try:
        v2.configure(folder)
        for t in tasks:
            r = v2.base.run_case(t)
            st = read(folder / 'cases' / t['name'] / 'evidence/rounds/round-002/gate-state.json')
            print('SMOKE ' + json.dumps(dict(task=t['name'], rounds=r['completed_rounds'],
                  q_deployed=sum(not d[t['policy']]['contributes'] for d in st['decisions'].values()))), flush=True)
    finally:
        del v2.base.range


def main():
    global LAB
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command', choices=('prepare', 'guard', 'guard-decide', 'evaluation', 'smoke'))
    ap.add_argument('--workers', type=int, default=2); ap.add_argument('--lab', type=Path, default=LAB); ap.add_argument('--smoke-dir', type=Path)
    a = ap.parse_args(); LAB = a.lab
    if a.command == 'prepare':
        prepare()
    elif a.command == 'guard-decide':
        guard_decide()
    else:
        patch()
        {'guard': lambda: v2.run_phase('guard', a.workers), 'evaluation': lambda: v2.run_phase('evaluation', a.workers),
         'smoke': lambda: smoke(a.smoke_dir)}[a.command]()


if __name__ == '__main__':
    main()
