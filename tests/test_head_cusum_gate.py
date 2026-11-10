import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import head_cusum_gate as g  # noqa: E402


def export(encoder, head):
    return {'parameters': [
        {'name': 'encoder.0.weight', 'dtype': 'float32', 'values': list(map(float, encoder))},
        {'name': 'classification_head.weight', 'dtype': 'float32', 'values': list(map(float, head))},
    ]}


def round_exports(rng, n=8, head_scale=None):
    base = export(np.zeros(20), np.zeros(4))
    locals_ = [export(rng.normal(0, 1, 20) + 1, rng.normal(0, 1, 4) + 1) for _ in range(n)]
    if head_scale is not None:  # client00 manipulates the head only
        e = locals_[0]
        e['parameters'][1]['values'] = list(map(float, -head_scale * np.ones(4)))
    return base, locals_, [f'client{i:02d}' for i in range(n)]


def clean_records(seed=0, histories=4, rounds=6, cohort='iid'):
    rng = np.random.default_rng(seed); out = []
    for h in range(histories):
        for r in range(1, rounds + 1):
            base, locals_, ids = round_exports(rng)
            for c, f in g.compute_features(base, locals_, ids).items():
                out.append(dict(cohort=cohort, round=r, history=f'h{h}', client=c, features=f))
    return out


def model():
    recs = clean_records(0) + clean_records(1, cohort='non-iid')
    refs = g.fit_references(recs)
    cal = clean_records(2) + clean_records(3, cohort='non-iid')
    return dict(references=refs, thresholds=g.fit_thresholds(refs, cal))


def test_head_only_manipulation_is_visible_in_head_features():
    base, locals_, ids = round_exports(np.random.default_rng(5), head_scale=5.0)
    f = g.compute_features(base, locals_, ids)
    assert f['client00']['head_cosine_to_median'] < min(f[c]['head_cosine_to_median'] for c in ids[1:])
    assert f['client00']['head_relative_norm'] > max(f[c]['head_relative_norm'] for c in ids[1:])


def test_score_is_non_compensatory():
    m = model(); refs = m['references']
    normal = {k: refs['iid'][k]['median'] * g.DIRECTIONS[k] for k in g.FEATURES}
    bad = dict(normal); bad['head_cosine_to_median'] = normal['head_cosine_to_median'] - 50 * refs['iid']['head_cosine_to_median']['scale']
    # four perfectly normal indicators cannot pull the score of one extreme indicator down
    assert g.round_score(bad, refs, 'iid') == pytest.approx(50.0)
    assert g.round_score(normal, refs, 'iid') == pytest.approx(0.0)


def test_cusum_accumulates_and_resets():
    assert g.cusum_step(0.0, 1.0, 0.5) == 0.5
    assert g.cusum_step(0.5, 1.0, 0.5) == 1.0
    assert g.cusum_step(1.0, 0.0, 2.0) == 0.0
    with pytest.raises(ValueError):
        g.cusum_step(-1.0, 1.0, 0.5)


def test_clean_calibration_rate_is_bounded_by_target():
    m = model()
    for cohort in g.COHORTS:
        t = m['thresholds'][cohort]
        assert t['calibration_rate_max'] <= 0.02 and t['calibration_rate_cusum'] <= 0.02


def test_fitting_rejects_label_fields_and_gaps():
    rec = clean_records()[0]
    with pytest.raises(ValueError):
        g.fit_references([{**rec, 'attacker': True}])
    refs = g.fit_references(clean_records(0) + clean_records(1, cohort='non-iid'))
    gap = [r for r in clean_records(2) + clean_records(3, cohort='non-iid') if r['round'] != 3]
    with pytest.raises(ValueError):
        g.fit_thresholds(refs, gap)


def test_decide_trust_veto_and_flags():
    m = model(); refs = m['references']
    normal = {k: refs['iid'][k]['median'] * g.DIRECTIONS[k] for k in g.FEATURES}
    out = g.decide(m, 'iid', {'a': normal}, {}, trust_admissible=False)
    assert all(not d['contributes'] for d in out['a']['decisions'].values())
    out = g.decide(m, 'iid', {'a': normal}, {})
    assert all(d['contributes'] for d in out['a']['decisions'].values())
    huge = m['thresholds']['iid']['cusum_threshold'] + m['thresholds']['iid']['k'] + 1
    out = g.decide(m, 'iid', {'a': normal}, {'a': huge})
    assert out['a']['decisions']['head_cusum']['status'] == 'quarantined'
    assert out['a']['decisions']['head_max']['status'] == 'accepted'


def test_unsupported_cohort_and_schema():
    m = model()
    with pytest.raises(ValueError):
        g.decide(m, 'other', {'a': {k: 0.0 for k in g.FEATURES}}, {})
    base, locals_, ids = round_exports(np.random.default_rng(1))
    locals_[1]['parameters'][0]['name'] = 'renamed'
    with pytest.raises(ValueError):
        g.compute_features(base, locals_, ids)
