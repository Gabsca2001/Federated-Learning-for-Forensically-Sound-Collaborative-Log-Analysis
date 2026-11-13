"""Independent arithmetic reconciliation and scoped publication of the guard audit."""
import csv
import hashlib
import heapq
import json
from collections import Counter,defaultdict
from fractions import Fraction
from pathlib import Path
import os
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
LAB=ROOT/'artifacts/revision-admission-mass-safety-v1'
OLD=ROOT/'artifacts/revision-severe-tail-gate-v1'
OUT=ROOT/'results/gates-probes/revision-admission-mass-safety-v1'
LOCAL=(Path(os.environ["FL_FORENSICS_OUTPUT_ROOT"]) / 'mass-safety-mail-audit-20261106')


def read(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def table(name):
    with (LAB/name).open(newline='') as stream:return list(csv.DictReader(stream))
def dump(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def main():
    assert not OUT.exists(),'Preserve independent closure'
    p=read(LAB/'protocol-before-audit.json');summary=read(LAB/'summary.json')
    assert summary['status']=='verified' and p['posthoc'] and summary['new_profile_ASR'] is None
    for relative,digest in p['source_locks'].items():assert sha(ROOT/relative)==digest
    for name,digest in read(LAB/'inventory.json')['files'].items():assert sha(LAB/name)==digest
    assert sha(OLD/'evaluation/verified/summary.json')==p['source_verified_sha256']
    for relative,digest in read(OLD/'protocol-before-clean-fitting.json')['source_locks'].items():assert sha(ROOT/relative)==digest
    assert sha(ROOT/'results/gates-probes/revision-severe-tail-gate-v1/publication-verification.json')==p['source_publication_sha256']
    source=read(OLD/'evaluation/verified/summary.json')['cases']
    published=table('rounds.csv');cases=table('cases.csv');aggregate=table('aggregate.csv')
    lookup={(r['case'],r['guard'],int(r['round'])):r for r in published}
    assert len(lookup)==len(published)==2824 and len(cases)==192 and len(aggregate)==64
    bycase={(r['case'],r['guard']):r for r in cases};rejected=0;expected_groups=defaultdict(Counter)
    for c in source:
        t=c['task']
        for name,policy in p['policies'].items():
            deferred=[];group=expected_groups[(t['cohort'],t['method'],t['mode'],name)]
            group['source_cases']+=1
            for row in c['rows']:
                r=lookup[(t['name'],name,row['round'])]
                masses={i:Fraction(m) for i,m in row['masses'].items()};total=sum(masses.values());nominal=sum(row['example_counts'].values())
                retention=total/nominal;coefficients=[m/total for m in masses.values()] if total else None
                top=sum(heapq.nlargest(policy['maximum_group_size'],coefficients),Fraction()) if coefficients else None
                reasons=[]
                if sum(m>0 for m in masses.values())<policy['minimum_contributors']:reasons.append('insufficient_contributors')
                if not total:reasons.append('zero_effective_mass')
                if retention<Fraction(policy['minimum_retained_mass']):reasons.append('insufficient_retained_mass')
                if top is not None and top>Fraction(policy['maximum_group_share']):reasons.append('excessive_group_share')
                assert r['retained_mass']==str(retention) and r['maximum_at_most_k_share']==(str(top) if top is not None else '')
                assert r['decision']==('defer' if reasons else 'ready') and r['reasons']=='|'.join(reasons)
                if reasons:deferred.append(row['round']);rejected+=1
                group['source_rounds']+=1;group['locally_deferred_rounds']+=bool(reasons);group.update(reasons)
            recorded=bycase[(t['name'],name)];first=min(deferred,default=None)
            assert recorded['first_deferred_round']==(str(first) if first else '')
            compatible=not deferred and c['complete'];assert recorded['uninterrupted_source_prefix_compatible']==str(compatible)
            group['uninterrupted_compatible_cases']+=compatible
    for r in aggregate:
        group=expected_groups[(r['cohort'],r['method'],r['mode'],r['guard'])]
        for key,value in group.items():assert int(r.get(key) or 0)==value
    checks=read(LAB/'backend-checks.json');assert rejected==checks['rejected_callbacks_not_invoked']==1314
    assert len(checks['checks'])==summary['backend_checks']==89
    assert len({(r['case'],r['round']) for r in checks['checks']})==89
    source_map={c['task']['name']:c for c in source}
    for r in checks['checks']:
        assert lookup[(r['case'],'retention_and_group_cap',r['round'])]['decision']=='ready'
        path=OLD/'evaluation/cases'/r['case']/'evidence/rounds'/f'round-{r["round"]:03d}'/'global-model.json'
        model=read(path)
        serialized=json.dumps(model,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'
        digest=hashlib.sha256(serialized).hexdigest()
        assert digest==r['model_sha256']
    tests=ET.parse(LAB/'focused-tests.xml').getroot();suites=list(tests.iter('testsuite'))
    assert sum(int(s.attrib['tests']) for s in suites)==21
    assert all(int(s.attrib.get(k,0))==0 for s in suites for k in ('failures','errors','skipped'))
    lines=['# Admission mass safety: implementation and retrospective validation','',
        'The new opt-in guard authorizes or defers original sample-weighted FedAvg. It never restores quarantined mass, alters an existing decision, or manufactures a checkpoint when conditions fail. Production defaults, the measured core, all historical campaigns and the thesis are unchanged. The implementation remains a research adapter, not a completed live TPM integration.','',
        '## Exact contract','',
        'With authenticated complete eligible counts n_i and actual admission masses m_i, let R=sum(m_i)/sum(n_i) and a_i=m_i/sum(m_i). The joint guard requires at least10 positive contributors, R>=4/5 and the sum of the three largest a_i<=1/3. Unknown, mismatched or inexact mass/action/count inputs fail explicitly. A mandatory-trust or statistical quarantine keeps m_i=0. When deferred, authorized coefficients and the guarded checkpoint are undefined; computable proposed coefficients remain diagnostic only.',
        'The three-largest sum bounds every subset of at most three nonnegative coefficients by ordering. Interpreting that subset as all attackers additionally assumes at most three authorized adversarial identities. This is not an attacker detector, a Sybil guarantee or a bound on unbounded tensors. When separately composed with fixed tensor clipping, existing fixed-input removal algebra yields2*A*C per tensor for removed mass A; it does not prove ASR prevention or later recovery.',
        'The4/5 floor reuses the preceding study\'s per-round guard. The1/3 group budget is a conservative declared allocation, not a learned threshold or a robustness theorem. A retention-only control disables the concentration constraint. Both choices are reported without selecting a winner from attack outcomes.','',
        '## What was actually validated','',
        '-21 tests passed:12 new guard tests and9 existing admission tests. They cover veto preservation, exact policy boundaries, zero/unknown normalization, no re-admission, malformed evidence, tampering, backend suppression and exhaustive subset checks on50 small populations.',
        '-2,824 assessments reconstruct two fixed policies on1,412 verified source rounds from96 previously observed histories. A separate standard-library checker recomputes ratios, top-k shares, every decision, first deferrals and64 summary groups.',
        '-89 actual Flower outputs are repeated at the first/last locally authorized joint-guard rounds, using authenticated original models, decisions and parents. Backend coefficients and checkpoint contents match. In1,314 deferred assessments, a forbidden numerical callback is demonstrably never invoked.',
        '-No new local training or TPM Quote is produced. No defended ASR is calculated. In particular, later source checkpoints after the first hypothetical deferral cannot be counted as a new guarded continuation.','',
        '## Availability result on the preceding severe-tail method','',
        '| Cohort | Source mode | Guard | Local deferrals / observed rounds | Uninterrupted compatible histories /3 |',
        '|---|---|---|---:|---:|']
    for r in aggregate:
        if r['method']=='severe_gate':lines.append('| '+' | '.join([r['cohort'],r['mode'],r['guard'],r['locally_deferred_rounds']+'/'+r['source_rounds'],r['uninterrupted_compatible_cases']])+' |')
    lines+=['','The joint guard would defer all45 observed clean non-IID rounds, and each of those three histories at its first round. It also defers30 of90 IID distributed/full-trigger source rounds because their retained nominal mass falls below the floor. These are explicit availability costs, not successful attack prevention. The retention-only guard defers17 of45 clean non-IID source rounds and leaves only one of three clean histories uninterrupted.',
        'This confirms that count quorum alone misses substantial influence concentration, while a conservative static coefficient cap is incompatible with the present non-IID sample-weight distribution. Simply forcing admission would invalidate quarantine guarantees. A deployable continuation requires a separately declared support/recovery or aggregation-weight policy and fresh evaluation; this audit does not select or validate that policy.','',
        '## Boundaries and reproduction','',
        'Trusted clean calibration, complete authenticated rosters/counts, correct callers and appropriate runtime bindings remain assumptions. The module does not authenticate them itself. Robust/geometric-median beta coefficients and tensor transformations have their separate contracts; original FedAvg coefficients are not silently substituted for them. No administrative witness independence, physical TPM protection, general robustness or certified unlearning follows.', '',
        '```bash','PYTHONPATH=scripts .venv/bin/python -m pytest -q tests/test_admission_mass_safety.py tests/test_composite_admission.py',
        '.venv/bin/python scripts/revision_mass_safety_audit.py',
        '.venv/bin/python scripts/finalize_mass_safety.py','```','',
        'Evidence and controllers are versioned in the original WSL repository. Existing audit/publication destinations refuse overwrite. Final closure pins include this independent publisher, input artifacts, guard source and test receipts. The thesis remains frozen.','']
    text='\n'.join(lines)
    for a,b in {'least10':'least 10','yields2':'yields 2','The4/5':'The 4/5','The1/3':'The 1/3',
        '-21':'- 21',':12':': 12','and9':'and 9','on50':'on 50','-2,824':'- 2,824','on1,412':'on 1,412','from96':'from 96','and64':'and 64','-89':'- 89','In1,314':'In 1,314',
        'all45':'all 45','defers30':'defers 30','of90':'of 90','defers17':'defers 17','of45':'of 45'}.items():text=text.replace(a,b)
    OUT.mkdir();(OUT/'README.md').write_text(text)
    proof=dict(status='verified',independent_arithmetic=True,assessment_count=2824,case_guard_pairs=192,
        focused_tests_passed=21,new_guard_tests=12,actual_backend_checks=89,deferred_backend_not_invoked=1314,
        no_defended_ASR_inferred=True,thesis_edited=False,publisher_sha256=sha(Path(__file__)),
        protocol_sha256=sha(LAB/'protocol-before-audit.json'),source_verified_sha256=p['source_verified_sha256'])
    dump(OUT/'validation.json',proof)
    for pth in LAB.iterdir():
        if pth.is_file():(OUT/pth.name).write_bytes(pth.read_bytes())
    for pth in OUT.iterdir():
        if pth.is_file():(LOCAL/('published-'+pth.name)).write_bytes(pth.read_bytes())
    (LOCAL/'MASS_SAFETY_REPORT.md').write_text(text)
    files={str(path.relative_to(ROOT)):sha(path) for path in OUT.iterdir() if path.is_file()}
    files.update({str((ROOT/'scripts'/name).relative_to(ROOT)):sha(ROOT/'scripts'/name) for name in
        ('admission_mass_safety.py','revision_mass_safety_audit.py','finalize_mass_safety.py')})
    dump(OUT/'closure.json',dict(files=files,publisher_sha256=sha(Path(__file__))))
    (LOCAL/'mass-safety-publication-closure.json').write_bytes((OUT/'closure.json').read_bytes())
    print(json.dumps(proof,indent=2))


if __name__=='__main__':main()
