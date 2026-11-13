"""Exact necessary-condition certificates; no attack labels or new fitting."""
from fractions import Fraction
from pathlib import Path
import os
import hashlib,json

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'artifacts/revision-severe-tail-gate-v1'
OUT=ROOT/'results/gates-probes/revision-admission-mass-feasibility-v1'
LOCAL=(Path(os.environ["FL_FORENSICS_OUTPUT_ROOT"]) / 'mass-safety-mail-audit-20261106')
def read(path):return json.loads(path.read_text())
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    assert not OUT.exists(),'Preserve feasibility certificates'
    protocol=read(SOURCE/'protocol-before-clean-fitting.json');r=Fraction(4,5);gamma=Fraction(1,3)
    threshold=1-r*(1-gamma);assert threshold==Fraction(7,15)
    certificates=[]
    for cohort,seed in protocol['stages']['evaluation']:
        path=SOURCE/'partitions'/str(seed)/'manifest.json';assert sha(path)==protocol['partitions'][str(seed)]
        manifest=read(path);counts={x['client_id']:x['train_row_count'] for x in manifest['clients']}
        largest=sorted(counts,key=lambda c:(-counts[c],c))[:3];n=sum(counts.values())
        c=Fraction(sum(counts[i] for i in largest),n)
        lower=max(Fraction(),1-(1-c)/r);max_retention=min(Fraction(1),(1-c)/(1-gamma))
        impossible=c>threshold
        assert impossible==(lower>gamma)==(max_retention<r)
        certificates.append(dict(cohort=cohort,seed=seed,manifest_sha256=sha(path),largest_nominal_subset=largest,
            nominal_counts=counts,nominal_share=str(c),minimum_required_retention=str(r),maximum_group_share=str(gamma),
            unavoidable_share_lower_bound_at_retention_floor=str(lower),
            retention_upper_bound_at_group_cap=str(max_retention),constraints_incompatible=impossible))
    assert sum(c['constraints_incompatible'] for c in certificates)==3
    assert all(c['constraints_incompatible']==(c['cohort']=='non-iid') for c in certificates)
    lines=['# Why the proposed mass floor and group cap conflict','',
        'This is a conditional algebraic necessary-condition proof, with exact certificates on six pinned clean partitions. It is not an attack-success experiment or a new fitted threshold. The guard and all earlier evidence remain unchanged.', '',
        'Let authenticated nominal counts be n_i>0, N=sum(n_i), effective masses satisfy0<=m_i<=n_i, and M=sum(m_i). The policy requires M>=r*N. For any fixed subset S with at most k identities and nominal share c=sum_S(n_i)/N, the outside mass is at most(1-c)*N. Thus', '',
        '    sum_S(m_i)/M >= max(0, 1-(1-c)*N/M) >= max(0, 1-(1-c)/r).', '',
        'If every at-most-k subset must have coefficient mass at most gamma, a necessary condition is', '',
        '    c <= 1-r*(1-gamma).', '',
        'The condition applies to the subset with largest nominal counts even if it is no longer the largest subset after downweighting. If it fails, no admissible continuous choice of m_i can satisfy both constraints; the original discrete factors0,1/2,1 cannot do so either. With r=4/5, gamma=1/3 and k=3, the threshold is7/15. Equivalently any feasible retained mass fraction must be <=(1-c)/(1-gamma).', '',
        '| Cohort | Seed | Top-three nominal share (%) | Unavoidable subset share at80% retention (%) | Maximum retention with1/3 cap (%) | Incompatible |',
        '|---|---:|---:|---:|---:|---|']
    for item in certificates:
        values=[f'{100*float(Fraction(item[k])):.3f}' for k in ('nominal_share','unavoidable_share_lower_bound_at_retention_floor','retention_upper_bound_at_group_cap')]
        lines.append('| '+' | '.join([item['cohort'],str(item['seed']),*values,str(item['constraints_incompatible'])])+' |')
    lines+=['','All three non-IID nominal top-three shares exceed7/15, so under the current sample-weighted-mass contract the two policy requirements are incompatible. A different statistical alarm threshold cannot fix this incompatibility. The guard correctly defers instead of silently violating one of the requirements.',
        'This does not disprove every influence cap. A separately declared final reweighting beta can redistribute coefficients while retaining original admission masses for accounting. It is then a different operator: final beta, transformation dependencies and verification must be explicit, as for the existing bounded/robust profiles. Alternatively the retention/influence goals, eligible support or data allocation must change. No such alternative is selected or validated here, and none of these mathematical bounds guarantees low ASR.','']
    text='\n'.join(lines)
    for a,b in {'satisfy0':'satisfy 0','most(1':'most (1','factors0':'factors 0','is7/15':'is 7/15','at80':'at 80','with1/3':'with 1/3','exceed7':'exceed 7'}.items():text=text.replace(a,b)
    OUT.mkdir();(OUT/'README.md').write_text(text)
    result=dict(profile='admission-mass-feasibility-v1',status='verified_exact_necessary_condition',
        certificates=certificates,script_sha256=sha(Path(__file__)),new_fitting=False,new_attack_evaluation=False,
        theorem_scope='Original masses satisfy0<=m_i<=n_i and final coefficients equal m_i/sum(m). No claim for separately transformed beta or ASR.')
    (OUT/'certificates.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    (OUT/'closure.json').write_text(json.dumps(dict(files={p.name:sha(p) for p in OUT.iterdir() if p.is_file()}),indent=2)+'\n')
    (LOCAL/'FEASIBILITY.md').write_text(text)
    (LOCAL/'feasibility-certificates.json').write_bytes((OUT/'certificates.json').read_bytes())
    (LOCAL/'feasibility-closure.json').write_bytes((OUT/'closure.json').read_bytes())
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
