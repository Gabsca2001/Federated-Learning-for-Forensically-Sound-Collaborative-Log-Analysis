from pathlib import Path
import json

out=Path(__file__).parent;root=out.parent
data=json.loads((root/'sequential-benchmark.json').read_bytes())
p=out/'candidate/content/chapters/research_final_verification.tex'
s=p.read_text();assert 'tab:research-costs' not in s
names={'bounded_mean':'Bounded mean + derivation','robust_bounded':'Robust bounded + derivation',
'flame':'FLAME cached kernel','weidetect':'WeiDetect cached kernel','gated_composite':'Composite cached-mass sum',
'gradient_fedavg':'Gradient FedAvg recurrence','literal_eq2':'Literal Eq.~(2) recurrence',
'literal_eq3':'Literal Eq.~(3) recurrence','normalized_eq2_adaptation':'Normalized recurrence'}
rows=[names[r['method']]+f" & {r['contexts']} & {r['calls']} & {r['median_wall_ms']:.2f} & {r['p95_wall_ms']:.2f}"+r' \\' for r in data['summaries']]
s+=r'''

\begin{table}[tbp]
\centering\small
\caption[Sequential cached-operation costs]{A single-thread sequential
benchmark on verified fixed inputs. One warm-up precedes five timed calls per
context. Values are milliseconds; methods retain distinct timed scopes.}
\label{tab:research-costs}
\begin{tabularx}{\linewidth}{>{\raggedright\arraybackslash}Xrrrr}
\toprule
Timed operation & Contexts & Calls & Median & 95th percentile \\
\midrule
'''+ '\n'.join(rows)+r'''
\bottomrule
\end{tabularx}
\end{table}

Bounded operations include generation of their numerical derivation records
and in-memory checkpoint export. The literature kernels use cached vectors
and auxiliary scores; the composite row uses already decided masses, not
statistical scoring. Native rows include their history-based server
recurrence and export. These scopes do not support a single overall defense
speed ranking. Input loading, local training, attack search, indicator
inference, detector fitting and TPM operations lie outside the timers.
Equivalence checks also occur outside the timed interval. No other research
campaign runs concurrently, although unrelated host activity is not excluded.
This is measured cached-operation cost, not end-to-end federated latency.
'''
p.write_text(s)
print('Measured costs staged:',sum(r['calls'] for r in data['summaries']),'calls')
