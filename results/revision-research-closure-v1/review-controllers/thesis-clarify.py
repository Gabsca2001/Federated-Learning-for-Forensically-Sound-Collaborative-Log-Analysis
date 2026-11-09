from pathlib import Path
import json

out=Path(__file__).parent;stage=out/'candidate';changes=[]
p=stage/'content/chapters/chap4.tex';s=p.read_text(encoding='utf-8-sig')
anchor=r'\subsubsection{Original trust-only and composite policies}'
assert s.count(anchor)==1
s=s.replace(anchor,r'\subsubsection{The four original admission policies}')
anchor='Separate frozen policy comparisons retain TPM-only, statistics-only, and\njoint admission controls under their declared contracts.'
assert s.count(anchor)==1
s=s.replace(anchor,(out/'policy_names.tex').read_text()+'\n'+anchor)
p.write_text(s,encoding='utf-8',newline='\n')
changes.append({'file':'content/chapters/chap4.tex','reason':'Define all four original policy names, distinguish within-round sequential from temporal evidence, and map policies to experiments.'})
p=stage/'content/chapters/formal_revision_closure.tex';s=p.read_text(encoding='utf-8-sig')
anchor=r'\begin{table}[tbp]'
assert s.count(anchor)==1
s=s.replace(anchor,(out/'robust_math.tex').read_text()+'\n'+anchor)
p.write_text(s,encoding='utf-8',newline='\n')
changes.append({'file':'content/chapters/formal_revision_closure.tex','reason':'Define the separate finite robust-reweighting operator, its convex cap and fixed-versus-recomputed weight intervention scope.'})
p=stage/'bibliography.bib';s=p.read_text(encoding='utf-8-sig')
assert 'pillutla2022robust' not in s
s+='''
@article{pillutla2022robust,
  title={Robust Aggregation for Federated Learning},
  author={Pillutla, Krishna and Kakade, Sham M. and Harchaoui, Zaid},
  journal={IEEE Transactions on Signal Processing},
  year={2022},
  doi={10.1109/TSP.2022.3153135},
  eprint={1912.13445},
  archivePrefix={arXiv}
}
'''
p.write_text(s,encoding='utf-8',newline='\n')
changes.append({'file':'bibliography.bib','reason':'Cite the primary robust-aggregation work while stating the implementation adaptation.'})
(out/'changes.json').write_text(json.dumps(changes,indent=2)+'\n')
print('Original policy definitions and robust mathematical scope staged; experimental outcomes still pending.')
