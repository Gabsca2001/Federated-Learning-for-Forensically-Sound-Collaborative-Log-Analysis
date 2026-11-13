from pathlib import Path
import json
import shutil

out=Path(__file__).parent; root=out.parent; stage=out/'candidate'
read=lambda n:json.loads((root/n).read_bytes())
shared=read('SHARED_GRADIENT_SUMMARY.json')['rows']
index={(r['cohort'],r['mode'],r['method']):r for r in shared}
methods={'gradient_fedavg':'Gradient FedAvg','literal_eq2':'Literal Eq.~(2)',
 'literal_eq3':'Literal Eq.~(3)','normalized_eq2_adaptation':'Normalized adaptation',
 'flame':'FLAME adaptation','weidetect':'WeiDetect adaptation','gated_composite':'Original composite'}
pct=lambda v:f'{100*v:.2f}'
body=[]
for method,name in methods.items():
    a=index['iid','adaptive-gradient',method];b=index['non-iid','adaptive-gradient',method]
    clean=[index[c,'clean',method] for c in ('iid','non-iid')]
    det='--' if a['manipulated_excluded'] is None else str(a['manipulated_excluded']+b['manipulated_excluded'])
    fp='--' if a['unmodified_excluded'] is None else str(sum(index[c,m,method]['unmodified_excluded'] for c in ('iid','non-iid') for m in ('clean','adaptive-gradient')))
    body.append(name+' & '+pct(a['peak_conditional_full_ASR'])+'/'+pct(a['peak_conditional_worst_ASR'])+' & '+pct(b['peak_conditional_full_ASR'])+'/'+pct(b['peak_conditional_worst_ASR'])+' & '+pct(min(r['clean_macro_F1_min'] for r in clean))+' & '+pct(min(a['clean_macro_F1_min'],b['clean_macro_F1_min']))+' & '+det+'/'+fp+r' \\')
den=sum(index[c,'adaptive-gradient','flame']['manipulated_denominator'] for c in ('iid','non-iid'))
unmod=sum(index[c,m,'flame']['unmodified_denominator'] for c in ('iid','non-iid') for m in ('clean','adaptive-gradient'))
deg=sum(index[c,m,'weidetect']['degenerate_WeiDetect_fits'] for c in ('iid','non-iid') for m in ('clean','adaptive-gradient'))
text=r'''\begin{table}[tbp]
\centering\scriptsize
\caption[Conditional common-gradient comparison]{Common-input validation
comparison. ASR columns give peak full/worst-trigger percentages across the
retained conditional outputs. F1 columns give the minimum ordinary macro-F1
percentage on clean-source and attacked-source contexts. TP/FP counts refer
to excluded manipulated/unmodified exports, not an intent classifier.}
\label{tab:research-shared-gradient}
\begin{tabularx}{\linewidth}{>{\raggedright\arraybackslash}Xrrrrr}
\toprule
Method & IID ASR & Non-IID ASR & Clean F1 & Attack F1 & TP/FP \\
\midrule
'''+ '\n'.join(body)+r'''
\bottomrule
\end{tabularx}
\par\smallskip\raggedright\footnotesize
'''+f'TP denominator: {den}; unmodified denominator: {unmod}. A dash means the rule supplies no client-selection metric. WeiDetect uses its declared degenerate-fit extension in {deg}/120 contexts.\n'+r'\end{table}'+'\n'
(stage/'content/chapters/research_shared_table.tex').write_text(text)
rows=read('ROBUST_SUMMARY.json')['pairs']
body=[]
for r in rows:
    body.append(r['cohort'].upper()+' / '+str(r['seed'])[-2:]+' & '+str(r['bounded_rounds'])+'/'+str(r['robust_rounds'])+' & '+pct(r['bounded_peak_full_ASR'])+' & '+pct(r['robust_peak_full_ASR'])+' & '+pct(r['robust_final_worst_ASR'])+' & '+pct(r['max_clean_F1_loss'])+r' \\')
text=r'''\begin{table}[tbp]
\centering\small
\caption[Reserved robust-bounded evaluation]{New reserved assignments.
Peaks are full-trigger validation ASR; the robust endpoint is the worst
full/component ASR. Clean loss is the largest paired macro-F1 difference in
percentage points. A missing control tail is retained as a failure.}
\label{tab:research-robust-reserved}
\begin{tabularx}{\linewidth}{>{\raggedright\arraybackslash}Xrrrrr}
\toprule
Case & Rounds B/R & B peak & R peak & R final & Clean loss \\
\midrule
'''+ '\n'.join(body)+r'''
\bottomrule
\end{tabularx}
\end{table}
'''
(stage/'content/chapters/research_robust_table.tex').write_text(text)
shutil.copy2(root/'robust-reserved-asr.pdf',stage/'images/research-robust-reserved-asr.pdf')
shutil.copy2(out/'research_closure.tex',stage/'content/chapters/revision_research_closure.tex')

def replace(name,old,new):
    p=stage/name;s=p.read_text(encoding='utf-8-sig');assert s.count(old)==1,(name,old[:100]);p.write_text(s.replace(old,new),encoding='utf-8',newline='\n')
replace('content/chapters/chap5.tex',r'\input{content/chapters/revision_containment_validation}',r'\input{content/chapters/revision_containment_validation}'+'\n'+r'\input{content/chapters/revision_research_closure}')
replace('content/chapters/chap5.tex','algorithm adaptations and information budgets; the unstable native-gradient\nFedGradTrace branch remains explicitly incomplete.','algorithm adaptations and information budgets. The native-gradient follow-up\ncloses all planned cases as either complete histories or reproduced terminal\nnumerical failures; it does not reproduce the complete FedXLog system.')
replace('content/chapters/chap5.tex','The earlier zero-ASR pilot does not justify automatic semantic exclusion\nor deployment claims.','The reserved robust-reweighting follow-up reduces two effective control\npeaks, but retains a 75.72\\% peak in one case and does not improve semantic\nidentification. The earlier zero-ASR pilot does not justify automatic semantic\nexclusion or deployment claims.')
replace('content/chapters/chap5.tex','Retrospective group analysis requires additional independently reserved\nidentities and distributions, and a stronger account of multiple candidate\nsearches.','The new reserved group histories expose additional false candidates and\nmissed attackers. Further independent distributions and a stronger account\nof multiple candidate searches remain necessary.')
replace('content/chapters/chap2.tex','labels both readings, uses actual gradients in a separate native experiment,\nand reports the interrupted formulation without inventing later rounds','labels both readings. The reserved follow-up in\nSection~\\ref{subsec:revision-native-gradient-closure} uses actual honest\ngradients, explicitly forged malicious gradients and reproduced terminal\nfailures without inventing later rounds')
replace('content/chapters/revision_dba_groups.tex','\n\\subsection{Measured Computational Scope}', '\nThe reserved follow-up in Section~\\ref{subsec:revision-native-gradient-closure}\ncompletes a new explicitly selective attack protocol and reproduces terminal\nfailures. It does not overwrite this earlier development history.\n\n\\subsection{Measured Computational Scope}')
changes=json.loads((out/'changes.json').read_bytes())
changes.extend([{'file':str(p.relative_to(stage)).replace('\\','/'),'reason':'Consolidate reserved positive and negative outcomes, distinguish historical cases, or scope the formal FedAvg identity.'}
 for p in stage.rglob('*') if p.is_file() and p.suffix in ('.tex','.bib') and ((out/'before'/p.relative_to(stage)).exists() and p.read_bytes()!=(out/'before'/p.relative_to(stage)).read_bytes() or not (out/'before'/p.relative_to(stage)).exists()) and not any(x['file']==str(p.relative_to(stage)).replace('\\','/') for x in changes)])
(out/'changes.json').write_text(json.dumps(changes,indent=2)+'\n')
print(json.dumps({'shared_manipulated_denominator':den,'unmodified_denominator':unmod,'WeiDetect_degenerate_fits':deg,'staged_changes':len(changes)}))
