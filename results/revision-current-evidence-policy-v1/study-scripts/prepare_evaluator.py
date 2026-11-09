"""Derive the new independent source verifier, preserving the previous script."""
from pathlib import Path
import re

out=Path(__file__).parent
text=(out.parent/'sequential-policy-20261103/evaluate_online_study.py').read_text()
text=text.replace('revision-sequential-round-policy-v1','revision-current-evidence-policy-v1').replace('active-sequential','active-current-evidence')
text=text.replace("'reserved-online-policy-evaluation-v1'","'reserved-current-evidence-evaluation-v1'")
text=re.sub(r'\bseq\b','primary',text)
text=text.replace("streak=np.zeros((15,2),dtype=int)","streak=np.zeros((15,2),dtype=int);high_streak=np.zeros(15,dtype=int);previous_quarantine=set()")
old="""            primary={c for i,c in enumerate(clients) if sq[i].all()};instant={c for i,c in enumerate(clients) if ins[i].all()}
            review={c for i,c in enumerate(clients) if c not in primary and (warning[i].any() or (sq[i,0]!=sq[i,1]))}
"""
new="""            sequential={c for i,c in enumerate(clients) if sq[i].all()};instant={c for i,c in enumerate(clients) if ins[i].all()}
            high=ins.all(axis=1);high_streak=np.where(high,high_streak+1,0)
            primary={c for i,c in enumerate(clients) if high[i] and high_streak[i]>=2}
            review={c for i,c in enumerate(clients) if c not in primary and
                (warning[i].any() or (sq[i,0]!=sq[i,1]) or c in instant or c in previous_quarantine)}
"""
assert old in text;text=text.replace(old,new)
text=text.replace("cumulative[:]=0;streak[:]=0;primary=set();instant=set();review=set(clients)",
    "cumulative[:]=0;streak[:]=0;high_streak[:]=0;primary=set();instant=set();sequential=set();review=set(clients)")
old="""            if c in primary:latency[c]['quarantine_rounds'].append(number)
"""
new="""            assert decision['clients'][c]['consecutive_current_high_rounds']==int(high_streak[i])
            assert decision['clients'][c]['current_high_in_both_views']==(c in instant)
            expected_transition=('continued' if c in previous_quarantine else 'entered') if c in primary else (
                'released' if c in previous_quarantine else 'confirmation_pending' if c in instant else 'none')
            assert decision['quarantine_transitions'][c]==expected_transition
            assert decision['clients'][c]['quarantine_transition']==expected_transition
            if expected_transition=='released':metrics['release_client_rounds']+=1
            if c in primary:latency[c]['quarantine_rounds'].append(number)
"""
assert old in text;text=text.replace(old,new)
text=text.replace("[('sequential',primary),('instantaneous',instant)]","[('current',primary),('instantaneous',instant),('sequential',sequential)]")
old="""            if number>max(task['attack_rounds']):metrics[f'{method}_after_cessation_attacker_quarantines']+=len(clean_scheduled)
"""
new=old+"""            if min(task['attack_rounds'])<number<max(task['attack_rounds']) and number not in task['attack_rounds']:
                metrics[f'{method}_clean_gap_attacker_quarantines']+=len(clean_scheduled)
"""
assert old in text;text=text.replace(old,new)
text=text.replace("'instantaneous_shadow_proposal':sorted(instant),'supported':supported,",
    "'instantaneous_shadow_proposal':sorted(instant),'sequential_shadow_proposal':sorted(sequential),\n            'quarantine_transitions':decision['quarantine_transitions'],'supported':supported,")
text=text.replace("previous=decision['decision_digest'];expected_base=sha256_file(prefix/'global-model.json')",
    "previous_quarantine=set(primary);previous=decision['decision_digest'];expected_base=sha256_file(prefix/'global-model.json')")
text=text.replace("t>=onset]","t>=onset and t in entry['actually_poisoned_rounds']]")
text=text.replace("        entry['ever_intended_attacker']=c in intended", """        entry['ever_intended_attacker']=c in intended
        bursts=[]
        for t in entry['actually_poisoned_rounds']:
            if not bursts or t!=bursts[-1][-1]+1:bursts.append([t])
            else:bursts[-1].append(t)
        entry['burst_evaluations']=[{'start':b[0],'end':b[-1],
            'poisoned_updates_quarantined':sum(t in entry['quarantine_rounds'] for t in b),
            'first_quarantine_delay':next((t-b[0] for t in b if t in entry['quarantine_rounds']),None)} for b in bursts]""")
text=text.replace("'sequential_TP':metrics['sequential_poisoned_update_quarantines']","'current_TP':metrics['current_poisoned_update_quarantines']")
text=text.replace("'never_attacker_FP':metrics['sequential_never_attacker_quarantines']","'never_attacker_FP':metrics['current_never_attacker_quarantines']")
start=text.index("active=[c for c in cases if c['task']['branch']=='active-current-evidence'];attacked=")
end=text.index("result={'profile':",start)
text=text[:start]+"""active=[c for c in cases if c['task']['branch']=='active-current-evidence'];attacked=[c for c in cases if c['task']['mode']=='distributed']
acceptance={'zero_never_attacker_quarantine_proposals':all(c['metrics'].get('current_never_attacker_quarantines',0)==0 for c in cases),
    'zero_after_cessation_clean_source_proposals':all(c['metrics'].get('current_after_cessation_attacker_quarantines',0)==0 for c in cases),
    'at_least_one_poisoned_update_proposed_per_attacked_episode':all(c['metrics'].get('current_poisoned_update_quarantines',0)>0 for c in attacked),
    'no_active_quorum_failure':all(c['finished_rounds']==15 and c['metrics'].get('quorum_failures',0)==0 for c in active)}
assert set(acceptance)==set(read(lab/'protocol-before-new-training.json')['experimental_acceptance'])
"""+text[end:]
text=text.replace('Instantaneous proposals are shadow comparisons','Instantaneous and original sequential proposals are shadow comparisons')
(out/'evaluate_online_study.py').write_text(text)
print('CURRENT-EVIDENCE SOURCE VERIFIER PREPARED')
