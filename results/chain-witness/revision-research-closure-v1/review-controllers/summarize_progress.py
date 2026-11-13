from pathlib import Path
import json

root=Path.cwd()/'artifacts/revision-research-closure-v1'
for name in ['native-gradients-evaluation','robust-development','robust-evaluation']:
    p=root/name/'results.json'
    if not p.exists():continue
    data=json.loads(p.read_bytes())
    summary=[]
    for c in data['cases']:
        task=c['task'];rounds=c['rounds']
        metrics=lambda r:r.get('metrics',r.get('validation'))
        summary.append({'task':task,'rounds':len(rounds),
            'peak':max([r['worst_trigger_asr'] for r in rounds],default=None),
            'final':rounds[-1]['worst_trigger_asr'] if len(rounds)==15 else None,
            'min_F1':min([metrics(r)['clean']['macro_f1_all_model_classes'] for r in rounds],default=None),
            'failure':c.get('terminal_failure',c.get('failure'))})
    if name=='robust-development':
        clean=[c for c in data['cases'] if c['task']['mode']=='clean']
        loss=max(a['validation']['clean']['macro_f1_all_model_classes']-b['validation']['clean']['macro_f1_all_model_classes']
                 for a,b in zip(clean[0]['rounds'],clean[1]['rounds'],strict=True))
        print(json.dumps({'study':name,'clean_max_loss':loss,'cases':summary}),flush=True)
    else:
        print(json.dumps({'study':name,'cases':summary}),flush=True)
