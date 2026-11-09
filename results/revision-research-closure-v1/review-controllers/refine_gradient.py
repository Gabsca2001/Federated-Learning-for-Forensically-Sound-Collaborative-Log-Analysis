"""Preserve the first development controller and add a selective-attack guard."""
from pathlib import Path
import shutil

out=Path(__file__).parent
p=out/'gradient_study.py'
shutil.copy2(p,out/'gradient_study-development-v1.py')
s=p.read_text()
s=s.replace("choices=['development','evaluation']", "choices=['development','development-v2','evaluation']")
s=s.replace("if args.phase=='development':", "if args.phase.startswith('development'):")
s=s.replace("save(root/'protocol-before-execution.json',protocol)",
            "protocol['attack_utility_guard'] = 'For development-v2 and evaluation, select only candidates within .05 clean macro-F1 of the same-round unmodified gradient-FedAvg reference; if none exists retain alpha0 as an explicit search failure, not a successful stealth attack.'\n    save(root/'protocol-before-execution.json',protocol)\n    (root/'controller.py').write_bytes(Path(__file__).read_bytes())")
s=s.replace("_, alpha, model, report, metric, gradients, next_history = max(candidates,key=lambda x:(x[0],x[1]))", """search_failed = False
        if active and root.name != 'native-gradients-development':
            ref_path = root / f\"{task['cohort']}-gradient_fedavg-clean/rounds/round-{number:03d}/round.json\"
            ref_f1 = read(ref_path)['metrics']['clean']['macro_f1_all_model_classes']
            allowed = [x for x in candidates if x[4]['clean']['macro_f1_all_model_classes'] >= ref_f1-.05]
            if not allowed:
                allowed = [x for x in candidates if x[1]==0.]
                search_failed = True
            candidates = allowed or candidates
        _, alpha, model, report, metric, gradients, next_history = max(candidates,key=lambda x:(x[0],x[1]))""")
s=s.replace("'attack_active':active,", "'attack_active':active,'selective_search_failed':search_failed,")
p.write_text(s)
print('Development v1 retained; selective utility guard added for the next named protocol.')
