"""Build a separate auditable ablation; never mutate the frozen source studies."""
from pathlib import Path
import shutil

R = Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
O = Path(__file__).parent

def replace_once(s, a, b):
    assert s.count(a) == 1, (a, s.count(a))
    return s.replace(a, b)

protocol = (R/'scripts/coherent_gradient_protocol.py').read_text()
protocol = protocol.replace('from fltrust_screen_aggregation import fltrust_delta',
                            'from normonly_aggregation import normonly_delta as fltrust_delta')
protocol = protocol.replace("PROFILE='coherent-gradient-round-v1'", "PROFILE='coherent-normonly-ablation-round-v1'")
protocol = protocol.replace('coherent_fltrust', 'coherent_normonly')
protocol = protocol.replace('undefined_reference_or_alignment', 'undefined_reference_or_nonzero_support')
protocol = protocol.replace('Opt-in research gradient round with explicit no-quorum pause semantics.',
                            'Separate uniform root-norm research ablation with explicit pause semantics.')
source = (R/'scripts/revision_coherent_endpoint_dba.py').read_text()
changes = [
    ('Separate Byzantine endpoint DBA study; original one-step failures are preserved.',
     'Root-norm-only ablation of the separately frozen learned-endpoint DBA study.'),
    ('from coherent_gradient_protocol import *', 'from normonly_gradient_protocol import *'),
    ('results/revision-coherent-endpoint-dba-v1', 'results/revision-normonly-endpoint-dba-v1'),
    ('output/coherent-dba-20261107/endpoint-study', 'output/normonly-dba-20261107'),
    ("'endpoint_attack_selection.py','revision_coherent_endpoint_dba.py','coherent_gradient_protocol.py'",
     "'endpoint_attack_selection.py','revision_normonly_endpoint_dba.py','normonly_gradient_protocol.py','normonly_aggregation.py','coherent_gradient_protocol.py','revision_coherent_endpoint_dba.py'"),
    ("paths.extend([R/'tests/test_coherent_dba_selection.py',R/'tests/test_endpoint_attack_selection.py'])",
     "paths.extend([R/'tests/test_coherent_dba_selection.py',R/'tests/test_endpoint_attack_selection.py',R/'tests/test_normonly_ablation.py'])"),
    ("for method in ('coherent_fedavg','coherent_fltrust'):", "for method in ('coherent_normonly',):"),
    ("'profile':'coherent60-root-byzantine-endpoint-dba-v1'", "'profile':'coherent60-root-normonly-endpoint-ablation-v1'"),
    ("'methods':['coherent_fedavg','coherent_fltrust']", "'methods':['coherent_normonly']"),
    ("'clean_controls':'Four newly executed clean histories; must reproduce known coherent baseline/full60 recovery checkpoints. They are mechanism replications, not independent clean validation.'",
     "'clean_controls':'Two fresh norm-only clean trajectories. Each adaptive attack uses its own same-round norm-only clean control. Prior four raw/FLTrust clean histories are immutable external comparators.'"),
    ("if task['method']=='coherent_fltrust' else None", "if task['method']=='coherent_normonly' else None"),
    ("'development':'Chosen after a separate warm-parent feasibility probe. Keep both predefined seeds and distributed/full variants, including ineffective outcomes. Development is not independent confirmation.'",
     "'development':'Mechanism ablation after observed FLTrust containment. All seeds/modes retained, no retuning. Exploratory reused validation, not independent confirmation.',\n       'ablation':'Remove only cosine direction weighting from the FLTrust operator: equal weights on all nonzero eligible deltas, each normalized to the unchanged trusted-root magnitude. Root data are still used for that magnitude. No sample-count weights. This does not establish root-free defense.',\n       'comparator_protocol_sha256':sha256_file(R/'results/revision-coherent-endpoint-dba-v1/protocol-before-training.json'),\n       'comparator_checksums_sha256':sha256_file(R/'results/revision-coherent-endpoint-dba-v1/file-checksums.json')"),
    ('Minimum10 positive coefficient contributors.', 'Minimum10 nonzero eligible positive-coefficient contributors. No cosine direction veto.'),
    ('on this FLTrust rule.', 'on this normalization-only rule.'),
]
for a,b in changes:
    source = replace_once(source, a, b)
start = source.index("            if task['mode']=='clean':\n")
end = source.index('            model=next_model', start)
source = source[:start] + source[end:]
needle = '    return pp,op,old\n'
source = replace_once(source, needle, "    import revision_coherent_endpoint_dba as prior\n    q=read(prior.D/'protocol-before-training.json');prior.check(q)\n    assert sha256_file(prior.D/'protocol-before-training.json')==p['comparator_protocol_sha256']\n    assert sha256_file(prior.D/'file-checksums.json')==p['comparator_checksums_sha256']\n    assert all(sha256_file(prior.D/n)==h for n,h in read(prior.D/'file-checksums.json').items())\n" + needle)

outputs = [('normonly_aggregation.py', (O/'normonly_aggregation.py').read_text(), 'scripts'),
           ('normonly_gradient_protocol.py', protocol, 'scripts'),
           ('revision_normonly_endpoint_dba.py', source, 'scripts'),
           ('test_normonly_ablation.py', (O/'test_normonly_ablation.py').read_text(), 'tests')]
for name, text, folder in outputs:
    dest = R/folder/name
    assert not dest.exists(), dest
    dest.write_text(text)
    if not (O/name).exists():
        shutil.copy2(dest, O/name)
print('Separate norm-only sources installed; frozen comparator sources untouched.')
