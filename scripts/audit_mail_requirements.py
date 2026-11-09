"""Read-only source/evidence/manuscript bindings for the current email audit."""
import ast
import hashlib
import json
from pathlib import Path
from fl_forensics.round_derivation import implementation_sha256

ROOT=Path(__file__).resolve().parents[1]
WIN=Path('/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1')
LOCAL=WIN/'output/mass-safety-mail-audit-20261106'
OUT=ROOT/'results/revision-mail-requirements-status-20261106'
def read(path):return json.loads(path.read_text(encoding='utf-8-sig'))
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def ws(path):
    drive,tail=path.split(':',1)
    return Path('/mnt')/drive.lower()/tail.lstrip('\\/').replace('\\','/')


def main():
    assert not OUT.exists(),'Preserve completed correspondence audit'
    identity=implementation_sha256()
    chain=read(WIN/'output/unified-chain-20261105/validation.json')
    assert identity==chain['implementation_sha256']=='8d7efa28b62a47d306a12958d66b3081d6527518f25641545cc81456640d2e64'
    modules={
        'round_derivation':['materialize_round_derivation'],
        'in_round_admission':['admit_and_aggregate_in_round','verify_in_round_secure_round'],
        'submission_evidence':['verify_submission_receipt','verify_submission_coverage'],
        'ingestion_coverage':['verify_ingestion_coverage'],
        'review_ledger':['verify_review_ledger'],
        'campaign_derivation':['verify_campaign_derivation','structural_blast_radius'],
        'counterfactual_round':['_proposal_metrics','verify_counterfactual_round'],
        'retraining_replay':['create_retraining_replay','verify_retraining_replay'],
        'retrospective_groups':['pair_descriptors','calibrate_groups','detect_groups'],
        'literature_baselines':['flame_aggregate','weidetect_aggregate','fedgradtrace_global_gradient'],
        'submission_witness':['verify_policy','verify_registration','verify_witness_snapshot','verify_witness_inventory'],
        'checkpoint_verification':['verify_witness_checkpoint'],
        'system_chain':['verify_system_chain'],
        'unified_preservation':['verify_unified_recovery'],
        'bounded_aggregation':['aggregate_bounded','verify_bounded'],
        'robust_bounded_aggregation':['aggregate_robust_bounded','verify_robust_bounded'],
    }
    bindings=[]
    for module,names in modules.items():
        path=ROOT/'src/fl_forensics'/f'{module}.py';text=path.read_text();lines=text.splitlines(keepends=True)
        definitions={node.name:node for node in ast.parse(text).body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))}
        for name in names:
            assert name in definitions,(module,name)
            node=definitions[name]
            bindings.append(dict(path=str(path.relative_to(ROOT)),file_sha256=sha(path),function=name,line=node.lineno,
                function_sha256=hashlib.sha256(''.join(lines[node.lineno-1:node.end_lineno]).encode()).hexdigest()))
    references=[
        'output/formal-closure-20261103/FORMAL_CORRESPONDENCE_CLOSURE.md',
        'output/formal-closure-20261103/PROPERTY_CODE_EVIDENCE_MATRIX.md',
        'output/formal-closure-20261103/original-proposal-extracted.txt',
        'output/mail-correspondence-audit-20261104/REPORT.md',
        'output/baseline-dba-closure-20261103/BASELINE_DBA_VALIDATION.md',
        'output/group-validation-20261103/RETROSPECTIVE_GROUP_VALIDATION.md',
        'output/research-closure-20261104/FINAL_REPORT.md',
        'output/research-closure-20261104/GROUP_SUMMARY.json',
        'output/research-closure-20261104/NATIVE_GRADIENT_SUMMARY.json',
        'output/research-closure-20261104/SHARED_GRADIENT_SUMMARY.json',
        'output/research-closure-20261104/ROBUST_SUMMARY.json',
        'output/witness-external-20261105/REPORT.md',
        'output/witness-independence-verdict-20261105/REPORT.md',
        'output/unified-chain-20261105/REPORT.md','output/unified-chain-20261105/validation.json',
        'output/severe-gate-20261106/REPORT.md','output/severe-gate-20261106/summary.json',
        'output/severe-gate-20261106/publication-verification.json',
        'output/mass-safety-mail-audit-20261106/MASS_SAFETY_REPORT.md',
        'output/mass-safety-mail-audit-20261106/mass-safety-publication-closure.json',
        'output/mass-safety-mail-audit-20261106/FEASIBILITY.md',
        'output/mass-safety-mail-audit-20261106/feasibility-certificates.json',
    ]
    pins={name:sha(WIN/name) for name in references}
    mail_paths=[Path('/mnt/c/Users/scama/.codex/attachments')/folder/'Pasted text.txt' for folder in
        ('70152b64-6d6e-455f-9a64-c1404d00b597','095d6d4c-485f-4f39-9cfa-bd11b2606b65')]
    mails={str(path):sha(path) for path in mail_paths}
    original=Path('/mnt/c/Users/scama/Downloads/Proposta_modello_formale_derivazione_Gabriele_Scamardo.docx')
    if original.exists():mails[str(original)]=sha(original)
    guard_path=WIN/'output/unified-chain-20261105/manuscript-readonly-guard.json';guard=read(guard_path)
    manuscript_root=ws(guard['root']);changed=[name for name,digest in guard['files'].items() if sha(manuscript_root/name.replace('\\','/'))!=digest]
    assert len(guard['files'])==110 and not changed
    targets={'formal_revision_closure.tex':[51,52,53,54],'chap4.tex':[2407,3112],'chap5.tex':[773,780]}
    observations=[]
    for name,numbers in targets.items():
        path=manuscript_root/'content/chapters'/name;lines=path.read_text().splitlines()
        observations.append(dict(path=str(path),sha256=sha(path),lines={str(n):lines[n-1] for n in numbers}))
    matrix=LOCAL/'EMAIL_REQUIREMENTS_STATUS.md'
    index=dict(profile='email-correspondence-audit-20261106',status='verified_readonly_bindings',
        implementation_sha256=identity,core_matches_unified_release=True,core_modules=130,
        original_supervisor_message_source='User-provided chat text; not a fabricated independent email retrieval.',
        correspondence_sha256=mails,project_evidence_sha256=pins,source_functions=bindings,
        manuscript=dict(files_checked=110,changed=[],guard_sha256=sha(guard_path),observations=observations),
        audit_document_sha256=sha(matrix),audit_script_sha256=sha(Path(__file__)),
        new_full_suite_run=False,new_math_proof_review_of_entire_core=False,ToN_IoT_resumed=False,
        scope='Read-only correspondence, function-location and file-identity audit. Historical proofs/tests retain their source and premises; no administrative independence or robustness is inferred.')
    OUT.mkdir();(OUT/'README.md').write_bytes(matrix.read_bytes())
    (OUT/'evidence-index.json').write_text(json.dumps(index,indent=2,sort_keys=True)+'\n')
    (OUT/'closure.json').write_text(json.dumps(dict(files={p.name:sha(p) for p in OUT.iterdir() if p.is_file()},audit_script_sha256=sha(Path(__file__))),indent=2)+'\n')
    (LOCAL/'email-evidence-index.json').write_bytes((OUT/'evidence-index.json').read_bytes())
    (LOCAL/'email-audit-closure.json').write_bytes((OUT/'closure.json').read_bytes())
    print(json.dumps(dict(status=index['status'],core_modules=130,implementation_sha256=identity,
        source_functions=len(bindings),evidence_files=len(pins),correspondence_files=len(mails),
        manuscript_files_checked=110,manuscript_files_changed=0),indent=2))


if __name__=='__main__':main()
