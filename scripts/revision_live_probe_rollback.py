"""swtpm-backed live case: per-key probe gate and global rollback in the signed derivation graph.

Branches (same partition, initial model, DBA plan and bounded+envelope configuration as
revision-live-bounded-tpm-v2): clean (probe enforce), active (DBA, probe enforce), rollback (DBA,
client probe audit-only, global rollback enforced). Mechanism demonstration, not an efficacy study.
`--stage prepare` (host, before any container) builds the lab, configurations and frozen policy."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import revision_attested_dba as legacy

CLIENTS = legacy.CLIENTS
BRANCHES = ('clean','active','rollback')
ROUNDS = 5
TRUST_CONFIG = Path('/app/configs/revision-bounded-live-trust.yaml')
TCTI = legacy.TCTI
sha, save = legacy.sha, legacy.save
def omitted(*args):return False


def internal(stage,branch,number):
    global BRANCHES
    BRANCHES=tuple(json.loads(Path('/evidence/reserved-protocol-before-training.json').read_text())['branches'])
    legacy.BRANCHES=BRANCHES;legacy.ROUNDS=ROUNDS;legacy.TRUST_CONFIG=TRUST_CONFIG
    legacy.CONFIG=Path('/evidence/config/federation.yaml')
    root=Path('/evidence');campaign=root/'branches'/branch
    workspace=campaign/'rounds'/f'round-{number:03d}'
    if stage=='bootstrap':
        from fl_forensics.trust import initialize_trust_workspace
        from fl_forensics.secure_round import _coordinator_signer
        from fl_forensics.round_derivation import implementation_sha256
        protocol=json.loads((root/'reserved-protocol-before-training.json').read_bytes())
        assert protocol['implementation_sha256']==implementation_sha256()
        initialize_trust_workspace(workspace=root/'trust',project_root=Path('/app'),
            trust_config_path=TRUST_CONFIG,clients_config_path=Path('/app/configs/clients.yaml'))
        _coordinator_signer(root/'coordinator',create=True)
        for name in BRANCHES:shutil.copytree(root/'coordinator/authority',root/'branches'/name/'authority')
        save(root/'protocol.json',{'reserved_protocol_sha256':sha(root/'reserved-protocol-before-training.json'),
            'emulated_TPM':True,'source_implementation_sha256':implementation_sha256()})
        return {'status':'initialized'}
    if stage=='init':
        from fl_forensics.secure_round import initialize_secure_round
        return initialize_secure_round(workspace=workspace,trust_workspace=root/'trust',
            partition_manifest_path=root/'partition/manifest.json',config_path=root/'config/federation.yaml',
            secure_config_path=Path('/app/configs/secure-round.yaml'),coordinator_workspace=campaign,
            campaign_id='live-probe-rollback-'+branch+'-20261112-v1',round_number=number,
            previous_round_workspace=campaign/'rounds'/f'round-{number-1:03d}' if number>1 else None,
            in_round_admission_config_path=root/'config'/f'{branch}.yaml',
            dba_training_config_path=root/'config/dba-plan.json' if branch!='clean' else None,
            initial_model_path=root/'initial-model.json' if number==1 else None,
            partition_config_path=Path('/app/configs/federation.yaml'))
    if stage=='aggregate':
        from fl_forensics.submission_evidence_workspace import create_submission_inventory_workspace
        from fl_forensics.in_round_admission import admit_and_aggregate_in_round
        receipts=root/'client-copies'/branch/f'round-{number:03d}';inventory=root/'inventories'/branch/f'round-{number:03d}.json'
        intake=create_submission_inventory_workspace(workspace=workspace,trust_workspace=root/'trust',client_receipts=receipts,
            submissions_root=workspace/'submissions',inventory_path=inventory,coordinator_workspace=campaign)
        save(root/'reports'/f'{branch}-{number:03d}-intake.json',intake)
        result=admit_and_aggregate_in_round(workspace=workspace,trust_workspace=root/'trust',submissions_root=workspace/'submissions',
            validation_split_path=root/'partition/server/splits/validation.json',coordinator_workspace=campaign,
            client_receipts=receipts,input_inventory_path=inventory)
        save(root/'reports'/f'{branch}-{number:03d}-admission.json',result)
        assert result['status']=='aggregated',result
        return result
    return legacy.internal(stage,branch,number)

def host(args):
    root = Path(__file__).resolve().parents[1]
    lab = (root / args.workspace).resolve()
    global BRANCHES
    BRANCHES = tuple(json.loads((lab / 'reserved-protocol-before-training.json').read_text())['branches'])
    assert lab.is_relative_to(root / "artifacts")
    lab.mkdir(parents=True, exist_ok=True)
    log = lab / "logs"
    log.mkdir(exist_ok=True)
    uid = f"{os.getuid()}:{os.getgid()}"
    image = args.image

    def docker(arguments, name):
        with (log / f"{name}.txt").open("ab") as stream:
            p = subprocess.run(
                ["docker", *arguments],
                cwd=root,
                stdout=stream,
                stderr=subprocess.STDOUT,
                check=False,
            )
        if p.returncode:
            raise RuntimeError(f"{name} failed with {p.returncode}; see {log / name}")

    def runtime(mounts, arguments, name):
        docker(
            [
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--user",
                uid,
                "--tmpfs",
                "/tmp:rw,size=512m",
                *mounts,
                image,
                *arguments,
            ],
            name,
        )

    full = [
        "-v",
        f"{lab}:/evidence",
        "-v",
        f"{root / 'artifacts/m2-data24-parquet'}:/dataset:ro",
    ]

    def stage(which, branch="baseline", n=1):
        runtime(
            full,
            [
                "/app/scripts/revision_live_probe_rollback.py",
                "--stage",
                which,
                "--branch",
                branch,
                "--round",
                str(n),
            ],
            f"{branch}-{n:03d}-{which}",
        )
        print(f"{which} {branch} {n}", flush=True)

    def client(which, c, branch="baseline", n=1):
        node = lab / "nodes" / c
        node.mkdir(parents=True, exist_ok=True)
        socket = lab / "tpm-sockets" / c
        socket.mkdir(parents=True, exist_ok=True)
        mounts = ["-v", f"{node}:/runtime", "-v", f"{socket}:/run/swtpm"]
        common = ["-m", "fl_forensics"]
        if which == "provision":
            command = [
                "m4-tpm-provision",
                "--workspace",
                "/runtime",
                "--project-root",
                "/app",
                "--config",
                str(TRUST_CONFIG),
                "--client-id",
                c,
                "--node-id",
                c.replace("client", "node"),
                "--tpm-instance",
                c.replace("client", "tpm"),
                "--tcti",
                TCTI,
                "--trust-level",
                "swtpm",
            ]
        elif which == "quote":
            command = ["m4-tpm-quote", "--workspace", "/runtime", "--tcti", TCTI]
        else:
            rw = lab / "branches" / branch / "rounds" / f"round-{n:03d}"
            dest = rw / "submissions" / c
            dest.mkdir(parents=True, exist_ok=True)
            receipts = lab / "client-copies" / branch / f"round-{n:03d}" / c
            receipts.mkdir(parents=True, exist_ok=True)
            mounts += [
                "-v",
                f"{lab / 'partition/clients' / c}:/client:ro",
                "-v",
                f"{rw / 'public'}:/campaign/public:ro",
                "-v",
                f"{dest}:/submission",
                "-v",
                f"{receipts}:/client-receipts",
            ]
            command = [
                "m5-client-update",
                "--public-workspace",
                "/campaign/public",
                "--client-dataset",
                "/client/dataset.json",
                "--client-manifest",
                "/client/manifest.json",
                "--node-workspace",
                "/runtime",
                "--submission-workspace",
                "/submission",
                "--client-id",
                c,
                "--tcti",
                TCTI,
                "--client-receipt-root",
                "/client-receipts",
            ]
        runtime(mounts, [*common, *command], f"{branch}-{n:03d}-{c}-{which}")

    def parallel(action, clients):
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(action, clients))

    if not (lab / "protocol.json").exists():
        stage("bootstrap")
    containers = []
    try:
        if not (lab / "trust/registry/index.json").exists():
            raise ValueError("missing trust init")
        index = json.loads((lab / "trust/registry/index.json").read_text())
        for c in CLIENTS:
            state = lab / "tpm-state" / c
            state.mkdir(parents=True, exist_ok=True)
            socket = lab / "tpm-sockets" / c
            socket.mkdir(parents=True, exist_ok=True)
            name = f"{lab.name}-tpm-{c}"
            exists = (
                subprocess.run(
                    ["docker", "inspect", name], capture_output=True, check=False
                ).returncode
                == 0
            )
            if exists:
                docker(["start", name], f"{c}-tpm-start")
            else:
                docker(
                    [
                        "run",
                        "-d",
                        "--name",
                        name,
                        "--network",
                        "none",
                        "--read-only",
                        "--cap-drop",
                        "ALL",
                        "--cap-add",
                        "FOWNER",
                        "--tmpfs",
                        "/tmp:rw,size=16m",
                        "-v",
                        f"{state}:/var/lib/swtpm",
                        "-v",
                        f"{socket}:/run/swtpm",
                        "--entrypoint",
                        "/bin/sh",
                        image,
                        "/app/scripts/run_swtpm.sh",
                    ],
                    f"{c}-tpm-start",
                )
            containers.append(name)
        parallel(lambda c: client("provision", c), CLIENTS)
        if not index["enrollments"]:
            stage("enroll")
        for b in BRANCHES:
            for n in range(1, ROUNDS + 1):
                rw = lab / "branches" / b / "rounds" / f"round-{n:03d}"
                if not (rw / "checkpoint/manifest.json").exists():
                    if not (rw / "public/round-context.json").exists():
                        stage("challenge", b, n)
                        parallel(lambda c, b=b, n=n: client("quote", c, b, n), CLIENTS)
                        stage("attest", b, n)
                        stage("init", b, n)
                    selected = [c for c in CLIENTS if not omitted(b, n, c)]
                    parallel(lambda c, b=b, n=n: client("train", c, b, n), selected)
                    collector = lab / "client-copies" / b / f"round-{n:03d}"
                    if not (rw / "client-receipts").exists():
                        shutil.copytree(collector, rw / "client-receipts")
                    stage("aggregate", b, n)
                stage("verify", b, n)
        for b in BRANCHES:
            stage("campaign", b, ROUNDS)
        image_meta = subprocess.check_output(["docker", "image", "inspect", image], text=True)
        save(lab / "runtime-image.json", json.loads(image_meta))
        print("LIVE PROBE ROLLBACK TPM CASE COMPLETED", flush=True)
    finally:
        for name in containers:
            docker(["stop", name], f"{name}-stop")



SOURCE_LAB = 'artifacts/revision-live-bounded-tpm-v2'
VARIANTS = {
    'bounded': ({'clean': 'enforce', 'active': 'enforce', 'rollback': 'rollback_only'}, 'active.yaml'),
    # Declared after the bounded case showed no live rollback: same DBA, plain FedAvg + retreat envelope
    # (no clipping), client probe audit-only, rollback enforced. Threshold and attack unchanged.
    'fedavg': ({'fedavg-rollback': 'rollback_only'}, 'control.yaml'),
}


def prepare(workspace, variant='bounded'):
    MODES, source_cfg = VARIANTS[variant]
    """Host-side: copy the bounded case inputs, add the frozen probe policy, reserve the protocol."""
    import numpy as np
    import yaml
    from fl_forensics.federated_model import dependencies
    from fl_forensics.in_round_admission import _model_from_export
    from fl_forensics.live_probe_gate import POLICY_FILE, PROFILE
    from fl_forensics.probe_gate import probe_inputs, shortcuts
    from fl_forensics.round_derivation import implementation_sha256
    root = Path(__file__).resolve().parents[1]; src = root / SOURCE_LAB; lab = root / workspace
    assert not lab.exists(), 'preserve the existing lab'
    (lab / 'config').mkdir(parents=True)
    shutil.copytree(src / 'partition', lab / 'partition')
    shutil.copytree(src / 'config/observable-assets', lab / 'config/observable-assets')
    for name in ('federation.yaml', 'dba-plan.json'):
        shutil.copy(src / 'config' / name, lab / 'config' / name)
    shutil.copy(src / 'initial-model.json', lab / 'initial-model.json')
    cohort = json.loads((lab / 'partition/manifest.json').read_text())['partition_mode']
    keyscales = json.loads((root / 'results/revision-probe-keynorm-confirm/calibration/key-scales.json').read_text())
    gscales = json.loads((root / 'results/revision-global-probe-confirm/calibration/global-scales.json').read_text())
    torch = dependencies()[1]; initial = json.loads((lab / 'initial-model.json').read_text())
    rows = json.loads((lab / 'partition/server/splits/validation.json').read_text())['rows']['validation']
    stacked, keys, n = probe_inputs(rows)
    init = shortcuts(_model_from_export(initial, torch=torch), stacked, keys, n, initial['class_names'].index('benign'), torch)
    policy = {
        'profile': PROFILE, 'values': [3.0, 6.0, 12.0], 'cohort': cohort,
        'client': {'floor': keyscales['floor'], 'multiplier': keyscales['multiplier'], 'scales': keyscales['scales'][cohort]},
        'global': {'floor': gscales['floor'], 'multiplier': gscales['multiplier'], 'scales': gscales['scales'][cohort],
                   'initial_model_sha256': sha(lab / 'initial-model.json'), 'initial_shortcuts': [[k[0], k[1], v] for k, v in init.items()]},
        'sources': {'client_scales': 'results/revision-probe-keynorm-confirm/calibration/key-scales.json',
                    'global_scales': 'results/revision-global-probe-confirm/calibration/global-scales.json'},
    }
    (lab / 'config' / POLICY_FILE).write_text(json.dumps(policy, indent=1, sort_keys=True) + '\n')
    base_cfg = yaml.safe_load((src / 'config' / source_cfg).read_text())
    for branch, mode in MODES.items():
        cfg = json.loads(json.dumps(base_cfg)); cfg['runtime_admission']['policy_id'] = f'live-probe-rollback-{branch}-v1'
        cfg['runtime_admission']['probe_policy'] = {'profile': PROFILE, 'mode': mode, 'policy_sha256': sha(lab / 'config' / POLICY_FILE)}
        (lab / 'config' / f'{branch}.yaml').write_text(yaml.safe_dump(cfg, sort_keys=True))
    save(lab / 'reserved-protocol-before-training.json', {
        'case_role': 'Mechanism demonstration on emulated TPMs: probe and rollback decisions appear in the signed derivation graph and verify offline. Not an efficacy study.',
        'branches': list(MODES), 'rounds': ROUNDS, 'probe_modes': MODES, 'variant': variant, 'source_config': source_cfg,
        'attack_plan': json.loads((lab / 'config/dba-plan.json').read_text()),
        'implementation_sha256': implementation_sha256(),
        'config_files': {str(p.relative_to(lab)): sha(p) for p in sorted((lab / 'config').rglob('*')) if p.is_file()},
        'initial_model_sha256': sha(lab / 'initial-model.json'), 'source_lab': SOURCE_LAB, 'emulated_TPM': True})
    print('PREPARED', sha(lab / 'reserved-protocol-before-training.json'), flush=True)


def main():
    p=argparse.ArgumentParser();p.add_argument('--stage');p.add_argument('--branch',default='clean');p.add_argument('--round',type=int,default=1)
    p.add_argument('--variant',default='bounded');p.add_argument('--image',default='revision-live-probe-rollback:20261112-v1');p.add_argument('--workspace',default='artifacts/revision-live-probe-rollback-v1')
    args=p.parse_args()
    if args.stage=='prepare': prepare(args.workspace, args.variant)
    elif args.stage: print(json.dumps(internal(args.stage,args.branch,args.round),indent=2),flush=True)
    else:host(args)

if __name__=='__main__':main()
