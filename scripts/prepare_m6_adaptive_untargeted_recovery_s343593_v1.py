import copy, json
from datetime import UTC, datetime
from pathlib import Path
root=Path("/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis")
seed=343593
tag=f"m6-adaptive-untargeted-paired-s{seed}-v1"
plan_path=root/f"configs/{tag}.json"
lock_path=root/f"configs/{tag}.lock.json"
rec_path=root/f"configs/{tag}-recovery-v1.json"
src_path=root/"scripts/recover_m6_adaptive_untargeted_paired_v1.py"
dst_path=root/f"scripts/recover_m6_adaptive_untargeted_paired_s{seed}_v1.py"
incident_path=root/f"artifacts/{tag}-network-failure-record.json"
targets=(rec_path,dst_path,incident_path)
if any(p.exists() for p in targets):
    raise FileExistsError("Refusing to overwrite recovery inputs or incident evidence")
plan=json.loads(plan_path.read_text(encoding="utf-8"))
lock=json.loads(lock_path.read_text(encoding="utf-8"))
incident={
 "schema_version":"1.0",
 "artifact_type":"m6_adaptive_untargeted_infrastructure_failure_record",
 "experiment_id":tag,
 "recorded_at":datetime.now(UTC).isoformat(),
 "stage":"M4 client provisioning, client01",
 "failure_class":"docker_address_pools_exhausted",
 "message":"all predefined address pools have been fully subnetted",
 "training_started":False,
 "enrollment_started":False,
 "stdout_saved_as_original_log":False,
 "capture_note":"Recorded from the runner command output; no original file redirection was used."
}
incident_data=(json.dumps(incident,indent=2)+"\n").encode()
rec={
 "schema_version":"1.0",
 "artifact_type":"m6_adaptive_untargeted_infrastructure_recovery_plan",
 "experiment_id":tag,
 "network_internal":True,
 "network_name":"flforensics_"+tag.replace("-","_")+"_trust",
 "network_subnet":"10.254.253.0/24",
 "plan_sha256":__import__("hashlib").sha256(plan_path.read_bytes()).hexdigest(),
 "static_lock_sha256":__import__("hashlib").sha256(lock_path.read_bytes()).hexdigest(),
 "provisioning":"compose.m4.yaml client01-client15 sequential --no-deps --rm",
 "failure_record":str(incident_path.relative_to(root)),
 "reason":"Docker address pools exhausted before client01 provisioning; no enrollment or training began.",
 "training_protocol_change":False
}
rec_data=(json.dumps(rec,indent=2)+"\n").encode()
text=src_path.read_text(encoding="utf-8")
text=text.replace("import run_m6_adaptive_untargeted_paired_v1 as frozen",
                  f"import run_m6_adaptive_untargeted_paired_s{seed}_v1 as frozen")
text=text.replace("s342593",str(seed))
text=text.replace('R=ROOT/"configs/m6-adaptive-untargeted-paired-s343593-v1-recovery-v1.json"',
                  f'R=ROOT/"configs/{tag}-recovery-v1.json"')
text=text.replace('LOG=ROOT/"m6-adaptive-untargeted-paired-v1.log"',
                  f'FAILURE_RECORD=ROOT/"artifacts/{tag}-network-failure-record.json"')
text=text.replace(f'PROC=ROOT/"artifacts/{tag}-recovery-process.json"',
                  f'PROC=ROOT/"artifacts/{tag}-network-recovery-process.json"')
text=text.replace(f'SETUP=ROOT/"artifacts/{tag}-recovery-receipt.json"',
                  f'SETUP=ROOT/"artifacts/{tag}-network-recovery-receipt.json"')
text=text.replace("if not LOG.is_file(): raise FileNotFoundError(\"Original failed log missing\")",
                  "if not FAILURE_RECORD.is_file(): raise FileNotFoundError(\"Incident failure record missing\")\n    failure=read(FAILURE_RECORD)\n    if failure.get(\"training_started\") is not False or failure.get(\"failure_class\")!=\"docker_address_pools_exhausted\": raise RuntimeError(\"Failure record does not match the documented pre-training incident\")")
text=text.replace('"original_failure_log_sha256"','"failure_record_sha256"')
text=text.replace("sha(LOG)","sha(FAILURE_RECORD)")
if "LOG" in text or "s342593" in text:
    raise ValueError("Recovery clone still contains old log/seed references")
for p,data in ((incident_path,incident_data),(rec_path,rec_data),(dst_path,text.encode())):
    with p.open("xb") as f: f.write(data)
print(json.dumps({"status":"recovery_prepared","seed":seed,"subnet":rec["network_subnet"],"incident_record":str(incident_path),"recovery_plan":str(rec_path),"recovery_script":str(dst_path)},indent=2))
