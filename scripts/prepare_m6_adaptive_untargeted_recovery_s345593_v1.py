import hashlib, json
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEED = 345593
TAG = f"m6-adaptive-untargeted-paired-s{SEED}-v1"
PLAN = ROOT / f"configs/{TAG}.json"
LOCK = ROOT / f"configs/{TAG}.lock.json"
LOG = ROOT / f"{TAG}.log"
RECORD = ROOT / f"artifacts/{TAG}-network-failure-record.json"
RECOVERY_PLAN = ROOT / f"configs/{TAG}-recovery-v2.json"
SOURCE = ROOT / "scripts/recover_m6_adaptive_untargeted_paired_s344593_v2.py"
RECOVERY_SCRIPT = ROOT / f"scripts/recover_m6_adaptive_untargeted_paired_s{SEED}_v2.py"

for path in (RECORD, RECOVERY_PLAN, RECOVERY_SCRIPT):
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite: {path}")
if not LOG.is_file():
    raise FileNotFoundError(f"Captured fresh-run log missing: {LOG}")
lock = json.loads(LOCK.read_text())
if lock.get("plan_sha256") != hashlib.sha256(PLAN.read_bytes()).hexdigest():
    raise ValueError("Seed plan does not match its frozen lock")

record = {
    "schema_version": "1.0",
    "artifact_type": "m6_adaptive_untargeted_infrastructure_failure_record",
    "experiment_id": TAG,
    "recorded_at": datetime.now(UTC).isoformat(),
    "stage": "M4 client provisioning, client01",
    "failure_class": "docker_address_pools_exhausted",
    "message": "all predefined address pools have been fully subnetted",
    "training_started": False,
    "enrollment_started": False,
    "stdout_saved_as_original_log": True,
    "original_log_path": LOG.name,
    "original_log_sha256": hashlib.sha256(LOG.read_bytes()).hexdigest(),
    "capture_note": "Fresh-only runner stopped during Docker trust-network creation before enrollment or training; full output is preserved in the local ignored log."
}
recovery = {
    "schema_version": "1.0",
    "artifact_type": "m6_adaptive_untargeted_infrastructure_recovery_plan",
    "experiment_id": TAG,
    "network_internal": True,
    "network_name": "flforensics_" + TAG.replace("-", "_") + "_trust",
    "network_subnet": "10.254.251.0/24",
    "plan_sha256": hashlib.sha256(PLAN.read_bytes()).hexdigest(),
    "static_lock_sha256": hashlib.sha256(LOCK.read_bytes()).hexdigest(),
    "provisioning": "compose.m4.yaml client01-client15 sequential --no-deps --rm",
    "failure_record": str(RECORD.relative_to(ROOT)),
    "reason": "Docker address pools exhausted before client01 provisioning; no enrollment or training began.",
    "training_protocol_change": False
}
text = SOURCE.read_text()
if "s344593" not in text or "recovery-v2.json" not in text:
    raise ValueError("Known-good s344 recovery-v2 template differs")
text = text.replace("s344593", f"s{SEED}").replace("10.254.252.0/24", "10.254.251.0/24")
if "s344593" in text or "s345593" not in text:
    raise ValueError("Recovery script seed substitution failed")

for path, data in (
    (RECORD, (json.dumps(record, indent=2) + "\n").encode()),
    (RECOVERY_PLAN, (json.dumps(recovery, indent=2) + "\n").encode()),
    (RECOVERY_SCRIPT, text.encode()),
):
    with path.open("xb") as stream:
        stream.write(data)
print(json.dumps({"status": "recovery_prepared", "seed": SEED,
    "subnet": recovery["network_subnet"], "incident_record": str(RECORD),
    "recovery_plan": str(RECOVERY_PLAN), "recovery_script": str(RECOVERY_SCRIPT)}, indent=2))
