"""Operational resume with two isolated jobs and host-disk guards; protocol unchanged."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / 'artifacts/revision-capped-final-v1'
PYTHON = ROOT / '.venv/bin/python'
JOB = ROOT / 'scripts/capped_final_job.py'
PROTOCOL = LAB / 'protocol-before-training.json'
PIN = '13cb93e46e48eb4481a79979399a27f80b0d8b2e6a1c46fdcbe13844e78f8ddc'
WORKERS = 2
START_RESERVE = 6_000_000_000
STOP_RESERVE = 4_000_000_000
RUN = LAB / 'operational-resume-20261106'
RUN.mkdir(exist_ok=True)
lock = threading.Lock()
active = {}
stop = threading.Event()
completed = {'train': set(), 'audit': set()}

def emit(**value):
    with lock:
        print(json.dumps(value, sort_keys=True), flush=True)

def atomic_json(path, value):
    temporary = path.with_name(path.name + f'.{os.getpid()}.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    os.replace(temporary, path)

def preserve_resource_failure(path):
    assert path.resolve() == path and path.is_relative_to(LAB / 'cases') and path.is_dir()
    destination = LAB / 'interrupted-attempts' / f'after-space-resource-{time.time_ns()}' / path.name
    assert destination.resolve().is_relative_to(LAB / 'interrupted-attempts')
    files = {str(item.relative_to(path)): hashlib.sha256(item.read_bytes()).hexdigest()
             for item in path.rglob('*') if item.is_file()}
    destination.parent.mkdir(parents=True)
    path.rename(destination)
    atomic_json(destination.parent / 'preservation.json', {
        'reason': 'Explicit resource exception; not an algorithmic or security result',
        'relocated_to': str(destination.relative_to(LAB)), 'files': files,
        'frozen_generation_changed': False})

def is_resource_exception(result):
    text = str(result.get('error', '')).lower()
    return not result.get('complete', False) and any(marker in text for marker in (
        '[errno 28]', 'no space left on device', '[errno 12]', 'cannot allocate memory'))

def execute(phase, index):
    for attempt in range(1, 4):
        if stop.is_set():
            raise RuntimeError('Supervisor stopped before launching another job')
        free = shutil.disk_usage('/mnt/c').free
        if free < START_RESERVE:
            stop.set()
            raise RuntimeError(f'Host reserve reached before launch: {free} bytes')
        log_path = RUN / f'{phase}-{index:03d}-attempt-{attempt}.log'
        # Preserve previous operational logs as well as scientific attempts.
        if log_path.exists():
            log_path = RUN / f'{phase}-{index:03d}-attempt-{attempt}-{time.time_ns()}.log'
        started = time.monotonic()
        with log_path.open('x') as log:
            process = subprocess.Popen([str(PYTHON), '-u', str(JOB), phase, str(index)],
                cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
            with lock:
                active[process.pid] = {'phase': phase, 'index': index, 'process': process}
            emit(event='job_started', phase=phase, index=index, attempt=attempt,
                 host_free_bytes=free, pid=process.pid)
            try:
                while process.poll() is None:
                    if stop.is_set() or shutil.disk_usage('/mnt/c').free < STOP_RESERVE:
                        stop.set()
                        process.terminate()
                        try:
                            process.wait(timeout=20)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                        raise RuntimeError('Owned job stopped to preserve host-disk reserve')
                    time.sleep(1)
            finally:
                with lock:
                    active.pop(process.pid, None)
        if process.returncode == 0:
            if phase == 'train':
                task = protocol['tasks'][index]
                case = LAB / 'cases' / task['name']
                result = json.loads((case / 'result.json').read_text())
                if is_resource_exception(result):
                    preserve_resource_failure(case)
                    emit(event='resource_terminal_preserved_for_retry', phase=phase, index=index)
                    continue
            with lock:
                if phase in completed:
                    completed[phase].add(index)
                counts = {key: len(value) for key, value in completed.items()}
                atomic_json(RUN / 'state.json', {
                    'phase': phase, 'completed_job_counts': counts,
                    'planned_cases': len(protocol['tasks']), 'workers': WORKERS,
                    'protocol_sha256': PIN, 'host_free_bytes': shutil.disk_usage('/mnt/c').free,
                    'updated_at': datetime.now(timezone.utc).isoformat()})
            emit(event='job_finished', phase=phase, index=index, elapsed_seconds=time.monotonic()-started,
                 completed_job_counts=counts)
            return
        tail = log_path.read_text(errors='replace')[-3000:]
        emit(event='job_failed', phase=phase, index=index, attempt=attempt,
             returncode=process.returncode, diagnostic_tail=tail)
        if attempt < 3:
            time.sleep(2)
    stop.set()
    raise RuntimeError(f'Repeated operational failure: {phase} index {index}; evidence retained')

def batch(phase, indices):
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = [pool.submit(execute, phase, index) for index in indices]
        try:
            for future in as_completed(futures):
                future.result()
        except BaseException:
            stop.set()
            for future in futures:
                future.cancel()
            raise

assert hashlib.sha256(PROTOCOL.read_bytes()).hexdigest() == PIN
protocol = json.loads(PROTOCOL.read_text())
assert len(protocol['tasks']) == 108
atomic_json(RUN / 'operational-contract.json', {
    'protocol_sha256': PIN, 'workers': WORKERS, 'host_start_reserve_bytes': START_RESERVE,
    'host_stop_reserve_bytes': STOP_RESERVE, 'generation_and_thresholds_changed': False,
    'test_inference_only_after_all_training_terminal': True,
    'admission_policy': 'tpm_only', 'default_framework_policy_changed': False})
emit(event='supervisor_started', protocol_sha256=PIN, planned_cases=108, workers=WORKERS,
     host_free_bytes=shutil.disk_usage('/mnt/c').free)
try:
    batch('train', range(108))
    execute('close_training', 0)
    # Initialize the shared verification header once before concurrent audit jobs.
    execute('audit', 0)
    batch('audit', range(1, 108))
    execute('close_audit', 0)
    emit(event='campaign_and_numerical_audit_complete', cases=108)
except BaseException as exc:
    stop.set()
    atomic_json(RUN / 'supervisor-error.json', {'exception_type': type(exc).__name__, 'error': str(exc),
        'protocol_sha256': PIN, 'scientific_evidence_preserved': True})
    raise
