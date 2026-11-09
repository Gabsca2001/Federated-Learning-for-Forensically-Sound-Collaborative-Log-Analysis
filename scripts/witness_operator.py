"""Offline recovery of a sealed receipt witness with externally retained pins.

Backups contain private signing material and must stay with the witness
operator. This tool does not back up an open round or assert administrator
independence. SQLite's backup API supplies a consistent database snapshot;
the external policy/closure pins authenticate its logical history.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import stat
import sys
from contextlib import closing
from pathlib import Path

from fl_forensics.canonical import sha256_file
from fl_forensics.crypto import SoftwareECDSASigner, load_public_key
from fl_forensics.secure_round_models import SecureRoundContext
from fl_forensics.storage import load_json
from fl_forensics.submission_witness import verify_witness_snapshot
from fl_forensics.submission_witness_cli import _keys
from fl_forensics.witness_models import (
    WitnessClosure,
    WitnessPolicy,
    WitnessRegistration,
    WitnessSnapshot,
)

DATABASE = "registrations.sqlite3"
MANIFEST = "operator-backup-manifest.json"
REQUIRED = (
    DATABASE,
    "witness-private.pem",
    "witness-public.pem",
    "coordinator-public.pem",
    "policy.json",
    "context.json",
    "settings.json",
    "tsa-trust-store.pem",
    "client-keys.json",
)


def private_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError("witness state must be an existing real directory")
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("witness directory must be owned by the operator and mode 0700")


def files(path: Path) -> dict[str, str]:
    result = {}
    for entry in sorted(path.rglob("*")):
        if entry.is_symlink():
            raise ValueError("symlinks are not allowed in witness recovery state")
        if entry.is_file():
            result[entry.relative_to(path).as_posix()] = sha256_file(entry)
        elif not entry.is_dir():
            raise ValueError("special files are not allowed in witness recovery state")
    return result


def inspect(state: Path, policy_pin: str, closure_pin: str, acknowledgements: list[Path]):
    private_directory(state)
    files(state)
    for name in REQUIRED:
        if not (state / name).is_file():
            raise ValueError(f"required existing witness file is missing: {name}")
    for name in (DATABASE, "witness-private.pem"):
        info = (state / name).stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError(f"private operator file has unsafe ownership/permissions: {name}")
    for binding in load_json(state / "client-keys.json").values():
        value = binding["public_key"] if isinstance(binding, dict) else binding
        if not (state / value).resolve().is_relative_to(state.resolve()):
            raise ValueError("client public keys must be retained inside recovery state")
    # Read-only URI deliberately prevents sqlite3 from creating a missing DB.
    with closing(
        sqlite3.connect((state / DATABASE).resolve().as_uri() + "?mode=ro", uri=True)
    ) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ValueError("witness database integrity check failed")
        row = db.execute("SELECT artifact FROM closure WHERE id=1").fetchone()
        if row is None:
            raise ValueError("only sealed witness state can be backed up/restored by this tool")
        registrations = [
            WitnessRegistration.model_validate_json(row[0])
            for row in db.execute("SELECT artifact FROM registrations ORDER BY sequence")
        ]
        closure = WitnessClosure.model_validate_json(row[0])
        policy = WitnessPolicy.model_validate(load_json(state / "policy.json"))
        if db.execute("SELECT digest FROM policy WHERE id=1").fetchone() != (policy.core_digest,):
            raise ValueError("journal policy differs from state policy")
    snapshot = WitnessSnapshot(
        context=SecureRoundContext.model_validate(load_json(state / "context.json")),
        policy=policy,
        registrations=registrations,
        closure=closure,
    )
    if SoftwareECDSASigner.load(state / "witness-private.pem").key_id != policy.core.witness_key_id:
        raise ValueError("private signing key differs from authenticated witness policy")
    if load_json(state / "settings.json")["expected_policy_digest"] != policy_pin:
        raise ValueError("operator settings differ from externally retained policy")
    report = verify_witness_snapshot(
        snapshot=snapshot,
        expected_policy_digest=policy_pin,
        expected_closure_digest=closure_pin,
        witness_public_key=load_public_key((state / "witness-public.pem").read_bytes()),
        coordinator_public_key=load_public_key((state / "coordinator-public.pem").read_bytes()),
        client_public_keys=_keys(state / "client-keys.json"),
        trust_store=(state / "tsa-trust-store.pem").read_bytes(),
        retained_acknowledgements=[
            WitnessRegistration.model_validate(load_json(p)) for p in acknowledgements
        ],
    )
    if not report["registration_set_verified"]:
        raise ValueError("sealed recovery verification failed: " + str(report["errors"]))
    return {
        "status": "verified_sealed_witness",
        "policy_digest": policy_pin,
        "closure_digest": closure_pin,
        "registered_receipts": len(registrations),
        "eligible_receipts": report["eligible_receipt_count"],
        "retained_acknowledgements_checked": len(acknowledgements),
        "private_backup": True,
        "administrative_independence_demonstrated": False,
        "open_round_backup_supported": False,
    }


def new_destination(source: Path, destination: Path) -> None:
    resolved = destination.resolve()
    if resolved == source.resolve() or resolved.is_relative_to(source.resolve()):
        raise ValueError("destination must be outside the source witness directory")
    if destination.exists() or destination.is_symlink():
        raise ValueError("recovery destination must not already exist")


def copy_state(source: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    for entry in sorted(source.rglob("*")):
        relative = entry.relative_to(source)
        if relative.as_posix() in {
            DATABASE,
            MANIFEST,
            DATABASE + "-wal",
            DATABASE + "-shm",
            DATABASE + "-journal",
        }:
            continue
        target = destination / relative
        if entry.is_dir():
            target.mkdir(mode=0o700)
        else:
            # Exclusive creation makes copied secrets private from their first byte.
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(entry.read_bytes())
    fd = os.open(destination / DATABASE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    with (
        closing(
            sqlite3.connect((source / DATABASE).resolve().as_uri() + "?mode=ro", uri=True)
        ) as src,
        closing(sqlite3.connect(destination / DATABASE)) as dst,
    ):
        src.backup(dst)


def execute(args):
    source = args.state
    result = inspect(
        source, args.expected_policy_digest, args.expected_closure_digest, args.acknowledgement
    )
    if args.command == "check":
        return result
    new_destination(source, args.output)
    if args.command == "restore":
        manifest = load_json(source / MANIFEST)
        actual = {k: v for k, v in files(source).items() if k != MANIFEST}
        if actual != manifest["files"]:
            raise ValueError("backup file manifest differs from actual contents")
        if (
            manifest["policy_digest"] != args.expected_policy_digest
            or manifest["closure_digest"] != args.expected_closure_digest
        ):
            raise ValueError("backup manifest differs from externally retained references")
    copy_state(source, args.output)
    recovered = inspect(
        args.output, args.expected_policy_digest, args.expected_closure_digest, args.acknowledgement
    )
    if args.command == "backup":
        manifest = dict(result, files=files(args.output))
        fd = os.open(args.output / MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(manifest, handle, indent=2)
    return dict(recovered, operation=args.command, output=str(args.output))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "backup", "restore"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--expected-policy-digest", required=True)
    parser.add_argument("--expected-closure-digest", required=True)
    parser.add_argument("--acknowledgement", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command != "check" and args.output is None:
        parser.error("--output is required for backup/restore")
    try:
        print(json.dumps(execute(args), sort_keys=True))
    except (ValueError, OSError, KeyError, sqlite3.Error) as exc:
        print(json.dumps({"status": "rejected", "error": str(exc)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
