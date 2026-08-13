"""tpm2-tools adapter shared by swtpm and one physical TPM 2.0 node."""

from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .canonical import digest_object, sha256_bytes
from .config import load_yaml
from .crypto import DigestSigner, load_public_key, public_key_id
from .storage import atomic_json, load_json, utc_now, write_json_once
from .trust import build_measurement_log, create_enrollment_request, replay_pcrs
from .trust_models import (
    AttestationChallenge,
    EnrollmentRecord,
    MeasurementLog,
    QuoteEvidence,
    QuoteEvidenceCore,
)


EK_HANDLE = "0x81010001"
AK_HANDLE = "0x81010002"
ESK_HANDLE = "0x81010003"
ESK_PARENT_HANDLE = "0x81010004"
REQUIRED_TOOLS = (
    "tpm2_createek",
    "tpm2_createak",
    "tpm2_createprimary",
    "tpm2_create",
    "tpm2_load",
    "tpm2_evictcontrol",
    "tpm2_flushcontext",
    "tpm2_readpublic",
    "tpm2_pcrextend",
    "tpm2_pcrread",
    "tpm2_quote",
    "tpm2_checkquote",
    "tpm2_getcap",
)


def _require_tools(names: tuple[str, ...] = REQUIRED_TOOLS) -> None:
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise RuntimeError(f"required tpm2-tools are missing: {', '.join(missing)}")


def _run(
    command: list[str],
    *,
    tcti: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    if tcti:
        environment["TPM2TOOLS_TCTI"] = tcti
    result = subprocess.run(
        command,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{' '.join(command)} failed: {detail}")
    return result


@dataclass(frozen=True)
class TPM2ToolsSigner(DigestSigner):
    key_context: str
    public_key_pem: bytes
    tcti: str

    @property
    def key_id(self) -> str:
        return public_key_id(load_public_key(self.public_key_pem))

    def sign_digest(self, digest_hex: str) -> str:
        digest = bytes.fromhex(digest_hex)
        if len(digest) != 32:
            raise ValueError("TPM signer requires a SHA-256 digest")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            digest_path = root / "digest.bin"
            signature_path = root / "signature.der"
            digest_path.write_bytes(digest)
            _run(
                [
                    "tpm2_sign",
                    "-Q",
                    "-c",
                    self.key_context,
                    "-g",
                    "sha256",
                    "-d",
                    "-f",
                    "plain",
                    "-o",
                    str(signature_path),
                    str(digest_path),
                ],
                tcti=self.tcti,
            )
            return base64.b64encode(signature_path.read_bytes()).decode()


def _read_public(handle: str, output: Path, tcti: str) -> bool:
    result = _run(
        ["tpm2_readpublic", "-Q", "-c", handle, "-f", "pem", "-o", str(output)],
        tcti=tcti,
        check=False,
    )
    return result.returncode == 0


@contextmanager
def _managed_transient_handles(tcti: str) -> Iterator[None]:
    """Flush all transient TPM objects without masking an earlier TPM error.

    A context file passed to ``tpm2_evictcontrol`` is not guaranteed to remain
    a reusable ESYS_TR serialization afterwards.  Flushing transient handles by
    type avoids reopening a consumed context file and also releases any parent
    object created during a partially failed provisioning attempt.
    """
    body_failed = False
    try:
        yield
    except BaseException:
        body_failed = True
        raise
    finally:
        result = _run(
            ["tpm2_flushcontext", "-Q", "-t"],
            tcti=tcti,
            check=False,
        )
        if result.returncode != 0 and not body_failed:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"tpm2_flushcontext -Q -t failed: {detail}")


def _provision_keys(key_root: Path, tcti: str) -> tuple[bytes, bytes, bytes]:
    key_root.mkdir(parents=True, exist_ok=True)
    ek_pem = key_root / "ek.public.pem"
    ak_pem = key_root / "ak.public.pem"
    esk_pem = key_root / "esk.public.pem"

    if not _read_public(EK_HANDLE, ek_pem, tcti):
        _run(
            [
                "tpm2_createek",
                "-Q",
                "-G",
                "ecc",
                "-c",
                EK_HANDLE,
                "-u",
                str(key_root / "ek.public.tss"),
            ],
            tcti=tcti,
        )
        if not _read_public(EK_HANDLE, ek_pem, tcti):
            raise RuntimeError("created EK cannot be read from its persistent handle")

    if not _read_public(AK_HANDLE, ak_pem, tcti):
        ak_context = key_root / "ak.ctx"
        with _managed_transient_handles(tcti):
            _run(
                [
                    "tpm2_createak",
                    "-Q",
                    "-C",
                    EK_HANDLE,
                    "-G",
                    "ecc",
                    "-g",
                    "sha256",
                    "-s",
                    "ecdsa",
                    "-c",
                    str(ak_context),
                    "-u",
                    str(key_root / "ak.public.tss"),
                    "-n",
                    str(key_root / "ak.name"),
                ],
                tcti=tcti,
            )
            _run(
                [
                    "tpm2_evictcontrol",
                    "-Q",
                    "-C",
                    "o",
                    "-c",
                    str(ak_context),
                    AK_HANDLE,
                ],
                tcti=tcti,
            )
        if not _read_public(AK_HANDLE, ak_pem, tcti):
            raise RuntimeError("created AK cannot be read from its persistent handle")

    if not _read_public(ESK_HANDLE, esk_pem, tcti):
        primary = key_root / "owner-primary.ctx"
        primary_pem = key_root / "owner-primary.public.pem"
        esk_context = key_root / "esk.ctx"

        # Keep the ESK storage parent persistent.  This is important when the
        # TPM has very few transient-object slots: loading a child beneath a
        # transient parent would require both objects to be resident at once.
        if not _read_public(ESK_PARENT_HANDLE, primary_pem, tcti):
            with _managed_transient_handles(tcti):
                _run(
                    [
                        "tpm2_createprimary",
                        "-Q",
                        "-C",
                        "o",
                        "-G",
                        "ecc",
                        "-g",
                        "sha256",
                        "-c",
                        str(primary),
                    ],
                    tcti=tcti,
                )
                _run(
                    [
                        "tpm2_evictcontrol",
                        "-Q",
                        "-C",
                        "o",
                        "-c",
                        str(primary),
                        ESK_PARENT_HANDLE,
                    ],
                    tcti=tcti,
                )
            if not _read_public(ESK_PARENT_HANDLE, primary_pem, tcti):
                raise RuntimeError(
                    "created ESK parent cannot be read from its persistent handle"
                )

        with _managed_transient_handles(tcti):
            _run(
                [
                    "tpm2_create",
                    "-Q",
                    "-C",
                    ESK_PARENT_HANDLE,
                    "-G",
                    "ecc:ecdsa-sha256",
                    "-g",
                    "sha256",
                    "-a",
                    "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
                    "-u",
                    str(key_root / "esk.public.tss"),
                    "-r",
                    str(key_root / "esk.private.tss"),
                ],
                tcti=tcti,
            )
            _run(
                [
                    "tpm2_load",
                    "-Q",
                    "-C",
                    ESK_PARENT_HANDLE,
                    "-u",
                    str(key_root / "esk.public.tss"),
                    "-r",
                    str(key_root / "esk.private.tss"),
                    "-c",
                    str(esk_context),
                ],
                tcti=tcti,
            )
            _run(
                [
                    "tpm2_evictcontrol",
                    "-Q",
                    "-C",
                    "o",
                    "-c",
                    str(esk_context),
                    ESK_HANDLE,
                ],
                tcti=tcti,
            )
        if not _read_public(ESK_HANDLE, esk_pem, tcti):
            raise RuntimeError("created ESK cannot be read from its persistent handle")

    return ek_pem.read_bytes(), ak_pem.read_bytes(), esk_pem.read_bytes()


def provision_tpm_node(
    *,
    node_workspace: Path,
    project_root: Path,
    trust_config_path: Path,
    client_id: str,
    node_id: str,
    tpm_instance_id: str,
    tcti: str,
    trust_level: str,
) -> dict[str, Any]:
    if trust_level not in {"swtpm", "tpm2"}:
        raise ValueError("TPM adapter trust level must be swtpm or tpm2")
    _require_tools(REQUIRED_TOOLS + ("tpm2_sign",))
    _run(["tpm2_getcap", "-Q", "properties-fixed"], tcti=tcti)
    config, _ = load_yaml(trust_config_path)
    expected_log = build_measurement_log(project_root, config)
    selection = [int(value) for value in config["attestation"]["pcr_selection"]]
    selection_text = f"sha256:{','.join(str(item) for item in selection)}"
    pcr_result = _run(["tpm2_pcrread", selection_text], tcti=tcti)
    current_pcrs = _parse_pcr_output(pcr_result.stdout, selection)
    expected_pcrs = replay_pcrs(expected_log, selection)
    zero_pcrs = {str(index): "0" * 64 for index in selection}
    log_path = node_workspace / "measurement_log.json"
    if log_path.exists():
        existing_log = MeasurementLog.model_validate(load_json(log_path))
        if existing_log != expected_log:
            raise RuntimeError(
                "TPM state has an existing measurement log for different bytes; use a new state"
            )
        measurement_log = existing_log
    else:
        if current_pcrs != zero_pcrs:
            raise RuntimeError(
                "TPM PCRs are non-zero but the corresponding measurement log is missing"
            )
        measurement_log = expected_log
    if current_pcrs == zero_pcrs:
        for event in expected_log.events:
            _run(
                [
                    "tpm2_pcrextend",
                    "-Q",
                    f"{event.pcr_index}:sha256={event.measurement_sha256}",
                ],
                tcti=tcti,
            )
    elif current_pcrs != expected_pcrs:
        raise RuntimeError("current TPM PCRs do not match the approved or reset state")
    if not log_path.exists():
        write_json_once(log_path, expected_log.model_dump(mode="json"))

    ek_public, ak_public, esk_public = _provision_keys(node_workspace / "tpm-objects", tcti)
    esk_signer = TPM2ToolsSigner(
        key_context=ESK_HANDLE, public_key_pem=esk_public, tcti=tcti
    )
    request = create_enrollment_request(
        node_workspace=node_workspace,
        client_id=client_id,
        node_id=node_id,
        tpm_instance_id=tpm_instance_id,
        trust_level=trust_level,
        ek_public_bytes=ek_public,
        ak_public_pem=ak_public,
        esk_public_pem=esk_public,
        esk_signer=esk_signer,
        measurement_log=measurement_log,
    )
    summary = {
        "status": "provisioned",
        "client_id": client_id,
        "node_id": node_id,
        "tpm_instance_id": tpm_instance_id,
        "trust_level": trust_level,
        "tcti_profile": "swtpm-unix-socket" if trust_level == "swtpm" else "physical-device",
        "ek_public_sha256": sha256_bytes(ek_public),
        "ak_key_id": public_key_id(load_public_key(ak_public)),
        "esk_key_id": esk_signer.key_id,
        "enrollment_request_id": request.core.request_id,
    }
    atomic_json(node_workspace / "provisioning_summary.json", summary)
    return summary


def _parse_pcr_output(output: str, selection: list[int]) -> dict[str, str]:
    values: dict[str, str] = {}
    pattern = re.compile(r"^\s*(\d+)\s*:\s*(?:0x)?([0-9A-Fa-f]{64})\s*$")
    for line in output.splitlines():
        match = pattern.match(line)
        if match and int(match.group(1)) in selection:
            values[match.group(1)] = match.group(2).lower()
    if set(values) != {str(value) for value in selection}:
        raise RuntimeError("tpm2_pcrread did not return every selected SHA-256 PCR")
    return values


def create_tpm_quote_evidence(
    *, node_workspace: Path, tcti: str
) -> dict[str, Any]:
    _require_tools(("tpm2_quote", "tpm2_pcrread"))
    challenge = AttestationChallenge.model_validate(load_json(node_workspace / "challenge.json"))
    record = EnrollmentRecord.model_validate(load_json(node_workspace / "enrollment_record.json"))
    log = MeasurementLog.model_validate(load_json(node_workspace / "measurement_log.json"))
    selection_text = f"sha256:{','.join(str(item) for item in challenge.core.pcr_selection)}"
    pcr_result = _run(["tpm2_pcrread", selection_text], tcti=tcti)
    observed = _parse_pcr_output(pcr_result.stdout, challenge.core.pcr_selection)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        message_path = root / "quote.msg"
        signature_path = root / "quote.sig"
        _run(
            [
                "tpm2_quote",
                "-Q",
                "-c",
                AK_HANDLE,
                "-l",
                selection_text,
                "-q",
                challenge.core.nonce,
                "-m",
                str(message_path),
                "-s",
                str(signature_path),
                "-g",
                "sha256",
            ],
            tcti=tcti,
        )
        basis = {
            "enrollment_id": record.core.enrollment_id,
            "challenge_id": challenge.core.challenge_id,
            "client_id": record.core.client_id,
            "node_id": record.core.node_id,
            "ak_key_id": record.core.ak_key_id,
            "quote_format": "tpm2-tools-tpms-attest",
            "nonce": challenge.core.nonce,
            "pcr_bank": "sha256",
            "pcr_selection": challenge.core.pcr_selection,
            "observed_pcr_values": observed,
            "measurement_log_digest": digest_object(log.model_dump(mode="json")),
            "quote_message_b64": base64.b64encode(message_path.read_bytes()).decode(),
            "quote_signature_b64": base64.b64encode(signature_path.read_bytes()).decode(),
            "generated_at": utc_now(),
        }
    core = QuoteEvidenceCore(evidence_id=f"quote-{digest_object(basis)[:24]}", **basis)
    evidence = QuoteEvidence(
        core=core, core_digest=digest_object(core.model_dump(mode="json"))
    )
    write_json_once(
        node_workspace / "quotes" / f"{core.evidence_id}.json",
        evidence.model_dump(mode="json"),
    )
    atomic_json(node_workspace / "quote_evidence.json", evidence.model_dump(mode="json"))
    return {
        "status": "quoted",
        "client_id": core.client_id,
        "challenge_id": core.challenge_id,
        "evidence_id": core.evidence_id,
        "pcr_selection": core.pcr_selection,
    }


def verify_tpm2_quote(
    evidence: QuoteEvidence,
    record: EnrollmentRecord,
    expected_pcrs: dict[str, str],
) -> tuple[bool, str]:
    _require_tools(("tpm2_checkquote",))
    if evidence.core.quote_format != "tpm2-tools-tpms-attest":
        return False, "quote is not a tpm2-tools TPMS_ATTEST object"
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        ak_path = root / "ak.pem"
        message_path = root / "quote.msg"
        signature_path = root / "quote.sig"
        expected_path = root / "expected-pcr-values.bin"
        ak_path.write_text(record.core.ak_public_key_pem, encoding="utf-8")
        message_path.write_bytes(base64.b64decode(evidence.core.quote_message_b64, validate=True))
        signature_path.write_bytes(
            base64.b64decode(evidence.core.quote_signature_b64, validate=True)
        )
        expected_path.write_bytes(
            b"".join(
                bytes.fromhex(expected_pcrs[str(index)])
                for index in evidence.core.pcr_selection
            )
        )
        selection_text = f"sha256:{','.join(str(item) for item in evidence.core.pcr_selection)}"
        result = _run(
            [
                "tpm2_checkquote",
                "-u",
                str(ak_path),
                "-m",
                str(message_path),
                "-s",
                str(signature_path),
                "-f",
                str(expected_path),
                "-l",
                selection_text,
                "-g",
                "sha256",
                "-q",
                evidence.core.nonce,
            ],
            check=False,
        )
    if result.returncode == 0:
        return True, "AK signature, nonce, and expected PCR values verified by tpm2_checkquote"
    detail = result.stderr.strip() or result.stdout.strip()
    return False, f"tpm2_checkquote rejected the quote: {detail}"


def physical_tpm_preflight(*, tcti: str = "device:/dev/tpmrm0") -> dict[str, Any]:
    _require_tools(("tpm2_getcap", "tpm2_getrandom"))
    properties = _run(["tpm2_getcap", "properties-fixed"], tcti=tcti)
    random_result = _run(["tpm2_getrandom", "8"], tcti=tcti)
    return {
        "status": "available",
        "adapter": "tpm2-tools",
        "tcti": tcti,
        "properties_sha256": sha256_bytes(properties.stdout.encode()),
        "random_command_completed": random_result.returncode == 0,
    }