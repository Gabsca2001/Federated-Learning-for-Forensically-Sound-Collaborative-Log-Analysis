"""RFC 3161 evidence with explicit signed accuracy, policy and external CA pins.

The authority's clock accuracy and key custody remain trust assumptions. The
verifier never treats JSON dates or an operating-system clock as TSA evidence.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from .canonical import sha256_bytes
from .timestamp_anchor import (
    _extract_certificates,
    _field,
    _message_imprint,
    _openssl_query,
    _openssl_verify,
    _post_timestamp,
    _timestamp_details,
)
from .witness_models import TimestampEvidence, WitnessPolicy


@dataclass(frozen=True)
class TimeInterval:
    lower: datetime
    upper: datetime


class TimestampProvider(Protocol):
    def stamp(self, subject: bytes) -> TimestampEvidence: ...


@dataclass(frozen=True)
class RFC3161Provider:
    url: str
    timeout: int = 15

    def stamp(self, subject: bytes) -> TimestampEvidence:
        request = _openssl_query(subject)
        response = _post_timestamp(self.url, request, self.timeout)
        return TimestampEvidence(
            request_b64=base64.b64encode(request).decode("ascii"),
            response_b64=base64.b64encode(response).decode("ascii"),
        )


def _accuracy(value: str) -> timedelta:
    # OpenSSL prints each ASN.1 integer in hexadecimal, or "unspecified".
    match = re.fullmatch(
        r"(0x[0-9a-fA-F]+|unspecified) seconds, "
        r"(0x[0-9a-fA-F]+|unspecified) millis, "
        r"(0x[0-9a-fA-F]+|unspecified) micros",
        value,
    )
    if match is None or all(v == "unspecified" for v in match.groups()):
        raise ValueError("TSA must provide an explicit signed accuracy")
    seconds, millis, micros = [0 if v == "unspecified" else int(v, 16) for v in match.groups()]
    if not 0 <= seconds <= 60 or not 0 <= millis <= 999 or not 0 <= micros <= 999:
        raise ValueError("invalid TSA accuracy")
    return timedelta(seconds=seconds, milliseconds=millis, microseconds=micros)


def verify_timestamp(
    subject: bytes, evidence: TimestampEvidence, *, policy: WitnessPolicy, trust_store: bytes
) -> TimeInterval:
    if sha256_bytes(trust_store) != policy.core.tsa_trust_store_sha256:
        raise ValueError("TSA trust store differs from pinned policy")
    request = base64.b64decode(evidence.request_b64, validate=True)
    response = base64.b64decode(evidence.response_b64, validate=True)
    certificates = _extract_certificates(response)
    _openssl_verify(
        request_bytes=request,
        response_bytes=response,
        certificates=certificates,
        trust_store=trust_store,
    )
    details = _timestamp_details(response)
    if _field(details, "Status") not in {"Granted.", "Granted with mods."}:
        raise ValueError("TSA did not grant the timestamp")
    if _field(details, "Hash Algorithm").lower() != "sha256":
        raise ValueError("TSA imprint algorithm must be SHA-256")
    if _message_imprint(details) != sha256_bytes(subject):
        raise ValueError("TSA message imprint differs from registration/closure")
    if _field(details, "Policy OID") != policy.core.tsa_policy_oid:
        raise ValueError("unexpected TSA policy")
    if not re.fullmatch(r"0x[0-9a-fA-F]+", _field(details, "Nonce")):
        raise ValueError("TSA evidence requires a nonce")
    accuracy = _accuracy(_field(details, "Accuracy"))
    if accuracy > timedelta(microseconds=policy.core.maximum_accuracy_microseconds):
        raise ValueError("TSA accuracy exceeds pinned policy")
    # Locale-independent parsing of OpenSSL's GMT display, including fractions.
    match = re.fullmatch(
        r"([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(\.\d{1,6})? (\d{4}) GMT",
        _field(details, "Time stamp"),
    )
    if match is None:
        raise ValueError("unsupported TSA time representation")
    month, day, hour, minute, second, fraction, year = match.groups()
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    time = datetime(
        int(year),
        months.index(month) + 1,
        int(day),
        int(hour),
        int(minute),
        int(second),
        int((fraction or ".0")[1:].ljust(6, "0")),
        tzinfo=UTC,
    )
    return TimeInterval(time - accuracy, time + accuracy)
