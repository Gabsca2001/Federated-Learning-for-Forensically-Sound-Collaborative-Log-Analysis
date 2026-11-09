"""Bounded confirmation of current envelope excess, independently of its peak.

This is an empirical current-round policy, not evidence of malicious intent.
Historical retreat-policy decisions remain reproducible under their own profile.
"""

from __future__ import annotations

import copy
from fractions import Fraction

from .client_envelope_policy import ClientEnvelopePolicy
from .sequential_decision import digest

PROFILE = "persistent-client-envelope-policy-v1"


class PersistentEnvelopePolicy:
    """Keep the retreat channel and add a finite current-high confirmation bound."""

    def __init__(self, calibration, envelope, *, minimum_contributors=8, confirmation_rounds=3):
        if type(confirmation_rounds) is not int or confirmation_rounds not in (2, 3, 4):
            raise ValueError("confirmation_rounds must be 2, 3 or 4")
        self._retreat = ClientEnvelopePolicy(
            calibration, envelope, minimum_contributors=minimum_contributors
        )
        self.clients = list(self._retreat.clients)
        self.confirmation_rounds = confirmation_rounds
        self.minimum = minimum_contributors
        self.round = 0
        self.head = "0" * 64
        self._streak = dict.fromkeys(self.clients, 0)
        self._quarantined = set()
        self._last_previous = None
        self._last_basis_digest = None
        self.last_result = None

    def step(
        self,
        round_number,
        risk,
        *,
        context_supported,
        mandatory_gate,
        masses,
        expected_previous_digest,
        source_observation_sha256,
    ):
        if type(round_number) is not int or round_number < 1:
            raise ValueError("round must be a positive integer")
        retry = round_number == self.round
        if expected_previous_digest != (self._last_previous if retry else self.head):
            raise ValueError("trusted predecessor mismatch")
        if not retry and round_number != self.round + 1:
            raise ValueError("round order mismatch")
        basis = self._retreat.step(
            round_number,
            risk,
            context_supported=context_supported,
            mandatory_gate=mandatory_gate,
            masses=masses,
            expected_previous_digest=(
                self._retreat._last_previous if retry else self._retreat.head
            ),
            source_observation_sha256=source_observation_sha256,
        )
        if retry:
            if basis["decision_digest"] != self._last_basis_digest:
                raise ValueError("conflicting evidence retry")
            return copy.deepcopy(self.last_result)
        records = copy.deepcopy(basis["clients"])
        streak = {
            c: self._streak[c] + 1
            if basis["supported"] and records[c]["client_envelope_current_high"]
            else 0
            for c in self.clients
        }
        bounded = {c for c in self.clients if streak[c] >= self.confirmation_rounds}
        selected = set(basis["quarantine_current_round"]) | bounded
        quarantine, reviews, rejected, transitions = [], [], [], {}
        for client in self.clients:
            previous = client in self._quarantined
            if not mandatory_gate[client]:
                action = "protocol_reject"
                rejected.append(client)
            elif not basis["supported"]:
                action = "abstain_requires_review"
                reviews.append(client)
            elif client in selected:
                action = "quarantine_current_round"
                quarantine.append(client)
            elif streak[client] or previous or records[client]["action"] == "review_required":
                action = "review_required"
                reviews.append(client)
            else:
                action = "no_statistical_alert"
            transition = (
                ("continued" if previous else "entered")
                if client in quarantine
                else (
                    "released" if previous else "confirmation_pending" if streak[client] else "none"
                )
            )
            records[client].update(
                action=action,
                quarantine_transition=transition,
                consecutive_client_envelope_high_rounds=streak[client],
                bounded_persistence_proposal=client in bounded,
            )
            transitions[client] = transition
        effective = {
            c: Fraction(0) if c in quarantine or c in rejected else Fraction(str(masses[c]))
            for c in self.clients
        }
        core = {
            "profile": PROFILE,
            "round": round_number,
            "source_observation_sha256": source_observation_sha256,
            "previous_decision_digest": self.head,
            "retreat_decision_digest": basis["decision_digest"],
            "calibration_digest": basis["calibration_digest"],
            "envelope_calibration_digest": basis["envelope_calibration_digest"],
            "input_digest": digest(
                {"retreat": basis["input_digest"], "confirmation_rounds": self.confirmation_rounds}
            ),
            "supported": basis["supported"],
            "clients": records,
            "quarantine_current_round": quarantine,
            "review_required": reviews,
            "mandatory_rejections": rejected,
            "quarantine_transitions": transitions,
            "bounded_persistence_quarantine": sorted(bounded),
            "proposed_effective_masses": {c: str(v) for c, v in effective.items()},
            "proposal_quorum_satisfied": sum(v > 0 for v in effective.values()) >= self.minimum,
            "minimum_contributors": self.minimum,
            "confirmation_rounds": self.confirmation_rounds,
            "cumulative_evidence_role": "review_only",
            "client_ban_performed": False,
            "automatic_deployment_validated": False,
        }
        result = {**core, "decision_digest": digest(core)}
        self._last_previous = self.head
        self._last_basis_digest = basis["decision_digest"]
        self.head, self.round = result["decision_digest"], round_number
        self._streak, self._quarantined = streak, set(quarantine)
        self.last_result = copy.deepcopy(result)
        return result
