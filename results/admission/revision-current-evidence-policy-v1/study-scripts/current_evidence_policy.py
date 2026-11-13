"""Current-evidence quarantine with prefix-only confirmation and immediate release.

Cumulative scores remain review evidence. They never authorize quarantine.
This experimental policy does not prove semantic malice or authorize live use.
"""
from __future__ import annotations

import copy
from fractions import Fraction

from .sequential_decision import SequentialRoundPolicy, digest

PROFILE = "current-evidence-round-policy-v1"


class CurrentEvidencePolicy:
    """Require two consecutive strong current observations; never hold on memory."""

    def __init__(self, calibration, *, minimum_contributors=8):
        self._evidence = SequentialRoundPolicy(
            calibration, minimum_contributors=minimum_contributors, kind="instantaneous"
        )
        self.cal = copy.deepcopy(self._evidence.cal)
        self.clients = list(self._evidence.clients)
        self.minimum = minimum_contributors
        self.round = 0
        self.head = "0" * 64
        self._high_streak = dict.fromkeys(self.clients, 0)
        self._quarantined = set()
        self._last_previous = None
        self._last_basis_digest = None
        self.last_result = None

    def step(self, round_number, risk, *, context_supported, mandatory_gate, masses,
             expected_previous_digest, source_observation_sha256):
        if type(round_number) is not int or round_number < 1:
            raise ValueError("round number must be a positive integer")
        retry = round_number == self.round
        required = self._last_previous if retry else self.head
        if expected_previous_digest != required:
            raise ValueError("trusted predecessor mismatch")
        if not retry and round_number != self.round + 1:
            raise ValueError("round order mismatch")
        # The evidence engine validates input and canonicalizes masses. Its own
        # internal chain is distinct from the action chain exposed by this API.
        basis = self._evidence.step(
            round_number, risk, context_supported=context_supported,
            mandatory_gate=mandatory_gate, masses=masses,
            expected_previous_digest=(self._evidence.last_previous if retry else self._evidence.head),
            source_observation_sha256=source_observation_sha256,
        )
        if retry:
            if basis["decision_digest"] != self._last_basis_digest:
                raise ValueError("conflicting evidence retry")
            return copy.deepcopy(self.last_result)

        supported = basis["supported"]
        records = copy.deepcopy(basis["clients"])
        streak = {}
        quarantine, reviews, rejected, transitions = [], [], [], {}
        for client in self.clients:
            current_high = supported and records[client]["instantaneous_proposal"]
            streak[client] = self._high_streak[client] + 1 if current_high else 0
            was_quarantined = client in self._quarantined
            if not mandatory_gate[client]:
                action = "protocol_reject"
                rejected.append(client)
            elif not supported:
                action = "abstain_requires_review"
                reviews.append(client)
            elif current_high and streak[client] >= 2:
                action = "quarantine_current_round"
                quarantine.append(client)
            elif (current_high or was_quarantined
                  or records[client]["action"] == "review_required"):
                action = "review_required"
                reviews.append(client)
            else:
                action = "no_statistical_alert"
            now_quarantined = action == "quarantine_current_round"
            transition = ("continued" if was_quarantined else "entered") if now_quarantined else (
                "released" if was_quarantined else "confirmation_pending" if current_high else "none"
            )
            records[client].update(
                action=action, current_high_in_both_views=current_high,
                consecutive_current_high_rounds=streak[client], quarantine_transition=transition,
                quarantine_authorized_by_cumulative_evidence=False,
            )
            transitions[client] = transition

        weights = {c: Fraction(str(masses[c])) for c in self.clients}
        effective = {c: Fraction(0) if c in quarantine or c in rejected else weights[c] for c in self.clients}
        quorum = (sum(v > 0 for v in effective.values()) >= self.minimum
                  and sum(effective.values(), Fraction(0)) > 0)
        core = {
            "profile": PROFILE, "policy_kind": "confirmed-current-evidence", "round": round_number,
            "source_observation_sha256": source_observation_sha256,
            "calibration_digest": basis["calibration_digest"],
            "input_digest": basis["input_digest"], "evidence_decision_digest": basis["decision_digest"],
            "previous_decision_digest": self.head, "supported": supported,
            "clients": records, "quarantine_current_round": quarantine, "review_required": reviews,
            "mandatory_rejections": rejected, "quarantine_transitions": transitions,
            "proposed_effective_masses": {c: str(v) for c, v in effective.items()},
            "proposal_quorum_satisfied": quorum, "minimum_contributors": self.minimum,
            "entry_consecutive_current_high_rounds": 2, "release_without_current_high": True,
            "cumulative_evidence_role": "review_only", "automatic_deployment_validated": False,
            "client_ban_performed": False,
        }
        result = {**core, "decision_digest": digest(core)}
        self._last_previous = self.head
        self._last_basis_digest = basis["decision_digest"]
        self.head = result["decision_digest"]
        self.round = round_number
        self._high_streak = streak
        self._quarantined = set(quarantine)
        self.last_result = copy.deepcopy(result)
        return result
