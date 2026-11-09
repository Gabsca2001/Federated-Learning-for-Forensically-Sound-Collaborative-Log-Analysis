"""Compose full round, graph, anchored review and counterfactual verification.

This analyst module may be loaded beside a preserved numerical source release.
It does not weaken that release's implementation fingerprint checks.
"""
from __future__ import annotations

import json
from pathlib import Path

from fl_forensics.campaign_derivation import structural_blast_radius_set
from fl_forensics.canonical import sha256_file
from fl_forensics.counterfactual_round import verify_counterfactual_round
from fl_forensics.crypto import load_public_key, public_key_id
from fl_forensics.in_round_admission import verify_in_round_secure_round
from fl_forensics.review_ledger import verify_review_ledger


def verify_investigation(
    *, graph_workspace, expected_graph_sha256, round_inputs, product_workspaces,
    selected_submission_ids, counterfactual_inputs, review_inputs,
    coordinator_public_key, graph_authority_public_key,
):
    """Fail closed unless ALL graph rounds pass the full admission verifier.

    round_inputs is keyed by externally pinned derivation manifest hashes; each
    value contains the keyword arguments of verify_in_round_secure_round except
    require_derivation. Other inputs include explicit authority keys and hashes.
    Reviews are optional; an empty list yields selected_reviews_verified=False.
    No verification of review judgments' truth or witness deadlines is claimed.
    """
    report = {
        'status': 'failed', 'profile': 'composed-retrospective-investigation-v1', 'errors': [],
        'historical_policy_decisions_revalidated': False, 'selected_reviews_verified': False,
        'deadline_verified': False, 'delivery_verified': False,
        'global_artifact_completeness_verified': False, 'product_payloads_recomputed': False,
        'rounds': {}, 'reviews': [], 'counterfactuals': [],
    }

    def require_verified(result, label):
        if result.get('status') != 'verified':
            raise ValueError(f'{label} failed: {result.get("errors", [])}')

    try:
        selected = set(selected_submission_ids)
        if not selected or len(selected) != len(selected_submission_ids) or not counterfactual_inputs:
            raise ValueError('a unique nonempty selection and counterfactuals are required')
        graph_path = Path(graph_workspace) / 'manifest.json'
        if sha256_file(graph_path) != expected_graph_sha256:
            raise ValueError('changed graph pin')
        graph = json.loads(graph_path.read_bytes())
        graph_pins = {r['manifest_sha256'] for r in graph['core']['rounds']}
        if graph_pins != set(round_inputs):
            raise ValueError('full inputs are required for exactly every graph round')
        workspaces = {}
        origins = {}
        for pin, inputs in round_inputs.items():
            workspace = Path(inputs['workspace'])
            manifest_path = workspace / 'derivation/manifest.json'
            if sha256_file(manifest_path) != pin:
                raise ValueError('changed source round pin')
            key = load_public_key((workspace / 'public/round-coordinator.public.pem').read_bytes())
            if public_key_id(key) != public_key_id(coordinator_public_key):
                raise ValueError('source coordinator authority differs')
            if inputs.get('client_receipts') is None:
                raise ValueError('explicit retained client receipt copies are required')
            result = verify_in_round_secure_round(**inputs, require_derivation=True)
            require_verified(result, 'full source admission')
            report['rounds'][pin] = result
            workspaces[pin] = workspace
            manifest = json.loads(manifest_path.read_bytes())
            for item in manifest['core']['dispositions']:
                if item['submission_id'] in origins:
                    raise ValueError('ambiguous source submission')
                origins[item['submission_id']] = pin
        if not selected <= set(origins):
            raise ValueError('selection outside authenticated sources')
        radius = structural_blast_radius_set(
            workspace=Path(graph_workspace), expected_sha256=expected_graph_sha256,
            submission_ids=selected_submission_ids, round_workspaces=workspaces,
            product_workspaces=product_workspaces, coordinator_public_key=coordinator_public_key,
            authority_public_key=graph_authority_public_key,
        )
        require_verified(radius, 'graph and structural radius')
        for node in radius['reachable']:
            for path in node['paths']:
                kinds = sorted(set(path['edge_kinds']))
                path['exact_edge_type_set'] = kinds
                path['mixed_dependency_types'] = len(kinds) > 1
        report['structural_radius'] = radius
        reviewed = set()
        for supplied in review_inputs:
            inputs = dict(supplied)
            workspace = Path(inputs['round_workspace'])
            pin = sha256_file(workspace / 'derivation/manifest.json')
            if pin not in workspaces or workspace.resolve() != workspaces[pin].resolve():
                raise ValueError('review belongs to a different source round')
            if inputs.get('expected_head') is None:
                raise ValueError('a retained external review head is required')
            result = verify_review_ledger(**inputs, require_tip_anchor=True)
            require_verified(result, 'anchored review')
            reviewed.update(sid for sid, state in result['semantic_states'].items() if state['label'] != 'not_reviewed')
            report['reviews'].append(result)
        if review_inputs and not selected <= reviewed:
            raise ValueError('selected submissions lack an anchored attributed review')
        interventions = set()
        for supplied in counterfactual_inputs:
            inputs = dict(supplied)
            path = Path(inputs['workspace']) / 'manifest.json'
            if sha256_file(path) != inputs['expected_sha256']:
                raise ValueError('changed counterfactual pin')
            core = json.loads(path.read_bytes())['core']
            source = core['source_manifest_sha256']
            removed = set(core['removed_submission_ids'])
            if not removed or not removed <= selected or any(origins[sid] != source for sid in removed):
                raise ValueError('counterfactual removal differs from reviewed graph selection')
            if source not in workspaces or Path(inputs['round_workspace']).resolve() != workspaces[source].resolve():
                raise ValueError('counterfactual belongs to a different source')
            source_inputs = round_inputs[source]
            for key in ('submissions_root', 'validation_split_path'):
                if Path(inputs[key]).resolve() != Path(source_inputs[key]).resolve():
                    raise ValueError('counterfactual input differs from fully verified source')
            if public_key_id(inputs['coordinator_public_key']) != public_key_id(coordinator_public_key):
                raise ValueError('counterfactual coordinator authority differs')
            result = verify_counterfactual_round(**inputs)
            require_verified(result, 'counterfactual')
            report['counterfactuals'].append(result)
            interventions.update(removed)
        if interventions != selected:
            raise ValueError('counterfactuals do not cover the exact selected submission set')
        report.update(status='verified', historical_policy_decisions_revalidated=True,
            selected_reviews_verified=bool(review_inputs), graph_manifest_sha256=expected_graph_sha256,
            selected_submission_ids=sorted(selected),
            interpretation='Full historical admission recomputed for every supplied graph round; exact selection bound to interventions and, when supplied, anchored attributed reviews. Standalone verifier flags retain their narrower meaning. No fresh training, quote, witness deadline, global artifact closure or semantic truth is inferred.')
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ArithmeticError) as exc:
        report['errors'].append(str(exc))
    return report
