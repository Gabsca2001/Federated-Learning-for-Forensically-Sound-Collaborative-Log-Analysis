import unittest

import test_counterfactual_round as cf_tests

from fl_forensics.canonical import sha256_file
from fl_forensics.investigation_verifier import verify_investigation


class InvestigationVerifierTests(unittest.TestCase):
    def setUp(self):
        self.cf = cf_tests.CounterfactualRoundTests()
        self.cf.setUp()
        self.addCleanup(self.cf.doCleanups)
        self.case = self.cf.case
        self.sid = self.cf._sid(self.case, 'client02')
        self.cf._create(mode='rescore_round', remove=[self.sid])
        self.graph = self.cf.fixture
        self.graph._create()
        self.pin = sha256_file(self.case.manifest_path)
        self.inputs = dict(
            graph_workspace=self.graph.output, expected_graph_sha256=self.graph.pin,
            round_inputs={self.pin: {**self.case._options(), 'client_receipts': self.case.client_receipts}},
            product_workspaces={}, selected_submission_ids=[self.sid], review_inputs=[],
            counterfactual_inputs=[{**self.cf._source(), 'workspace': self.cf.output, 'expected_sha256': self.cf.pin}],
            coordinator_public_key=self.case.fixture.coordinator.private_key.public_key(),
            graph_authority_public_key=self.cf.authority.private_key.public_key(),
        )

    def test_full_source_and_intervention_are_composed_without_overclaiming(self):
        result = verify_investigation(**self.inputs)
        self.assertEqual(result['status'], 'verified', result['errors'])
        self.assertTrue(result['historical_policy_decisions_revalidated'])
        self.assertFalse(result['counterfactuals'][0]['analysis']['historical_policy_decisions_revalidated'])
        self.assertFalse(result['selected_reviews_verified'])
        self.assertFalse(result['deadline_verified'])
        analysis = result['counterfactuals'][0]['analysis']
        self.assertEqual(analysis['separated_influence_diagnostics']['survivor_policy_total_variation']['numerator'], '0')
        self.assertTrue(all('observed_trust_eligible' in x and 'effective_mandatory_gate_passed' in x and 'participated_in_scoring' in x for x in analysis['historical_gate_and_scoring_membership'].values()))
        self.assertTrue(all('exact_edge_type_set' in path for node in result['structural_radius']['reachable'] for path in node['paths']))

    def test_missing_retained_receipt_rejected_even_when_standalone_cf_passes(self):
        self.case._remove(next(self.case.client_receipts.glob('*.json')))
        self.assertEqual(self.cf._verify()['status'], 'verified')
        result = verify_investigation(**self.inputs)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['historical_policy_decisions_revalidated'])

    def test_graph_round_subset_cannot_claim_full_verification(self):
        result = verify_investigation(**{**self.inputs, 'round_inputs': {}})
        self.assertEqual(result['status'], 'failed')

    def test_selection_cannot_be_changed_to_another_authenticated_submission(self):
        result = verify_investigation(**{**self.inputs, 'selected_submission_ids': [self.cf._sid(self.case, 'client01')]})
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['historical_policy_decisions_revalidated'])

    def test_missing_review_tip_is_not_accepted_as_reviewed_evidence(self):
        result = verify_investigation(**{**self.inputs, 'review_inputs': [{'round_workspace': self.case.workspace}]})
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['selected_reviews_verified'])
