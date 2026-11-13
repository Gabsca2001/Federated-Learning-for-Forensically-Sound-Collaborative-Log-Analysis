"""Repair occurrence identity; preserve pre-fix sources, tests and review output."""
from pathlib import Path
import json
import shutil
import difflib
from fl_forensics.canonical import sha256_file
from fl_forensics.preprocessing import derived_json_bytes

repo=Path.cwd();out=Path(__file__).parent
before=json.loads((out/'before-review.json').read_bytes())
files=['src/fl_forensics/round_derivation.py','src/fl_forensics/campaign_derivation.py','tests/test_campaign_derivation.py']
original={n:(repo/n).read_text() for n in files}
for n in files:
    if n.startswith('src/'):assert sha256_file(repo/n)==before['sources'][n]
    dest=out/'pre-fix'/n;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy(repo/n,dest)
for name in ('full-tests.xml','full-tests.log','current-obligation-checks.json','PROPERTY_CODE_EVIDENCE_MATRIX.md','property-code-evidence-matrix.json'):
    shutil.copy(out/name,out/'pre-fix'/name)
for n in ('FORMAL_MODEL_THEOREMS.md','FORMAL_PROFILE_CORRESPONDENCE.md'):
    dest=out/'pre-fix/docs'/n;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy(repo/'docs'/n,dest)
round_source=original[files[0]]
old='''        kind: str, digest: str, *, prefix: str | None = None, commitment_only: bool = False
    ) -> str:
        identity = (prefix or kind) + ":" + digest'''
new='''        kind: str, digest: str, *, prefix: str | None = None, commitment_only: bool = False,
        occurrence_id: str | None = None,
    ) -> str:
        identity = (prefix or kind) + ":" + (digest if occurrence_id is None else occurrence_id)'''
assert round_source.count(old)==1;round_source=round_source.replace(old,new)
old='''            item.bundle_sha256,
            commitment_only=entry.outcome != "ready_for_admission",'''
new='''            item.bundle_sha256,
            # Identical bundle bytes can be claimed in another context/client slot.
            # Keep that rejected submission separate from the original occurrence.
            occurrence_id=item.submission_id,
            commitment_only=entry.outcome != "ready_for_admission",'''
assert round_source.count(old)==1;round_source=round_source.replace(old,new)
campaign=original[files[1]]
assert campaign.count('item.submission_id: f"update_bundle:{item.bundle_sha256}"')==1
campaign=campaign.replace('item.submission_id: f"update_bundle:{item.bundle_sha256}"','item.submission_id: f"update_bundle:{item.submission_id}"')
old='''            for item in checkpoint.core.accepted_inputs:
                edges.add((base, f"update_bundle:{item.bundle_sha256}", "num"))'''
new='''            for item in manifest.core.dispositions:
                if Decimal(item.effective_weight_decimal) > 0:
                    edges.add((base, f"update_bundle:{item.submission_id}", "num"))'''
assert campaign.count(old)==1;campaign=campaign.replace(old,new)
test=original[files[2]]
test=test.replace('from contextlib import redirect_stdout','from contextlib import redirect_stdout\nfrom unittest.mock import patch')
test=test.replace('from fl_forensics.storage import write_json_once, write_once','from fl_forensics.storage import write_json_once, write_once\nfrom fl_forensics.submission_evidence import submission_identity')
old='''    def _round(self, parent=None, *, value=0.5, minimum=1, wrong_base=False):'''
new='''    def _round(self, parent=None, *, value=0.5, minimum=1, wrong_base=False,
               replay_bundle_from=None, borrowed_client=None):'''
assert test.count(old)==1;test=test.replace(old,new)
old='''        case._prepare(second_value=value, minimum=minimum)
        result = case._run()'''
new='''        case._prepare(second_value=value, minimum=minimum)
        if replay_bundle_from is not None:
            self._claim_bundle(case, replay_bundle_from, "client01", "client01")
        if borrowed_client is not None:
            self._claim_bundle(case, case, "client01", borrowed_client)
        result = case._run()'''
assert test.count(old)==1;test=test.replace(old,new)
insertion='''    def _claim_bundle(self, case, source, source_client, claim_client):
        """A legitimate signer claims bytes which must fail bundle admission."""
        source_path = source.fixture.submissions_root / source_client / "bundle.json"
        raw = source_path.read_bytes()
        bundle = json.loads(raw)
        previous = case.receipts[claim_client]
        signer = case.signers[claim_client]
        core = previous.core.model_copy(update={
            "submission_id": submission_identity(case.context, claim_client, sha256_bytes(raw)),
            "bundle_id": bundle["bundle_id"], "bundle_sha256": sha256_bytes(raw),
            "bundle_core_digest": bundle["core_digest"],
        })
        digest = digest_object(core.model_dump(mode="json"))
        receipt = previous.model_copy(update={
            "core": core, "core_digest": digest, "receipt_id": "submission-receipt-" + digest,
            "signature": previous.signature.model_copy(update={
                "key_id": signer.key_id, "value_b64": signer.sign_digest(digest),
            }),
        })
        case._remove(case.client_receipts / f"{previous.core.submission_id}.json")
        case._replace(case.fixture.submissions_root / claim_client / "bundle.json", raw)
        data = derived_json_bytes(receipt.model_dump(mode="json"))
        case._replace(case.fixture.submissions_root / claim_client / "submission-receipt.json", data)
        case._replace(case.client_receipts / f"{receipt.core.submission_id}.json", data)
        case.receipts[claim_client] = receipt

    def _assert_separate_bundle_origins(self, case, accepted_case):
        self.assertEqual(case._verify()["status"], "verified")
        rejected = next(x for x in case._manifest()["core"]["dispositions"]
                        if x["client_id"] == ("client02" if case is accepted_case else "client01"))
        self.assertEqual(rejected["kind"], "protocol_rejection")
        self._create()
        graph = json.loads((self.output / "manifest.json").read_bytes())["core"]
        contexts = {r["context_digest"]: r for r in graph["rounds"]}
        accepted_sid = accepted_case.receipts["client01"].core.submission_id
        accepted_node = contexts[accepted_case.context.core_digest]["submissions"][accepted_sid]
        rejected_node = contexts[case.context.core_digest]["submissions"][rejected["submission_id"]]
        self.assertNotEqual(accepted_node, rejected_node)
        nodes = {n["node_id"]: n for n in graph["nodes"]}
        self.assertEqual(nodes[accepted_node]["sha256"], nodes[rejected_node]["sha256"])
        self.assertEqual(len(nodes[accepted_node]["contexts"]), 1)
        self.assertEqual(len(nodes[rejected_node]["contexts"]), 1)
        radius = self._blast(case, client=rejected["client_id"])
        self.assertEqual(radius["status"], "verified", radius)
        self.assertFalse(any(n["kind"] in {"checkpoint", "checkpoint_model", "round_scoring_state"}
                             for n in radius["reachable"]))
        self.assertEqual(self._verify()["status"], "verified")

    def test_replayed_rejected_bundle_keeps_its_own_round_occurrence(self):
        second = self._round(self.first, replay_bundle_from=self.first)
        self._assert_separate_bundle_origins(second, self.first)

    def test_borrowed_bundle_keeps_its_own_client_occurrence(self):
        case = self._round(borrowed_client="client02")
        self._assert_separate_bundle_origins(case, case)

'''
assert test.count('    def _common(self):')==1
test=test.replace('    def _common(self):',insertion+'    def _common(self):')
# Restore documentation to its before-review bytes; rebuild it after the fix.
for n in ('FORMAL_MODEL_THEOREMS.md',):shutil.copy(out/'before/docs'/n,repo/'docs'/n)
updated=dict(zip(files,(round_source,campaign,test),strict=True));diff=[]
for name,content in updated.items():
    diff.extend(difflib.unified_diff(original[name].splitlines(keepends=True),content.splitlines(keepends=True),fromfile='a/'+name,tofile='b/'+name))
    (repo/name).write_text(content)
(out/'submission-occurrence-fix.patch').write_text(''.join(diff))
from fl_forensics.round_derivation import implementation_sha256
record={'profile':'formal-review-source-correction-v1','reason':'Valid rejected replay/borrowed-byte claims must remain distinct submission occurrences; content merging caused cycles and false radius attribution.',
    'before_implementation_sha256':before['implementation_sha256'],'after_implementation_sha256':implementation_sha256(),
    'source_changes':{n:{'before_sha256':sha256_file(out/'pre-fix'/n),'after_sha256':sha256_file(repo/n)} for n in files},
    'historical_evidence_rewritten':False,'numerical_training_or_aggregation_algorithm_changed':False,
    'graph_node_identity_profile':'submission-occurrence-v2; node content sha256 remains the bundle byte hash',
    'historical_round_and_graph_verification':'Use the original preserved source release; old signed graphs are not relabelled.'}
(out/'source-correction.json').write_bytes(derived_json_bytes(record))
print('OCCURRENCE IDENTITY FIX INSTALLED',record['after_implementation_sha256'],flush=True)
