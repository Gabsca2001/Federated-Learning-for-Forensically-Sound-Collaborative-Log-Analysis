"""Probe cross-round content reuse with valid signed negative intake evidence."""
from pathlib import Path
import json
from unittest.mock import patch
import test_campaign_derivation as campaign_tests
import test_round_derivation as round_tests
from fl_forensics.canonical import sha256_file,digest_object
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.submission_evidence import submission_identity
from fl_forensics.round_derivation import implementation_sha256

fixture=campaign_tests.CampaignDerivationTests('test_explicit_submission_set_deduplicates_descendants_and_retains_each_origin')
fixture.setUp()
try:
    first=fixture.first
    assert first._verify()['status']=='verified'
    raw=(first.fixture.submissions_root/'client01/bundle.json').read_bytes();old=json.loads(raw)
    prepare=round_tests.RoundDerivationTests._prepare
    def replay(case,*args,**kwargs):
        prepare(case,*args,**kwargs)
        previous=case.receipts['client01'];signer=case.signers['client01']
        core=previous.core.model_copy(update={'submission_id':submission_identity(case.context,'client01',sha256_file(first.fixture.submissions_root/'client01/bundle.json')),
            'bundle_id':old['bundle_id'],'bundle_sha256':sha256_file(first.fixture.submissions_root/'client01/bundle.json'),'bundle_core_digest':old['core_digest']})
        digest=digest_object(core.model_dump(mode='json'))
        receipt=previous.model_copy(update={'core':core,'core_digest':digest,'receipt_id':'submission-receipt-'+digest,
            'signature':previous.signature.model_copy(update={'key_id':signer.key_id,'value_b64':signer.sign_digest(digest)})})
        case._remove(case.client_receipts/f'{previous.core.submission_id}.json')
        case._replace(case.fixture.submissions_root/'client01/bundle.json',raw)
        case._replace(case.fixture.submissions_root/'client01/submission-receipt.json',derived_json_bytes(receipt.model_dump(mode='json')))
        case._replace(case.client_receipts/f'{receipt.core.submission_id}.json',derived_json_bytes(receipt.model_dump(mode='json')))
        case.receipts['client01']=receipt
    with patch.object(round_tests.RoundDerivationTests,'_prepare',replay):second=fixture._round(first)
    verification=second._verify();assert verification['status']=='verified',verification
    disposition=next(r for r in second._manifest()['core']['dispositions'] if r['client_id']=='client01')
    assert disposition['kind']=='protocol_rejection',disposition
    result={'implementation_sha256':implementation_sha256(),'source_rounds_full_verified':True,'replayed_submission_kind':disposition['kind'],
        'identical_bundle_sha256':sha256_file(second.fixture.submissions_root/'client01/bundle.json')}
    try:
        fixture._create();result['graph_created']=True
    except Exception as exc:result.update(graph_created=False,error_type=type(exc).__name__,error=str(exc))
    (Path(__file__).parent/'replayed-bundle-probe-reproduced.json').write_bytes(derived_json_bytes(result))
    print(json.dumps(result),flush=True)
finally:fixture.doCleanups()
