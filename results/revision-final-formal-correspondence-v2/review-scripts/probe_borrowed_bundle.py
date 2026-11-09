"""Compare signed borrowed-byte submission attribution under both releases."""
from pathlib import Path
import json
import test_campaign_derivation as cases
from fl_forensics.round_derivation import implementation_sha256
from fl_forensics.preprocessing import derived_json_bytes

out=Path(__file__).parent;revision=json.loads((out/'source-correction.json').read_bytes())
fp=implementation_sha256();assert fp in (revision['before_implementation_sha256'],revision['after_implementation_sha256'])
fixture=cases.CampaignDerivationTests('test_borrowed_bundle_keeps_its_own_client_occurrence');fixture.setUp()
try:
    case=fixture._round(borrowed_client='client02');assert case._verify()['status']=='verified'
    rejected=next(r for r in case._manifest()['core']['dispositions'] if r['client_id']=='client02')
    assert rejected['kind']=='protocol_rejection'
    fixture._create();radius=fixture._blast(case,client='client02');assert radius['status']=='verified'
    nodes=[r for r in radius['reachable'] if r['kind'] in ('checkpoint','checkpoint_model','round_scoring_state')]
    result={'implementation_sha256':fp,'full_source_round_verified':True,'intake_kind':rejected['kind'],
        'graph_verified':fixture._verify()['status']=='verified','rejected_origin_reaches_numeric_or_scoring_nodes':bool(nodes),
        'unexpected_node_kinds':sorted({n['kind'] for n in nodes}),
        'fixture_profile':'Real signatures/intake/round graph, simulated numerical backend; no TPM claim.'}
    phase='before' if fp==revision['before_implementation_sha256'] else 'after'
    assert bool(nodes)==(phase=='before')
    (out/f'borrowed-bundle-probe-{phase}.json').write_bytes(derived_json_bytes(result))
    print(json.dumps(result),flush=True)
finally:fixture.doCleanups()
