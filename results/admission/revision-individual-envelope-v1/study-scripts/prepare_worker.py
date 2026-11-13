from pathlib import Path
out=Path(__file__).parent
source=(out.parent/'current-evidence-policy-20261103/policy_worker.py').read_text()
prefix=source[:source.index('for line in sys.stdin:')]
prefix=prefix.replace('from fl_forensics.current_evidence_policy import CurrentEvidencePolicy',
    'from fl_forensics.current_evidence_policy import CurrentEvidencePolicy\nfrom fl_forensics.client_envelope_policy import ClientEnvelopePolicy')
body='''for line in sys.stdin:
    try:
        request=json.loads(line)
        allowed={'op','request_id','cohort','observation_sha256','stream','round','previous','masses','mandatory_gate','policy_variant'}
        if set(request)-allowed:raise ValueError('unexpected request fields')
        op=request['op']
        if op=='stop':emit({'stopped':True});break
        if op!='step':raise ValueError('this reserved worker accepts only current-round steps')
        scored=score(request)
        if len(scored['frame_ids'])!=1:raise ValueError('one current frame required')
        stream=request['stream'];cohort=request['cohort'];variant=request['policy_variant']
        if variant not in ('prior','envelope'):raise ValueError('unknown algorithm variant')
        if stream not in sessions:
            calibration=read(Path('/policy')/f'{cohort}.json');binding=read(Path('/policy/closure.json'))
            envelope=read(Path('/policy')/f'{cohort}-envelope.json');eb=read(Path('/policy/envelope-closure.json'))
            assert binding['model_closure_sha256']==eb['model_closure_sha256']==model_pin
            assert sha(Path('/policy')/f'{cohort}.json')==binding['files'][f'{cohort}.json']
            assert sha(Path('/policy')/f'{cohort}-envelope.json')==eb['files'][f'{cohort}-envelope.json']
            sessions[stream]=(cohort,variant,{
                'prior':CurrentEvidencePolicy(calibration,minimum_contributors=8),
                'envelope':ClientEnvelopePolicy(calibration,envelope,minimum_contributors=8)})
        bound_cohort,bound_variant,policies=sessions[stream]
        if (cohort,variant)!=(bound_cohort,bound_variant):raise ValueError('stream binding changed')
        selected=policies[variant]
        expected=selected._last_previous if request['round']==selected.round else selected.head
        if request['previous']!=expected:raise ValueError('trusted action predecessor mismatch')
        old=policies['prior'].cal;envelope=policies['envelope'].envelope
        supported=all(scored['state_distances'][v][0]<=min(old['state_support_limits'][v],envelope['state_support_limits'][v])*(1+1e-12)+1e-12 for v in ('conditioned','state-disabled'))
        decisions={}
        for name,policy in policies.items():
            decisions[name]=policy.step(request['round'],{v:values[0] for v,values in scored['risk'].items()},
                context_supported=supported,mandatory_gate=request['mandatory_gate'],masses=request['masses'],
                expected_previous_digest=policy._last_previous if request['round']==policy.round else policy.head,
                source_observation_sha256=request['observation_sha256'])
        emit({'request_id':request['request_id'],'decision':decisions[variant],
            'comparison_decisions':decisions,'scored':scored})
    except Exception as exc:
        emit({'error':type(exc).__name__+': '+str(exc)});raise
'''
(out/'policy_worker.py').write_text(prefix+body)
print('THREE-TRAJECTORY WORKER PREPARED')
