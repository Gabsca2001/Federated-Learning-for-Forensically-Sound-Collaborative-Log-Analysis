"""Prepare source-host/minute windows from the entire verified official release."""
from pathlib import Path
from collections import Counter,defaultdict
import datetime as dt,gzip,hashlib,importlib.util,io,json,shutil,zipfile,sys
import numpy as np
import pyarrow as pa
import pyarrow.csv as pacsv
import pyarrow.compute as pc
from host_windows import HostAccumulator,canonical_host
from fl_forensics.ton_iot_windows import WindowAccumulator

O=Path(__file__).resolve().parent;ROOT=O.parent
I=ROOT/'ton-iot-official-20261108/collection-complete.json'
F=ROOT/'ton-iot-official-20261108/feature-preflight-v2/collection-preflight.json'
P=ROOT/'ton-iot-transfer-20261109'
D=O/'windows'
FIELDS=('ts','src_ip','dst_ip','dst_port','proto','service','duration','src_bytes','dst_bytes','conn_state','src_pkts','dst_pkts','label','type')
FLOATS={'ts','duration'};INTEGERS={'dst_port','src_bytes','dst_bytes','src_pkts','dst_pkts','label'}
def load(p):return json.loads(p.read_text())
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def save(p,v):
    with p.open('x') as f:json.dump(v,f,indent=2,allow_nan=False);f.write('\n')
def progress(v):
    with (O/'source-progress.jsonl').open('a') as f:f.write(json.dumps(v)+'\n')
    print(json.dumps(v),flush=True)
def main():
    assert not D.exists();assert shutil.disk_usage(O).free>=6*1024**3;D.mkdir()
    index=load(I);preflight=load(F);old_protocol=load(P/'protocol-before-source-processing.json')
    assert sha(I)==old_protocol['source_index_sha256'] and sha(F)==old_protocol['preflight_sha256']
    spec=importlib.util.spec_from_file_location('reader',P/'revision_ton_iot_collection_preflight.py');reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
    protocol=dict(name='ToN-IoT-source-host-minute-representation-v1',created_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
        source_index_sha256=sha(I),preflight_sha256=sha(F),source_profile='Every valid official CSV occurrence; no physical-flow deduplication claim.',
        grouping='Canonical source IP and UTC minute, globally across all 23 source files; address is aggregation metadata only.',
        features='Same 25 original aggregates, computed separately per source host; any constituent attack labels its host/minute attacked.',
        reject_policy='Exactly the source-bound measurement/address-invalid occurrences identified in the complete preflight; all category conventions unchanged.',
        duplicate_boundary='Primary occurrence view only; exact-projection sensitivity from earlier global studies does not validate this new grouping.',
        split_intention='Use the unchanged corrected chronological parent minute inventories (6061 train,1080 validation,718 test), assigning all hosts of a minute together.',
        model_plan='Before fitting: fixed 30 rounds,15 numerical IID clients,2 local epochs,batch256,Adam .001,MLP128/64/32; training cap30000 units per profile chosen from training only; three seeds,log1p scaler fitted on train; global-minute control and host-minute models, selected on common pooled validation macro-F1.',
        common_evaluation='Max host score and any host true attack reconstruct the original global minute; report host-level and common-minute metrics separately.',
        source_driver_sha256=sha(Path(__file__)),host_module_sha256=sha(O/'host_windows.py'),old_window_module_sha256=sha(Path(WindowAccumulator.add.__code__.co_filename)),
        storage='No raw copies or new duplicate index; compact host aggregates, metadata and at most selected model tensors; preserve at least six GiB free.',
        limitations='New representation, not unchanged Data24 model transfer; dates already examined, exploratory chronological assessment; no host-disjoint/TPM/Byzantine claim.')
    save(O/'protocol-before-source-processing.json',protocol)
    reports={r['name']:r for r in preflight['source_files']};windows={};archives={};host_cache={};ordinal=0;accepted=0;source_counts={}
    try:
        for entry in index['files']:
            report=reports[entry['name']];assert not report['rejection_detail_truncated'];rejected=np.asarray([r['record_number'] for r in report['rejected_occurrences_first10000']],dtype=np.int64)
            if entry['storage']=='zip_entry':
                path=reader.native_path(entry,'archive_path')
                if path not in archives:archives[path]=zipfile.ZipFile(path)
                raw=archives[path].open(entry['archive_entry'])
            else:raw=reader.native_path(entry,'path').open('rb')
            hashed=reader.DigestReader(raw);buffer=io.BufferedReader(hashed,buffer_size=1024*1024)
            arrow=pacsv.open_csv(buffer,read_options=pacsv.ReadOptions(block_size=4*1024*1024,use_threads=False),
                parse_options=pacsv.ParseOptions(newlines_in_values=True),
                convert_options=pacsv.ConvertOptions(include_columns=list(FIELDS),column_types={name:pa.string() for name in FIELDS},null_values=[],strings_can_be_null=False))
            count=0;kept=0;next_progress=250000
            for batch in arrow:
                length=batch.num_rows;file_numbers=np.arange(count+1,count+length+1);ordinals=np.arange(ordinal,ordinal+length,dtype=np.int64)
                mask=~np.isin(file_numbers,rejected);count+=length;ordinal+=length
                if not mask.all():batch=batch.filter(pa.array(mask));ordinals=ordinals[mask]
                if not len(ordinals):continue
                cols={}
                for name in FIELDS:
                    values=pc.utf8_trim_whitespace(batch.column(batch.schema.get_field_index(name)))
                    if name in FLOATS or name in INTEGERS:
                        floats=pc.cast(values,pa.float64()).to_numpy(zero_copy_only=False)
                        cols[name]=floats.astype(np.int64) if name in INTEGERS else floats
                    else:cols[name]=values.to_numpy(zero_copy_only=False)
                buckets=np.floor(cols['ts']).astype(np.int64)//60
                hosts,codes=np.unique(cols['src_ip'],return_inverse=True)
                canonical=[]
                for host in hosts:
                    if host not in host_cache:host_cache[host]=canonical_host(host)
                    canonical.append(host_cache[host])
                canonical,canonical_codes=np.unique(np.asarray(canonical),return_inverse=True)
                codes=canonical_codes[codes]
                order=np.lexsort((ordinals,codes,buckets));bs=buckets[order];cs=codes[order]
                starts=np.r_[0,np.flatnonzero((bs[1:]!=bs[:-1])|(cs[1:]!=cs[:-1]))+1,len(order)]
                for left,right in zip(starts[:-1],starts[1:]):
                    ix=order[left:right];key=(int(bs[left]),canonical[int(cs[left])])
                    if key not in windows:windows[key]=HostAccumulator()
                    windows[key].add_block({name:values[ix] for name,values in cols.items() if name not in ('ts','src_ip')},ordinals[ix],entry['name'])
                accepted+=len(ordinals);kept+=len(ordinals)
                if count>=next_progress:
                    progress(dict(status='source_chunk',file=entry['name'],file_records=count,global_records=ordinal,host_windows=len(windows)))
                    next_progress=count+250000
            assert count==report['rows'];assert kept==report['usable_rows_under_explicit_category_policy']
            assert hashed.byte_count==entry['bytes'] and hashed.digest.hexdigest()==entry['sha256']
            arrow.close();buffer.close();raw.close();source_counts[entry['name']]=kept
            progress(dict(status='source_verified',file=entry['name'],global_records=ordinal,accepted=accepted,host_windows=len(windows),free_GiB=shutil.disk_usage(O).free/1024**3))
            assert shutil.disk_usage(O).free>=6*1024**3
        assert ordinal==preflight['scanned_rows'] and accepted==preflight['usable_rows_under_explicit_category_policy']
    finally:
        for archive in archives.values():archive.close()
    original=load(P/'windows/occurrence-windows.json');lookup={r['window_start_epoch']//60:r for r in original['rows']}
    by_minute=defaultdict(list)
    for (bucket,host),acc in windows.items():by_minute[bucket].append(acc)
    assert set(by_minute)==set(lookup)
    max_error=0.
    for bucket,accs in by_minute.items():
        merged=WindowAccumulator()
        for acc in accs:
            merged.durations.extend(acc.durations);merged.hosts.update(acc.hosts);merged.ports.update(acc.ports)
            for name in ('protocols','services','states','labels','types','sources'):getattr(merged,name).update(getattr(acc,name))
            merged.sums=[a+b for a,b in zip(merged.sums,acc.sums)]
        actual=merged.finish(bucket,profile='occurrence');expected=lookup[bucket]
        np.testing.assert_allclose(actual['features'],expected['features'],rtol=1e-10,atol=1e-10)
        assert actual['source_record_count']==expected['source_record_count'] and actual['label']==expected['label']
        assert actual['binary_record_counts']==expected['binary_record_counts'] and actual['source_type_counts']==expected['source_type_counts']
        max_error=max(max_error,float(np.max(np.abs(np.asarray(actual['features'])-expected['features']))))
    progress(dict(status='all_global_minutes_reconstructed',minutes=len(lookup),max_absolute_feature_error=max_error))
    rows=[];total_sources=Counter()
    with gzip.open(D/'host-window-lineage.jsonl.gz','wt',encoding='utf-8',compresslevel=6) as f:
        for (bucket,host),acc in sorted(windows.items()):
            row=acc.finish_host(host,bucket);total_sources.update(acc.sources)
            f.write(json.dumps(row,separators=(',',':'),allow_nan=False)+'\n');rows.append(row)
    assert dict(total_sources)==source_counts
    np.savez_compressed(D/'host-windows.npz',features=np.asarray([r['features'] for r in rows],float),
        actual=np.asarray([r['label']=='attack' for r in rows],dtype=np.int8),bucket=np.asarray([r['window_start_epoch']//60 for r in rows],dtype=np.int64),
        host=np.asarray([r['originator_host_sha256'] for r in rows]),record_count=np.asarray([r['source_record_count'] for r in rows]),
        attack_count=np.asarray([r['binary_record_counts'].get('1',0) for r in rows]),
        family=np.asarray(['benign' if r['label']=='benign' else min((-n,name) for name,n in r['source_type_counts'].items() if name!='normal')[1] for r in rows]))
    splits=load(ROOT/'ton-iot-retraining-20261109/study/split-and-partition.json')['splits'];keep=load(ROOT/'ton-iot-retraining-20261109/study/flow-end-selection-v2/protocol-before-reselection.json')['retained_validation_indices']
    split_buckets={role:set(splits[role]['buckets']) for role in ('train','validation','test')};split_buckets['validation']={splits['validation']['buckets'][i] for i in keep}
    support={}
    for role,buckets_set in split_buckets.items():
        selected=[r for r in rows if r['window_start_epoch']//60 in buckets_set]
        daily=defaultdict(Counter)
        for r in selected:daily[r['capture_id']][r['label']]+=1
        support[role]=dict(global_minutes=len(buckets_set),host_windows=len(selected),binary_counts=dict(Counter(r['label'] for r in selected)),daily_counts={day:dict(n) for day,n in sorted(daily.items())},
            attack_family_windows=dict(Counter(min((-n,name) for name,n in r['source_type_counts'].items() if name!='normal')[1] for r in selected if r['label']=='attack')))
    summary=dict(status='verified_host_windows_prepared',source_rows=ordinal,accepted_occurrences=accepted,rejected_occurrences=ordinal-accepted,
        host_windows=len(rows),unique_hosts=len({host for _,host in windows}),source_counts=source_counts,split_support=support,
        global_minutes_reconstructed=len(lookup),max_absolute_global_feature_error=max_error,
        protocol_sha256=sha(O/'protocol-before-source-processing.json'),host_matrix_sha256=sha(D/'host-windows.npz'),lineage_sha256=sha(D/'host-window-lineage.jsonl.gz'),
        duplicate_sensitivity_claimed=False,source_files_modified=False)
    save(D/'preparation-summary.json',summary)
    progress(dict(status='host_preparation_complete',summary=summary,free_GiB=shutil.disk_usage(O).free/1024**3))
if __name__=='__main__':main()
