"""Independently rebuild deterministic, bounded source windows with the original function."""
from pathlib import Path
from collections import defaultdict
import csv,hashlib,io,json,zipfile
from fl_forensics.preprocessing import build_window_row
from fl_forensics.ton_iot import normalize_network_record

O=Path(__file__).resolve().parent
OLD=O.parent/'ton-iot-official-20261108'

def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def main():
    dataset=json.loads((O/'windows/occurrence-windows.json').read_text())
    audit=json.loads((OLD/'feature-preflight-v2/collection-preflight.json').read_text())
    index=json.loads((OLD/'collection-complete.json').read_text())
    selected={}
    for day in sorted({r['capture_id'] for r in dataset['rows']}):
        choices=[r for r in dataset['rows'] if r['capture_id']==day and r['source_record_count']<=500]
        if choices:
            row=min(choices,key=lambda r:hashlib.sha256(r['window_id'].encode()).hexdigest());selected[row['window_start_epoch']//60]=row
    boundaries=sorted([r for r in dataset['rows'] if len(r['source_file_counts'])>1 and r['source_record_count']<=50000],key=lambda r:r['source_record_count'])[:2]
    for row in boundaries:selected[row['window_start_epoch']//60]=row
    assert selected and sum(r['source_record_count'] for r in selected.values())<=105000
    plan=dict(selection='One deterministic hashed small window per observed day, plus two smallest bounded file-boundary windows.',
              selected_buckets=sorted(selected),expected_records=sum(r['source_record_count'] for r in selected.values()),
              occurrence_dataset_sha256=sha(O/'windows/occurrence-windows.json'),verifier_sha256=sha(Path(__file__)))
    with (O/'source-window-verification-plan.json').open('x') as f:json.dump(plan,f,indent=2)
    needed={source for r in selected.values() for source in r['source_file_counts']}
    reject={f['name']:{r['record_number'] for r in f['rejected_occurrences_first10000']} for f in audit['source_files']}
    events=defaultdict(list)
    def native(value):
        value=value.replace('\\','/')
        return Path('/mnt/'+value[0].lower()+value[2:]) if len(value)>2 and value[1]==':' else Path(value)
    for entry in index['files']:
        if entry['name'] not in needed:continue
        if entry['storage']=='zip_entry':
            archive=zipfile.ZipFile(native(entry['archive_path']));raw=archive.open(entry['archive_entry'])
        else:archive=None;raw=native(entry['path']).open('rb')
        with raw,io.TextIOWrapper(raw,encoding='utf-8-sig',newline='') as f:
            for number,row in enumerate(csv.DictReader(f),1):
                if number in reject[entry['name']]:continue
                bucket=int(float(row['ts']))//60
                if bucket in selected:
                    events[bucket].append(normalize_network_record(row,source_sha256=entry['sha256'],source_name=entry['name'],record_number=number))
        if archive:archive.close()
    checked=[]
    for bucket,expected in selected.items():
        actual,_=build_window_row(events=events[bucket],capture_id=expected['capture_id'],bucket=bucket,window_seconds=60,
                                  client_id='toniot-independent-source-check',benign_labels={'benign'},mixed_attack_label=None,
                                  split_seed=0,split_percentages={'train':0,'validation':0,'test':100})
        assert actual['features']==expected['features'],bucket
        assert actual['label']==expected['label'] and len(events[bucket])==expected['source_record_count']
        checked.append(dict(bucket=bucket,source_records=len(events[bucket]),source_files=len(expected['source_file_counts']),all_25_features_identical=True,binary_label_identical=True))
    result=dict(status='verified',checked_windows=len(checked),checked_source_records=sum(r['source_records'] for r in checked),
                actual_cross_file_windows_checked=sum(r['source_files']>1 for r in checked),checks=checked,
                original_window_function_sha256=sha(Path(build_window_row.__code__.co_filename)),full_source_rebuild=False,
                qualification='Deterministic bounded source spot-check plus full input hash/count accounting; not a full independent second derivation.')
    (O/'source-window-verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2),flush=True)


if __name__=='__main__':main()
