"""Post-test descriptive feature-collision and repeated-error audit; no fitting."""
from pathlib import Path
from collections import Counter,defaultdict
import hashlib,json
import numpy as np
O=Path(__file__).resolve().parent;W=O/'study';T=O.parent/'ton-iot-transfer-20261109'
dataset=json.loads((T/'windows/occurrence-windows.json').read_text())
splits=json.loads((W/'split-and-partition.json').read_text())['splits']
by_bucket={r['window_start_epoch']//60:r for r in dataset['rows']}
split_by_bucket={bucket:name for name,record in splits.items() for bucket in record['buckets']}
groups=defaultdict(list)
for row in dataset['rows']:
    if split_by_bucket[row['window_start_epoch']//60]=='embargo':continue
    groups[tuple(row['features'])].append(row)
mixed=[rows for rows in groups.values() if len({r['label'] for r in rows})>1]
test_rows=[by_bucket[b] for b in splits['test']['buckets']]
fp_sets=[];fn_sets=[]
for seed in (341593,342593,343593):
    with np.load(W/'runs'/f'occurrence-target-standard-s{seed}'/'test-predictions.npz',allow_pickle=False) as data:
        y,pred=data['actual'],data['predicted']
        assert len(y)==len(test_rows)
        fp_sets.append(set(np.flatnonzero((y==0)&(pred==1)).tolist()))
        fn_sets.append(set(np.flatnonzero((y==1)&(pred==0)).tolist()))
examples=[]
for index in sorted(set.union(*fp_sets)):
    row=test_rows[index];equal=groups[tuple(row['features'])]
    examples.append(dict(bucket=row['window_start_epoch']//60,capture_id=row['capture_id'],source_records=row['source_record_count'],
                         feature_vector_sha256=hashlib.sha256(np.asarray(row['features'],dtype='<f8').tobytes()).hexdigest(),
                         same_feature_vector_labels=dict(Counter(r['label'] for r in equal)),
                         same_feature_vector_training_labels=dict(Counter(r['label'] for r in equal if split_by_bucket[r['window_start_epoch']//60]=='train')),
                         false_positive_in_seed_count=sum(index in values for values in fp_sets)))
test_groups=defaultdict(Counter)
for row in test_rows:test_groups[tuple(row['features'])][row['label']]+=1
report=dict(scope='Exploratory post-test diagnosis; no weights, transforms, thresholds or selections changed.',
            primary_false_positive_counts=[len(s) for s in fp_sets],false_positives_shared_by_all_seeds=len(set.intersection(*fp_sets)),
            primary_false_negative_counts=[len(s) for s in fn_sets],false_negatives_shared_by_all_seeds=len(set.intersection(*fn_sets)),
            exact_25_feature_groups_with_conflicting_observed_binary_labels=len(mixed),
            non_embargo_windows_in_conflicting_feature_groups=sum(len(rows) for rows in mixed),
            empirical_minimum_errors_for_one_deterministic_feature_only_rule_on_combined_observed_rows=sum(min(Counter(r['label'] for r in rows).values()) for rows in mixed),
            empirical_test_only_feature_collision_error_bound=sum(min(counts.values()) for counts in test_groups.values() if len(counts)>1),
            false_positive_feature_examples=examples,
            interpretation='An identical feature vector with different observed labels prevents perfect separation of those observations by a deterministic rule using only these features. This does not prove that any particular false positive is unavoidable or give a population error bound.')
(W/'error-audit.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='false_positive_feature_examples'},indent=2))
