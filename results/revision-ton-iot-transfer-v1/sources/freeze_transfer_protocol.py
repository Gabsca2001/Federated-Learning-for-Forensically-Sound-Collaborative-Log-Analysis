"""Pin the locally available validation-selected Data24 model before ToN inference."""
from pathlib import Path
import datetime as dt,hashlib,json,shutil
from fl_forensics.secure_campaign import verify_secure_campaign
from fl_forensics.preprocessing import FEATURE_NAMES

R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
O=Path(__file__).resolve().parent
C=R/'artifacts/m5-secure-multiround-local-test-v1'
P=R/'artifacts/m3-data24-parquet-iid-local-test-v1'
D=R/'artifacts/m2-data24-parquet'
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
campaign=json.loads((C/'campaign-manifest.json').read_bytes());core=campaign['core']
partition=json.loads((P/'manifest.json').read_bytes())
model=C/'rounds'/f'round-{core["selected_round"]:03d}'/'checkpoint/global-model.json'
assert sha(model)==core['selected_model_sha256']
assert sha(P/'manifest.json')==core['partition_manifest_sha256']
assert sha(D/'scaler.json')==partition['source_m2_scaler_sha256']
assert json.loads((D/'scaler.json').read_bytes())['feature_names']==FEATURE_NAMES
verified=verify_secure_campaign(workspace=C,trust_workspace=R/'artifacts/m4-trust-local-test-v1',
                                partition_manifest_path=P/'manifest.json',server_evaluation_path=P/partition['server_evaluation_path'])
(O/'reference-campaign-verification.json').write_text(json.dumps(verified,indent=2)+'\n')
assert verified['status']=='verified',verified
for path,name in [(model,'frozen-model.json'),(D/'scaler.json','frozen-scaler.json')]:shutil.copyfile(path,O/name)
old=O.parent/'ton-iot-official-20261108'
protocol=dict(protocol='frozen-Data24-ToN-IoT-transfer-v1',created_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
               source_index_path=str(old/'collection-complete.json'),source_index_sha256=sha(old/'collection-complete.json'),
               preflight_path=str(old/'feature-preflight-v2/collection-preflight.json'),preflight_sha256=sha(old/'feature-preflight-v2/collection-preflight.json'),
               selected_round=core['selected_round'],selected_model_sha256=sha(model),scaler_sha256=sha(D/'scaler.json'),
               campaign_manifest_sha256=sha(C/'campaign-manifest.json'),partition_manifest_sha256=sha(P/'manifest.json'),
               reference_campaign_verified=True,selection_scope='Existing Data24 validation maximum macro-F1, earliest round on ties; no ToN-IoT selection.',
               primary='All valid official CSV occurrences; no inferred physical-connection deduplication.',
               sensitivity='One earliest occurrence per exact common non-label projection, excluding uid, with binary label union; no physical identity claim.',
               reject_policy='The 869 source-bound measurement/address-invalid occurrences identified by the complete preflight.',
               group_policy='Globally merge all CSVs by UTC day and floor(ts/60), never split by file or source IP.',
               window_label='attack if at least one retained constituent is attack, otherwise benign',
               binary_prediction='argmax over frozen six-class logits, then benign vs all other classes; not a new 0.5 threshold.',
               score_diagnostics='1 minus benign softmax probability for threshold-free AUROC/AP diagnostics only; primary decisions remain argmax collapse.',
               metrics=['confusion matrix','balanced accuracy','attack precision/recall/F1','benign specificity/FPR','AUROC','average precision','feature shift','per-day support'],
               comparison_policy='Report primary and duplicate sensitivity unconditionally; never choose the better external result.',
               previous_Data22_published_model_sha256='007e3fafd35f292eb72cc4c42c1f05b51210f90637af7da9b345d1e45a123e6e',
               same_checkpoint_as_old_Data22_publication=sha(model)=='007e3fafd35f292eb72cc4c42c1f05b51210f90637af7da9b345d1e45a123e6e',
               preparation_driver_sha256=sha(O/'prepare_ton_iot_windows.py'),window_module_sha256=sha(O/'ton_iot_windows.py'),
               storage_budget='Temporary duplicate index below 1.1 GB plus compact windows; preserve six GiB free. No CSV extraction or new raw copies.',
               ToN_IoT_training_performed=False,manuscript_changed=False)
target=O/'protocol-before-source-processing.json'
with target.open('x') as stream:json.dump(protocol,stream,indent=2);stream.write('\n')
print(json.dumps({k:v for k,v in protocol.items() if k.endswith('sha256') or k in ('selected_round','same_checkpoint_as_old_Data22_publication')},indent=2),flush=True)
