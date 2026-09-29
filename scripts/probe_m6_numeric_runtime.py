"""Unsigned diagnostic replay of one clean client; no test access or evidence edits."""
import hashlib,json,argparse
from pathlib import Path
from fl_forensics.secure_round import _model_from_export
from fl_forensics.federated_model import dependencies,train_local,export_state
from fl_forensics.preprocessing import derived_json_bytes
parser=argparse.ArgumentParser();parser.add_argument("--client",required=True);parser.add_argument("--round",type=int,required=True);args=parser.parse_args()
root=Path("/study")
source=root/"artifacts/m6-adaptive-paired-s341593-v3/clean/rounds"/f"round-{args.round:03d}"
partition=root/"artifacts/m3-data24-parquet-iid-local-test-v1/clients"/args.client
read=lambda p:json.loads(p.read_text())
base=read(source/"public/base-model.json");contract=read(source/"public/training-contract.json");context=read(source/"public/round-context.json")["core"]
snapshot=read(partition/"dataset.json");manifest=read(partition/"manifest.json")
np,torch,_,_,_,accuracy,confusion,precision=dependencies()
assert torch.get_num_threads()==torch.get_num_interop_threads()==1
model=_model_from_export(base,torch=torch,np=np)
train_local(model=model,rows=snapshot["rows"]["train"],class_names=contract["class_names"],
    class_weights={k:float(v) for k,v in contract["global_class_weights"].items()},
    epochs=context["local_epochs"],batch_size=context["batch_size"],learning_rate=float(context["learning_rate_decimal"]),
    seed=context["seed"]+context["round_number"]*10000+int(manifest["partition_id"]),device_name="cpu",torch=torch,np=np,
    validation_rows=snapshot["rows"].get("validation",[]),evaluation_functions=(accuracy,confusion,precision),record_history=True)
export=export_state(model,architecture=base["architecture"],class_names=base["class_names"])
print(json.dumps({"diagnostic_only":True,"client":args.client,"round":args.round,"threads":torch.get_num_threads(),"interop_threads":torch.get_num_interop_threads(),
    "update_sha256":hashlib.sha256(derived_json_bytes(export)).hexdigest(),"test_data_accessed":False}))
