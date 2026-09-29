"""Independent container repetitions before the next paired experiment."""
import hashlib,json,subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
ROOT=Path(__file__).resolve().parents[1]
IMAGE="flforensics-m6-adaptive-live-v1:latest"
IMAGE_ID="sha256:c5fdc9897569c01651e5af83be32f10bd63ff53d8a3288fe2391544a7cc9e1f0"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    output=ROOT/"results/m6-numeric-runtime-preflight-v1";output.mkdir(exist_ok=False)
    actual=subprocess.check_output(["docker","image","inspect",IMAGE,"--format","{{.Id}}"],text=True).strip()
    if actual!=IMAGE_ID:raise ValueError("Runtime image changed")
    cases=[(1,f"client{i:02d}") for i in range(1,16)]+[(10,c) for c in ["client01","client02","client15"]]
    tasks=[(round_number,client,repeat) for round_number,client in cases for repeat in [1,2]]
    def probe(task):
        number,client,repeat=task
        cmd=["docker","run","--rm","--network","none","--entrypoint","python","-v",str(ROOT)+":/study:ro",IMAGE,
            "/study/scripts/m6_numeric_runtime.py","script","/study/scripts/probe_m6_numeric_runtime.py","--client",client,"--round",str(number)]
        result=subprocess.run(cmd,capture_output=True,text=True,check=True)
        value=json.loads(result.stdout.strip().splitlines()[-1]);value["repeat"]=repeat
        path=output/f"round-{number:03d}-{client}-repeat-{repeat}.json"
        path.write_text(json.dumps(value,indent=2)+"\n")
        print(f"PROBE round={number} client={client} repeat={repeat} hash={value['update_sha256']}",flush=True)
        return value
    with ThreadPoolExecutor(max_workers=2) as pool:records=list(pool.map(probe,tasks))
    for number,client in cases:
        results=[v for v in records if v["round"]==number and v["client"]==client]
        if len({v["update_sha256"] for v in results})!=1:raise ValueError(f"Reproducibility mismatch: {number} {client}")
    files=[ROOT/"scripts/m6_numeric_runtime.py",ROOT/"scripts/probe_m6_numeric_runtime.py",Path(__file__)]
    summary={"status":"verified","runtime_image_id":IMAGE_ID,"case_count":len(cases),"independent_containers":len(records),
        "test_data_accessed":False,"code":{str(p.relative_to(ROOT)):sha(p) for p in files},
        "limitation":"Finite preflight, not a guarantee for all rounds; strict paired checkpoint equality remains enforced."}
    (output/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
    print(json.dumps(summary),flush=True)
if __name__=="__main__":main()
