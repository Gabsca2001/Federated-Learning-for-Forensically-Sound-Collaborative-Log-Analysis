"""Publish source-bound descriptive results of the frozen adaptive pilot."""
import csv
import hashlib
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
ROOT = Path(__file__).resolve().parents[1]
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    source=ROOT/"artifacts/m6-adaptive-frozen-pilot-v1"
    output=ROOT/"results/m6-adaptive-frozen-pilot-v1"
    summary=json.loads((source/"summary.json").read_text())
    queries=[json.loads(p.read_text()) for p in sorted(source.glob("queries/*/decision.json"))]
    if len(queries)!=summary["query_count"]: raise ValueError("Incomplete query inventory")
    selected=queries[summary["selected_query"]]
    if not selected["feasible"] or selected["targeted_asr"]!=summary["selected_targeted_asr"]: raise ValueError("Inconsistent selection")
    output.mkdir(exist_ok=False)
    fields=["query","kind","parent_query","radius","step","feasible","contributor_count","targeted_asr","targeted_loss","validation_macro_f1","validation_drop"]
    with (output/"queries.csv").open("w",newline="") as stream:
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader()
        writer.writerows({k:q[k] for k in fields} for q in queries)
    adaptive=[q for q in queries if q["kind"]=="adaptive"]
    result=dict(summary,adaptive_feasible_count=sum(q["feasible"] for q in adaptive),adaptive_attempt_count=len(adaptive))
    (output/"summary.json").write_text(json.dumps(result,indent=2)+"\n")
    fig,axes=plt.subplots(3,1,figsize=(10,9),sharex=True)
    for feasible,color,label in [(True,"#167d8d","All attackers contribute"),(False,"#b14545","Feasibility failed")]:
        subset=[q for q in queries if q["feasible"]==feasible]
        for ax,key in zip(axes,["targeted_asr","targeted_loss","validation_drop"]):
            ax.scatter([q["query"]+1 for q in subset],[q[key] for q in subset],s=25,c=color,label=label)
    axes[0].axhline(summary["baseline_targeted_asr"]+.1,color="black",ls="--",label="Declared ASR success threshold")
    for ax in axes:
        ax.axvline(selected["query"]+1,color="#c88b00",ls=":")
        ax.grid(alpha=.2)
    axes[0].set_ylabel("Targeted ASR");axes[0].legend(fontsize=8)
    axes[1].set_ylabel("Target cross-entropy")
    axes[2].set_ylabel("Macro-F1 decrease");axes[2].set_xlabel("Query number (1-based; first two are controls)")
    fig.suptitle("Frozen adaptive search: validation optimization only")
    fig.tight_layout()
    for ext in ["png","pdf"]:fig.savefig(output/f"query-outcomes.{ext}",dpi=170)
    plt.close(fig)
    text=f"""# Frozen adaptive attack pilot — observed result

The declared targeted objective was not achieved: reconnaissance-to-benign ASR
remained {summary['selected_targeted_asr']:.3f}, with an absolute gain of
{summary['selected_asr_gain']:.3f} against the clean control. This is a negative result
for this finite search, not evidence that all adaptive attacks fail.

The search evaluated {len(adaptive)} adaptive proposals and two controls.
{result['adaptive_feasible_count']} adaptive proposals retained all three attackers
and the required contributor count. The selected query is {selected['query']+1}
(one-based; artifact index {selected['query']}). Selection followed the predeclared
ASR, then target cross-entropy, then earliest-query rule; it did not maximize F1 loss.
Its pooled validation macro-F1 was {selected['validation_macro_f1']:.6f}, versus
{summary['baseline_validation_macro_f1']:.6f} for the clean aggregate: a decrease of
{100*summary['selected_validation_drop']:.3f} percentage points. Admission therefore
does not imply the targeted attack succeeded, and ASR failure does not imply zero damage.

## Interpretation and limits

All optimization feedback comes from the same privileged validation oracle used by
the gate. No test or temporal holdout is accessed. There is one seed and one frozen
round, no independent generalization estimate and no live model trajectory.
Candidate tensors are derived experimental artifacts, not newly TPM-signed updates.
The original signatures remain attached only to the original source submissions.
The fixed sign-flip control failed the feasibility condition.

The figure shows all attempts, including rejected ones. Its vertical dotted line
marks selection; the horizontal dashed line marks the predeclared targeted success
threshold. The loss plot explains the tie-break when ASR stays unchanged.

## Reproduction

Run `python scripts/run_m6_adaptive_frozen.py verify` for byte-for-byte search
recomputation. This report checks inventory and selection consistency; it is not a
substitute for that verifier. `report-manifest.json` binds every input decision,
the experiment summary, reporting code and published files by SHA-256.
The next experiment must separately bind live proposals, adaptive selection and
new client signatures before aggregation, using fresh evidence directories.
"""
    (output/"README.md").write_text(text)
    inputs=[source/"summary.json",*sorted(source.glob("queries/*/decision.json")),Path(__file__)]
    manifest={"inputs":{str(p.relative_to(ROOT)):sha(p) for p in inputs},"outputs":{p.name:sha(p) for p in output.iterdir() if p.is_file()}}
    (output/"report-manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(json.dumps({"status":"reported","output":str(output),"adaptive_feasible_count":result["adaptive_feasible_count"],"selected_query_index":selected["query"]}))
if __name__=="__main__": main()
