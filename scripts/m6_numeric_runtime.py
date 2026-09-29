"""Explicit CPU numerical runtime; configure before importing numerical libraries."""
import os
import runpy
import sys
SETTINGS={"OMP_NUM_THREADS":"1","MKL_NUM_THREADS":"1","OPENBLAS_NUM_THREADS":"1","NUMEXPR_NUM_THREADS":"1","MKL_CBWR":"COMPATIBLE"}
def configure():
    for key,value in SETTINGS.items():os.environ[key]=value
    import torch
    torch.set_num_threads(1)
    torch.set_num_interop_threads(1)
    os.environ["M6_NUMERIC_RUNTIME"]="single-thread-compatible-v1"
def main():
    if len(sys.argv)<3 or sys.argv[1] not in ["module","script"]:raise SystemExit("usage: numeric_runtime.py module|script target [args]")
    mode,target=sys.argv[1:3];sys.argv=[target,*sys.argv[3:]]
    configure()
    if mode=="module":runpy.run_module(target,run_name="__main__",alter_sys=True)
    else:
        from pathlib import Path
        sys.path.insert(0,str(Path(target).resolve().parent))
        runpy.run_path(target,run_name="__main__")
if __name__=="__main__":main()
