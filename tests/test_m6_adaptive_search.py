import importlib.util
from pathlib import Path
import numpy as np

spec=importlib.util.spec_from_file_location("adaptive",Path(__file__).resolve().parents[1]/"scripts/run_m6_adaptive_frozen.py")
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def test_projection_bounds_all_tensor_perturbations():
    original=[np.zeros((2,2),dtype=np.float32),np.zeros(2,dtype=np.float32)]
    candidate=[np.ones((2,2),dtype=np.float32)*10,np.ones(2,dtype=np.float32)*10]
    projected=module.project_arrays(candidate,original,2.)
    assert np.isclose(np.sqrt(sum((x*x).sum() for x in projected)),2.)
    assert all(x.dtype==np.float32 for x in projected)
    assert all(np.array_equal(x,y) for x,y in zip(module.project_arrays(original,original,2.),original))

def test_selection_requires_admission_and_excludes_controls():
    q=[dict(query=0,kind="clean_control",feasible=True,targeted_asr=.9,targeted_loss=.1),dict(query=1,kind="adaptive",feasible=False,targeted_asr=1.,targeted_loss=0.),dict(query=2,kind="adaptive",feasible=True,targeted_asr=.3,targeted_loss=1.),dict(query=3,kind="adaptive",feasible=True,targeted_asr=.3,targeted_loss=.8),dict(query=4,kind="adaptive",feasible=True,targeted_asr=.3,targeted_loss=.8)]
    assert module.selected_query(q)["query"]==3
    assert module.selected_query(q[:2]) is None
