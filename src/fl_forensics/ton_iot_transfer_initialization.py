"""Copy a compatible source encoder while preserving a new binary head."""

import numpy as np


def initialize_target_encoder(source_arrays, target_arrays):
    source = [np.asarray(v, dtype=np.float32) for v in source_arrays]
    target = [np.asarray(v, dtype=np.float32) for v in target_arrays]
    if len(source) != 8 or len(target) != 8:
        raise ValueError("Expected three encoder affine layers and one classification head")
    if any(not np.isfinite(v).all() for v in source + target):
        raise ValueError("Finite model tensors required")
    for index in range(6):
        if source[index].shape != target[index].shape:
            raise ValueError("Encoder shape mismatch")
    if target[-2].ndim != 2 or target[-2].shape[0] != 2 or target[-1].shape != (2,):
        raise ValueError("A new two-output target head is required")
    if source[-2].ndim != 2 or source[-2].shape[1] != target[-2].shape[1]:
        raise ValueError("Source and target embedding widths differ")
    if source[-1].shape != (source[-2].shape[0],):
        raise ValueError("Invalid source classification head")
    return [v.copy() for v in source[:6]] + [v.copy() for v in target[-2:]]
