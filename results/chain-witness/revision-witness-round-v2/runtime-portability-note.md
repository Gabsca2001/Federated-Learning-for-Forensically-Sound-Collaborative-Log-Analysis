# Exact numerical runtime boundary

The public package also verifies after relocation in the pinned CPU Docker
image. A host check outside that image differs in one raw statistical
indicator by one unit in the last place: 0.12465515702709776 versus
0.12465515702709777. The exact verifier rejects the changed reconstruction.
Host Torch is 2.14.0; the recorded CPU image is 2.14.0+cpu. This observation
does not attribute the last-bit difference solely to the version string.
The diagnostic is retained in host-runtime-diagnostic.json. Signed artifacts
and comparison rules are unchanged. Reproduce with the retained image/source
release; matching Python-source digests do not establish numerical equivalence
across arbitrary runtime builds, kernels, thread settings or hardware.
