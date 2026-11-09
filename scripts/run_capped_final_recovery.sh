#!/usr/bin/env bash
set -euo pipefail
cd /home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis
exec .venv/bin/python -u scripts/revision_capped_final_study.py pipeline --workers 2 > revision-capped-final-v1-retry-1.log 2>&1
