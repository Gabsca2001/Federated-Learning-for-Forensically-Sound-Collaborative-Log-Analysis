"""Regression checks for maintained links, catalogues and evidence boundaries."""
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from repository_audit import audit, catalogues, check_evidence, link_findings


def base(tmp_path):
    (tmp_path / 'docs').mkdir()
    (tmp_path / 'results').mkdir()
    (tmp_path / 'README.md').write_text('# Framework\n')
    mapping = dict(reviewed='2026-11-08', maintained_pages=['README.md'],
                   generated_pages=['docs/REFERENCE_INDEX.md', 'results/CATALOG.md'],
                   references=[], studies=[], protected_markdown_sha256={})
    for rel, text in catalogues(mapping).items():
        (tmp_path / rel).write_text(text)
    # Fixture links resolve to representative maintained entry points.
    for rel in ('docs/README.md', 'docs/STATUS.md', 'results/README.md'):
        (tmp_path / rel).write_text('# Reference\n')
        mapping['maintained_pages'].append(rel)
    return mapping


def evidence(tmp_path, entries=None):
    directory = tmp_path / 'results/study'
    directory.mkdir(parents=True)
    (directory / 'report.md').write_text('retained result\n')
    records = entries or {'report.md': hashlib.sha256(b'retained result\n').hexdigest()}
    index = directory / 'file-checksums.json'
    index.write_text(json.dumps(records))
    return dict(studies=[dict(path='results/study', checksum_index_sha256=hashlib.sha256(index.read_bytes()).hexdigest())])


def test_documentation_check_rejects_broken_maintained_links(tmp_path):
    mapping = base(tmp_path)
    assert audit(tmp_path, mapping)['status'] == 'passed'
    (tmp_path / 'README.md').write_text('[Absent](docs/absent.md)\n')
    result = audit(tmp_path, mapping)
    assert any(e['kind'] == 'maintained_link' for e in result['errors'])


def test_heading_links_handle_duplicates_and_code_fences(tmp_path):
    page = tmp_path / 'page.md'
    page.write_text('# Results\n# Results\n[Second](#results-1)\n```text\n[Example](missing.md)\n```\n')
    assert link_findings(page) == []
    page.write_text(page.read_text() + '[Unknown](#absent)\n')
    assert link_findings(page)[0]['reason'] == 'local_heading_missing'


def test_new_reference_or_study_requires_registration(tmp_path):
    mapping = base(tmp_path)
    (tmp_path / 'docs/unregistered.md').write_text('# Unregistered\n')
    (tmp_path / 'results/new-study').mkdir()
    kinds = {x['kind'] for x in audit(tmp_path, mapping)['errors']}
    assert {'documentation_registration', 'study_registration'} <= kinds


def test_historical_reference_is_preserved_and_not_rewritten(tmp_path):
    mapping = base(tmp_path)
    old = tmp_path / 'docs/old.md'
    old.write_text('# Historical\n[Local resource](absent.md)\n')
    digest = hashlib.sha256(old.read_bytes()).hexdigest()
    mapping['references'] = [dict(path='docs/old.md', title='Historical', group='History')]
    mapping['protected_markdown_sha256'] = {'docs/old.md': digest}
    for rel, text in catalogues(mapping).items():
        (tmp_path / rel).write_text(text)
    result = audit(tmp_path, mapping)
    assert result['status'] == 'passed' and result['historical_local_link_findings']
    assert hashlib.sha256(old.read_bytes()).hexdigest() == digest
    old.write_text('# Rewritten\n')
    assert any(x['kind'] == 'retained_markdown_changed_or_missing' for x in audit(tmp_path, mapping)['errors'])


def test_evidence_check_detects_payload_and_index_changes(tmp_path):
    mapping = evidence(tmp_path)
    assert check_evidence(tmp_path, mapping, 'results/study')['status'] == 'passed'
    (tmp_path / 'results/study/report.md').write_text('changed\n')
    assert check_evidence(tmp_path, mapping, 'results/study')['failures'] == ['report.md']
    (tmp_path / 'results/study/file-checksums.json').write_text('{}')
    with pytest.raises(ValueError, match='differs'):
        check_evidence(tmp_path, mapping, 'results/study')


def test_evidence_check_rejects_paths_outside_selected_study(tmp_path):
    mapping = evidence(tmp_path, {'../../secret': '0' * 64})
    with pytest.raises(ValueError, match='escapes'):
        check_evidence(tmp_path, mapping, 'results/study')


def test_fast_check_retains_known_runtime_pages_and_full_scan_discovers_new_ones(tmp_path):
    mapping = base(tmp_path)
    old = tmp_path / 'artifacts/retained/report.md'
    old.parent.mkdir(parents=True)
    old.write_text('# Retained\n')
    mapping['protected_markdown_sha256'][str(old.relative_to(tmp_path))] = hashlib.sha256(old.read_bytes()).hexdigest()
    fresh = tmp_path / 'artifacts/new/report.md'
    fresh.parent.mkdir(parents=True)
    fresh.write_text('[Unretained local link](missing.md)\n')
    fast = audit(tmp_path, mapping)
    assert fast['status'] == 'passed' and not fast['runtime_scan_performed']
    assert not fast['historical_local_link_findings']
    full = audit(tmp_path, mapping, scan_runtime=True)
    assert full['runtime_scan_performed']
    assert any(x['path'] == 'artifacts/new/report.md' for x in full['historical_local_link_findings'])
    old.write_text('# Altered\n')
    assert any(x['kind'] == 'retained_markdown_changed_or_missing' for x in audit(tmp_path, mapping)['errors'])
