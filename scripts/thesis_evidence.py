"""Check the retained evidence listed in docs/thesis-evidence.txt.

For every listed path (globs allowed) the check confirms that it exists. Studies
registered with a flat checksum index are additionally verified through
repository_audit.py; other studies are reported as authenticated by their own
profile verifier. Nothing is retrained, re-signed or written.
"""
from __future__ import annotations

import argparse
import glob
import json
import subprocess
import sys
from pathlib import Path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--list', type=Path, default=None)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    listing = args.list or root / 'docs/thesis-evidence.txt'
    mapping = json.loads((root / 'docs/documentation-map.json').read_text(encoding='utf-8'))
    flat = {s['path'] for s in mapping['studies'] if s['flat_checksum_index']}
    failures = 0
    for line in listing.read_text(encoding='utf-8').splitlines():
        entry = line.split('#', 1)[0].strip()
        if not entry:
            continue
        matches = sorted(glob.glob(str(root / entry)))
        if not matches:
            print(f'MISSING   {entry}')
            failures += 1
            continue
        for match in matches:
            rel = str(Path(match).relative_to(root))
            if rel in flat:
                result = subprocess.run(
                    [sys.executable, str(root / 'scripts/repository_audit.py'), 'evidence', '--study', rel,
                     '--root', str(root)], capture_output=True, text=True)
                status = 'CHECKSUM  ' if result.returncode == 0 else 'FAILED    '
                failures += result.returncode != 0
            else:
                status = 'PRESENT   '
            print(f'{status}{rel}')
    print(f'\n{failures} problem(s). PRESENT entries rely on their own profile verifier.')
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
