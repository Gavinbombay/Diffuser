#!/usr/bin/env python3
"""Offline RUN33 carry and close-out verification."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tools'))
from target_paths import target_dir
EXCLUDED = {'proof', 'token-sha', 'registry.json', 'specs', 'kit', 'stalled',
            '.git', '.aws', '.codex', '.agents', '__pycache__'}
LABELS = ('s1', 's2', 's3', 's4', 's5', 's6', 's8')
BASELINE = 'f5e2de8'


def carry():
    items = (ROOT / 'ITEMS.md').read_text().splitlines()
    report = (ROOT / 'CONT_REPORT.md').read_text()
    notes = (ROOT / 'FOLD-NOTES.md').read_text()
    block = notes.split('### RUN32 carry\n', 1)[1].split('\n### ', 1)[0]
    carried = []
    for number in range(1, 7):
        label = f'R{number}'
        row = next(line for line in reversed(items) if re.match(r'^- \[x\] ' + label + r'\.', line))
        suffix = row.split(' -- ', 1)[1]
        wips = re.findall(r'WIP ' + label + r': HARD LIMIT: ([^\n]+)', report)
        if suffix.startswith('DEFERRED:') or wips:
            blocker = suffix.removeprefix('DEFERRED: ') if suffix.startswith('DEFERRED:') else wips[-1]
            assert f'| {label} | {blocker} |' in block, label
            carried.append({'item': label, 'blocker': blocker})
    assert re.findall(r'^\| (R[1-6]) \|', block, re.MULTILINE) == [row['item'] for row in carried]
    if not carried:
        assert 'None.' in block
    result = {'result': 'PASS', 'passed': 1, 'carry': carried, 'source_items': [f'R{n}' for n in range(1, 7)]}
    (target_dir(ROOT) / 'run33-s6-carry.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'result': 'PASS', 'passed': 1, 'carry_items': [row['item'] for row in carried]}))

def allowed(path):
    return not path.is_absolute() and '..' not in path.parts and not EXCLUDED.intersection(path.parts) and not (path.name.startswith('RUN') and path.name.endswith('_REPORT.md'))


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def files():
    paths = set()
    for folder in ('src', 'tests', 'docs', 'tools', 'third_party'):
        for directory, folders, names in os.walk(ROOT / folder, followlinks=False):
            folders[:] = sorted(name for name in folders if name not in EXCLUDED
                                and not (Path(directory) / name).is_symlink())
            for name in names:
                path = Path(directory) / name
                if allowed(path.relative_to(ROOT)) and not path.is_symlink():
                    paths.add(path)
    paths.update(ROOT / name for name in ('Cargo.toml', 'Cargo.lock', 'README.md',
                 'CONTRACT-5820.md', 'FOLD-NOTES.md', 'CONT_REPORT.md', 'ITEMS.md'))
    paths.update(path for path in (target_dir(ROOT)).glob('run33-*') if path.is_file())
    paths.update(target_dir(ROOT) / name for name in ('suite-timing.json', 'suite-timing-previous.json',
                 'suite-timing-delta.json', 'run23-openapi-coverage.json', 'run21-error-coverage.json',
                 'run27-example-validation.json', 'debug/lane-router'))
    return sorted(paths)


def series():
    records = []
    prior = None
    for number in range(1, 4):
        label = f'run33-final-current-serial-{number}'
        report = json.loads((target_dir(ROOT) / (label + '.json')).read_text())
        assert report['result'] == 'PASS' and report['main_passes'] >= 1339
        assert report['isolated_checks'] >= 70 and report['reported_total'] >= 1401 + 8
        assert report['failed'] == 0 and report['source_inputs_unchanged']
        assert report['temporary_directory_isolated']
        assert report['groups'] > 0 and report['timing_result'] == 'PASS'
        log = ROOT / report['log']
        assert allowed(Path(report['log'])) and digest(log) == report['log_sha256']
        timing = json.loads((target_dir(ROOT) / (label + '-timing.json')).read_text())
        previous = json.loads((target_dir(ROOT) / (label + '-timing-previous.json')).read_text())
        delta = json.loads((target_dir(ROOT) / (label + '-timing-delta.json')).read_text())
        assert len(timing['groups']) == report['groups']
        assert all(row['result'] == 'ok' and row['passed'] > 0 and row['failed'] == 0
                   and row['ignored'] == 0 for row in timing['groups'])
        assert delta['status'] == 'REPORT' and len(delta['groups']) >= len(timing['groups'])
        if prior is not None:
            assert previous == prior, 'serial timing predecessor mismatch'
        prior = timing
        line = max(at for at, text in enumerate(log.read_text().splitlines(), 1)
                   if text.startswith(f'test result: ok. {report["main_passes"]} passed;'))
        records.append({'report': str(target_dir(ROOT) / (label + '.json')), 'cite': report['log'] + ':' + str(line),
                        'main': report['main_passes'], 'isolated': report['isolated_checks'],
                        'total': report['reported_total'], 'groups': report['groups']})
    (target_dir(ROOT) / 'run33-final-series.json').write_text(json.dumps({'result': 'PASS', 'serial_runs': records}, indent=2) + '\n')
    print(json.dumps({'result': 'PASS', 'runs': len(records), 'total_per_run': records[-1]['total']}))


def audit():
    pinned = []
    for line in (ROOT / 'SHA256SUMS.run32').read_text().splitlines():
        sha, name = line.split(None, 1)
        assert allowed(Path(name)), 'unsafe baseline path'
        if name in ('Cargo.toml', 'Cargo.lock', 'docs/command-policy.json',
                    'tests/b5_differences.json', 'tests/b6_differences.json') or name.startswith(('third_party/', 'tests/fixtures/')):
            assert digest(ROOT / name) == sha, name
            pinned.append(name)
    assert len(pinned) > 100
    prior_items = subprocess.run(['git', 'show', BASELINE + ':ITEMS.md'], cwd=ROOT,
                                 capture_output=True, check=True).stdout.decode().splitlines()
    historical = lambda lines: [row for row in lines if re.match(r'^- \[.\] ', row)
                                and not re.match(r'^- \[.\] S[1-8]\.', row)]
    assert historical(prior_items) == historical((ROOT / 'ITEMS.md').read_text().splitlines()), 'historical item drift'
    items = (ROOT / 'ITEMS.md').read_text().splitlines()
    for label, state in [('I7', '~'), ('I8', '~'), ('S1a', '~'), ('S1b', '~'),
                         ('16', '!'), ('O7', '~'), ('P7', '~'), ('Q7', '~'), ('R7', '~'), ('S7', '~')]:
        assert any(re.match(r'^- \[' + re.escape(state) + r'\] ' + label + r'(?:\b|\.)', row) for row in items), label
    assert not ((ROOT.parent / 'lanes-router-keyin/RELEASE_D_DECISIONS').exists()
                and (ROOT / 'docs/I7-DECISIONS.md').exists()), 'S7 gate changed'
    notes = (ROOT / 'FOLD-NOTES.md').read_text()
    for number in range(1, 7):
        assert f'### S{number}\n' in notes
        assert any(row.startswith(f'- [x] S{number}.') for row in items)
    report = (ROOT / 'CONT_REPORT.md').read_text()
    followups = report.split('### RUN33 NOTES-TO-UPDATE\n', 1)[1].split('\n2026-', 1)[0]
    expected = [row for row in followups.splitlines() if row.startswith('- ')]
    ledger = (ROOT / 'docs/RUN33-NOTES-TO-UPDATE.md').read_text().split('## RUN33 NOTES-TO-UPDATE\n', 1)[1]
    actual = [row for row in ledger.splitlines() if row.startswith('- ')]
    assert expected and actual == expected, 'RUN33 follow-up ledger drift'
    for row in expected:
        line = report.splitlines().index(row) + 1
        assert f'CONT_REPORT.md:{line}' in ledger, 'RUN33 follow-up cite drift'
    scan_roots = ['.'] + [str(path) for path in files()
                          if path.is_relative_to(target_dir(ROOT))]
    scan_roots += [path.name for path in sorted(ROOT.glob('SHA256SUMS.run33*'))]
    scan = subprocess.run([sys.executable, 'tools/name-scan.py', *scan_roots], cwd=ROOT, capture_output=True)
    assert scan.returncode == 0 and not scan.stderr, 'counts-only scan failed'
    counts = [int(line) for line in scan.stdout.splitlines()]
    assert len(counts) == len(scan_roots) and all(value == 0 for value in counts), 'nonzero name scan count'
    result = {'result': 'PASS', 'name_matches': sum(counts), 'name_scan_root_counts': counts,
              'pinned_files_unchanged': len(pinned), 'held_and_flagged_rows_preserved': True,
              'baseline': 1401, 'new_main_tests': 8, 'required_total': 1409}
    (target_dir(ROOT) / 'run33-audit.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'result': 'PASS', 'name_matches': sum(counts), 'pinned_files_unchanged': len(pinned)}))


def manifests():
    paths = files()
    assert all(allowed(path.relative_to(ROOT)) and path.is_file() for path in paths)
    entries = ''.join(digest(path) + '  ' + str(path.relative_to(ROOT)) + '\n' for path in paths)
    item_manifests = []
    for label in LABELS:
        path = ROOT / ('SHA256SUMS.run33-' + label)
        path.write_text(entries)
        item_manifests.append(path)
    final = entries + ''.join(digest(path) + '  ' + path.name + '\n' for path in item_manifests)
    (ROOT / 'SHA256SUMS.run33').write_text(final)
    for manifest in item_manifests + [ROOT / 'SHA256SUMS.run33']:
        for line in manifest.read_text().splitlines():
            sha, name = line.split(None, 1)
            assert allowed(Path(name)) and digest(ROOT / name) == sha, name
    print(json.dumps({'result': 'PASS', 'files_per_item': len(paths), 'manifests': len(item_manifests) + 1}))


def inventory():
    from collections import Counter
    baseline_rows = dict((name, sha) for sha, name in
                         (row.split(None, 1) for row in (ROOT / 'SHA256SUMS.run32').read_text().splitlines()))
    declarations = re.compile(r'#\[\s*(?:tokio::)?test(?:\([^]]*\))?\s*\]')
    rows = []
    added = removed = missing_assertions = 0
    for folder in ('src', 'tests'):
        for path in sorted((ROOT / folder).rglob('*.rs')):
            relative = str(path.relative_to(ROOT))
            prior = subprocess.run(['git', 'show', BASELINE + ':' + relative], cwd=ROOT, capture_output=True)
            if relative in baseline_rows:
                assert prior.returncode == 0 and hashlib.sha256(prior.stdout).hexdigest() == baseline_rows[relative], relative + ': baseline mismatch'
            before = prior.stdout.decode() if prior.returncode == 0 else ''
            after = path.read_text()
            old_tests = len(declarations.findall(before))
            new_tests = len(declarations.findall(after))
            assertions = lambda text: Counter(line.strip() for line in text.splitlines() if re.search(r'\bassert(?:_eq|_ne)?!', line))
            missing = list((assertions(before) - assertions(after)).elements())
            assert not missing, relative + ': removed assertion lines'
            assert new_tests >= old_tests, relative + ': test declarations fell'
            if new_tests != old_tests:
                rows.append({'file': relative, 'before': old_tests, 'after': new_tests})
            added += max(0, new_tests - old_tests)
            removed += max(0, old_tests - new_tests)
            missing_assertions += len(missing)
    assert added == 8 and removed == 0 and missing_assertions == 0
    # Historical maintenance guards stay intact.
    retained = ['tests/maintenance_guards.rs', 'tests/run30_core.rs', 'tests/run32_contracts.rs']
    retained = [name for name in retained if (ROOT / name).exists()]
    for name in retained:
        prior = subprocess.run(['git', 'show', BASELINE + ':' + name], cwd=ROOT, capture_output=True, check=True)
        assert prior.stdout == (ROOT / name).read_bytes(), name
    result = {'result': 'PASS', 'baseline_commit': BASELINE, 'added_test_declarations': added, 'removed_test_declarations': removed,
              'removed_assertion_lines': missing_assertions, 'changed_test_counts': rows,
              'retained_files_unchanged': retained}
    (target_dir(ROOT) / 'run33-test-inventory.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'result': 'PASS', 'new_tests': added, 'removed_tests': removed, 'removed_assertions': missing_assertions}))


if __name__ == '__main__':
    try:
        {'carry': carry, 'series': series, 'audit': audit, 'manifests': manifests, 'inventory': inventory}[sys.argv[1]]()
    except (OSError, ValueError, AssertionError, KeyError, IndexError, subprocess.CalledProcessError) as error:
        print('close-out failed: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
