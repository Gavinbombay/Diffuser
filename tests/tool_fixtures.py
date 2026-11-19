"""Offline tool entry-point fixtures. All inputs and outputs live in tempdirs."""
import hashlib
import json
from pathlib import Path
import tempfile


def run(context, kind):
    assert kind in ('clean', 'planted')
    tool = Path(context['__file__']).stem
    with tempfile.TemporaryDirectory(prefix='fold-tool-fixture-') as scratch:
        root = Path(scratch)
        (root / 'artifacts').mkdir()
        context['target_dir'] = lambda _root: root / 'artifacts'
        context['ROOT'] = root
        if tool == 'coverage-gate':
            doc = {'paths': {'/fixture': {'get': {'responses': {'200': {}}}}}}
            responses = {'get /fixture 200': {}}
            if kind == 'planted':
                responses['get /fixture 599'] = {}
            (root / 'input.json').write_text(json.dumps(responses))
            failures = context['check'](doc, json.loads((root / 'input.json').read_text()),
                                        {'fixture-code': ['fixture-test']}, {'fixture-code'}, {'fixture-code'})
            (root / 'result.json').write_text(json.dumps(failures))
            assert not failures, 'coverage fixture refused'
        elif tool == 'test-suite':
            content = 'test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.25s\n'
            if kind == 'planted':
                content = content.replace('3 passed', '0 passed')
            (root / 'input.log').write_text(content)
            report = context['write_timing_report']((root / 'input.log').read_text(), root / 'result.json', 0.25)
            delta = context['write_timing_delta'](report, None, root / 'delta.json')
            assert delta['groups'][0]['missing_from'] == ['previous']
            assert report['result'] == 'PASS', 'timing fixture refused'
        elif tool == 'name-scan':
            tree = root / 'tree'
            tree.mkdir()
            reference = root / 'reference.txt'
            reference.write_text('counted fixture\n')
            (tree / 'input.txt').write_text('counted fixture\n' if kind == 'planted' else '[R]\n')
            patterns = reference.read_bytes().splitlines()
            count = context['count'](tree, patterns)
            (root / 'result.json').write_text(json.dumps({'count': count}))
            assert count == 0, 'name fixture refused'
        elif tool == 'cli-cancel':
            row = {'state': 'cancelled', 'journal': [{'dst': 'cancelled'}],
                   'attempts': [{'state': 'cancelled'}], 'active_children': 0}
            stored = json.loads(json.dumps(row))
            if kind == 'planted':
                row['active_children'] = 1
            (root / 'input.json').write_text(json.dumps(row))
            (root / 'stored.json').write_text(json.dumps(stored))
            context['check_settlement'](json.loads((root / 'input.json').read_text()),
                                         json.loads((root / 'stored.json').read_text()), False,
                                         ['cancel requested'], 2)
        elif tool in ('run28-audit', 'run29-audit', 'run30-audit'):
            number = int(tool[3:5])
            main, isolated = {28: (1293, 62), 29: (1300, 70), 30: (1310, 70)}[number]
            timing = {'result': 'PASS', 'wall_seconds': 0.25,
                      'groups': [{'group': 'group-001', 'result': 'ok', 'passed': main,
                                  'failed': 0, 'ignored': 0, 'wall_seconds': 0.25}]}
            for index in range(1, 4):
                label = f'run{number}-final-serial-{index}'
                log = root / 'artifacts' / (label + '.log')
                log.write_text(f'test result: ok. {main} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.25s\n')
                report = {'result': 'PASS', 'main_passes': main, 'isolated_checks': isolated,
                          'reported_total': main + isolated, 'failed': 0,
                          'source_inputs_unchanged': True, 'temporary_directory_isolated': True,
                          'groups': 1, 'timing_result': 'PASS',
                          'log': str(log.relative_to(root)),
                          'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest()}
                if kind == 'planted' and index == 1:
                    report['main_passes'] = 0
                for suffix, value in [('.json', report), ('-timing.json', timing),
                                      ('-timing-previous.json', timing),
                                      ('-timing-delta.json', {'status': 'REPORT', 'groups': timing['groups']})]:
                    (root / 'artifacts' / (label + suffix)).write_text(json.dumps(value))
            context['series']()
            assert json.loads((root / 'artifacts' / f'run{number}-final-series.json').read_text())['result'] == 'PASS'
        else:
            raise AssertionError('tool fixture missing')
