"""Portable synthetic transcript regressions; real evidence is explicitly supplied."""
import copy
import json
import os
import re
import runpy
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from harness_accounting import AccountingError, acceptance, classify, expected_targets, unique_source_test_inventory

VECTOR_IDS = ['real-legacy-accounting', 'real-native-identity', 'crew-memory-bridge-omitted', 'crew-memory-bridge-duplicate', 'crew-memory-bridge-failed', 'crew-memory-bridge-zero', 'crew-memory-bridge-ignored', 'lane-router-omitted', 'lane-router-duplicate', 'lane-router-failed', 'lane-router-zero', 'lane-router-ignored', 'lanes-ctl-omitted', 'lanes-ctl-duplicate', 'lanes-ctl-failed', 'lanes-ctl-zero', 'lanes-ctl-ignored', 'diffuser-omitted', 'diffuser-duplicate', 'diffuser-failed', 'diffuser-zero', 'diffuser-ignored', 'lane-router-below-main-floor', 'diffuser-below-main-floor', 'unknown-target', 'shared-source-not-deduped', 'quiet-production-output', 'spoof-order-size', 'metadata-failure', 'metadata-test-selection', 'nested-none-primary-inflation', 'nested-47', 'nested-48', 'nested-orphan', 'nested-duplicate-summary', 'nested-truncated', 'nested-interleaved', 'nested-count-mismatch', 'nested-bad-timing', 'nested-failed-child', 'nested-ignored-child', 'nested-zero-child', 'nested-unfiltered-child', 'pending-parent-pretty', 'primary-corpus-missing', 'coverage-fail', 'cargo-nonzero', 'input-drift', 'group-timing-fail', 'legacy-timing-selftests', 'legacy-suite-fixture', 'all-shipped-tool-fixtures', 'fresh-nonquiet-rerun']

NAMES = ("crew-memory-bridge", "lane-router", "lanes-ctl", "diffuser")
COUNTS = dict(zip(NAMES, (5, 1377, 4, 1377)))

def metadata(root):
    """Synthetic metadata, with paths explicitly bound to this fixture's root."""
    return {"resolve": {"root": "synthetic-root"}, "packages": [{"id": "synthetic-root", "features": {},
        "targets": [{"name": n, "kind": ["bin"], "test": True,
          "src_path": str(root / ("src/main.rs" if n in NAMES[1::2] else "src/bin/" + n + ".rs"))} for n in NAMES]}]}

def transcript(root, target, counts=None, children=48):
    counts = counts or COUNTS
    blocks = {}
    for name in NAMES:
        path = "src/main.rs" if name in ("lane-router", "diffuser") else "src/bin/" + name + ".rs"
        lines = [f"     Running unittests {path} ({target}/debug/deps/{name.replace('-', '_')}-0123456789abcdef)", f"running {counts[name]} tests"]
        for i in range(counts[name]):
            case = ("main" if path == "src/main.rs" else name.replace('-', '_')) + f"_{i}"
            if name == "lane-router" and i < children:
                lines += [f"test {case} ...", "running 1 test", ".", "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1376 filtered out; finished in 0.01s", "ok"]
            else:
                lines.append(f"test {case} ... ok")
        lines.append(f"test result: ok. {counts[name]} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s")
        blocks[name] = "\n".join(lines) + "\n"
    return blocks

def run():
    root = ROOT.resolve(); target = root / "synthetic-target"; m = metadata(root)
    expected = expected_targets(m, root); blocks = transcript(root, target)
    text = "# SYNTHETIC ONLY\n" + "".join(blocks.values())
    base = classify(text, m, root, target)
    assert not acceptance(base, expected)
    results = {}
    def rejected(candidate, meta=m, **kwargs):
        try:
            result = classify(candidate, meta, root, target)
            return bool(acceptance(result, expected, **kwargs))
        except AccountingError:
            return True
    def check(identifier, condition, detail):
        if not condition:
            raise AssertionError(identifier + ": " + detail)
        results[identifier] = {"outcome": "PASS", "provenance": "SYNTHETIC", "detail": detail}
    def chunks(changed):
        return "# SYNTHETIC ONLY\n" + "".join(changed.values())
    for name in NAMES:
        for mutation in ("omitted", "duplicate", "failed", "zero", "ignored"):
            b = blocks.copy()
            if mutation == "omitted": b[name] = ""
            elif mutation == "duplicate": b[name] += b[name]
            elif mutation == "zero":
                count = COUNTS.copy(); count[name] = 0
                b = transcript(root, target, count)
            else:
                suffix = "FAILED" if mutation == "failed" else "ignored"
                status_field = "failed" if mutation == "failed" else "ignored"
                # Change an ordinary case, never a nested child.
                case = ("main" if name in ("lane-router", "diffuser") else name.replace('-', '_')) + "_" + str(COUNTS[name]-1)
                b[name] = b[name].replace(f"test {case} ... ok", f"test {case} ... {suffix}")
                b[name] = b[name].replace(f"{COUNTS[name]} passed; 0 failed; 0 ignored", f"{COUNTS[name]-1} passed; " + ("1 failed; 0 ignored" if status_field == "failed" else "0 failed; 1 ignored"))
                if mutation == "failed":
                    pos = b[name].rfind("test result: ok.")
                    b[name] = b[name][:pos] + b[name][pos:].replace("test result: ok.", "test result: FAILED.", 1)
            check(name + "-" + mutation, rejected(chunks(b)), mutation + " target rejected")
    for name in ("lane-router", "diffuser"):
        counts = COUNTS.copy(); counts[name] = 1234
        check(name + "-below-main-floor", rejected(chunks(transcript(root,target,counts))), "1234 rejected independently")
    check("unknown-target", rejected(text.replace("crew_memory_bridge-0123456789abcdef", "alien-0123456789abcdef", 1)), "unknown artifact rejected")
    check("shared-source-not-deduped", len(base["primary_targets"]) == 4 and len(unique_source_test_inventory(base)) == 1386, "both shared-source targets retained")
    check("quiet-production-output", rejected(re.sub(r"^ *Running .*\n", "", text, flags=re.M)), "anonymous targets rejected")
    check("spoof-order-size", rejected(text.replace("src/bin/lanes-ctl.rs", "src/main.rs", 1)), "source/artifact mismatch rejected")
    check("metadata-failure", rejected(text, {}), "malformed metadata rejected")
    drift = copy.deepcopy(m); drift['packages'][0]['targets'][0]['test'] = False
    check("metadata-test-selection", rejected(text, drift), "selection drift rejected")
    for count, ident, should_reject in [(0,"nested-none-primary-inflation",True),(47,"nested-47",True),(48,"nested-48",False)]:
        check(ident, rejected(chunks(transcript(root,target,children=count))) == should_reject, f"{count} child threshold")
    child = "running 1 test\n.\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1376 filtered out; finished in 0.01s"
    mutations = {
      "nested-orphan": text.replace("running 1 test\n.\n", "", 1),
      "nested-duplicate-summary": text.replace(child, child + "\n" + child.split("\n")[-1], 1),
      "nested-truncated": text.replace(child + "\nok", child, 1),
      "nested-interleaved": text.replace(child, child.replace("running 1 test", blocks['lanes-ctl'].splitlines()[0], 1), 1),
      "nested-count-mismatch": text.replace(child, child.replace("running 1 test", "running 2 tests", 1), 1),
      "nested-bad-timing": text.replace(child, child.replace("0.01s", "...s"), 1),
      "nested-failed-child": text.replace(child, child.replace(".\ntest result: ok. 1 passed; 0 failed", "test inner ... FAILED\ntest result: FAILED. 0 passed; 1 failed"), 1),
      "nested-ignored-child": text.replace(child, child.replace(".\ntest result: ok. 1 passed; 0 failed; 0 ignored", "test inner ... ignored\ntest result: ok. 0 passed; 0 failed; 1 ignored"), 1),
      "nested-zero-child": text.replace(child, child.replace("running 1 test\n.\n", "running 0 tests\n").replace("1 passed", "0 passed"), 1),
      "nested-unfiltered-child": text.replace(child, child.replace("1376 filtered", "0 filtered"), 1),
    }
    for ident, candidate in mutations.items(): check(ident, rejected(candidate), "invalid child rejected")
    interrupted = text.replace("test main_0 ...\n", "test main_0 ... policy_sha256=fixture\n", 1)
    check("pending-parent-pretty", not rejected(interrupted), "diagnostic and terse child preserve pending parent")
    # Review regressions, exercised separately from the authored vector list.
    probes = [text.replace("test crew_memory_bridge_0 ... ok", "test crew_memory_bridge_0 ... FAILED", 1),
              text.replace("test crew_memory_bridge_1 ... ok", "test crew_memory_bridge_0 ... ok", 1),
              text.replace(child + "\nok", child + "\nok\nok", 1),
              text.replace(child, child.replace(".\n", "", 1), 1),
              text.replace(child, child.replace(".\n", ".....\n", 1), 1),
              text.replace(child, child.replace(".\n", "test inner ...\n", 1), 1),
              text + "running nonsense\n", text + "test ghost ... ok\n"]
    assert all(rejected(probe) for probe in probes), "review false-acceptance probe accepted"
    assert rejected(text.replace(child + "\nok", child, 1)), "missing parent completion accepted"
    assert rejected(text.replace(child, child.replace('0.01s', '9' * 400 + '.0s'), 1)), "infinite duration accepted"
    assert rejected(text.replace('-0123456789abcdef', '-fixturehash', 1)), "malformed artifact accepted"
    sibling = text.replace(child + "\nok", child + "\n" + child + "\nok", 1)
    assert not rejected(sibling), "sequential children rejected"
    grandchild = ("running 1 test\ntest inner ...\nrunning 1 test\n.\n"
                  "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s\nok\n"
                  "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1376 filtered out; finished in 0.01s")
    assert not rejected(text.replace(child, grandchild, 1)), "nested child scope rejected"
    suite = runpy.run_path(str(ROOT / "tools/test-suite.py"))
    original = json.loads((ROOT / 'tests/original_case_inventory.json').read_text())['targets']
    complete = [{'name': n, 'result': 'ok'} for n in original['lane-router']['cases']]
    by_target = suite['per_target_corpus']('', {'lane-router': {'cases': complete}, 'diffuser': {'cases': []}})
    check("primary-corpus-missing", all(not v['missing_tests'] for v in by_target['lane-router'].values()) and all(v['missing_tests'] for v in by_target['diffuser'].values()), "one main cannot mask the other's missing corpus")
    for ident, kwargs in [("coverage-fail", {'coverage_result':'FAIL'}), ("cargo-nonzero", {'cargo_status':1}), ("input-drift", {'unchanged':False}), ("group-timing-fail", {'timing_result':'FAIL'})]:
        check(ident, rejected(text, **kwargs), "acceptance predicate rejected")
    def invoke(args):
        return subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE":"1"})
    check("legacy-timing-selftests", all(invoke(['tools/test-suite.py','--self-test',v]).returncode == 0 for v in ('empty','report','delta')), "three legacy subprocesses")
    def fixture(tool):
        clean=invoke([tool,'--fixture-test','clean']); planted=invoke([tool,'--fixture-test','planted'])
        return clean.returncode == 0 and planted.returncode == 1 and 'PASS' not in planted.stdout
    check("legacy-suite-fixture", fixture('tools/test-suite.py'), "clean and planted subprocesses")
    check("all-shipped-tool-fixtures", all(fixture('tools/'+tool+'.py') for tool in ('coverage-gate','test-suite','cli-cancel','run28-audit','run29-audit','run30-audit','name-scan')), "seven clean and planted subprocess pairs")
    # Real inputs are supplied by explicit paths, never synthesized or reconstructed.
    legacy = os.environ.get('HARNESS_LEGACY_LOG')
    if legacy:
        real = Path(legacy).read_text(errors='replace')
        summaries = re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out', real)
        primary = sum(int(x[0]) for x in summaries if int(x[4]) == 0)
        total = sum(int(x[0]) for x in summaries)
        assert (primary,total,total-primary) == (2763,2903,140)
        results['real-legacy-accounting'] = {'outcome':'PASS','provenance':'REAL_CAPTURE', 'detail':{'primary':primary,'nested':total-primary,'total':total}}
    else: results['real-legacy-accounting'] = {'outcome':'PENDING','provenance':'REAL_CAPTURE','detail':'HARNESS_LEGACY_LOG not supplied'}
    native = os.environ.get('HARNESS_NATIVE_INVENTORY')
    if native:
        data=json.loads(Path(native).read_text()); groups=[g for g in data['all_groups'] if g['depth']==0]
        stderr_path = os.environ.get('HARNESS_NATIVE_STDERR')
        stdout_path = os.environ.get('HARNESS_NATIVE_STDOUT')
        assert stderr_path and stdout_path, 'explicit original native streams required'
        stderr = Path(stderr_path).read_text(errors='replace'); stdout = Path(stdout_path).read_text(errors='replace')
        for stem in ('crew_memory_bridge', 'lane_router', 'lanes_ctl', 'diffuser'):
            assert re.search(r'Running unittests .*?/deps/' + stem + r'-[0-9a-f]{16}\)', stderr)
        assert sorted(g['passed'] for g in groups)==[4,5,1377,1377] and sum(g['passed'] for g in data['all_groups'] if g['depth']>0)==140
        assert len(re.findall(r'^test result:', stdout, re.M)) == 144
        results['real-native-identity']={'outcome':'PASS','provenance':'REAL_SEPARATE_STREAMS_INVENTORY','detail':'original streams inspected separately and corroborated with parsed inventory; not reconstructed'}
    else: results['real-native-identity']={'outcome':'PENDING','provenance':'REAL_CAPTURE','detail':'HARNESS_NATIVE_INVENTORY not supplied'}
    fresh = os.environ.get('HARNESS_FRESH_REPORT')
    if fresh:
        report=json.loads(Path(fresh).read_text()); assert report['result']=='PASS' and len(report['primary_targets'])==4 and report['nested_passes']>=48
        import hashlib
        log=Path(report['log']); assert hashlib.sha256(log.read_bytes()).hexdigest()==report['log_sha256']
        actual_metadata=json.loads(Path(os.environ['HARNESS_FRESH_METADATA']).read_text())
        actual_target=Path(os.environ['HARNESS_FRESH_TARGET']).resolve()
        observed=classify(log.read_text(errors='replace'), actual_metadata, ROOT, actual_target)
        assert observed['primary_passes']==report['primary_passes'] and observed['nested_passes']==report['nested_passes']
        results['fresh-nonquiet-rerun']={'outcome':'PASS','provenance':'REAL_FRESH_REPORT','detail':fresh}
    else: results['fresh-nonquiet-rerun']={'outcome':'PENDING','provenance':'REAL_FRESH_REPORT','detail':'HARNESS_FRESH_REPORT not supplied'}
    spec = os.environ.get('HARNESS_VECTOR_SPEC')
    if spec:
        assert {v['id'] for v in json.loads(Path(spec).read_text())['vectors']} == set(VECTOR_IDS)
    assert set(results)==set(VECTOR_IDS) and len(results)==53
    return {'result':'PASS' if all(v['outcome']=='PASS' for v in results.values()) else 'PENDING_REAL_EVIDENCE', 'vector_count':len(results), 'vectors':results, 'synthetic_policy':'SYNTHETIC ONLY; fixture metadata bound to ROOT'}

if __name__ == '__main__': print(json.dumps(run(), sort_keys=True))
