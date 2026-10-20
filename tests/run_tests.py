"""Runs every regression test and prints a pass / fail summary. Exit code 0 = all passed.

    python tests\\run_tests.py            (or double-click run_tests.bat)

Tests that open captures use the .pcap / .pcapng files in tests\\captures (not in git - put a BACnet/IP capture and
an MS/TP capture there) or the folder named by the BI_CAPTURES environment variable. Without captures those tests
are skipped. Screenshots go to tests\\out.
"""
import glob
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CAPS = os.environ.get('BI_CAPTURES') or os.path.join(HERE, 'captures')


def captures():
    found = sorted(glob.glob(os.path.join(CAPS, '*.pcap')) + glob.glob(os.path.join(CAPS, '*.pcapng')),
                   key=os.path.getsize)
    return found


def failed(out):
    """Problems a test reports in its output even when it exits normally."""
    bad = []
    if 'Traceback (most recent call last)' in out:
        bad.append('traceback')
    m = re.search(r'^(\d+) exception\(s\)', out, re.M)
    if m and m.group(1) != '0':
        bad.append(f'{m.group(1)} exception(s)')
    for m in re.finditer(r'^(?:exceptions|ERRORS): (\[.*\])$', out, re.M):
        if m.group(1) != '[]':
            bad.append(m.group(0)[:200])
    return bad


def main():
    caps = captures()
    py = sys.executable
    tests = [('lint', [py, '-m', 'pyflakes'] + sorted(glob.glob(os.path.join(ROOT, '*.py'))) + sorted(glob.glob(os.path.join(HERE, '*.py'))), False),
             ('MS/TP engine on a simulated trunk', [py, 'mstp_test.py'], False),
             ('Discover over MS/TP (UI)', [py, 'mstp_ui_test.py'], False),
             ('Discover tree labels', [py, 'tree_test.py'], False),
             ('Discover through a BBMD', [py, 'bbmd_test.py'], False),
             ('site inventory', [py, 'inventory_test.py'], False),
             ('navigation and Back', [py, 'nav_test.py'], False),
             ('problem log and Report a problem', [py, 'log_test.py'], False),
             ('smoke: every view and export', [py, 'smoke.py'] + caps, True),
             ('QA: every view, both themes, two sizes', [py, 'qa.py'] + caps, True),
             ('alarms, properties, Excel, sorting', [py, 'features_test.py'] + (caps[:1] + caps[-1:] if caps else []), True)]
    env = dict(os.environ, PYTHONIOENCODING='utf-8')
    os.makedirs(os.path.join(HERE, 'out', 'shots'), exist_ok=True)
    results = []
    for name, cmd, needs_caps in tests:
        if needs_caps and not caps:
            results.append((name, 'SKIP', 'no captures in ' + CAPS))
            print(f'-- {name}: skipped (no captures)')
            continue
        print(f'-- {name} ...', flush=True)
        t0 = time.time()
        try:
            p = subprocess.run(cmd, cwd=HERE, env=env, capture_output=True, text=True, encoding='utf-8',
                               errors='replace', timeout=900)
            out = p.stdout + p.stderr
            bad = failed(out) + ([f'exit code {p.returncode}'] if p.returncode else [])
        except subprocess.TimeoutExpired:
            out, bad = '', ['timed out after 15 minutes']
        if bad:
            print(out[-3000:])
        results.append((name, 'FAIL' if bad else 'pass', '; '.join(bad) or f'{time.time() - t0:.0f} s'))
    print('\n' + '=' * 60)
    for name, st, note in results:
        print(f'{st:5} {name}  ({note})')
    nfail = sum(st == 'FAIL' for _, st, _ in results)
    print('=' * 60)
    print('ALL PASSED' if not nfail else f'{nfail} FAILED')
    return 1 if nfail else 0


if __name__ == '__main__':
    sys.exit(main())
