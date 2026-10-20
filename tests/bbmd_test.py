"""Discover through a BBMD: registration accepted / refused / no answer, custom port, and the final status line."""
import os
import sys
import tempfile
import time

os.environ['LOCALAPPDATA'] = tempfile.mkdtemp(prefix='bi_bbmd_test_')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # the app's folder
import bi_store  # noqa: E402
import bi_explore as E  # noqa: E402

_sleep = time.sleep
E.time.sleep = lambda s: _sleep(min(s, 0.05))           # keep the scan quick


class Relay:
    """Stands in for the network: records what is sent and answers like a BBMD would."""
    def __init__(self, answer):
        self.answer, self.sent, self.ex = answer, [], None

    def send(self, dest, b):
        self.sent.append((dest, b[:2].hex()))
        if b[:2] == b'\x81\x05' and self.answer is not None:      # Register-Foreign-Device
            self.ex._rx({'hex': bytes([0x81, 0, 0, 6, self.answer >> 8, self.answer & 255]).hex(), 'ip': dest, 'port': 47808})
        return ''

    def armed_left(self):
        return 0


fails = []
for name, answer, bbmd, want_dbtn, want_msg in [
        ('accepted', 0, '10.20.0.5', True, 'Scanned other subnets through the BBMD'),
        ('refused', 0x30, '10.20.0.5', False, 'refused the registration (code 0x30)'),
        ('no answer', None, '10.20.0.5', True, 'No answer from the BBMD'),
        ('custom port', 0, '10.20.0.5:47809', True, 'Scanned other subnets'),
        ('no BBMD', None, '', False, 'Done – 0 device(s) found.')]:
    r = Relay(answer)
    x = E.Explorer(r, bi_store.Store('settings-bbmd.json'))
    r.ex = x
    x.opt.update(bbmd=bbmd)
    x.scan()
    dbtn = [d for d, k in r.sent if k == '8109']
    port_ok = all(d.endswith(':47809') for d, k in r.sent if k in ('8105', '8109')) if 'custom' in name else True
    ok = bool(dbtn) == want_dbtn and want_msg in x.msg and port_ok and x.msg.startswith('Done')
    print(f'{name:12} {"ok  " if ok else "FAIL"} sent={[k for _, k in r.sent]} msg={x.msg!r}')
    if not ok:
        fails.append(name)
print('exceptions:', fails)
