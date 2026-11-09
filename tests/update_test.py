"""Updates that go wrong: the reason is said in words, every attempt is logged (with the installer's own log), and the
failure box offers the download page. Nothing is downloaded or installed: the network and the installer are faked."""
import os
import sys
import tempfile
import urllib.error

os.environ['LOCALAPPDATA'] = tempfile.mkdtemp(prefix='bi_update_test_')
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import bacnet_live as BL  # noqa: E402

BAD = []


def check(ok, msg):
    print(('ok   ' if ok else 'FAIL ') + msg, flush=True)
    if not ok:
        BAD.append(msg)


# ---- the reasons, in words
check('proxy' in BL._why_fetch(urllib.error.HTTPError('u', 407, 'Proxy Authentication Required', {}, None)), 'proxy sign-in')
check('security product' in BL._why_fetch(urllib.error.URLError('[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed')),
      'HTTPS inspection')
check('timed out' in BL._why_fetch(TimeoutError('timed out')), 'timeout')
check('not connected' in BL._why_fetch(urllib.error.URLError('[Errno 11001] getaddrinfo failed')), 'no internet')

# ---- the install, with the network and the installer faked
LOG = os.path.join(BL.state_dir(), 'logs', 'update.log')
r = BL.update_install()
check(r['ok'] is False and 'installed Windows app' in r['error'], 'not the installed app: refused')
check(os.path.isfile(LOG) and 'FAILED' in open(LOG, encoding='utf-8').read(), 'the attempt is logged')
sys.frozen = True
GOOD = b'MZ' + b'\0' * 1000
import hashlib  # noqa: E402
MAN = {'version': '9.9.9', 'url': 'https://example.invalid/Wirescope-Setup-9.9.9.exe', 'sha256': hashlib.sha256(GOOD).hexdigest()}
BL.update_manifest = lambda: (dict(MAN), '')
BL._fetch = lambda url, limit: GOOD[:500]                                          # cut short on the way
r = BL.update_install()
check(r['ok'] is False and 'checksum' in r['error'] and '500 bytes arrived' in r['error'], f"checksum: {r['error']}")


def no_net(url, limit):
    raise urllib.error.URLError('[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed')


BL._fetch = no_net
r = BL.update_install()
check(r['ok'] is False and r['error'].startswith('The download failed: a security product'), f"download: {r['error']}")
BL._fetch = lambda url, limit: GOOD
calls = []


def popen_blocked(args, **kw):
    raise PermissionError(5, 'Access is denied')


REAL = (BL.subprocess.Popen, BL.threading.Timer)
BL.subprocess.Popen = popen_blocked
r = BL.update_install()
check(r['ok'] is False and 'did not let the installer start' in r['error'], f"blocked installer: {r['error']}")
BL.subprocess.Popen = lambda args, **kw: calls.append(args)


class NoExit:                                                                      # the real one quits the app
    def __init__(self, *a):
        pass

    def start(self):
        calls.append('timer')


BL.threading.Timer = NoExit
r = BL.update_install()
check(r['ok'] is True and calls and any(str(a).startswith('/LOG=') and a.endswith('setup-9.9.9.log') for a in calls[0]),
      f'the installer is started with its own log ({calls[0] if calls else None})')
log = open(LOG, encoding='utf-8').read()
check(log.count('FAILED') == 4 and 'started the installer' in log, 'every attempt is in update.log')
check(BL.install_dir_writable() in (True, False), 'the write check runs')
del sys.frozen
BL.subprocess.Popen, BL.threading.Timer = REAL                            # the fakes were for the update only

# ---- the failure box
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402
BL.load_session = lambda: {}
BL.save_session = lambda u: None
import bi_store, bi_app  # noqa: E401,E402
app = QApplication(sys.argv)
w = bi_app.MainWindow(bi_store.Store('settings-upd.json'))
w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
w.show()
seen = {}


def fake_exec(box):
    seen['text'] = box.text()
    seen['buttons'] = [b.text() for b in box.buttons()]
    return 0


QMessageBox.exec = fake_exec
w.upd = {'page': 'https://example.invalid/releases/latest'}
w.upd_failed('The download failed: the connection timed out.')
check('connection timed out' in seen['text'] and 'download Wirescope-Setup' in seen['text'], 'the box says why and how to update by hand')
check({'Open download page', 'Report a problem…'} <= set(seen['buttons']), f"buttons: {seen['buttons']}")
w.close()
print('exceptions:', [f'check failed: {b}' for b in BAD], flush=True)
