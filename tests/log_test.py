"""The problem log: errors in the UI thread and in background threads are logged, the toast appears,
and Help > Report a problem shows them. Uses a throw-away LOCALAPPDATA so the real log is not touched."""
import os
import sys
import tempfile
import threading
import time

tmp = tempfile.mkdtemp(prefix='bi_log_test_')
os.environ['LOCALAPPDATA'] = tmp
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # the app's folder
from PySide6.QtCore import Qt, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication, QDialog, QPlainTextEdit  # noqa: E402
import bacnet_live as BL  # noqa: E402
BL.load_session = lambda: {}
BL.save_session = lambda u: None
import bi_store, bi_app, bi_log  # noqa: E401,E402

app = QApplication(sys.argv)
app.setStyle('windows11')
bi_log.install()
store = bi_store.Store('settings-logtest.json')
w = bi_app.MainWindow(store)
w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
w.show()
toasts = []
bi_log.on_error = lambda s: w.bridge.call.emit(lambda: toasts.append(s))


def pump(s):
    end = time.time() + s
    while time.time() < end:
        app.processEvents()
        time.sleep(0.02)


pump(0.5)
QTimer.singleShot(0, lambda: 1 / 0)                       # error in the UI thread
pump(0.3)
bi_log._last_popup = 0
t = threading.Thread(target=lambda: {}['missing'], name='worker')   # error in a background thread
t.start()
t.join()
pump(0.3)
log = open(bi_log.log_path(), encoding='utf-8').read()
ok = all(x in log for x in ('Started.', 'ZeroDivisionError', "KeyError: 'missing'", 'background task worker'))
print('logged both errors:', ok, '| toasts:', toasts, '| count:', bi_log.error_count())
seen = {}


def grab():
    for d in app.topLevelWidgets():
        if isinstance(d, QDialog) and d.isVisible():
            seen['text'] = d.findChild(QPlainTextEdit).toPlainText()
            d.accept()


QTimer.singleShot(400, grab)
w.report_problem()
print('report window shows the errors:', 'ZeroDivisionError' in seen.get('text', ''))
w.close()
pump(0.2)
fine = ok and len(toasts) == 2 and bi_log.error_count() == 2 and 'ZeroDivisionError' in seen.get('text', '')
print('exceptions: []' if fine else 'exceptions: [\'log test failed\']')
