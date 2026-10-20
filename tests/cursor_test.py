"""The galactic cursor: windows get it, text boxes keep the I-beam, View > Galactic cursor turns it off and on."""
import os
import sys
import tempfile
import time

os.environ['LOCALAPPDATA'] = tempfile.mkdtemp(prefix='bi_cursor_test_')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # the app's folder
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QDialog  # noqa: E402
import bacnet_live as BL  # noqa: E402
BL.load_session = lambda: {}
BL.save_session = lambda u: None
import bi_store, bi_app, bi_ui as U  # noqa: E401,E402

ERR = []
sys.excepthook = lambda t, v, tb: ERR.append(f'{t.__name__}: {v}')
app = QApplication(sys.argv)
app.setStyle('windows11')
store = bi_store.Store('settings-cursortest.json')
w = bi_app.MainWindow(store)
w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
w.show()
U.set_galaxy_cursor(store.get('bi_galaxy', True))


def pump(s):
    end = time.time() + s
    while time.time() < end:
        app.processEvents()
        time.sleep(0.02)


BMP = Qt.CursorShape.BitmapCursor
pump(0.3)
main_on = w.cursor().shape() == BMP
ibeam = w.qbox.cursor().shape() == Qt.CursorShape.IBeamCursor
d = QDialog(w)
d.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
d.show()
pump(0.2)
dialog_on = d.cursor().shape() == BMP
d.close()
w.m_galaxy.setChecked(False)
pump(0.2)
off = w.cursor().shape() != BMP and store.get('bi_galaxy') is False
w.m_galaxy.setChecked(True)
pump(0.2)
back = w.cursor().shape() == BMP
print(f'main window: {main_on} | filter box keeps I-beam: {ibeam} | dialog: {dialog_on} | off: {off} | on again: {back}')
w.close()
pump(0.2)
ok = main_on and ibeam and dialog_on and off and back
print('exceptions:', ERR if ok else ERR + ['cursor check failed'])
