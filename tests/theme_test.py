"""Theme check on the real screen (not offscreen): switch Automatic / Light / Dark and sample the colours of the
title bar, the sidebar, the top bar and the page, so a part left in the wrong theme is caught.
Run on Windows with a desktop: python tests/theme_test.py   (a window opens for a few seconds)."""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'out', 'theme')
os.makedirs(OUT, exist_ok=True)
sys.path.insert(0, os.path.dirname(HERE))
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtGui import QColor, QGuiApplication  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402
import bacnet_live as BL  # noqa: E402
BL.load_session = lambda: {}
BL.save_session = lambda u: None
import bi_store, bi_app, bi_ui as U  # noqa: E401,E402

app = QApplication(sys.argv)
app.setStyle('windows11')
store = bi_store.Store('settings-theme-test.json')
store.set('bi_toured', 'done')
U.apply_fonts(app)
U.apply_palette(app)
w = bi_app.MainWindow(store)
w.first_run_ui = False
try:
    QGuiApplication.styleHints().colorSchemeChanged.connect(lambda *_: w.theme_soon())
except AttributeError:
    pass
w.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, True)     # do not take the focus from whoever is at the PC
w.setGeometry(120, 120, 1300, 820)
w.show()


def pump(s):
    end = time.time() + s
    while time.time() < end:
        app.processEvents()
        time.sleep(0.01)


def lum(c):
    return 0.299 * c.red() + 0.587 * c.green() + 0.114 * c.blue()


def caption():
    """The colour the app last gave Windows for the title bar (Windows cannot report it back)."""
    return QColor(getattr(w, 'caption_color', '#ff00ff'))


def sample(tag):
    img = w.grab().toImage()                    # the window as the app draws it
    img.save(os.path.join(OUT, tag + '.png'))
    dpr = img.width() / w.width()

    def px(x, y):
        return img.pixelColor(int(x * dpr), int(y * dpr))
    side = w.sidew.mapTo(w, w.sidew.rect().bottomLeft())
    return {'title bar': caption(),
            'sidebar': px(30, side.y() - 30),
            'top bar': px(w.width() * 0.6, w.menuBar().height() + 14),
            'page': px(w.width() * 0.6, w.height() * 0.6)}


def os_dark():
    import winreg
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize')
    return winreg.QueryValueEx(k, 'AppsUseLightTheme')[0] == 0


pump(1.5)
bad = []
for v in ['', 'light', 'dark', '', 'dark', 'light', '']:
    w.set_theme(v)
    pump(1.2)
    want_dark = {'light': False, 'dark': True}.get(v, os_dark())
    s = sample((v or 'auto') + '-' + str(len(bad)))
    row = '  '.join(f"{k} {c.name()}" for k, c in s.items())
    print(f"{v or 'auto':6} want {'dark' if want_dark else 'light':5}: {row}")
    for k, c in s.items():
        if (lum(c) < 110) != want_dark:
            bad.append(f"{v or 'auto'}: {k} is {c.name()}, expected {'dark' if want_dark else 'light'}")
w.set_theme('')
store.flush()
try:
    os.remove(store.path)
except OSError:
    pass
print('\n'.join(bad) or 'theme test: all parts follow the theme')
sys.stdout.flush()
os._exit(1 if bad else 0)                       # skip Qt teardown noise at exit
