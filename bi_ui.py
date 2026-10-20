"""
bi_ui.py - the app's look and feel: fonts, one accent colour, line icons, the sliding segmented
control, toasts, the thin progress bar, spinners, skeleton rows, empty states, view fades, the
Ctrl+K command palette, tips, the first-run tour and the About / What's new windows.
"""
from __future__ import annotations

import ctypes
import os
import sys
import time

from PySide6.QtCore import (QByteArray, QEasingCurve, QEvent, QPointF, QPropertyAnimation, QRect, QRectF, QSize, Qt,
                            QTimer, QVariantAnimation)
from PySide6.QtGui import (QColor, QFont, QFontDatabase, QIcon, QLinearGradient, QPainter, QPainterPath, QPalette, QPen,
                           QPixmap, QPolygonF)
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QButtonGroup, QDialog, QFrame, QGraphicsDropShadowEffect,
                               QGraphicsOpacityEffect,
                               QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QPushButton, QSizePolicy,
                               QStyle, QStyledItemDelegate, QVBoxLayout, QWidget)

from bi_common import colors, is_dark, label

# ------------------------------------------------------------------ fonts --
BODY_PT = 10


def ui_family():
    fams = set(QFontDatabase.families())
    return 'Segoe UI Variable Text' if 'Segoe UI Variable Text' in fams else 'Segoe UI'


def apply_fonts(app):
    """Segoe UI Variable at a comfortable size, with tabular (fixed-width) digits so numbers line up."""
    f = QFont(ui_family())
    f.setPointSizeF(BODY_PT)
    try:
        f.setFeature(QFont.Tag('tnum'), 1)
    except (AttributeError, TypeError, ValueError):
        pass
    app.setFont(f)


def apply_palette(app):
    """One accent colour everywhere: selection, checkboxes, links and focus use the app's blue."""
    c = colors()
    pal = QPalette()                  # only the roles set here are overridden; the rest follow light / dark mode
    ac = QColor(c['ac'])
    for g in (QPalette.ColorGroup.Active, QPalette.ColorGroup.Inactive):
        pal.setColor(g, QPalette.ColorRole.Highlight, ac)
        pal.setColor(g, QPalette.ColorRole.Accent, ac)
        pal.setColor(g, QPalette.ColorRole.Link, ac)
    app.setPalette(pal)


def style_titlebar(w):
    """Windows 11: give the title bar the window's own colour so it blends into the app (one seamless top)."""
    if sys.platform != 'win32':
        return
    try:
        hwnd = int(w.winId())
        dw = ctypes.windll.dwmapi
        v = ctypes.c_int(1 if is_dark() else 0)
        dw.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(v), 4)                 # dark title bar text / buttons
        col = w.palette().color(QPalette.ColorRole.Window)
        cref = ctypes.c_int(col.red() | col.green() << 8 | col.blue() << 16)
        dw.DwmSetWindowAttribute(hwnd, 35, ctypes.byref(cref), 4)              # caption colour (Windows 11 only)
        rnd = ctypes.c_int(2)
        dw.DwmSetWindowAttribute(hwnd, 33, ctypes.byref(rnd), 4)               # rounded corners
    except (AttributeError, OSError):
        pass


# ------------------------------------------------------------------ icons --
# 24 x 24 line drawings (stroked, round caps), in the style of SF Symbols / Lucide.
PATHS = {
    'p': 'M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01',
    'f': 'M9 18h6M10 21.5h4M12 2.5a6.5 6.5 0 0 0-3.8 11.8c.5.4.8 1 .8 1.7V16h6v-.1c0-.7.3-1.3.8-1.7A6.5 6.5 0 0 0 12 2.5z',
    'd': 'M7 7h10v10H7zM10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4',
    'w': 'M4 20l4-1 11-11-3-3L5 16zM14 6l3 3',
    't': 'M5 20V10M12 20V4M19 20v-7',
    's': 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7v5l3 2',
    'o': 'M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M2 9a14.5 14.5 0 0 1 20 0M12 19.5h.01',
    'g': 'M12 3a2 2 0 1 0 0 4 2 2 0 0 0 0-4zM5 17a2 2 0 1 0 0 4 2 2 0 0 0 0-4zM19 17a2 2 0 1 0 0 4 2 2 0 0 0 0-4zM12 7v5M12 12l-6.3 5.3M12 12l6.3 5.3',
    'a': 'M5 9h14M5 15h14M10 4L8 20M16 4l-2 16',
    'n': 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18',
    'm': 'M3 12h4l3-7 4 14 3-7h4',
    'b': 'M4 17a8 8 0 1 1 16 0M12 17l4-5',
    'c': 'M9 4h11v11H9zM4 9v11h11',
    'x': 'M12 3a9 9 0 1 0 9 9M12 7a5 5 0 1 0 5 5M12 12l6-6',
    'search': 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20.5 20.5l-4.5-4.5',
    'terminal': 'M4 5h16v14H4zM8 10l3 2.5L8 15M13 15h4',
    'back': 'M15 18l-6-6 6-6',
    'fwd': 'M9 18l6-6-6-6',
    'up': 'M18 15l-6-6-6 6',
    'down': 'M6 9l6 6 6-6',
    'home': 'M3.5 11L12 4l8.5 7M6 9.5V20h12V9.5',
    'plus': 'M12 5v14M5 12h14',
    'close': 'M18 6L6 18M6 6l12 12',
    'check': 'M20 6L9 17l-5-5',
    'refresh': 'M20 11a8 8 0 0 0-14.3-4.9L4 8M4 4v4h4M4 13a8 8 0 0 0 14.3 4.9L20 16M20 20v-4h-4',
    'file': 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5M9 13h6M9 17h4',
    'wave': 'M2 12h3l2-6 3 12 3-9 2 5 2-2h5',
    'bell': 'M6 9a6 6 0 0 1 12 0c0 6 2.5 8 2.5 8h-17S6 15 6 9M10 20.5a2.2 2.2 0 0 0 4 0',
    'sparkle': 'M12 3l1.8 5.6L19.5 10l-5.7 1.6L12 17.5l-1.8-5.9L4.5 10l5.7-1.4zM19 15l.8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8z',
    'info': 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 16.5v-5M12 7.5h.01',
    'cmd': 'M9 6a3 3 0 1 0-3 3h12a3 3 0 1 0-3-3v12a3 3 0 1 0 3-3H6a3 3 0 1 0 3 3z',
    'tab': 'M4 6h16v13H4zM4 10h16',
    'point': 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z',
}
_ICONS = {}


def pixmap(name, color=None, px=20, sw=1.8):
    color = color or colors()['ac']
    path = PATHS.get(name, name)
    key = (path, color, px, sw)
    pm = _ICONS.get(key)
    if pm is None:
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="{path}" fill="none" stroke="{color}" '
               f'stroke-width="{sw}" stroke-linecap="round" stroke-linejoin="round"/></svg>')
        dpr = 3
        pm = QPixmap(px * dpr, px * dpr)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        QSvgRenderer(QByteArray(svg.encode())).render(p)
        p.end()
        pm.setDevicePixelRatio(dpr)
        _ICONS[key] = pm
    return pm


def icon(name, color=None, px=20, sw=1.8):
    return QIcon(pixmap(name, color, px, sw))


def dot(color, px=12, d=8):
    """A small filled status dot."""
    dpr = 3
    pm = QPixmap(px * dpr, px * dpr)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(color))
    o = (px - d) / 2 * dpr
    p.drawEllipse(QRectF(o, o, d * dpr, d * dpr))
    p.end()
    pm.setDevicePixelRatio(dpr)
    return QIcon(pm)


def ring(color, px=12, d=8):
    """A small hollow status dot."""
    dpr = 3
    pm = QPixmap(px * dpr, px * dpr)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(QPen(QColor(color), 1.4 * dpr))
    o = (px - d) / 2 * dpr + .7 * dpr
    p.drawEllipse(QRectF(o, o, d * dpr - 1.4 * dpr, d * dpr - 1.4 * dpr))
    p.end()
    pm.setDevicePixelRatio(dpr)
    return QIcon(pm)


def tool(btn, name, text=None, tip=None, px=16):
    """Give a tool button a line icon (and optional text beside it)."""
    btn.setIcon(icon(name, colors()['fg'] if not text else colors()['ac'], px))
    btn.setIconSize(QSize(px, px))
    if text is not None:
        btn.setText(text)
        btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
    else:
        btn.setText('')
    if tip:
        btn.setToolTip(tip)
    btn.setAutoRaise(True)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    return btn


def disclose(btn, text):
    """A 'Show more' toggle: a small chevron before the text, pointing right when closed and down when open."""
    btn.setCheckable(True)
    btn.setText(text)
    btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
    btn.setIconSize(QSize(12, 12))
    btn.setAutoRaise(True)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)

    def upd(on):
        btn.setIcon(icon('down' if on else 'fwd', colors()['mu'], 12, 2.2))
    btn.toggled.connect(upd)
    upd(btn.isChecked())
    return btn


def primary(btn):
    """The one filled, accent-coloured button on a page."""
    ac = QColor(colors()['ac'])
    hov = ac.lighter(112).name()
    btn.setStyleSheet(f'QPushButton{{background:{ac.name()};color:white;border:0;border-radius:6px;padding:6px 16px;font-weight:600}}'
                      f'QPushButton:hover{{background:{hov}}}QPushButton:disabled{{background:rgba(120,120,128,0.25);color:rgba(255,255,255,0.7)}}')
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    return btn


def surface_css(name, radius=12):
    """A raised, borderless card (white on light grey, soft grey on dark)."""
    return f"QFrame#{name}{{background:{colors()['card']};border-radius:{radius}px}}"


# ------------------------------------------------------- segmented control --
SEG_BTN = ('QToolButton{border:0;background:transparent;padding:5px 18px;font-weight:600;color:palette(window-text)}'
           'QToolButton:disabled{color:palette(mid)}')


class Segmented(QFrame):
    """A segmented control: the selected segment sits on a raised 'thumb' that slides when the choice changes."""

    def __init__(self, buttons, min_width=0):
        super().__init__()
        self.btns = list(buttons)
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(2, 2, 2, 2)
        lay.setSpacing(0)
        for b in self.btns:
            b.setCheckable(True)
            b.setStyleSheet(SEG_BTN)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            if min_width:
                b.setMinimumWidth(min_width)
            self.group.addButton(b)
            lay.addWidget(b)
            b.toggled.connect(lambda on, b=b: on and self._go(b))
        self._r = None
        self._a = QVariantAnimation(self)
        self._a.setDuration(220)
        self._a.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._a.valueChanged.connect(self._set)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

    def _target(self):
        b = next((b for b in self.btns if b.isChecked()), None)
        return QRectF(b.geometry()) if b else None

    def _go(self, b):
        t = QRectF(b.geometry())
        if self._r is None or not self.isVisible() or t.width() <= 0:
            self._r = t if t.width() > 0 else None
            self.update()
            return
        self._a.stop()
        self._a.setStartValue(QRectF(self._r))
        self._a.setEndValue(t)
        self._a.start()

    def _set(self, r):
        self._r = QRectF(r)
        self.update()

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._a.stop()
        self._r = self._target()

    def showEvent(self, e):
        super().showEvent(e)
        QTimer.singleShot(0, lambda: (self._a.stop(), setattr(self, '_r', self._target()), self.update()))

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        dark = is_dark()
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(118, 118, 128, 62 if dark else 32))
        p.drawRoundedRect(QRectF(self.rect()), 9, 9)
        if self._r is not None:
            r = QRectF(self._r)
            p.setBrush(QColor(0, 0, 0, 60 if dark else 26))
            p.drawRoundedRect(r.translated(0, 1), 7, 7)
            p.setBrush(QColor('#5a5a5e' if dark else '#ffffff'))
            p.drawRoundedRect(r, 7, 7)
        p.end()


# ------------------------------------------------------------------ toast --
class Toast(QFrame):
    """A small rounded banner at the bottom centre that fades in and out, with an optional action (Undo)."""

    def __init__(self, host):
        super().__init__(host)
        self.setObjectName('toast')
        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 10, 10, 10)
        lay.setSpacing(12)
        self.lab = QLabel()
        self.lab.setWordWrap(True)
        self.lab.setMaximumWidth(560)
        lay.addWidget(self.lab, 1)
        self.btn = QPushButton()
        self.btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn.clicked.connect(self._act)
        lay.addWidget(self.btn)
        self.setStyleSheet('QFrame#toast{background:rgba(44,44,46,240);border-radius:12px}'
                           'QFrame#toast QLabel{color:white}'
                           'QFrame#toast QPushButton{color:#64d2ff;font-weight:600;border:0;background:transparent;padding:2px 8px}'
                           'QFrame#toast QPushButton:hover{color:#9ee4ff}')
        self.eff = QGraphicsOpacityEffect(self)
        self.eff.setOpacity(0)
        self.setGraphicsEffect(self.eff)
        self.anim = QPropertyAnimation(self.eff, b'opacity', self)
        self.anim.setDuration(170)
        self.anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.anim.finished.connect(lambda: self.eff.opacity() < .05 and self.hide())
        self.timer = QTimer(self, singleShot=True, timeout=self.fade_out)
        self.fn = None
        self.hide()
        host.installEventFilter(self)

    def show_msg(self, text, action=None, action_text='Undo', ms=None):
        self.lab.setText(text)
        self.fn = action
        self.btn.setVisible(bool(action))
        self.btn.setText(action_text)
        self.adjustSize()
        self._place()
        self.raise_()
        self.show()
        self.anim.stop()
        self.anim.setStartValue(self.eff.opacity())
        self.anim.setEndValue(1.0)
        self.anim.start()
        self.timer.start(ms or (7000 if action else 3500))

    def text(self):
        return self.lab.text() if self.isVisible() else ''

    def _act(self):
        fn, self.fn = self.fn, None
        self.fade_out()
        if fn:
            fn()

    def fade_out(self):
        self.timer.stop()
        self.anim.stop()
        self.anim.setStartValue(self.eff.opacity())
        self.anim.setEndValue(0.0)
        self.anim.start()

    def _place(self):
        h = self.parentWidget()
        self.move(max(8, (h.width() - self.width()) // 2), h.height() - self.height() - 28)

    def eventFilter(self, o, e):
        if e.type() == QEvent.Type.Resize and self.isVisible():
            self._place()
        return False

    def enterEvent(self, e):
        self.timer.stop()
        super().enterEvent(e)

    def leaveEvent(self, e):
        self.timer.start(2500)
        super().leaveEvent(e)


# --------------------------------------------------------- progress bits --
class _Ticker:
    """One shared 30 fps timer for spinners, skeletons and the progress bar (only runs while one is visible)."""
    widgets = set()
    timer = None

    @classmethod
    def add(cls, w):
        cls.widgets.add(w)
        if cls.timer is None:
            cls.timer = QTimer()
            cls.timer.setInterval(33)
            cls.timer.timeout.connect(cls.tick)
        if not cls.timer.isActive():
            cls.timer.start()

    @classmethod
    def remove(cls, w):
        cls.widgets.discard(w)
        if not cls.widgets and cls.timer is not None:
            cls.timer.stop()

    @classmethod
    def tick(cls):
        for w in list(cls.widgets):
            try:
                w.update()
            except RuntimeError:                  # deleted
                cls.widgets.discard(w)


class _Animated(QWidget):
    def showEvent(self, e):
        super().showEvent(e)
        _Ticker.add(self)

    def hideEvent(self, e):
        _Ticker.remove(self)
        super().hideEvent(e)

    def closeEvent(self, e):
        _Ticker.remove(self)
        super().closeEvent(e)


class TopProgress(_Animated):
    """A 3-pixel progress line under the toolbar: a sliding segment while busy, or a filling bar with a percentage."""

    def __init__(self):
        super().__init__()
        self.setFixedHeight(3)
        self.on = False
        self.pct = None
        self.shown = 0.0

    def set_state(self, on, pct=None):
        if on == self.on and pct == self.pct:
            return
        self.on, self.pct = on, pct
        if on:
            _Ticker.add(self)
        self.update()

    def paintEvent(self, _e):
        if not self.on:
            _Ticker.remove(self)
            return
        p = QPainter(self)
        w = self.width()
        ac = QColor(colors()['ac'])
        if self.pct is not None:
            self.shown += (self.pct / 100 - self.shown) * .25
            p.fillRect(QRectF(0, 0, w * self.shown, 3), ac)
        else:
            ph = (time.monotonic() % 1.4) / 1.4
            seg = w * .28
            x = -seg + (w + seg) * QEasingCurve(QEasingCurve.Type.InOutCubic).valueForProgress(ph)
            g = QLinearGradient(x, 0, x + seg, 0)
            c0 = QColor(ac)
            c0.setAlpha(0)
            g.setColorAt(0, c0)
            g.setColorAt(.5, ac)
            g.setColorAt(1, c0)
            p.fillRect(QRectF(x, 0, seg, 3), g)
        p.end()


class Spinner(_Animated):
    """A small spinning arc (the 'working' indicator)."""

    def __init__(self, px=16):
        super().__init__()
        self.setFixedSize(px, px)

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor(colors()['ac']), 2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        a = int((time.monotonic() * 360) % 360)
        r = QRectF(self.rect()).adjusted(2, 2, -2, -2)
        p.drawArc(r, -a * 16, 270 * 16)
        p.end()


def busy_row(text):
    """Spinner + muted text, for 'reading…' messages."""
    w = QWidget()
    h = QHBoxLayout(w)
    h.setContentsMargins(0, 0, 0, 0)
    h.setSpacing(8)
    h.addWidget(Spinner())
    lab = label(text, muted=True)
    h.addWidget(lab, 1)
    w.lab = lab
    return w


class Skeleton(_Animated):
    """Grey placeholder rows with a soft shimmer, shown while data is loading."""

    def __init__(self, rows=6, row_h=30):
        super().__init__()
        self.rows, self.row_h = rows, row_h
        self.setFixedHeight(rows * row_h)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        dark = is_dark()
        base = QColor(255, 255, 255, 22) if dark else QColor(0, 0, 0, 16)
        hi = QColor(255, 255, 255, 46) if dark else QColor(255, 255, 255, 170)
        w = self.width()
        ph = (time.monotonic() % 1.6) / 1.6
        x = -w * .4 + w * 1.8 * ph
        for i in range(self.rows):
            y = i * self.row_h + (self.row_h - 12) / 2
            for x0, frac in ((0, .22), (w * .26, .30 if i % 2 else .42), (w * .78, .14)):
                r = QRectF(x0, y, w * frac, 12)
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(base)
                p.drawRoundedRect(r, 6, 6)
                g = QLinearGradient(x, 0, x + w * .4, 0)
                c0 = QColor(hi)
                c0.setAlpha(0)
                g.setColorAt(0, c0)
                g.setColorAt(.5, hi)
                g.setColorAt(1, c0)
                p.setBrush(g)
                p.drawRoundedRect(r, 6, 6)
        p.end()


# ------------------------------------------------------------ empty state --
class EmptyState(QWidget):
    """Centred icon, one title, one sentence and a primary button (instead of a blank page)."""

    def __init__(self, icon_name='file', title='', text='', buttons=()):
        super().__init__()
        v = QVBoxLayout(self)
        v.setContentsMargins(24, 24, 24, 24)
        v.setSpacing(8)
        v.addStretch(2)
        self.ic = QLabel()
        self.ic.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.addWidget(self.ic)
        v.addSpacing(4)
        self.t = label('', bold=True, size=17)
        self.t.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.addWidget(self.t)
        self.s = label('', muted=True)
        self.s.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.s.setFixedWidth(480)
        v.addWidget(self.s, 0, Qt.AlignmentFlag.AlignHCenter)
        self.busy = Spinner(20)
        v.addWidget(self.busy, 0, Qt.AlignmentFlag.AlignHCenter)
        self.busy.hide()
        v.addSpacing(8)
        self.bw = QWidget()
        self.bl = QHBoxLayout(self.bw)
        self.bl.setContentsMargins(0, 0, 0, 0)
        self.bl.setSpacing(8)
        v.addWidget(self.bw, 0, Qt.AlignmentFlag.AlignHCenter)
        v.addStretch(3)
        self._icon = None
        self.set(icon_name, title, text, buttons)

    def set(self, icon_name=None, title=None, text=None, buttons=None, busy=False):
        if icon_name is not None:
            self._icon = icon_name
        if self._icon:
            self.ic.setPixmap(pixmap(self._icon, colors()['mu'], 56, 1.4))
        if title is not None:
            self.t.setText(title)
        if text is not None:
            self.s.setText(text)
            self.s.setVisible(bool(text))
        self.busy.setVisible(busy)
        if buttons is not None:
            while self.bl.count():
                w = self.bl.takeAt(0).widget()
                if w:
                    w.setParent(None)
                    w.deleteLater()
            for i, (t, fn) in enumerate(buttons):
                b = QPushButton(t)
                b.clicked.connect(fn)
                if i == 0:
                    primary(b)
                self.bl.addWidget(b)
            self.bw.setVisible(bool(buttons))

    def retheme(self):
        self.set()


# ------------------------------------------------------------------ fade --
def fade_in(w, ms=170):
    """Fade a page in (used when switching views)."""
    if w.graphicsEffect() is not None:
        return
    eff = QGraphicsOpacityEffect(w)
    eff.setOpacity(0)
    w.setGraphicsEffect(eff)
    a = QPropertyAnimation(eff, b'opacity', w)
    a.setDuration(ms)
    a.setStartValue(0.0)
    a.setEndValue(1.0)
    a.setEasingCurve(QEasingCurve.Type.OutCubic)
    a.finished.connect(lambda: w.setGraphicsEffect(None))
    a.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)


def slide_width(w, to, ms=200):
    """Animate a panel's width (the inspector sliding in)."""
    a = QPropertyAnimation(w, b'maximumWidth', w)
    a.setDuration(ms)
    a.setStartValue(w.maximumWidth() if w.isVisible() else 0)
    a.setEndValue(to)
    a.setEasingCurve(QEasingCurve.Type.OutCubic)
    a.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
    return a


# --------------------------------------------------------- command palette --
def score(q, text):
    """How well text matches what was typed (None = no match)."""
    t = text.lower()
    if not q:
        return 0
    i = t.find(q)
    if i >= 0:
        return 1000 - i - len(t) * .05 + (300 if i == 0 else 150 if not t[i - 1].isalnum() else 0)
    ws = q.split()
    if len(ws) > 1 and all(w in t for w in ws):
        return 600 - len(t) * .05
    j = 0
    gaps = 0
    last = -1
    for k, ch in enumerate(t):
        if j < len(q) and ch == q[j]:
            if last >= 0:
                gaps += k - last - 1
            last = k
            j += 1
    if j == len(q) and gaps < 3 * len(q) + 6:
        return 300 - gaps * 4 - len(t) * .05
    return None


class _RowDelegate(QStyledItemDelegate):
    """Palette row: icon, title, and a muted subtitle on the right."""

    def paint(self, p, opt, ix):
        self.initStyleOption(opt, ix)
        st = opt.widget.style() if opt.widget else QApplication.style()
        title = opt.text
        opt.text = ''
        st.drawControl(QStyle.ControlElement.CE_ItemViewItem, opt, p, opt.widget)
        r = opt.rect.adjusted(40, 0, -14, 0)
        sub = ix.data(Qt.ItemDataRole.UserRole + 1) or ''
        p.save()
        fm = opt.fontMetrics
        sw = min(fm.horizontalAdvance(sub) + 8, int(r.width() * .45)) if sub else 0
        p.setPen(opt.palette.color(QPalette.ColorRole.Text))
        p.drawText(r.adjusted(0, 0, -sw, 0), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                   fm.elidedText(title, Qt.TextElideMode.ElideRight, r.width() - sw))
        if sub:
            p.setPen(QColor(colors()['mu']))
            p.drawText(r, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                       fm.elidedText(sub, Qt.TextElideMode.ElideLeft, sw))
        p.restore()

    def sizeHint(self, opt, ix):
        s = super().sizeHint(opt, ix)
        s.setHeight(36)
        return s


class CommandPalette(QDialog):
    """Ctrl+K: type to jump to a view, a device, a point, a capture tab or any menu command."""

    def __init__(self, win, items):
        super().__init__(win, Qt.WindowType.FramelessWindowHint | Qt.WindowType.Dialog)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.items = items                     # [(icon name, title, subtitle, fn, group)]
        self.setModal(True)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 12, 12, 12)
        box = QFrame()
        box.setObjectName('pal')
        dark = is_dark()
        box.setStyleSheet(f"QFrame#pal{{background:{'#2c2c2e' if dark else '#ffffff'};border-radius:14px;"
                          f"border:1px solid {'rgba(255,255,255,0.10)' if dark else 'rgba(0,0,0,0.12)'}}}")
        outer.addWidget(box)
        v = QVBoxLayout(box)
        v.setContentsMargins(8, 8, 8, 8)
        v.setSpacing(6)
        row = QHBoxLayout()
        row.setContentsMargins(10, 4, 6, 0)
        ic = QLabel()
        ic.setPixmap(pixmap('search', colors()['mu'], 20))
        row.addWidget(ic)
        self.q = QLineEdit()
        self.q.setPlaceholderText('Search views, devices, points and commands')
        f = self.q.font()
        f.setPointSizeF(13)
        self.q.setFont(f)
        self.q.setFrame(False)
        self.q.setStyleSheet('QLineEdit{background:transparent;border:0;padding:6px 2px}')
        row.addWidget(self.q, 1)
        hint = label('esc', muted=True, wrap=False)
        row.addWidget(hint)
        v.addLayout(row)
        ln = QFrame()
        ln.setFixedHeight(1)
        ln.setStyleSheet(f"background:{'rgba(255,255,255,0.08)' if dark else 'rgba(0,0,0,0.08)'}")
        v.addWidget(ln)
        self.lst = QListWidget()
        self.lst.setFrameShape(QFrame.Shape.NoFrame)
        self.lst.setItemDelegate(_RowDelegate(self.lst))
        self.lst.setUniformItemSizes(True)
        self.lst.setIconSize(QSize(18, 18))
        self.lst.setStyleSheet('QListWidget{background:transparent;outline:0}')
        self.lst.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.lst.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        v.addWidget(self.lst, 1)
        self.foot = label('', muted=True, wrap=False)
        v.addWidget(self.foot)
        self.q.textChanged.connect(self.fill)
        self.q.installEventFilter(self)
        self.lst.itemActivated.connect(self.go)
        self.lst.itemClicked.connect(self.go)
        self.resize(680, 460)
        g = win.geometry()
        self.move(g.x() + (g.width() - self.width()) // 2, g.y() + 70)
        self.fill('')

    def fill(self, q):
        q = q.strip().lower()
        self.lst.clear()
        scored = []
        for n, it in enumerate(self.items):
            ic, title, sub, fn, grp = it
            if not q:
                if grp in ('View', 'Command', 'Tab'):
                    scored.append((-n, it))
                continue
            s = score(q, title)
            s2 = score(q, sub) if sub else None
            if s is None and s2 is not None:
                s = s2 * .6
            if s is not None:
                scored.append((s, it))
        scored.sort(key=lambda x: -x[0])
        mu = colors()['mu']
        for _s, (ic, title, sub, fn, grp) in scored[:150]:
            li = QListWidgetItem(icon(ic, colors()['ac'] if grp != 'Command' else mu, 18), title)
            li.setData(Qt.ItemDataRole.UserRole, fn)
            li.setData(Qt.ItemDataRole.UserRole + 1, f'{sub}  ·  {grp}' if sub else grp)
            self.lst.addItem(li)
        if self.lst.count():
            self.lst.setCurrentRow(0)
        n = len(scored)
        self.foot.setText(('No matches' if q else '') if not n else
                          f"{n} result{'' if n == 1 else 's'}" + (' (showing 150)' if n > 150 else '') + '   ·   ↑↓ to move, Enter to open')

    def eventFilter(self, o, e):
        if o is self.q and e.type() == QEvent.Type.KeyPress:
            k = e.key()
            if k in (Qt.Key.Key_Down, Qt.Key.Key_Up, Qt.Key.Key_PageDown, Qt.Key.Key_PageUp):
                QApplication.sendEvent(self.lst, e)
                return True
            if k in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                it = self.lst.currentItem()
                if it:
                    self.go(it)
                return True
        return False

    def go(self, it):
        fn = it.data(Qt.ItemDataRole.UserRole)
        self.accept()
        if fn:
            QTimer.singleShot(0, fn)


# --------------------------------------------------------- about / news --
def _bullets(text):
    out = []
    for ln in (text or '').splitlines():
        ln = ln.strip()
        if ln.startswith(('- ', '* ', '• ')):
            out.append(ln[2:].strip())
        elif ln and out:
            out[-1] += ' ' + ln
    return out


def whats_new_dialog(parent, version, notes, on_tour=None):
    d = QDialog(parent)
    d.setWindowTitle('What’s new')
    v = QVBoxLayout(d)
    v.setContentsMargins(28, 24, 28, 20)
    v.setSpacing(12)
    hd = QHBoxLayout()
    ic = QLabel()
    ic.setPixmap(pixmap('sparkle', colors()['ac'], 36, 1.6))
    hd.addWidget(ic)
    tt = QVBoxLayout()
    tt.setSpacing(0)
    tt.addWidget(label('What’s new', bold=True, size=20))
    tt.addWidget(label(f'BACnet Inspector {version}', muted=True))
    hd.addLayout(tt, 1)
    v.addLayout(hd)
    from PySide6.QtWidgets import QScrollArea
    sa = QScrollArea()
    sa.setWidgetResizable(True)
    sa.setFrameShape(QFrame.Shape.NoFrame)
    inner = QWidget()
    il = QVBoxLayout(inner)
    il.setContentsMargins(0, 4, 8, 4)
    il.setSpacing(10)
    items = _bullets(notes) or ['Bug fixes and improvements.']
    for b in items:
        r = QHBoxLayout()
        r.setSpacing(10)
        ck = QLabel()
        ck.setPixmap(pixmap('check', colors()['no'], 16, 2.2))
        ck.setAlignment(Qt.AlignmentFlag.AlignTop)
        ck.setContentsMargins(0, 3, 0, 0)
        r.addWidget(ck, 0, Qt.AlignmentFlag.AlignTop)
        r.addWidget(label(b), 1)
        il.addLayout(r)
    il.addStretch(1)
    sa.setWidget(inner)
    v.addWidget(sa, 1)
    br = QHBoxLayout()
    if on_tour:
        tb = QPushButton('Take the tour')
        tb.clicked.connect(lambda: (d.accept(), QTimer.singleShot(150, on_tour)))
        br.addWidget(tb)
    br.addStretch(1)
    ok = primary(QPushButton('Continue'))
    ok.clicked.connect(d.accept)
    br.addWidget(ok)
    v.addLayout(br)
    d.resize(600, min(640, 220 + 34 * len(items)))
    d.exec()


def about_dialog(parent, version, on_updates, on_news, ico_path=None, page=None):
    d = QDialog(parent)
    d.setWindowTitle('About BACnet Inspector')
    v = QVBoxLayout(d)
    v.setContentsMargins(36, 28, 36, 22)
    v.setSpacing(6)
    ic = QLabel()
    ic.setAlignment(Qt.AlignmentFlag.AlignCenter)
    if ico_path and os.path.isfile(ico_path):
        ic.setPixmap(QIcon(ico_path).pixmap(QSize(80, 80)))
    v.addWidget(ic)
    v.addSpacing(6)
    for w in (label('BACnet Inspector', bold=True, size=20), label(f'Version {version}', muted=True),
              label('Capture analysis for BACnet/IP and MS/TP, with device discovery and live reads.', muted=True)):
        w.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.addWidget(w)
    v.addSpacing(14)
    br = QHBoxLayout()
    br.addStretch(1)
    for t, fn in (('What’s new', on_news), ('Check for updates…', on_updates)):
        b = QPushButton(t)
        b.clicked.connect(lambda _=False, fn=fn: (d.accept(), fn()))
        br.addWidget(b)
    if page:
        b = QPushButton('Website')
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        b.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(page)))
        br.addWidget(b)
    br.addStretch(1)
    v.addLayout(br)
    v.addSpacing(14)
    cr = label('Includes PuTTY 0.85 (MIT licence, © Simon Tatham) and Qt / PySide6 (LGPL v3).\n'
               'Everything you open stays on your computer.', muted=True)
    f = cr.font()
    f.setPointSizeF(BODY_PT - 1)
    cr.setFont(f)
    cr.setAlignment(Qt.AlignmentFlag.AlignCenter)
    v.addWidget(cr)
    d.setFixedWidth(520)
    d.exec()


# ------------------------------------------------------------- keyboard keys --
def keycaps(keys):
    """'Ctrl+K' or 'Ctrl+1 … Ctrl+9' drawn as little keyboard keys."""
    w = QWidget()
    h = QHBoxLayout(w)
    h.setContentsMargins(0, 0, 0, 0)
    h.setSpacing(3)
    c = colors()
    dark = is_dark()
    css = (f"QLabel{{background:{'#3a3a3c' if dark else '#ffffff'};color:{c['fg']};border:1px solid "
           f"{'rgba(255,255,255,0.16)' if dark else 'rgba(0,0,0,0.16)'};border-bottom-width:2px;border-radius:5px;"
           "padding:1px 6px;font-weight:600}")
    for tok in (keys or '').split():
        if tok in ('…', 'or', '/', 'then'):
            h.addWidget(label(tok, muted=True, wrap=False))
            continue
        for i, k in enumerate(tok.split('+')):
            if i:
                h.addWidget(label('+', muted=True, wrap=False))
            cap = QLabel(k.replace('Left', '←').replace('Right', '→'))
            cap.setStyleSheet(css)
            cap.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            h.addWidget(cap)
        h.addSpacing(4)
    h.addStretch(1)
    w.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
    return w


# ------------------------------------------------------------------ tips --
class TipBubble(QWidget):
    """A small speech bubble that points at a control and suggests a shortcut or a quicker way."""
    A = 9                                      # arrow size

    def __init__(self, host, on_off):
        super().__init__(host)
        self.host = host
        self.down = False                      # False: bubble below the control, arrow on top
        self.ax = 30
        self.setFixedWidth(340)
        v = QVBoxLayout(self)
        v.setSpacing(8)
        top = QHBoxLayout()
        top.setSpacing(6)
        self.ic = QLabel()
        top.addWidget(self.ic)
        self.title = label('Tip', bold=True, wrap=False)
        top.addWidget(self.title, 1)
        self.xb = QPushButton()
        self.xb.setFlat(True)
        self.xb.setFixedSize(22, 22)
        self.xb.setCursor(Qt.CursorShape.PointingHandCursor)
        self.xb.setToolTip('Close')
        self.xb.clicked.connect(self.close_tip)
        top.addWidget(self.xb)
        v.addLayout(top)
        self.text = label('', wrap=True)
        v.addWidget(self.text)
        self.kw = QWidget()
        self.kl = QVBoxLayout(self.kw)
        self.kl.setContentsMargins(0, 0, 0, 0)
        v.addWidget(self.kw)
        bot = QHBoxLayout()
        self.off = QPushButton('Turn off tips')
        self.off.setFlat(True)
        self.off.setCursor(Qt.CursorShape.PointingHandCursor)
        self.off.clicked.connect(lambda: (self.close_tip(), on_off()))
        bot.addWidget(self.off)
        bot.addStretch(1)
        self.ok = QPushButton('Got it')
        self.ok.clicked.connect(self.close_tip)
        bot.addWidget(self.ok)
        v.addLayout(bot)
        sh = QGraphicsDropShadowEffect(self)
        sh.setBlurRadius(28)
        sh.setOffset(0, 4)
        sh.setColor(QColor(0, 0, 0, 70))
        self.setGraphicsEffect(sh)
        self.timer = QTimer(self, singleShot=True, timeout=self.close_tip)
        self.anchor = None
        self.hide()
        host.installEventFilter(self)

    def retheme(self):
        c = colors()
        self.ic.setPixmap(pixmap('f', c['wa'], 18, 1.9))
        self.title.setStyleSheet(f"color:{c['fg']}")
        self.xb.setIcon(icon('close', c['mu'], 12, 2))
        self.off.setStyleSheet(f"QPushButton{{color:{c['mu']};border:0;padding:2px 0}}QPushButton:hover{{color:{c['ac']}}}")
        primary(self.ok)

    def show_tip(self, anchor, title, text, keys=''):
        self.retheme()
        self.title.setText(title)
        self.text.setText(text)
        while self.kl.count():
            w = self.kl.takeAt(0).widget()
            if w:
                w.setParent(None)
                w.deleteLater()
        if keys:
            self.kl.addWidget(keycaps(keys))
        self.kw.setVisible(bool(keys))
        self.anchor = anchor
        self._place()
        self.raise_()
        self.show()
        self.timer.start(12000)

    def _place(self):
        h = self.host
        a = self.anchor
        if a is not None and a.isVisible():
            r = QRect(a.mapTo(h, a.rect().topLeft()), a.size())
        else:
            r = QRect(h.width() // 2 - 1, 60, 2, 2)
        m = self.layout()
        m.setContentsMargins(16, 12 + self.A, 14, 12)
        self.adjustSize()
        hh = self.height()
        self.down = r.bottom() + hh + 8 > h.height() and r.top() - hh > 8
        m.setContentsMargins(16, 12 + (0 if self.down else self.A), 14, 12 + (self.A if self.down else 0))
        self.adjustSize()
        hh = self.height()
        cx = min(r.center().x(), r.left() + 60)
        x = max(8, min(h.width() - self.width() - 8, cx - 40))
        y = r.top() - hh - 2 if self.down else r.bottom() + 2
        self.ax = max(20, min(self.width() - 20, cx - x))
        self.move(int(x), int(max(4, min(h.height() - hh - 4, y))))
        self.update()

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        A = self.A
        body = QRectF(self.rect()).adjusted(.5, .5 + (0 if self.down else A), -.5, -.5 - (A if self.down else 0))
        path = QPainterPath()
        path.addRoundedRect(body, 12, 12)
        if self.down:
            tri = QPolygonF([QPointF(self.ax - A, body.bottom() - 1), QPointF(self.ax, body.bottom() + A),
                             QPointF(self.ax + A, body.bottom() - 1)])
        else:
            tri = QPolygonF([QPointF(self.ax - A, body.top() + 1), QPointF(self.ax, body.top() - A),
                             QPointF(self.ax + A, body.top() + 1)])
        t = QPainterPath()
        t.addPolygon(tri)
        path = path.united(t)
        p.setPen(QPen(QColor(255, 255, 255, 30) if is_dark() else QColor(0, 0, 0, 30), 1))
        p.setBrush(QColor('#2c2c2e' if is_dark() else '#ffffff'))
        p.drawPath(path)
        p.end()

    def close_tip(self):
        self.timer.stop()
        self.hide()

    def eventFilter(self, o, e):
        if e.type() == QEvent.Type.Resize and self.isVisible():
            self._place()
        return False

    def enterEvent(self, e):
        self.timer.stop()
        super().enterEvent(e)

    def leaveEvent(self, e):
        self.timer.start(6000)
        super().leaveEvent(e)


# ------------------------------------------------------------------ tour --
class Tour(QWidget):
    """A guided tour: dims the window, lights up one area at a time and explains it in a card.
    steps: [(target, title, text, keys)] where target is a widget, a callable returning a QRect in window
    coordinates, or None for a centred card."""

    def __init__(self, win, steps, on_done):
        super().__init__(win)
        self.win, self.steps, self.on_done = win, steps, on_done
        self.i = 0
        self.hole = None
        self.setGeometry(win.rect())
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.card = QFrame(self)
        self.card.setObjectName('tourcard')
        self.card.setFixedWidth(400)
        cv = QVBoxLayout(self.card)
        cv.setContentsMargins(22, 18, 22, 16)
        cv.setSpacing(8)
        self.step_l = label('', muted=True, wrap=False)
        cv.addWidget(self.step_l)
        self.t = label('', bold=True, size=17, wrap=False)
        cv.addWidget(self.t)
        self.x = label('')
        cv.addWidget(self.x)
        self.kw = QWidget()
        self.kl = QVBoxLayout(self.kw)
        self.kl.setContentsMargins(0, 2, 0, 2)
        cv.addWidget(self.kw)
        cv.addSpacing(4)
        row = QHBoxLayout()
        self.skip = QPushButton('Skip tour')
        self.skip.setFlat(True)
        self.skip.setCursor(Qt.CursorShape.PointingHandCursor)
        self.skip.clicked.connect(self.finish)
        row.addWidget(self.skip)
        row.addStretch(1)
        self.dots = QLabel()
        row.addWidget(self.dots)
        row.addStretch(1)
        self.prev = QPushButton('Back')
        self.prev.clicked.connect(lambda: self.go(self.i - 1))
        row.addWidget(self.prev)
        self.nxt = QPushButton('Next')
        self.nxt.clicked.connect(lambda: self.go(self.i + 1))
        row.addWidget(self.nxt)
        cv.addLayout(row)
        sh = QGraphicsDropShadowEffect(self.card)
        sh.setBlurRadius(40)
        sh.setOffset(0, 8)
        sh.setColor(QColor(0, 0, 0, 90))
        self.card.setGraphicsEffect(sh)
        win.installEventFilter(self)
        self.show()
        self.raise_()
        self.setFocus()
        self.go(0)

    def _rect(self, target):
        if target is None:
            return None
        if callable(target) and not isinstance(target, QWidget):
            r = target()
            return QRect(r) if r is not None else None
        if not target.isVisible():
            return None
        return QRect(target.mapTo(self.win, target.rect().topLeft()), target.size())

    def go(self, i):
        if i < 0:
            return
        if i >= len(self.steps):
            return self.finish()
        self.i = i
        target, title, text, keys = self.steps[i]
        r = self._rect(target)
        self.hole = r.adjusted(-6, -6, 6, 6) if r is not None else None
        c = colors()
        dark = is_dark()
        self.card.setStyleSheet(f"QFrame#tourcard{{background:{'#2c2c2e' if dark else '#ffffff'};border-radius:14px;"
                                f"border:1px solid {'rgba(255,255,255,0.12)' if dark else 'rgba(0,0,0,0.10)'}}}")
        self.skip.setStyleSheet(f"QPushButton{{color:{c['mu']};border:0;padding:2px 0}}QPushButton:hover{{color:{c['ac']}}}")
        primary(self.nxt)
        last = i == len(self.steps) - 1
        inner = not (i == 0 or last)
        self.step_l.setText(f'{i} of {len(self.steps) - 2}' if inner else '')
        self.step_l.setVisible(inner)
        self.t.setText(title)
        self.x.setText(text)
        while self.kl.count():
            w = self.kl.takeAt(0).widget()
            if w:
                w.setParent(None)
                w.deleteLater()
        if keys:
            self.kl.addWidget(keycaps(keys))
        self.kw.setVisible(bool(keys))
        self.prev.setVisible(inner)
        self.skip.setVisible(not last)
        self.nxt.setText('Start the tour' if i == 0 else 'Done' if last else 'Next')
        self.dots.setText(' '.join(f"<span style='color:{c['ac'] if k == i else c['bd']}'>●</span>"
                                   for k in range(len(self.steps))))
        self.card.adjustSize()
        self._place_card()
        fade_in(self.card, 200)
        self.update()
        self.nxt.setFocus()

    def _place_card(self):
        W, H = self.width(), self.height()
        cw, ch = self.card.width(), self.card.height()
        h = self.hole
        if h is None:
            x, y = (W - cw) // 2, (H - ch) // 2
        else:
            gap = 16
            spots = [(h.left(), h.bottom() + gap), (h.right() + gap, h.top()), (h.left(), h.top() - ch - gap),
                     (h.left() - cw - gap, h.top())]
            x, y = next(((x, y) for x, y in spots if y >= 8 and y + ch <= H - 8 and x <= W - 60 and x + cw >= 60),
                        ((W - cw) // 2, H - ch - 24))
            x = max(8, min(W - cw - 8, x))
            y = max(8, min(H - ch - 8, y))
        self.card.move(int(x), int(y))

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        path = QPainterPath()
        path.setFillRule(Qt.FillRule.OddEvenFill)
        path.addRect(QRectF(self.rect()))
        if self.hole is not None:
            path.addRoundedRect(QRectF(self.hole), 10, 10)
        p.fillPath(path, QColor(0, 0, 0, 125 if is_dark() else 100))
        if self.hole is not None:
            p.setPen(QPen(QColor(colors()['ac']), 2))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRoundedRect(QRectF(self.hole), 10, 10)
        p.end()

    def mousePressEvent(self, e):
        e.accept()                               # the window underneath waits until the tour is over

    def keyPressEvent(self, e):
        k = e.key()
        if k == Qt.Key.Key_Escape:
            self.finish()
        elif k in (Qt.Key.Key_Right, Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Space):
            self.go(self.i + 1)
        elif k == Qt.Key.Key_Left:
            self.go(self.i - 1)

    def eventFilter(self, o, e):
        if o is self.win and e.type() == QEvent.Type.Resize:
            self.setGeometry(self.win.rect())
            QTimer.singleShot(0, lambda: self.go(self.i))
        return False

    def finish(self):
        self.win.removeEventFilter(self)
        self.hide()
        self.deleteLater()
        if self.on_done:
            self.on_done()
