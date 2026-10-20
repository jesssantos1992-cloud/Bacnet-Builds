"""
bi_common.py - shared pieces for the native UI: theme colours, HTML for reports and saved web
pages, CSV, table helpers and the square-grid widget used by Available IDs / networks and MS/TP.
"""
from __future__ import annotations

import html
import re
import time

from PySide6.QtCore import QPoint, QRect, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QGuiApplication, QPainter, QPalette, QPen, QTextDocument
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QFrame, QHBoxLayout, QHeaderView, QLabel, QLayout,
                               QSizePolicy,
                               QStyle, QStyledItemDelegate, QStyleOptionViewItem, QTableWidget, QTableWidgetItem,
                               QToolTip, QVBoxLayout, QWidget)

MONO = 'Cascadia Mono, Consolas, monospace'
ROW_H = 28                     # tree and table row height
# type scale (points): display numbers, page titles, section headings; body text is the app font (10 pt)
DISPLAY, TITLE, HEADLINE = 22, 17, 13


def is_dark():
    hints = QGuiApplication.styleHints()
    try:
        cs = hints.colorScheme()
        if cs == Qt.ColorScheme.Dark:
            return True
        if cs == Qt.ColorScheme.Light:
            return False
    except AttributeError:
        pass
    return QGuiApplication.palette().color(QPalette.ColorRole.Window).lightness() < 128


def colors():
    """The app's accent / status colours, matching the original design, for light or dark mode."""
    if is_dark():
        return {'bg': '#1c1c1e', 'fg': '#f5f5f7', 'mu': '#98989d', 'bd': '#38383a', 'hd': '#2a2a2c', 'b': '#1e2631',
                'm': '#1d2a22', 'bad': '#3b1f22', 'ac': '#0a84ff', 'se': '#ff453a', 'wa': '#ff9f0a', 'no': '#30d158',
                'hit': '#fde68a', 'ip': '#23324f', 'mac': '#4a3416', 'net': '#3a2350', 'id': '#163d24',
                'card': '#2a2a2c', 'side': '#252527', 'hair': 'rgba(255,255,255,0.08)'}
    return {'bg': '#ffffff', 'fg': '#1d1d1f', 'mu': '#6e6e73', 'bd': '#e3e3e8', 'hd': '#f5f5f7', 'b': '#f3f7ff',
            'm': '#f3faf6', 'bad': '#ffecec', 'ac': '#0071e3', 'se': '#d70015', 'wa': '#b86e00', 'no': '#248a3d',
            'hit': '#fde68a', 'ip': '#d6e2fb', 'mac': '#f8e3c7', 'net': '#ead9f9', 'id': '#d0eedb',
            'card': '#ffffff', 'side': '#eaeaee', 'hair': 'rgba(0,0,0,0.08)'}


SEV_LABEL = {'SERIOUS': 'serious', 'WARNING': 'warnings', 'NOTE': 'notes'}


def sev_color(s):
    c = colors()
    return {'SERIOUS': c['se'], 'WARNING': c['wa'], 'NOTE': c['no']}.get(s, c['mu'])


def esc(s):
    return html.escape(str(s), quote=False)


def dev_name(name, dev_id):
    """A device's name, or '' when it is only the factory default (e.g. "device240011" for device 240011)."""
    if not name or dev_id is None:
        return name or ''
    return '' if re.sub(r'[\s_\-.]', '', str(name)).lower() == f'device{dev_id}' else name


def qa(s):
    return html.escape(str(s), quote=True)


# ---------------------------------------------------------------- labels --
class Labels:
    """Formats device / network names next to numbers (the original's lbs / lz / hl)."""

    def __init__(self, store):
        self.store = store

    def d(self, n):
        return self.store.label('d', n)

    def n(self, n):
        return self.store.label('n', n)

    def lz(self, s):
        """Plain text: add “name” after 'device 123' and 'network 5'."""
        s = re.sub(r'\b([Dd]evice) (\d+)\b', lambda m: m.group(0) + (f' “{self.d(m.group(2))}”' if self.d(m.group(2)) else ''), s)
        return re.sub(r'\bnetwork (\d+)\b', lambda m: m.group(0) + (f' “{self.n(m.group(1))}”' if self.n(m.group(1)) else ''), s)

    HRE = re.compile(r'(\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b)|(MS/TP MAC \d+|\bMAC \d+\b)|(\b(?:[Nn]etwork|net) \d+\b)|'
                     r'(\b[Dd]evice(?: ID)? \d+\b)|(\bvia gateway\b)')

    def hl(self, x, for_export=False, names=True):
        """HTML: colour IP addresses, MS/TP MACs, networks and device IDs (as on the original pages).
        names=False when the text already carries the “name” after each number."""
        c = colors() if not for_export else colors_light()
        out = []
        last = 0
        s = str(x)
        for m in self.HRE.finditer(s):
            out.append(esc(s[last:m.start()]))
            t = esc(m.group(0))
            if m.group(5):
                out.append(f'<b style="color:{c["ac"]}">{t}</b>')
            else:
                kind = 'ip' if m.group(1) else 'mac' if m.group(2) else 'net' if m.group(3) else 'id'
                out.append(f'<span style="background-color:{c[kind]};font-family:{MONO}">&nbsp;{t}&nbsp;</span>')
                num = re.search(r'\d+', m.group(0)).group(0) if kind in ('net', 'id') else None
                lab = (self.n(num) if kind == 'net' else self.d(num) if kind == 'id' else '') if names else ''
                if lab:
                    out.append(f' <i style="color:{c["mu"]}">“{esc(lab)}”</i>')
            last = m.end()
        out.append(esc(s[last:]))
        return ''.join(out)


LABELS = None          # set by the main window; used by HighlightDelegate


class RowDelegate(QStyledItemDelegate):
    """Gives tree / list rows a comfortable height."""

    def __init__(self, parent=None, row_h=ROW_H):
        super().__init__(parent)
        self.row_h = row_h

    def sizeHint(self, opt, ix):
        s = super().sizeHint(opt, ix)
        if self.row_h and s.height() < self.row_h:
            s.setHeight(self.row_h)
        return s


class HighlightDelegate(QStyledItemDelegate):
    """Draws a table / tree cell with IP addresses, MACs, networks and device IDs highlighted."""
    row_h = None

    def paint(self, p, opt, ix):
        o = QStyleOptionViewItem(opt)
        self.initStyleOption(o, ix)
        text = o.text
        if not text or LABELS is None or not Labels.HRE.search(text):
            return super().paint(p, opt, ix)
        o.text = ''
        w = o.widget
        st = w.style() if w else QApplication.style()
        st.drawControl(QStyle.ControlElement.CE_ItemViewItem, o, p, w)
        r = st.subElementRect(QStyle.SubElement.SE_ItemViewItemText, o, w)
        sel = bool(o.state & QStyle.StateFlag.State_Selected)
        fg = o.palette.color(QPalette.ColorRole.Text)      # the Windows 11 style marks selection with a light tint
        if sel and w is not None and w.style().name().lower() != 'windows11':
            fg = o.palette.color(QPalette.ColorRole.HighlightedText)
        b = o.index.data(Qt.ItemDataRole.ForegroundRole)
        if b is not None and not sel:
            fg = b.color() if hasattr(b, 'color') else QColor(b)
        doc = self._doc(text, o.font, fg)
        p.save()
        p.setClipRect(r)
        p.translate(r.left() + 1, r.top() + max(0, (r.height() - doc.size().height()) / 2))
        doc.drawContents(p)
        p.restore()

    @staticmethod
    def _doc(text, font, fg):
        doc = QTextDocument()
        doc.setDefaultFont(font)
        doc.setDocumentMargin(0)
        bold = 'font-weight:600;' if font.bold() else ''
        doc.setHtml(f'<span style="white-space:pre;color:{fg.name()};{bold}">{LABELS.hl(text, names=False)}</span>')
        return doc

    def sizeHint(self, opt, ix):
        s = super().sizeHint(opt, ix)
        text = ix.data(Qt.ItemDataRole.DisplayRole)
        if text and LABELS is not None and Labels.HRE.search(str(text)):
            o = QStyleOptionViewItem(opt)
            self.initStyleOption(o, ix)
            extra = s.width() - o.fontMetrics.horizontalAdvance(str(text))      # icon, indent and padding
            s.setWidth(int(self._doc(str(text), o.font, QColor('black')).idealWidth()) + max(extra, 12))
        if self.row_h and s.height() < self.row_h:
            s.setHeight(self.row_h)
        return s


def colors_light():
    return {'bg': '#ffffff', 'fg': '#1d1d1f', 'mu': '#6e6e73', 'bd': '#e3e3e8', 'hd': '#f5f5f7', 'b': '#f3f7ff',
            'm': '#f3faf6', 'bad': '#ffecec', 'ac': '#0071e3', 'se': '#d70015', 'wa': '#b86e00', 'no': '#248a3d',
            'hit': '#fde68a', 'ip': '#d6e2fb', 'mac': '#f8e3c7', 'net': '#ead9f9', 'id': '#d0eedb',
            'card': '#ffffff', 'side': '#eaeaee', 'hair': 'rgba(0,0,0,0.08)'}


# ------------------------------------------------------- saved web pages --
DOC_CSS = """
body{font:14px/1.5 'Segoe UI',system-ui,sans-serif;color:#1d1d1f;background:#fff;margin:0;padding:18px 24px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:26px 0 8px;border-bottom:2px solid #e3e3e8;padding-bottom:4px}
h3{font-size:15px;margin:20px 0 8px}.mu{color:#6e6e73}
table{border-collapse:collapse;margin:6px 0 14px;font-size:13px}
th,td{padding:4px 10px;text-align:left;border-bottom:1px solid #e3e3e8;vertical-align:top}
th{background:#f5f5f7;font-weight:600;font-size:12px;color:#6e6e73}
tr.b td{background:#f3f7ff}tr.m td{background:#f3faf6}tr.bad td{background:#ffecec}
.card{border-radius:10px;background:#f5f5f7;padding:12px 16px;margin:0 0 18px;border-left:5px solid #248a3d}
.card.SERIOUS{border-left-color:#d70015}.card.WARNING{border-left-color:#b86e00}
.tag{font-size:11px;font-weight:700}.SERIOUS .tag{color:#d70015}.WARNING .tag{color:#b86e00}.NOTE .tag{color:#248a3d}
.lb{margin:12px 0 4px;font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:#6e6e73;font-weight:700}
.pill{padding:2px 10px;border-radius:12px;font-weight:600;font-size:12px;background:#f0f0f2;margin-right:6px}
.pill.SERIOUS{color:#d70015}.pill.WARNING{color:#b86e00}.pill.NOTE{color:#248a3d}
ul.ev{list-style:none;padding:0}ul.ev li{background:#fff;border-radius:6px;padding:6px 10px;margin:4px 0}
.mono{font-family:Consolas,monospace}.cells{display:grid;gap:3px;max-width:560px}
.cl{font:11px Consolas,monospace;height:22px;display:flex;align-items:center;justify-content:center;border-radius:5px}
"""


def doc(title, body):
    return (f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<title>{esc(title)}</title><style>{DOC_CSS}</style></head><body>{body}</body></html>')


def stamp():
    return time.strftime('%Y-%m-%d %H:%M:%S')


def html_table(headers, rows, row_cls=None):
    h = ''.join(f'<th>{x}</th>' for x in headers)
    b = []
    for i, r in enumerate(rows):
        cls = f' class="{row_cls[i]}"' if row_cls and row_cls[i] else ''
        b.append(f'<tr{cls}>' + ''.join(f'<td>{c}</td>' for c in r) + '</tr>')
    return f'<table><thead><tr>{h}</tr></thead><tbody>{"".join(b)}</tbody></table>'


def csvc(v):
    v = '' if v is None else str(v)
    return '"' + v.replace('"', '""') + '"' if re.search(r'[",\n\r]', v) else v


def csv_text(header, rows):
    return '\r\n'.join([header] + [','.join(csvc(c) for c in r) for r in rows])


# ------------------------------------------------------------ Excel (.xlsx) --
_NUMCELL = re.compile(r'^-?(0|[1-9]\d{0,14})(\.\d+)?$')
_BADXML = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f]')


def _col(n):
    s = ''
    n += 1
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def xlsx(rows, sheet='Sheet1'):
    """A small Excel workbook (bold, frozen, filterable header row; sized columns) from a list of rows."""
    import io
    import zipfile
    from xml.sax.saxutils import escape
    rows = [list(r) for r in rows] or [['']]
    ncol = max(len(r) for r in rows)
    width = [8] * ncol
    out = []
    for i, r in enumerate(rows):
        cells = []
        for j, v in enumerate(r):
            v = '' if v is None else str(v)
            width[j] = min(60, max(width[j], len(v) + 2))
            ref = f'{_col(j)}{i + 1}'
            if i and _NUMCELL.match(v):
                cells.append(f'<c r="{ref}"><v>{v}</v></c>')
            elif v:
                st = ' s="1"' if i == 0 else ''
                cells.append(f'<c r="{ref}" t="inlineStr"{st}><is><t xml:space="preserve">{escape(_BADXML.sub("", v))}</t></is></c>')
        out.append(f'<row r="{i + 1}">{"".join(cells)}</row>')
    cols = ''.join(f'<col min="{j + 1}" max="{j + 1}" width="{w}" customWidth="1"/>' for j, w in enumerate(width))
    ws = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
          '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
          f'</sheetView></sheetViews><cols>{cols}</cols><sheetData>{"".join(out)}</sheetData>'
          f'<autoFilter ref="A1:{_col(ncol - 1)}{len(rows)}"/></worksheet>')
    files = {
        '[Content_Types].xml': '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>',
        '_rels/.rels': '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
        'xl/workbook.xml': '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<sheets><sheet name="{escape(sheet[:31])}" sheetId="1" r:id="rId1"/></sheets>'
        f'<definedNames><definedName name="_xlnm._FilterDatabase" localSheetId="0" hidden="1">\'{escape(sheet[:31])}\'!$A$1:${_col(ncol - 1)}${len(rows)}</definedName></definedNames></workbook>',
        'xl/_rels/workbook.xml.rels': '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>',
        'xl/styles.xml': '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
        '<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>',
        'xl/worksheets/sheet1.xml': ws}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def csv_to_xlsx(text, sheet='Sheet1'):
    """The same table as a CSV export, as an Excel workbook."""
    import csv
    import io
    return xlsx(list(csv.reader(io.StringIO(text.lstrip('﻿')))), sheet)


# ----------------------------------------------------------- table widget --
class Table(QTableWidget):
    """A read-only table. Each cell is text or (text, style) where style may set
    'fg', 'bg', 'bold', 'mono', 'tip'. Each row can carry data (e.g. a packet filter)."""
    rowActivated = Signal(object)

    def __init__(self, headers, parent=None, stretch_last=True):
        super().__init__(0, len(headers), parent)
        self.setHorizontalHeaderLabels(headers)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(False)
        self.setWordWrap(False)
        self.setShowGrid(False)
        self.setFrameShape(QFrame.Shape.NoFrame)
        hh = self.horizontalHeader()
        hh.setStretchLastSection(stretch_last)
        hh.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hh.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.verticalHeader().setDefaultSectionSize(ROW_H + 2)
        self.setItemDelegate(HighlightDelegate(self))
        self._data = []
        self.itemActivated.connect(lambda it: self.rowActivated.emit(self._data[it.row()] if it.row() < len(self._data) else None))

    def fill(self, rows, data=None, autosize=True):
        self.setUpdatesEnabled(False)
        self.setRowCount(0)
        self.setRowCount(len(rows))
        self._data = list(data) if data is not None else [None] * len(rows)
        bold = semibold(QFont(self.font()))
        mono = QFont('Cascadia Mono')
        mono.setStyleHint(QFont.StyleHint.Monospace)
        mono.setPointSizeF(self.font().pointSizeF() * .95)
        for i, r in enumerate(rows):
            for j, c in enumerate(r):
                st = {}
                if isinstance(c, tuple):
                    c, st = c
                it = QTableWidgetItem('' if c is None else str(c))
                if st.get('fg'):
                    it.setForeground(QBrush(QColor(st['fg'])))
                if st.get('bg'):
                    it.setBackground(QBrush(QColor(st['bg'])))
                if st.get('bold'):
                    it.setFont(bold)
                if st.get('mono'):
                    it.setFont(mono)
                if st.get('tip'):
                    it.setToolTip(st['tip'])
                elif c and len(str(c)) > 60:
                    it.setToolTip(str(c))
                if st.get('num'):
                    it.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                self.setItem(i, j, it)
        if autosize and len(rows) <= 2000:
            self.resizeColumnsToContents()
            for j in range(self.columnCount() - 1):
                if self.columnWidth(j) > 420:
                    self.setColumnWidth(j, 420)
        self.setUpdatesEnabled(True)

    def fit_height(self, max_rows=None):
        """Grow to show every row (for tables stacked on a scrolling page)."""
        n = self.rowCount() if max_rows is None else min(self.rowCount(), max_rows)
        h = self.horizontalHeader().height() + sum(self.rowHeight(i) for i in range(n)) + 2 * self.frameWidth() + 4
        if self.horizontalScrollBar().isVisible() or self.horizontalHeader().length() > self.viewport().width():
            h += self.horizontalScrollBar().sizeHint().height()
        self.setMinimumHeight(min(h, 100000))
        self.setMaximumHeight(min(h, 100000))
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff if max_rows is None else Qt.ScrollBarPolicy.ScrollBarAsNeeded)

    def row_data(self):
        r = self.currentRow()
        return self._data[r] if 0 <= r < len(self._data) else None


# ---------------------------------------------------------------- widgets --
def label(text='', wrap=True, muted=False, bold=False, size=None, rich=False, sel=False):
    w = QLabel()
    if rich:
        w.setTextFormat(Qt.TextFormat.RichText)
    else:
        w.setTextFormat(Qt.TextFormat.PlainText)
    w.setText(text)
    w.setWordWrap(wrap)
    if muted:
        w.setProperty('muted', True)
        pal = w.palette()
        pal.setColor(QPalette.ColorRole.WindowText, QColor(colors()['mu']))
        w.setPalette(pal)
    if bold or size:
        f = w.font()
        if bold:
            f.setWeight(QFont.Weight.DemiBold)
        if size:
            f.setPointSizeF(type_size(size))
        w.setFont(f)
    if sel:
        w.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return w


def type_size(size):
    """Snap a requested size onto the app's few type sizes."""
    return DISPLAY if size >= 19 else TITLE if size >= 14 else HEADLINE if size >= 11 else size


def semibold(f):
    f.setWeight(QFont.Weight.DemiBold)
    return f


def heading(text, size=HEADLINE):
    return label(text, bold=True, size=size, wrap=True)


class Pill(QLabel):
    def __init__(self, text, sev='NOTE'):
        super().__init__(text)
        c = sev_color(sev)
        col = QColor(c)
        bg = QColor(col)
        bg.setAlpha(36)
        self.setStyleSheet(f'QLabel{{color:{c};background:rgba({bg.red()},{bg.green()},{bg.blue()},{bg.alpha()});'
                           f'border-radius:9px;padding:2px 10px;font-weight:600}}')
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)


class FlowLayout(QLayout):
    """Lays widgets out left to right and wraps onto a new line when the row is full."""

    def __init__(self, parent=None, hspace=8, vspace=6):
        super().__init__(parent)
        self.items = []
        self.hs, self.vs = hspace, vspace
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item):
        self.items.append(item)

    def count(self):
        return len(self.items)

    def itemAt(self, i):
        return self.items[i] if 0 <= i < len(self.items) else None

    def takeAt(self, i):
        return self.items.pop(i) if 0 <= i < len(self.items) else None

    def expandingDirections(self):
        return Qt.Orientation(0)

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, w):
        return self._do(QRect(0, 0, w, 0), True)

    def setGeometry(self, r):
        super().setGeometry(r)
        self._do(r, False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        s = QSize()
        for it in self.items:
            s = s.expandedTo(it.minimumSize())
        m = self.contentsMargins()
        return s + QSize(m.left() + m.right(), m.top() + m.bottom())

    def _do(self, r, test):
        m = self.contentsMargins()
        x, y, line = r.x() + m.left(), r.y() + m.top(), 0
        right = r.right() - m.right()
        for it in self.items:
            sz = it.sizeHint()
            if x + sz.width() > right and line > 0:
                x = r.x() + m.left()
                y += line + self.vs
                line = 0
            if not test:
                it.setGeometry(QRect(QPoint(x, y), sz))
            x += sz.width() + self.hs
            line = max(line, sz.height())
        return y + line - r.y() + m.bottom()


def flow_row(widgets, hspace=8, vspace=6):
    """A row of widgets that wraps when the window is narrow."""
    w = QWidget()
    lay = FlowLayout(w, hspace, vspace)
    for x in widgets:
        lay.addWidget(x)
    w.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
    return w


def summary_row(title, pills, extra=()):
    """'Title  [pill] [pill]' line at the top of a view (wraps on narrow windows)."""
    t = label(title, bold=True, size=TITLE, wrap=False)
    return flow_row(([t] if title else []) + [Pill(text, sev) for text, sev in pills] + list(extra))


def hline():
    f = QFrame()
    f.setFrameShape(QFrame.Shape.HLine)
    f.setFrameShadow(QFrame.Shadow.Sunken)
    return f


class Page(QWidget):
    """A scrolling page with a centred column (the original's .fw layout)."""

    def __init__(self, max_width=1100):
        super().__init__()
        from PySide6.QtWidgets import QScrollArea
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer.addWidget(self.scroll)
        self.inner = QWidget()
        self.scroll.setWidget(self.inner)
        h = QHBoxLayout(self.inner)
        h.setContentsMargins(24, 16, 24, 24)
        self.col = QWidget()
        self.col.setMaximumWidth(max_width)
        h.addWidget(self.col, 1)
        if max_width < 10000:
            h.addStretch(0)
        self.lay = QVBoxLayout(self.col)
        self.lay.setContentsMargins(0, 0, 0, 0)
        self.lay.setSpacing(12)

    def clear(self):
        while self.lay.count():
            it = self.lay.takeAt(0)
            w = it.widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()

    def add(self, w, stretch=0):
        self.lay.addWidget(w, stretch)
        return w

    def end(self):
        self.lay.addStretch(1)


# ------------------------------------------------------------- cell grid --
class CellGrid(QWidget):
    """Numbered squares in a grid (free / taken IDs, MS/TP addresses). cells: [(text, state, tooltip)]."""

    def __init__(self, cells, cols=10, cell_w=None, max_width=560):
        super().__init__()
        self.cells = cells
        self.cols = cols
        self.max_width = max_width
        self.cell_h = 24
        self.gap = 4
        self.cell_w = cell_w
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)

    def _cw(self):
        if self.cell_w:
            return self.cell_w
        w = min(self.width(), self.max_width)
        return max(18, (w - self.gap * (self.cols - 1)) / self.cols)

    def sizeHint(self):
        rows = (len(self.cells) + self.cols - 1) // self.cols
        cw = self.cell_w or 40
        return QSize(int(min(self.max_width, self.cols * (cw + self.gap))), rows * (self.cell_h + self.gap))

    def minimumSizeHint(self):
        return QSize(self.cols * 18, self.sizeHint().height())

    def hasHeightForWidth(self):
        return False

    def _rect(self, i):
        cw = self._cw()
        r, c = divmod(i, self.cols)
        return QRectF(c * (cw + self.gap), r * (self.cell_h + self.gap), cw, self.cell_h)

    def paintEvent(self, _e):
        C = colors()
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        f = QFont('Cascadia Mono')
        f.setStyleHint(QFont.StyleHint.Monospace)
        f.setPixelSize(11)
        p.setFont(f)
        for i, (t, st, _tip) in enumerate(self.cells):
            r = self._rect(i)
            bg, fg, border, strike, alpha = self.style_of(st, C)
            p.setOpacity(alpha)
            p.setPen(QPen(QColor(border), 1) if border else Qt.PenStyle.NoPen)
            if st == 'b':
                p.setBrush(QBrush(QColor(C['bd']), Qt.BrushStyle.BDiagPattern))
            else:
                p.setBrush(QColor(bg) if bg else Qt.BrushStyle.NoBrush)
            p.drawRoundedRect(r.adjusted(.5, .5, -.5, -.5), 5, 5)
            p.setPen(QColor(fg))
            ff = QFont(f)
            if st in ('f', 'nx', 'master', 'slave', 'joining', 'dead'):
                ff.setBold(st in ('f', 'nx'))
            ff.setStrikeOut(strike)
            p.setFont(ff)
            p.drawText(r, Qt.AlignmentFlag.AlignCenter, str(t))
            p.setOpacity(1)
        p.end()

    @staticmethod
    def style_of(st, C):
        """(background, text, border, strike-through, opacity) for a cell state."""
        def tint(c, a):
            q = QColor(c)
            b = QColor(C['bg'])
            return QColor(int(q.red() * a + b.red() * (1 - a)), int(q.green() * a + b.green() * (1 - a)),
                          int(q.blue() * a + b.blue() * (1 - a))).name()
        if st == 't':
            return tint(C['se'], .16), C['se'], tint(C['se'], .4), True, 1
        if st == 'f':
            return tint(C['no'], .16), C['no'], tint(C['no'], .45), False, 1
        if st == 'nx':
            return C['no'], '#ffffff', C['no'], False, 1
        if st == 'b':
            return None, C['mu'], C['bd'], False, 1
        if st == 'x':
            return None, C['mu'], C['bd'], False, .3
        if st == 'master':
            return C['no'], '#ffffff', None, False, 1
        if st == 'slave':
            return C['ac'], '#ffffff', None, False, 1
        if st == 'joining':
            return '#00aaaa', '#ffffff', None, False, 1
        if st == 'dead':
            return C['se'], '#ffffff', None, False, 1
        if st == 'polled':
            return C['hd'], C['wa'], C['wa'], False, 1
        return C['hd'], C['mu'], None, False, 1

    def mouseMoveEvent(self, e):
        for i in range(len(self.cells)):
            if self._rect(i).contains(e.position()):
                tip = self.cells[i][2]
                if tip:
                    QToolTip.showText(e.globalPosition().toPoint(), tip, self)
                return
        QToolTip.hideText()

    def resizeEvent(self, e):
        rows = (len(self.cells) + self.cols - 1) // self.cols
        self.setFixedHeight(rows * (self.cell_h + self.gap))
        super().resizeEvent(e)


def legend(items):
    """Row of 'square + text' explanations under a grid."""
    w = QWidget()
    lay = QHBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(16)
    for st, text in items:
        g = CellGrid([('', st, '')], cols=1, cell_w=26)
        g.setFixedSize(26, 24)
        lay.addWidget(g)
        lay.addWidget(label(text, wrap=False, muted=True))
    lay.addStretch(1)
    return w
