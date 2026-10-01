"""
Szczegoly dowodu — czytelne dla czlowieka, a dane techniczne na zyczenie.

Do 2.1 „Szczegoly…" otwieralo okno z surowym JSON-em. To jest dobre dla
kogos, kto sprawdza dowod wlasnym narzedziem — i bezuzyteczne dla kazdego
innego. Teraz okno mowi po ludzku: co to za dokument, KIEDY istnial (trzy
czasy i skad kazdy z nich wiadomo), jak daleko dojrzal dowod i kto poza
Sigelith go potwierdza. JSON zostaje, zwiniety na dole — ten sam, ktory
zapisuje eksport `.beatproof`.
"""
from __future__ import annotations

import html
import json

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .. import __app_name__, beatcore, keys, proof, witness
from ..hashing import human_size
from ..i18n import _, ltr, rtl_block
from . import icons, journey
from .widgets import CopyField, ProofJourney, StatusBadge, label, section_label, fit_to_screen


class _Obj:
    """Widok na slownik `.beatproof` z tymi samymi nazwami pol co `Entry`."""

    def __init__(self, data: dict):
        self._d = data if isinstance(data, dict) else {}

    def __getattr__(self, name):
        mapping = {'ots_height': 'ots_bitcoin_height', 'time_bounds': 'time'}
        value = self._d.get(mapping.get(name, name))
        if name in ('anchors', 'inclusion_proof', 'problems'):
            return value if isinstance(value, list) else []
        if name in ('checkpoint', 'time_bounds'):
            return value if isinstance(value, dict) else {}
        return value


def _row(grid: QGridLayout, row: int, name: str, value: QWidget | str,
         tooltip: str = '') -> int:
    key = label(rtl_block(name), role='hint')
    key.setAlignment(Qt.AlignLeft | Qt.AlignTop)
    grid.addWidget(key, row, 0)
    if isinstance(value, str):
        widget = label(rtl_block(value), wrap=True, selectable=True)
        widget.setTextFormat(Qt.RichText)
    else:
        widget = value
    if tooltip:
        widget.setToolTip(tooltip)
    grid.addWidget(widget, row, 1)
    return row + 1


def _section(title: str, icon_name: str = '') -> tuple[QFrame, QGridLayout]:
    frame = QFrame()
    frame.setObjectName('card')
    outer = QVBoxLayout(frame)
    outer.setContentsMargins(18, 14, 18, 16)
    outer.setSpacing(10)
    head = QHBoxLayout()
    head.setSpacing(8)
    if icon_name:
        glyph = QLabel()
        icons.apply_label(glyph, icon_name, 'signal', 15)
        head.addWidget(glyph)
    head.addWidget(section_label(title), 1)
    outer.addLayout(head)
    grid = QGridLayout()
    grid.setHorizontalSpacing(18)
    grid.setVerticalSpacing(9)
    grid.setColumnMinimumWidth(0, 150)
    grid.setColumnStretch(1, 1)
    outer.addLayout(grid)
    return frame, grid


class DetailsDialog(QDialog):
    """Szczegoly wpisu albo wyniku weryfikacji.

    `data` to slownik dowodu (`bundle.build`) — ten sam, ktory trafia do
    `.beatproof`, wiec okno pokazuje dokladnie to, co eksport zapisze.
    `entry` (opcjonalnie) daje dostep do pol, ktorych w eksporcie nie ma
    (rozmiar pliku), a `on_note` pozwala zmienic notatke na miejscu.
    """

    def __init__(self, title: str, data: dict, parent: QWidget | None = None, *,
                 entry=None, witness_state: witness.WitnessState | None = None,
                 on_note=None, actions: list[tuple[str, str, object]] | None = None):
        super().__init__(parent)
        self.setWindowTitle(f'{title} — {__app_name__}')
        fit_to_screen(self, 820, 720)
        self._data = data if isinstance(data, dict) else {}
        self._entry = entry
        self._on_note = on_note
        obj = entry if entry is not None else _Obj(self._data)
        self._obj = obj

        body = QWidget()
        body.setObjectName('scrollBody')
        column = QVBoxLayout(body)
        column.setContentsMargins(18, 16, 18, 16)
        column.setSpacing(14)

        # --- Naglowek ---------------------------------------------------------
        name = str(getattr(obj, 'file_name', '') or '')
        digest = str(getattr(obj, 'digest', '') or '')
        headline = QLabel(name or (_('Digest %(short)s…') % {'short': digest[:16]}
                                   if digest else title))
        headline.setObjectName('h1')
        headline.setWordWrap(True)
        headline.setTextFormat(Qt.PlainText)
        self.badge = StatusBadge()
        level = journey._level(obj)
        trusted = journey._trusted(obj)
        kind = ('ok' if level.order >= proof.Level.SIGNED.order and trusted
                else 'info' if trusted else 'warn')
        self.badge.show_state(kind, level.label, level.description)
        top = QHBoxLayout()
        top.setSpacing(12)
        top.addWidget(headline, 1)
        top.addWidget(self.badge, 0, Qt.AlignTop)
        column.addLayout(top)
        seq = getattr(obj, 'seq', None)
        column.addWidget(label(
            (_('Entry no. %(seq)s in the public Sigelith register') % {'seq': seq})
            if seq else _('Proof data'), role='hint'))

        # --- Droga dowodu ----------------------------------------------------------
        self.journey = ProofJourney()
        self.journey.set_steps(journey.journey_steps(obj, witness_state))
        journey_card = QFrame()
        journey_card.setObjectName('card')
        jl = QVBoxLayout(journey_card)
        jl.setContentsMargins(16, 12, 16, 10)
        jl.addWidget(section_label(_('How far the proof has come')))
        jl.addWidget(self.journey)
        column.addWidget(journey_card)

        # --- Kiedy -------------------------------------------------------------------
        when_card, grid = _section(_('When'), 'clock-history')
        dt = beatcore.parse_iso_utc(str(getattr(obj, 'utc', '') or ''))
        r = 0
        r = _row(grid, r, _('Your local time'),
                 html.escape(ltr(beatcore.local_str(dt) + beatcore.zone_suffix(dt))))
        r = _row(grid, r, _('UTC time'), html.escape(ltr(beatcore.utc_str(dt))))
        r = _row(grid, r, _('@beat time'),
                 f"<b>{html.escape(ltr(getattr(obj, 'beat', '') or '—'))}</b>")
        bounds = getattr(obj, 'time_bounds', None) or {}
        for key, name_text, tip in (
                ('not_before', _('Not earlier than'), _(
                    'A Bitcoin block named in the last checkpoint issued BEFORE this '
                    'entry.\nThat checkpoint could not exist before the block was '
                    'mined,\nand the entry came after the checkpoint.')),
                ('not_after', _('Not later than'), _(
                    'The earliest anchor covering this entry: a Bitcoin block '
                    '(OpenTimestamps)\nor a bank transfer. The entry must have '
                    'existed before it.'))):
            when, what = journey.bound_parts(bounds.get(key) if isinstance(bounds, dict) else None)
            if when or what:
                r = _row(grid, r, name_text,
                         f'{html.escape(when)}<br><span style="color:#8a93a1">'
                         f'{html.escape(what)}</span>', tip)
        note = label(_(
            'The register gives the exact moment. The two bounds do not depend on '
            'the Sigelith clock at all — they can be checked in Bitcoin and at the '
            'bank.'), role='faint', wrap=True)
        grid.addWidget(note, r, 0, 1, 2)
        column.addWidget(when_card)

        # --- Dokument ------------------------------------------------------------------
        doc_card, grid = _section(_('Document'), 'file-earmark-text')
        r = 0
        if name:
            size = getattr(entry, 'file_size', 0) if entry is not None else 0
            r = _row(grid, r, _('File'), html.escape(name)
                     + (f' <span style="color:#8a93a1">({html.escape(human_size(size))})</span>'
                        if size else ''))
        digest_field = CopyField(tooltip=_('The only information that reached the '
                                           'Sigelith register'))
        digest_field.set_value(digest)
        r = _row(grid, r, _('SHA-256 digest'), digest_field)
        self.note = QLineEdit(str(getattr(obj, 'note', '') or ''))
        self.note.setPlaceholderText(_('Add a note — visible only on this computer'))
        self.note.setToolTip(_('The note stays only in the local history. It is not '
                               'sent anywhere.'))
        self.note.setReadOnly(on_note is None)
        if on_note is not None:
            self.note.editingFinished.connect(self._save_note)
        r = _row(grid, r, _('Note'), self.note)
        column.addWidget(doc_card)

        # --- Dowod -------------------------------------------------------------------------
        proof_card, grid = _section(_('Proof'), 'shield-check')
        r = 0
        r = _row(grid, r, _('Proof level'),
                 f'<b>{html.escape(level.label)}</b><br>'
                 f'<span style="color:#8a93a1">{html.escape(level.description)}</span>')
        week = str(getattr(obj, 'week', '') or '')
        if week:
            closed = bool(getattr(obj, 'week_closed', False))
            r = _row(grid, r, _('Week'), html.escape(
                f"{week} · {proof.week_range_text(week)} UTC · "
                f"{_('closed') if closed else _('still running')}"))
        signature = str(getattr(obj, 'root_signature', '') or '')
        pub = str(getattr(obj, 'public_key', '') or '')
        if signature:
            status = keys.classify(pub)
            text = {keys.SIGNER_CURRENT: _('valid, Sigelith key from the list built '
                                           'into the application'),
                    keys.SIGNER_RETIRED: _('made with a RETIRED key — the proof needs '
                                           'refreshing'),
                    }.get(status, _('key outside the built-in list'))
            r = _row(grid, r, _('Root signature'), html.escape(f'Ed25519 — {text}'))
        else:
            r = _row(grid, r, _('Root signature'), html.escape(
                _('arrives once the week closes (Monday 00:00 UTC)')))
        ots = str(getattr(obj, 'ots_status', '') or 'none')
        height = getattr(obj, 'ots_height', None)
        r = _row(grid, r, 'Bitcoin', html.escape(
            (_('in block %(h)s (OpenTimestamps)') % {'h': height}) if ots == 'bitcoin'
            else _('waiting for a block') if ots == 'pending'
            else _('after the week closes')))
        anchor = journey._bank_confirmed(obj)
        r = _row(grid, r, _('Bank'), html.escape(
            f"{anchor.get('bank')} · {str(anchor.get('date') or '')[:10]}"
            + (f" · {_('confirmation no.')} {anchor.get('bank_reference')}"
               if anchor.get('bank_reference') else '')
            if anchor else _('the transfer with the week root follows')))
        cp = getattr(obj, 'checkpoint', None) or {}
        if cp.get('n'):
            r = _row(grid, r, _('Log checkpoint'), html.escape(
                (_('#%(n)s — path checked by Sigelith Desktop') if cp.get('verified')
                 else _('#%(n)s — path NOT confirmed')) % {'n': cp.get('n')}))
            pin = witness.pinning(cp, witness_state) if witness_state else witness.Pinning()
            names = {'github': 'GitHub', 'wayback': 'Internet Archive', 'zenodo': 'Zenodo'}
            r = _row(grid, r, _('Independent copies'), html.escape(
                ', '.join(names[s] for s in pin.sources) if pin.sources
                else _('not published yet — they follow on their own')))
        else:
            r = _row(grid, r, _('Log checkpoint'), html.escape(
                _('the next daily checkpoint will contain this entry')))
        mode = str(getattr(obj, 'witness_mode', '') or '')
        if mode:
            r = _row(grid, r, _('Checked'), html.escape(
                _('privately — from the copy of the public log on this computer')
                if mode == witness.MODE_PRIVATE else
                _('by asking the server about this digest')))
        column.addWidget(proof_card)

        # --- Dane techniczne ---------------------------------------------------------------
        self.toggle = QToolButton()
        self.toggle.setText(_('Technical data (JSON) for experts'))
        self.toggle.setCheckable(True)
        self.toggle.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.toggle.setArrowType(Qt.RightArrow)
        self.toggle.setToolTip(_('The same values the .beatproof export writes — to be '
                                 'checked with your own tool'))
        self.toggle.toggled.connect(self._toggle)
        self.view = QPlainTextEdit()
        self.view.setObjectName('mono')
        self.view.setReadOnly(True)
        self.view.setPlainText(json.dumps(self._data, indent=2, ensure_ascii=False))
        self.view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.view.setMinimumHeight(260)
        self.view.hide()
        column.addWidget(self.toggle, 0, Qt.AlignLeft)
        column.addWidget(self.view)
        column.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(body)

        # --- Przyciski ---------------------------------------------------------------------
        row = QHBoxLayout()
        row.setSpacing(10)
        for index, (text, tip, slot) in enumerate(actions or []):
            button = QPushButton(text)
            icons.apply(button, ('file-earmark-pdf', 'file-earmark-lock', 'globe2',
                                 'info-circle')[min(index, 3)])
            button.setToolTip(tip)
            button.clicked.connect(slot)
            row.addWidget(button)
        copy = QPushButton(_('Copy everything'))
        icons.apply(copy, 'copy')
        copy.setToolTip(_('Copies the whole JSON document to the clipboard'))
        copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(
            self.view.toPlainText()))
        row.addWidget(copy)
        row.addStretch(1)
        close = QPushButton(_('Close'))
        close.setObjectName('primary')
        close.clicked.connect(self.accept)
        row.addWidget(close)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 14)
        layout.addWidget(scroll, 1)
        buttons = QWidget()
        buttons.setLayout(row)
        row.setContentsMargins(18, 0, 18, 0)
        layout.addWidget(buttons)

    def _toggle(self, on: bool) -> None:
        self.toggle.setArrowType(Qt.DownArrow if on else Qt.RightArrow)
        self.view.setVisible(on)

    def _save_note(self) -> None:
        if self._on_note is not None:
            self._on_note(self.note.text().strip())

    def json_text(self) -> str:
        return self.view.toPlainText()
