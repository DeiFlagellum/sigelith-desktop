"""
Zakladka „Swiadkowie" — co aplikacja sprawdza sama, kiedy jest otwarta.

Ta zakladka niczego nie liczy: pokazuje `witness.WitnessState`, ktory
przygotowuje `witness.refresh` w tle. Kazda karta mowi trzy rzeczy — CO
sprawdzono, SKAD to wiadomo i KIEDY — bo „zielona kropka" bez tych trzech
informacji jest dekoracja, a nie dowodem.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone

from PySide6.QtCore import Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from .. import beatcore, plural, witness
from ..config import SITE_BASE
from ..i18n import _, ltr, rtl_block
from . import icons
from .widgets import ElidedButton, PulseDot, StatusBadge, label, section_label


def _ago(iso: str, now: datetime | None = None) -> str:
    moment = witness._parse_iso(iso)
    if moment is None:
        return ''
    now = now or datetime.now(timezone.utc)
    seconds = max(0, int((now - moment).total_seconds()))
    if seconds < 60:
        return _('just now')
    if seconds < 3600:
        return _('%(n)s min ago') % {'n': seconds // 60}
    if seconds < 86400 * 2:
        return _('%(n)s h ago') % {'n': seconds // 3600}
    return _('%(n)s days ago') % {'n': seconds // 86400}


def _until(iso: str, now: datetime | None = None) -> str:
    moment = witness._parse_iso(iso)
    if moment is None:
        return ''
    now = now or datetime.now(timezone.utc)
    seconds = int((moment - now).total_seconds())
    if seconds <= 0:
        return _('any moment now')
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return _('in %(d)s d %(h)s h') % {'d': days, 'h': hours}
    if hours:
        return _('in %(h)s h %(m)s min') % {'h': hours, 'm': minutes}
    return _('in %(m)s min') % {'m': max(1, minutes)}


def _local(iso: str) -> str:
    moment = witness._parse_iso(iso)
    return ltr(beatcore.local_str(moment, '%d.%m %H:%M')) if moment else ''


class WitnessCard(QFrame):
    """Jedna karta swiadka: nazwa, wartosc, podpis i plakietka."""

    def __init__(self, title: str, tooltip: str, parent: QWidget | None = None,
                 icon_name: str = ''):
        super().__init__(parent)
        self.setObjectName('card')
        self.setToolTip(tooltip)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.title = section_label(rtl_block(title))
        # Naglowek sie zawija, zamiast rozpychac karte: po polsku „PUBLICZNY
        # DZIENNIK" obok plakietki „policzone lokalnie" wymuszalo szerokosc
        # wieksza niz okno i poziomy pasek przewijania.
        self.title.setWordWrap(True)
        self.title.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.title.setMinimumWidth(60)
        self.badge = StatusBadge()
        self.value = QLabel('—')
        self.value.setTextFormat(Qt.PlainText)
        self.value.setObjectName('bigNumber')
        self.value.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.setMinimumWidth(180)
        self.caption = label('', role='hint', wrap=True)
        self.caption.setTextFormat(Qt.PlainText)
        self.link = ElidedButton()
        self.link.setObjectName('link')
        self.link.setCursor(Qt.PointingHandCursor)
        self.link.set_hint(_('Opens the source of this check in the browser'))
        icons.apply(self.link, 'box-arrow-up-right', 'accent', 13)
        self.link.hide()
        self._url = ''
        self.link.clicked.connect(self._open)

        # Plakietka ma wlasny wiersz pod naglowkiem: ani naglowek (po polsku
        # „PUBLICZNY DZIENNIK"), ani liczba („175 wpisow") nie walcza z nia
        # o szerokosc karty.
        top = QHBoxLayout()
        top.setSpacing(8)
        if icon_name:
            glyph = QLabel()
            icons.apply_label(glyph, icon_name, 'signal', 15)
            top.addWidget(glyph, 0, Qt.AlignTop)
        top.addWidget(self.title, 1)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)
        layout.addLayout(top)
        layout.addWidget(self.badge, 0, Qt.AlignLeft)
        layout.addWidget(self.value)
        layout.addWidget(self.caption)
        layout.addWidget(self.link, 0, Qt.AlignLeft)
        layout.addStretch(1)

    def present(self, value: str, caption: str, kind: str, badge: str,
                url: str = '', link_text: str = '') -> None:
        self.value.setText(rtl_block(value))
        self.caption.setText(rtl_block(caption))
        self.badge.show_state(kind, badge)
        self._url = url
        if url and link_text:
            self.link.setText(link_text)
            self.link.set_hint(_('Opens in the browser: %(url)s') % {'url': url})
            self.link.show()
        else:
            self.link.hide()

    def _open(self) -> None:
        if self._url:
            QDesktopServices.openUrl(QUrl(self._url))


class WitnessPanel(QWidget):
    """Tresc zakladki „Swiadkowie"."""

    checkRequested = Signal()
    modeChanged = Signal(str)
    evidenceRequested = Signal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName('page')
        self._state = witness.WitnessState()
        self._mode = witness.MODE_PRIVATE
        self._running = False
        self._third_party = True
        self._next_run = ''
        self._entries: list = []

        # --- Naglowek: stan calosci ------------------------------------------
        hero = QFrame()
        hero.setObjectName('card')
        self.dot = PulseDot()
        self.headline = QLabel(_('The public log has not been checked yet'))
        self.headline.setTextFormat(Qt.PlainText)
        self.headline.setObjectName('h2')
        self.headline.setWordWrap(True)
        self.subline = label('', role='hint', wrap=True)
        # Niesie `state.last_error`, czyli czasem tresc odpowiedzi serwera.
        self.subline.setTextFormat(Qt.PlainText)
        self.check_button = QPushButton(_('Check now'))
        self.check_button.setObjectName('primary')
        self.check_button.setToolTip(_(
            'Downloads new checkpoints and checks them right away: the '
            'signature,\nthe chain of files, consistency with the previous one '
            'and the copies\nkept by third parties. (F8)'))
        self.check_button.clicked.connect(self.checkRequested)
        icons.apply(self.check_button, 'arrow-repeat', icons.ON_ACCENT)

        self.mode = QComboBox()
        self.mode.addItem(_('Private — the whole log on this computer'),
                          witness.MODE_PRIVATE)
        self.mode.addItem(_('Fast — ask only about my digests'), witness.MODE_FAST)
        self.mode.setToolTip(_(
            'Private: Sigelith Desktop keeps a copy of the whole public log and computes\n'
            'every proof itself. The server never learns which entries are yours\n'
            '— not when statuses are refreshed and not when you check a file.\n\n'
            'Fast: Sigelith Desktop asks the server about each digest separately. Less\n'
            'data, but the server sees what you ask about.\n\n'
            'Stamping always sends the digest — that is its only purpose.'))
        self.mode.currentIndexChanged.connect(self._mode_changed)

        head = QHBoxLayout()
        head.setSpacing(12)
        head.addWidget(self.dot, 0, Qt.AlignTop)
        texts = QVBoxLayout()
        texts.setSpacing(3)
        texts.addWidget(self.headline)
        texts.addWidget(self.subline)
        head.addLayout(texts, 1)
        side = QVBoxLayout()
        side.setSpacing(8)
        side.addWidget(self.check_button)
        side.addWidget(self.mode)
        head.addLayout(side)
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(18, 16, 18, 16)
        hero_layout.addLayout(head)

        # --- Alarmy ------------------------------------------------------------
        self.alarm_card = QFrame()
        self.alarm_card.setObjectName('cardAlarm')
        self.alarm_title = QLabel()
        self.alarm_title.setObjectName('errorText')
        alarm_icon = QLabel()
        icons.apply_label(alarm_icon, 'exclamation-octagon', 'error', 18)
        self.alarm_text = label('', wrap=True)
        self.alarm_text.setTextFormat(Qt.RichText)
        self.evidence_button = QPushButton(_('Open the evidence folder'))
        self.evidence_button.setToolTip(_(
            'Both conflicting signed files are kept there. Together they are a\n'
            'cryptographic proof — keep a copy somewhere safe.'))
        self.evidence_button.clicked.connect(self.evidenceRequested)
        icons.apply(self.evidence_button, 'folder-symlink')
        alarm_layout = QVBoxLayout(self.alarm_card)
        alarm_layout.setContentsMargins(18, 14, 18, 14)
        alarm_head = QHBoxLayout()
        alarm_head.addWidget(alarm_icon)
        alarm_head.addWidget(self.alarm_title, 1)
        alarm_layout.addLayout(alarm_head)
        alarm_layout.addWidget(self.alarm_text)
        alarm_layout.addWidget(self.evidence_button, 0, Qt.AlignLeft)
        self.alarm_card.hide()

        # --- Karty swiadkow -------------------------------------------------------
        self.cards = {
            'log': WitnessCard(_('Public log'), _(
                'Every entry of the public Sigelith log. In private mode Sigelith Desktop '
                'keeps\na copy, checks the hash chain of every entry and recomputes '
                'the root\nof every checkpoint from scratch.'), icon_name='journal-text'),
            'checkpoints': WitnessCard(_('Checkpoints'), _(
                'Signed states of the whole log, chained by the hash of the '
                'previous\nfile. Sigelith Desktop checks the Ed25519 signature, the key, '
                'the chain and\nthe RFC 9162 consistency proof between '
                'consecutive checkpoints.'), icon_name='bookmark-check'),
            'bitcoin': WitnessCard('Bitcoin', _(
                'Each checkpoint names a Bitcoin block — so it could not have been\n'
                'issued before that block. Sigelith Desktop asks an independent explorer\n'
                '(mempool.space, blockstream.info) whether that block really '
                'exists.'), icon_name='currency-bitcoin'),
            'bank': WitnessCard(_('Bank'), _(
                'Every week the Merkle root goes into the title of a bank transfer\n'
                '(MROOT). The weekly checkpoint lists those transfers.'), icon_name='bank'),
            'github': WitnessCard('GitHub', _(
                'Immutable weekly releases in the public repository\n'
                'DeiFlagellum/sigelith-log. Sigelith Desktop downloads the checkpoint '
                'files\nfrom there and compares them byte for byte.'), icon_name='github'),
            'wayback': WitnessCard('Internet Archive', _(
                'Snapshots in the Wayback Machine of the non-profit Internet '
                'Archive.\nSigelith Desktop compares the archived checkpoint file byte '
                'for byte.'), icon_name='archive'),
            'zenodo': WitnessCard('Zenodo', _(
                'A quarterly version of the complete log in Zenodo (CERN), with a '
                'DOI.\nSigelith Desktop compares the checkpoint files from the record.'), icon_name='database'),
            'mine': WitnessCard(_('Your proofs'), _(
                'Your stamps from the History, measured against the witnesses:\n'
                'how many are already inside a signed checkpoint and how many are\n'
                'kept by parties that Sigelith does not control.'), icon_name='person-check'),
        }
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)
        order = ('log', 'checkpoints', 'bitcoin', 'bank',
                 'github', 'wayback', 'zenodo', 'mine')
        for i, key in enumerate(order):
            grid.addWidget(self.cards[key], i // 4, i % 4)
        for column in range(4):
            grid.setColumnStretch(column, 1)

        # --- Najblizsze zdarzenia i potok ------------------------------------------
        self.events = QFrame()
        self.events.setObjectName('card')
        self.events_layout = QVBoxLayout(self.events)
        self.events_layout.setContentsMargins(18, 14, 18, 14)
        self.events_layout.setSpacing(6)
        self.events_title = section_label(_('Coming up — it happens by itself'))
        self.events_list = label('', wrap=True)
        self.events_list.setTextFormat(Qt.RichText)
        self.pipeline = label('', role='hint', wrap=True)
        # Nazwy sprawdzen przychodza z /api/proof/status — zwykly tekst.
        self.pipeline.setTextFormat(Qt.PlainText)
        self.events_layout.addWidget(self.events_title)
        self.events_layout.addWidget(self.events_list)
        self.events_layout.addSpacing(6)
        self.events_layout.addWidget(section_label(_('Sigelith proof pipeline')))
        self.events_layout.addWidget(self.pipeline)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(12)
        layout.addWidget(hero)
        layout.addWidget(self.alarm_card)
        layout.addLayout(grid)
        layout.addWidget(self.events)
        layout.addStretch(1)

        self._clock = QTimer(self)
        self._clock.setInterval(30_000)
        self._clock.timeout.connect(self._render_events)
        self._clock.start()
        self.render()

    # --- API dla okna glownego --------------------------------------------------

    def set_mode(self, mode: str) -> None:
        self._mode = mode
        index = self.mode.findData(mode)
        self.mode.blockSignals(True)
        self.mode.setCurrentIndex(max(0, index))
        self.mode.blockSignals(False)
        self.render()

    def set_third_party(self, enabled: bool) -> None:
        self._third_party = enabled
        self.render()

    def set_state(self, state: witness.WitnessState) -> None:
        self._state = state
        self.render()

    def set_history(self, entries: list) -> None:
        self._entries = list(entries)
        self._render_mine()

    def set_running(self, running: bool) -> None:
        self._running = running
        self.check_button.setEnabled(not running)
        self.render_head()

    def set_next_run(self, iso: str) -> None:
        self._next_run = iso
        self.render_head()

    def _mode_changed(self) -> None:
        mode = str(self.mode.currentData())
        if mode != self._mode:
            self._mode = mode
            self.modeChanged.emit(mode)
            self.render()

    # --- Rysowanie ---------------------------------------------------------------

    def summary(self) -> tuple[str, str]:
        """(rola koloru, krotki opis) — do pastylki w naglowku okna."""
        state = self._state
        if state.critical_alarms:
            return 'error', _('Witness alarm')
        if self._running:
            return 'signal', _('Checking the log…')
        latest = state.latest
        if latest is None:
            return 'text_faint', _('Log not checked yet')
        # Bez liczby kopii: pastylka skraca tekst ze srodka i przy dopisku
        # „· 2 niezalezne kopie" wycinala wlasnie numer checkpointu (audyt
        # 2026-09-27). Kopie widac w zakladce Swiadkowie.
        text = _('Log checked · checkpoint #%(n)s') % {'n': latest.n}
        return ('warn' if state.last_error else 'ok'), text

    def render(self) -> None:
        self.render_head()
        self._render_cards()
        self._render_mine()
        self._render_alarms()
        self._render_events()

    def render_head(self) -> None:
        state = self._state
        role, _text = self.summary()
        self.dot.set_state(role if role != 'text_faint' else 'text_faint', self._running)
        mode_text = (_('private mode — the whole log is on this computer')
                     if self._mode == witness.MODE_PRIVATE else
                     _('fast mode — the server is asked about each digest'))
        if state.critical_alarms:
            self.headline.setText(_('The log does not add up — see the alarm below'))
        elif self._running:
            self.headline.setText(_('Checking the public log…'))
        elif state.latest is None:
            self.headline.setText(_('The public log has not been checked yet'))
        elif state.last_error:
            self.headline.setText(_('No connection — showing the last check'))
        else:
            self.headline.setText(_('The public log checked by this application'))
        parts = []
        if state.last_success:
            parts.append(_('last check %(when)s') % {'when': _ago(state.last_success)})
        if self._next_run and not self._running:
            parts.append(_('next %(when)s') % {'when': _until(self._next_run)})
        parts.append(mode_text)
        if state.last_error:
            parts.append(state.last_error)
        self.subline.setText(' · '.join(parts))

    def _render_cards(self) -> None:
        state = self._state
        latest = state.latest
        # Dziennik
        card = self.cards['log']
        if self._mode == witness.MODE_PRIVATE and state.log_size:
            audited = [r for r in state.checkpoints.values() if r.audited]
            card.present(plural.entries(state.log_size),
                      _('the chain of every entry and the root of %(k)s checkpoints '
                        'recomputed on this computer') % {'k': len(audited)},
                      'ok', _('computed locally'))
        elif self._mode == witness.MODE_PRIVATE:
            card.present('—', _('the copy of the log is downloaded at the first check'),
                      'muted', _('waiting'))
        else:
            card.present('—', _('fast mode — the log is not downloaded; each digest is '
                             'asked about separately'), 'muted', _('fast mode'))

        # Checkpointy
        card = self.cards['checkpoints']
        if latest is None:
            card.present('—', _('the first check downloads every checkpoint and verifies '
                             'the whole chain'), 'muted', _('waiting'))
        else:
            consistent = all(r.consistent is not False for r in state.checkpoints.values())
            card.present(f'#{latest.n}', _(
                '%(kind)s · signature and key ✓ · chain from #1 ✓ · consistency ✓ · '
                'issued %(when)s') % {
                    'kind': _('weekly') if latest.kind == 'weekly' else _('daily'),
                    'when': _ago(latest.utc) or _local(latest.utc)},
                'ok' if consistent else 'error',
                _('verified') if consistent else _('inconsistent'),
                f'{SITE_BASE}/checkpoints/', _('Checkpoint archive'))

        # Bitcoin
        card = self.cards['bitcoin']
        block = None
        for n in sorted(state.checkpoints, reverse=True):
            btc = state.checkpoints[n].btc or {}
            if isinstance(btc.get('height'), int):
                block = (state.checkpoints[n], btc, state.blocks.get(str(btc['height'])) or {})
                break
        if block is None:
            card.present('—', _('no block in the checkpoints yet'), 'muted', _('waiting'))
        else:
            record, btc, seen = block
            height = f"{btc['height']:,}".replace(',', ' ')
            if seen.get('ok') is True:
                caption = _('block from checkpoint #%(n)s confirmed by %(source)s · '
                            'mined %(when)s') % {'n': record.n, 'source': seen.get('source'),
                                                 'when': _local(seen.get('time', ''))}
                card.present(height, caption, 'ok', _('confirmed'),
                          f'https://mempool.space/block/{btc.get("hash")}',
                          _('See the block'))
            elif seen.get('ok') is False:
                card.present(height, _('the explorer knows a different block at this height'),
                          'warn', _('differs'))
            elif not self._third_party:
                card.present(height, _('checks with outside services are turned off in the '
                                    'settings'), 'muted', _('off'))
            else:
                card.present(height, _('waiting for the independent explorer'), 'info',
                          _('waiting'))

        # Bank
        card = self.cards['bank']
        weekly = [r for r in state.checkpoints.values() if r.kind == 'weekly']
        if weekly:
            card.present(_('%(n)s weeks') % {'n': len(weekly)},
                      _('MROOT transfers are listed in the weekly checkpoints — the '
                        'transfer titles can be checked on a bank statement'),
                      'ok', _('in the log'))
        else:
            card.present('MROOT', _('the first weekly checkpoint lists every bank '
                                 'anchor so far'), 'muted', _('waiting'))

        # Osoby trzecie
        for source, name in (('github', 'GitHub'), ('wayback', 'Internet Archive'),
                             ('zenodo', 'Zenodo')):
            card = self.cards[source]
            info = state.copies.get(source) or {}
            weeks = info.get('weeks') or {}
            confirmed = int(info.get('max_n') or 0)
            last_key = sorted(weeks)[-1] if weeks else ''
            last = weeks.get(last_key) or {}
            if not self._third_party:
                card.present('—', _('checks with outside services are turned off in the '
                                 'settings'), 'muted', _('off'))
            elif any(a.get('source') == source and a.get('severity') == 'critical'
                     for a in state.alarms):
                card.present(_('differs'), _('the copy at %(name)s differs from what '
                                          'Sigelith served — see the alarm') % {'name': name},
                          'error', _('alarm'))
            elif confirmed:
                card.present(f'#{confirmed}', _('identical copy checked byte for byte · '
                                             '%(when)s') % {'when': _ago(last.get('checked', ''))},
                          'ok', _('identical'), last.get('url', ''), _('Open the copy'))
            elif last.get('status') == 'unreadable':
                # Kopia jest, ale nie da sie jej odczytac (np. migawka w kompresji,
                # ktorej Python nie zna). Nic nie dowodzi — ani za, ani przeciw.
                card.present('—', _('the copy at %(name)s cannot be read — it proves '
                                 'nothing either way; checked %(when)s, Sigelith Desktop '
                                 'tries again in a day')
                             % {'name': name, 'when': _ago(last.get('checked', ''))},
                             'muted', _('unreadable'), last.get('url', ''), _('Open the copy'))
            elif last.get('status') == 'unavailable':
                # Serwis nie odpowiedzial (np. indeks Internet Archive „Temporarily
                # Offline”) — to nie znaczy, ze kopii tam nie ma.
                card.present('—', _('%(name)s did not answer — checked %(when)s; Sigelith '
                                 'Desktop tries again every 3 h')
                             % {'name': name, 'when': _ago(last.get('checked', ''))},
                             'muted', _('waiting'))
            elif last:
                card.present('—', _('not published there yet — checked %(when)s; Sigelith Desktop '
                                 'tries again every 3 h') % {'when': _ago(last.get('checked', ''))},
                          'muted', _('waiting'))
            else:
                first = {'github': _('the first weekly release follows the weekly '
                                     'checkpoint (Monday)'),
                         'wayback': _('the snapshot follows the GitHub release'),
                         'zenodo': _('the first quarterly version: 2026-Q3, early '
                                     'October')}[source]
                card.present('—', first, 'muted', _('waiting'))

    def _render_mine(self) -> None:
        card = self.cards['mine']
        entries = [e for e in self._entries if getattr(e, 'source', '') == 'beattime']
        if not entries:
            card.present('—', _('nothing stamped on this computer yet'), 'muted',
                         _('empty'))
            return
        inside = sum(1 for e in entries if (e.checkpoint or {}).get('verified'))
        pinned = sum(1 for e in entries
                     if witness.pinning(e.checkpoint, self._state).sources)
        caption = _('%(inside)s of %(all)s inside a signed checkpoint · %(pinned)s '
                    'kept by independent parties') % {
                        'inside': inside, 'all': len(entries), 'pinned': pinned}
        kind = 'ok' if pinned == len(entries) else ('signal' if inside else 'muted')
        badge = (_('all pinned') if pinned == len(entries) else
                 _('maturing') if inside else _('waiting'))
        card.present(f'{inside}/{len(entries)}', caption, kind, badge)

    def _render_alarms(self) -> None:
        alarms = self._state.alarms
        if not alarms:
            self.alarm_card.hide()
            return
        critical = [a for a in alarms if a.get('severity') == 'critical']
        self.alarm_title.setText(
            _('ALARM — the log does not add up') if critical else
            _('Warning from the witnesses'))
        explain = {
            witness.ALARM_SIGNATURE: _('a checkpoint file is not signed with a Sigelith key'),
            witness.ALARM_FORK: _('a checkpoint does not continue the chain of the previous one'),
            witness.ALARM_EQUIVOCATION: _('Sigelith served two DIFFERENT signed files '
                                          'under the same checkpoint number'),
            witness.ALARM_CONSISTENCY: _('a new checkpoint does not extend the previous '
                                         'one — something was removed or rewritten'),
            witness.ALARM_LOG_ROOT: _('the root recomputed from the public log differs '
                                      'from the signed checkpoint'),
            witness.ALARM_LOG_REWRITTEN: _('entries of the public log that were already '
                                           'downloaded have changed'),
            witness.ALARM_COPY_MISMATCH: _('a copy kept by a third party differs from '
                                           'what Sigelith served'),
            witness.ALARM_BTC: _('the Bitcoin explorer knows a different block'),
        }
        lines = []
        for a in alarms[-6:]:
            text = explain.get(a.get('code'), a.get('code', ''))
            where = f" ({ltr('#' + str(a['n']))})" if a.get('n') else ''
            lines.append(f"• <b>{html.escape(text)}</b>{html.escape(where)} — "
                         f"{html.escape(_local(a.get('at', '')))}")
        if critical:
            lines.append('<br>' + html.escape(_(
                'This is exactly what the witnesses exist for. Sigelith Desktop kept the '
                'conflicting files as evidence. Do not delete them; report the case '
                'to Sigelith and keep your own copy.')))
        self.alarm_text.setText(rtl_block('<br>'.join(lines)))
        self.evidence_button.setVisible(any(a.get('evidence') for a in alarms))
        # `show()`, nie `present()`: to zwykla ramka, nie `WitnessCard`. Do 2.2.0
        # pierwszy zapisany alarm konczyl sie AttributeError przy KAZDYM
        # starcie programu (stan z alarmem czyta konstruktor okna).
        self.alarm_card.show()

    def _render_events(self) -> None:
        now = datetime.now(timezone.utc)
        names = {
            'daily': _('daily checkpoint'),
            'weekly': _('weekly checkpoint closing %(week)s'),
            'github': _('release %(week)s on GitHub (at the latest)'),
            'zenodo': _('quarterly version %(quarter)s in Zenodo (at the latest)'),
        }
        rows = []
        for event in witness.next_events(self._state, now):
            name = names.get(event['kind'], event['kind']) % event
            rows.append(f'<b>{html.escape(_until(event["at"], now))}</b> — '
                        f'{html.escape(name)} '
                        f'<span style="color:#8a93a1">({html.escape(_local(event["at"]))})</span>')
        self.events_list.setText('<br>'.join(rows))
        checks = (self._state.pipeline or {}).get('checks') or []
        if checks:
            ok = sum(1 for c in checks if isinstance(c, dict) and c.get('status') == 'ok')
            bad = [str(c.get('name')) for c in checks
                   if isinstance(c, dict) and c.get('status') != 'ok']
            text = _('%(ok)s of %(all)s checks OK') % {'ok': ok, 'all': len(checks)}
            if bad:
                text += ' · ' + _('attention: %(names)s') % {'names': ', '.join(bad)}
            text += ' · ' + _('reported by sigelith.org/api/proof/status %(when)s') % {
                'when': _ago(str(self._state.pipeline.get('checked') or ''))}
            self.pipeline.setText(text)
        else:
            self.pipeline.setText(_('the state of the Sigelith pipeline arrives with the '
                                    'first check'))
