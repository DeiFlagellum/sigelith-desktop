"""
Raport PDF dla bieglego — HANDOVER_SPEC.md §11.1 (obok pakietu) i §11.3.

Czytelny odczyt pakietu dowodowego albo dowodu wady: w jezyku interfejsu,
czasy w UTC, skroty, kazda kontrola i instrukcja, jak sprawdzic plik bez tej
aplikacji. Raport NIE jest dowodem — dowodem jest plik, ktorego SHA-256
raport podaje — i zapisujemy go OBOK pliku: czytniki odrzucaja ZIP z trzecim
plikiem (§11.1).

Qt (QTextDocument -> QPdfWriter), bez nowej zaleznosci: Qt osadza podzbiory
czcionek, uklada arabski od prawej i bierze pisma CJK z tych samych rodzin co
interfejs (theme.SCRIPT_FAMILIES — inaczej japonski dostaje chinskie ksztalty).
PDF/A-1b, format archiwalny. Platforma `offscreen` nie ma czcionek
systemowych: PDF z testow ma prostokaty zamiast liter, czytelny powstaje
w dzialajacej aplikacji.

Wszystko, co pochodzi z pliku (tytuly, nazwy, notatki), idzie przez
html.escape — nigdy jako HTML.
"""
from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import QMarginsF, Qt
from PySide6.QtGui import (QPageLayout, QPageSize, QPagedPaintDevice, QPdfWriter, QTextDocument,
                           QTextOption)

from .. import __version__, fonts
from ..handover import answer as A_, package as P
from ..handover.errors import HandoverError
from ..i18n import _, is_rtl, ltr
from . import handover_dialogs as D, theme
from .handover_panel import level_text

VERIFY_URL = 'https://sigelith.org/handover/verify/'
SOURCE_URL = 'https://github.com/DeiFlagellum/sigelith-desktop'

OK, NO, WARN, MUTED, INK, SOFT, LINE = ('#1a7f37', '#b42318', '#9a6700', '#57606a', '#1f2328',
                                        '#f6f8fa', '#d0d7de')
ROLE_COLOR = {'okText': OK, 'errorText': NO, 'warnText': WARN}


@dataclass(frozen=True)
class Source:
    """Sprawdzony plik — raport wskazuje dokladnie ten plik."""

    name: str
    size: int
    sha256: str


def utc(moment: datetime | None) -> str:
    """Czas w UTC, z mikrosekundami jak w dzienniku."""
    if moment is None:
        return _('not in the log')
    return ltr(moment.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f UTC'))


def _row(*cells: str, bg: str = '') -> str:
    """Wiersz tabeli. QTextDocument NIE odwraca kolumn w tekscie od prawej do
    lewej (ani <body dir>, ani <table dir>) — po arabsku odwracamy je sami,
    zeby etykieta stala po prawej, jak w oknie."""
    ordered = reversed(cells) if is_rtl() else cells
    return (f'<tr bgcolor="{bg}">' if bg else '<tr>') + ''.join(ordered) + '</tr>'


def _e(text: object) -> str:
    return html.escape(str(text), quote=False)


def _mono(text: object) -> str:
    return (f'<span style="font-family:\'{fonts.MONO_FAMILY}\', Consolas; font-size:8pt">'
            f'{_e(ltr(text))}</span>')


def _muted(text: str) -> str:
    return f'<span style="color:{MUTED}">{_e(text)}</span>'


def _h2(text: str) -> str:
    return f'<h2>{_e(text)}</h2>'


def _p(text: str) -> str:
    return f'<p>{_e(text)}</p>'


def _facts(rows: list[tuple[str, str]]) -> str:
    """Tabela etykieta/wartosc. Wartosc to GOTOWY HTML (wolajacy escapuje)."""
    cells = ''.join(_row(f'<td width="30%"><span style="color:{MUTED}">{_e(label)}</span></td>',
                         f'<td>{value}</td>') for label, value in rows)
    return f'<table width="100%" cellspacing="0" cellpadding="3">{cells}</table>'


def _box(inner: str) -> str:
    return (f'<table width="100%" cellspacing="0" cellpadding="8" border="1" '
            f'style="border-color:{LINE}; border-style:solid"><tr><td bgcolor="{SOFT}">{inner}'
            f'</td></tr></table>')


def _verdict(title: str, text: str, role: str) -> str:
    return _box(f'<p style="font-size:13pt; font-weight:700; color:{ROLE_COLOR.get(role, INK)}">'
                f'{_e(title)}</p><p>{_e(text)}</p>')


def _checks(checks: list, moment) -> str:
    rows = []
    for c in checks:
        mark = (f'<span style="color:{OK}; font-weight:700">✓</span>' if c.ok
                else f'<span style="color:{NO}; font-weight:700">✗</span>')
        body = f'<b>{_e(D.check_label(c.code))}</b>'
        detail = D.check_detail(c, moment=moment) if c.data else ''
        if detail:
            body += f'<br>{_e(detail)}'
        technical = f'{c.code}: {c.detail}' if c.detail else c.code
        body += f'<br><span style="color:{MUTED}; font-size:7.5pt">{_e(ltr(technical))}</span>'
        rows.append(_row(f'<td width="4%">{mark}</td>', f'<td>{body}</td>'))
    return f'<table width="100%" cellspacing="0" cellpadding="3">{"".join(rows)}</table>'


def _list(items: list[str]) -> str:
    """Numerowana lista GOTOWYCH fragmentow HTML."""
    return '<ol>' + ''.join(f'<li>{item}</li>' for item in items) + '</ol>'


def _head(title: str, source: Source) -> str:
    made = _('Made by Sigelith Desktop %(version)s on %(when)s.') % {
        'version': __version__, 'when': utc(datetime.now(timezone.utc))}
    return (f'<h1>{_e(title)}</h1><p>{_muted(made)}</p>'
            + _box(_p(_('This report is a reading of the file below. It is not evidence itself: '
                        'the evidence is the file, and anyone can check it again — see the '
                        'last section.')))
            + _h2(_('The file checked'))
            + _facts([(_('Name'), _e(source.name)),
                      (_('Size'), _e(f'{D.human_size(source.size)} ({source.size} B)')),
                      ('SHA-256', _mono(source.sha256))]))


def _independent(source: Source, keys: tuple[str, ...], *, defect: bool) -> str:
    steps = [
        _e(_('Compute the SHA-256 of the file and compare it with the value above. On '
             'Windows:')) + '<br>' + _mono(f'certutil -hashfile "{source.name}" SHA256'),
        _e(_('Open %(url)s in a current browser and drop the file in. The page recomputes '
             'everything in the browser and uploads nothing. Sigelith Desktop does the same '
             'offline (Verify evidence…).') % {'url': VERIFY_URL}),
    ]
    if not defect:
        steps.append(_e(_('The times rest on receipts signed with the Sigelith log key '
                          '(Ed25519): %(key)s. Within a day each entry is also confirmed '
                          'outside Sigelith\'s control — by a checkpoint in public archives, '
                          'then in Bitcoin.') % {'key': ', '.join(keys)}))
    steps.append(_e(_('The source code of the verifier and of the reference implementation is '
                      'open (Apache-2.0), with test vectors: %(url)s') % {'url': SOURCE_URL}))
    return _h2(_('How to check this independently')) + _list(steps)


def _card_rows(offer, attested: dict) -> list[tuple[str, str]]:
    rows = []
    for role, card, label_text in (('sender', offer.sender, _("Sender's card")),
                                   ('recipient', offer.recipient, _("Recipient's card"))):
        parts = [_('key in hardware, used only after the person unlocks it')
                 if card.storage == 'hardware-uv' else _('key stored in software')]
        if attested.get(role):
            parts.append(_('attested: %(what)s') % {'what': attested[role]})
        rows.append((label_text, _mono(card.fingerprint_text) + '<br>'
                     + _muted(' · '.join(parts))))
    return rows


def _first(report, code: str):
    return next((c for c in report.checks if c.code == code and c.data), None)


# --- pakiet dowodowy (§11.1) ------------------------------------------------------------

def evidence_html(check, source: Source, keys: tuple[str, ...]) -> str:
    """Raport z `handover_tasks.EvidenceCheck`."""
    report, doc = check.report, check.doc if isinstance(check.doc, dict) else {}
    offer = None
    try:
        offer = P.read_offer(doc.get('offer'))
    except HandoverError:
        pass
    title, text, role = D.verdict_text(report, moment=utc)
    parts = [_head(_('Sigelith Handover — report on an evidence package'), source),
             _h2(_('Result')), _verdict(title, text, role)]

    if offer is not None:
        rows = _card_rows(offer, report.attested)
        binding = _first(report, 'binding')
        if binding is not None:
            before = any(c.code == 'binding-before-offer' and c.ok for c in report.checks)
            day = binding.data['day']
            day = day.isoformat() if hasattr(day, 'isoformat') else str(day)
            rows.append((_('How the sender bound the recipient\'s card'),
                         _e(f'{level_text(binding.data)}, {ltr(day)}')
                         + '<br>' + _muted(_('recorded in the log before the offer') if before
                                           else _('not recorded in the log before the offer'))))
        else:
            rows.append((_('How the sender bound the recipient\'s card'),
                         _e(_('not documented — the package does not show who holds the '
                              'recipient\'s card'))))
        rows.append((_('Offer'), _mono(offer.digest.hex())))
        rows.append((_('Offer recorded in the log'), _e(utc(report.offer_stamped_at))))
        answer = None
        try:
            answer = A_.read_answer(doc.get('answer'), offer)
        except HandoverError:
            pass
        stamp = _first(report, 'answer-stamp')
        if answer is not None and answer.accepted:
            rows.append((_('Acceptance recorded in the log'),
                         _e(utc(stamp.data.get('at') if stamp else None))))
            rows.append((_('Acceptance valid until'), _e(utc(answer.valid_until))))
        if report.delivered_at is not None:
            rows.append((_('Key part recorded in the log'), _e(utc(report.delivered_at))))
        if report.refused_at is not None:
            rows.append((_('Refusal recorded in the log'), _e(utc(report.refused_at))))
        parts += [_h2(_('What the package shows')), _facts(rows)]
        if answer is not None:
            statement = (D.statement_accept(offer.digest.hex(), offer.sender.fingerprint_text,
                                            utc(answer.valid_until)) if answer.accepted
                         else D.statement_refuse(offer.digest.hex(),
                                                 offer.sender.fingerprint_text))
            # Wciety akapit bez tla: tlo (komorki albo akapitu) lamane miedzy
            # stronami rozlewa sie w Qt na dolny margines.
            parts += [_h2(_('What the recipient signed')),
                      f'<p style="margin-left:14px; margin-right:14px">{_e(statement)}</p>',
                      _p(_('The recipient signed a structured answer; this is its fixed reading, '
                           'not free text.'))]

    roles = D.log_roles(report)
    order = {role_name: n for n, role_name in enumerate(roles.values())}
    digests = sorted(set(check.proofs) | set(check.log_errors),
                     key=lambda d: (order.get(roles.get(d), 99), d))
    if digests:
        head = _row(*(f'<td><b>{_e(h)}</b></td>' for h in (
            _('What'), _('Time (UTC)'), _('Level'), _('Confirmed outside Sigelith'))), bg=SOFT)
        rows_html = []
        for digest in digests:
            proof = check.proofs.get(digest)
            # Skrot w czterech grupach po 16 znakow: bez spacji Qt nie lamie go
            # w tekscie od prawej do lewej i wiersz wychodzi poza strone.
            grouped = ' '.join(digest[i:i + 16] for i in range(0, len(digest), 16))
            what = _e(roles.get(digest, _('entry'))) + '<br>' + _mono(grouped)
            if proof is None:
                when = _e(_('not accepted (%(code)s)') % {
                    'code': check.log_errors.get(digest, 'log-structure')})
                level = conf = ''
            else:
                when = _e(utc(proof.utc))
                level = _e(proof_level(proof))
                conf = _e(D.confirmation_text(check.confirmations.get(digest)))
            rows_html.append(_row(f'<td>{what}</td>', f'<td>{when}</td>', f'<td>{level}</td>',
                                  f'<td>{conf}</td>'))
        parts += [_h2(_('Log proofs')),
                  f'<table width="100%" cellspacing="0" cellpadding="3" border="1" '
                  f'style="border-color:{LINE}; border-style:solid">'
                  f'{head}{"".join(rows_html)}</table>']

    disclosed = _first(report, 'disclosure')
    if disclosed is not None:
        files = ''.join(_row(f'<td>{_e(f["name"])}</td>', f'<td>{_e(D.human_size(f["size"]))}</td>',
                             f'<td>{_mono(f["sha256"])}</td>') for f in disclosed.data['files'])
        parts += [_h2(_('Disclosed content')),
                  _p(_('The sender attached the exact content of the package. It matches the hash '
                       'committed in the offer, so these are the files the recipient could open.')),
                  f'<table width="100%" cellspacing="0" cellpadding="3">{files}</table>']

    parts += [_h2(_('All checks')), _checks(report.checks, utc)]
    parts.append(_independent(source, keys, defect=False))
    parts += [_h2(_('What this proves — and what it does not')), _list([
        _e(_('The sender\'s key signed an offer to the recipient\'s key, committing to the exact '
             'encrypted package.')),
        _e(_('The recipient\'s key signed an acceptance, stating that it holds that encrypted '
             'package.')),
        _e(_('The key part was recorded in the public log after the acceptance and before its '
             'deadline. From that moment the recipient could open the package: that is the time '
             'of delivery.')),
        _e(_('With the disclosed content, anyone can check which files the package held.'))]),
        _p(_('It does not prove that anyone read or understood the content, or who stands behind '
             'a key — that is what binding a card to a person is for. It is not a formal service '
             'of documents under any particular law; what it weighs in a dispute is for a court '
             'to decide. Silence proves nothing: an offer without an answer is a status, not '
             'evidence.'))]
    return _page(_('Sigelith Handover — report on an evidence package'), ''.join(parts))


def proof_level(proof) -> str:
    if proof.level == 'anchored':
        return _('also in the root of week %(week)s, which the log declares anchored') % {
            'week': ltr(proof.week)}
    if proof.level == 'signed':
        return _('also in the signed root of week %(week)s') % {'week': ltr(proof.week)}
    return _('signed receipt of the log')


# --- dowod wady (§11.3) -----------------------------------------------------------------

def defect_html(check, source: Source) -> str:
    """Raport z `handover_tasks.DefectCheck`."""
    report, offer = check.report, check.offer
    title, text, role = D.defect_verdict_text(report)
    parts = [_head(_('Sigelith Handover — report on a defect proof'), source),
             _h2(_('Result')), _verdict(title, text, role),
             _p(_('This check is arithmetic only: it needs neither the log nor the network, and '
                  'anyone who repeats it gets the same result.'))]
    if offer is not None:
        rows = _card_rows(offer, {})
        rows.append((_('Offer'), _mono(offer.digest.hex())))
        rows.append((_('Encrypted package'), _e(D.human_size(offer.ciphertext_size))))
        parts += [_h2(_('What the package shows')), _facts(rows)]
    differences = D.defect_differences(report.checks[0].data) if report.checks else []
    if differences:
        parts += [_h2(_('What the preview showed — and what the package holds')), _facts([
            (what, _e(_('Preview: %(value)s') % {'value': shown}) + '<br>'
             + _e(_('Content: %(value)s') % {'value': held})) for what, shown, held in differences])]
    parts += [_h2(_('All checks')), _checks(report.checks, utc),
              _independent(source, (), defect=True),
              _h2(_('What this proves — and what it does not')), _list([
                  _e(_('A defect proof settles whether the package was what the sender offered: '
                       'anyone can recompute it, and a false claim fails the same computation.')),
                  _e(_('The defect proof holds the offer, both key parts and the encrypted '
                       'package. Anyone who gets it can open the package as far as it opens — '
                       'give it only to those who must judge the defect: the sender, a lawyer, '
                       'an expert or a court.'))])]
    return _page(_('Sigelith Handover — report on a defect proof'), ''.join(parts))


# --- strona i PDF -------------------------------------------------------------------------

def _page(title: str, body: str) -> str:
    direction = 'rtl' if is_rtl() else 'ltr'
    return (f'<html><head><title>{_e(title)}</title><style>'
            f'body {{ color:{INK}; }} '
            f'h1 {{ font-size:15pt; font-weight:700; margin-top:0; margin-bottom:2px; }} '
            f'h2 {{ font-size:11pt; font-weight:700; margin-top:14px; margin-bottom:4px; }} '
            f'p {{ margin-top:3px; margin-bottom:3px; }} td {{ vertical-align:top; }}'
            f'</style></head><body dir="{direction}">{body}</body></html>')


def write_pdf(page_html: str, target: Path, *, title: str) -> None:
    """HTML raportu -> PDF/A-1b, A4. Zapis przez plik `.part` i podmiane."""
    doc = QTextDocument()
    doc.setDefaultFont(theme.ui_font(9.5))
    if is_rtl():
        option = QTextOption()
        option.setTextDirection(Qt.RightToLeft)
        doc.setDefaultTextOption(option)
    doc.setHtml(page_html)
    partial = target.with_name(target.name + '.part')
    try:
        writer = QPdfWriter(str(partial))
        writer.setPdfVersion(QPagedPaintDevice.PdfVersion.PdfVersion_A1b)
        writer.setPageSize(QPageSize(QPageSize.A4))
        writer.setPageMargins(QMarginsF(16, 16, 16, 16), QPageLayout.Millimeter)
        writer.setResolution(300)
        writer.setTitle(title)
        writer.setCreator(f'Sigelith Desktop {__version__}')
        doc.print_(writer)
        del writer                                   # zamyka plik
        partial.replace(target)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
