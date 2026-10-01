"""
Droga dowodu i trzy czasy — jedno zrodlo dla wszystkich widokow.

Wynik stemplowania, wynik weryfikacji i okno szczegolow wpisu pokazuja te
same etapy i te same czasy. Gdyby kazdy widok skladal je sam, predzej czy
pozniej jeden mowilby „zakotwiczony", a drugi „czeka na Bitcoin" o tym
samym wpisie.

Obiekt wejsciowy to `history.Entry` albo `proof.VerificationResult` — oba
maja te same nazwy pol.
"""
from __future__ import annotations

import html

from .. import beatcore, proof, witness
from ..i18n import _, ltr
from . import theme
from .widgets import (
    STEP_ACTIVE,
    STEP_DONE,
    STEP_FAIL,
    STEP_PENDING,
    JourneyStep,
)


def _level(obj) -> proof.Level:
    raw = getattr(obj, 'level', '')
    raw = raw.value if hasattr(raw, 'value') else str(raw or '')
    try:
        return proof.Level(raw)
    except ValueError:
        return proof.Level.RECORDED


def _trusted(obj) -> bool:
    value = getattr(obj, 'verified_ok', None)
    if value is None:
        value = getattr(obj, 'trusted', False)
    return bool(value)


def _bank_confirmed(obj) -> dict | None:
    root = str(getattr(obj, 'week_root', '') or '')
    for anchor in getattr(obj, 'anchors', None) or []:
        if proof.anchor_confirms(anchor, root):
            return anchor
    return None


def journey_steps(obj, state: witness.WitnessState | None) -> list[JourneyStep]:
    """Etapy dowodu w kolejnosci, w jakiej przychodza."""
    problems = list(getattr(obj, 'problems', None) or [])
    level = _level(obj)
    proven = level.order >= proof.Level.SIGNED.order and _trusted(obj)
    moment = beatcore.parse_iso_utc(str(getattr(obj, 'utc', '') or ''))
    cp = getattr(obj, 'checkpoint', None) or {}
    bounds = getattr(obj, 'time_bounds', None) or {}

    steps: list[JourneyStep] = []
    steps.append(JourneyStep(
        _('Recorded'), STEP_DONE,
        ltr(beatcore.local_str(moment, '%d.%m %H:%M')) if moment else '',
        _('The digest is in the public, append-only register — the time of the '
          'entry will never change.')))

    if cp.get('verified'):
        steps.append(JourneyStep(
            _('Checkpoint'), STEP_DONE, f"#{cp.get('n')}",
            _('The entry is inside a signed checkpoint of the whole log, and '
              'Sigelith Desktop checked its path to the checkpoint root itself.')))
    elif cp.get('n'):
        steps.append(JourneyStep(_('Checkpoint'), STEP_FAIL, f"#{cp.get('n')}",
                                 _('The path to the checkpoint did not check out.')))
    else:
        steps.append(JourneyStep(
            _('Checkpoint'), STEP_PENDING, _('after 00:00 UTC'),
            _('The next daily checkpoint (after 00:00 UTC) will contain this entry.')))

    week = str(getattr(obj, 'week', '') or '')
    if problems:
        steps.append(JourneyStep(_('Week signed'), STEP_FAIL, week,
                                 '\n'.join(problems)))
    elif proven:
        steps.append(JourneyStep(
            _('Week signed'), STEP_DONE, week,
            _('The Merkle root of the week is frozen and signed with the Sigelith '
              'Ed25519 key; Sigelith Desktop checked the signature and the inclusion '
              'path.')))
    else:
        end = proof.week_end_text(week)
        steps.append(JourneyStep(
            _('Week signed'), STEP_PENDING, end.split(',')[0] if end else week,
            _('The week closes on Monday at 00:00 UTC; then its root is signed.')))

    ots = str(getattr(obj, 'ots_status', '') or '')
    upper = (bounds.get('not_after') or {}) if isinstance(bounds, dict) else {}
    btc_done = proven and (ots == 'bitcoin' or upper.get('source') == 'opentimestamps')
    height = getattr(obj, 'ots_height', None) or upper.get('height')
    steps.append(JourneyStep(
        'Bitcoin', STEP_DONE if btc_done else STEP_PENDING,
        (_('block %(h)s') % {'h': height}) if btc_done and height else '',
        _('The root is in the Bitcoin chain (OpenTimestamps) — rewriting it would '
          'mean rewriting Bitcoin.') if btc_done else
        _('A few hours after the week closes the root reaches a Bitcoin block.')))

    anchor = _bank_confirmed(obj) if proven else None
    steps.append(JourneyStep(
        _('Bank'), STEP_DONE if anchor else STEP_PENDING,
        str(anchor.get('date') or '')[:10] if anchor else '',
        _('The week root is in the title of a bank transfer (MROOT) — confirmed '
          'by the bank.') if anchor else
        _('A bank transfer with the week root follows within a few days.')))

    pin = witness.pinning(cp, state) if state is not None else witness.Pinning()
    names = {'github': 'GitHub', 'wayback': 'Archive', 'zenodo': 'Zenodo'}
    if pin.sources:
        steps.append(JourneyStep(
            _('Independent copies'), STEP_DONE,
            ', '.join(names[s] for s in pin.sources),
            _('A checkpoint containing this entry is kept, byte for byte, by '
              'parties that Sigelith does not control. Sigelith Desktop compared the '
              'copies itself.')))
    else:
        steps.append(JourneyStep(
            _('Independent copies'), STEP_PENDING, '',
            _('Copies at GitHub and in the Internet Archive follow every week, in '
              'Zenodo every quarter.')))

    # Pierwszy nieukonczony etap „trwa" — to ten, na ktory dowod teraz czeka.
    for step in steps:
        if step.state == STEP_PENDING:
            step.state = STEP_ACTIVE
            break
    return steps


# --- Czasy ------------------------------------------------------------------------

def bound_parts(bound: dict | None) -> tuple[str, str]:
    """(kiedy, skad) dla granicy czasu — tekst ZWYKLY."""
    if not isinstance(bound, dict) or not bound:
        return '', ''
    moment = witness.bound_moment(bound)
    when = ltr(beatcore.local_str(moment) + beatcore.zone_suffix(moment)) if moment else ''
    source = bound.get('source')
    if source == 'bitcoin_block':
        what = _('Bitcoin block %(height)s from checkpoint #%(n)s') % {
            'height': bound.get('height', '?'), 'n': bound.get('checkpoint', '?')}
        if bound.get('confirmed_by'):
            what += ' · ' + _('confirmed by %(source)s') % {'source': bound['confirmed_by']}
    elif source == 'opentimestamps':
        what = _('OpenTimestamps, Bitcoin block %(height)s') % {
            'height': bound.get('height', '?')}
    elif source == 'bank':
        what = _('bank transfer, %(bank)s') % {'bank': bound.get('bank', '')}
        if not when and bound.get('date'):
            when = ltr(bound['date'])
    else:
        return '', ''
    return when, what


def moment_html(obj) -> str:
    """„@beat · czas lokalny (strefa) · UTC" — wartosci escapowane."""
    beat = str(getattr(obj, 'beat', '') or '—')
    dt = beatcore.parse_iso_utc(str(getattr(obj, 'utc', '') or ''))
    muted = theme.MUTED_INK
    return (f'<b>{html.escape(ltr(beat))}</b> · '
            f'{html.escape(ltr(beatcore.local_str(dt) + beatcore.zone_suffix(dt)))} '
            f'<span style="color:{muted}">· {html.escape(ltr("UTC " + beatcore.utc_str(dt)))}'
            f'</span>')


def bounds_html(obj) -> str:
    """Dwie granice niezalezne od zegara Sigelith — albo '' gdy ich brak."""
    bounds = getattr(obj, 'time_bounds', None) or {}
    if not isinstance(bounds, dict):
        return ''
    muted = theme.MUTED_INK
    lines = []
    for key, name in (('not_before', _('not earlier than')),
                      ('not_after', _('not later than'))):
        when, what = bound_parts(bounds.get(key))
        if when or what:
            lines.append(f'<span style="color:{muted}">{html.escape(name)}:</span> '
                         f'{html.escape(when)} '
                         f'<span style="color:{muted}">— {html.escape(what)}</span>')
    return '<br>'.join(lines)
