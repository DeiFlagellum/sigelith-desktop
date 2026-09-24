"""
Zaufanie do kluczy po rotacji 2026-09-21.

Model: o tym, czy podpis korzenia pochodzi od BeatTime, decyduje WYLACZNIE
lista kluczy wbudowana w aplikacje (beatstamp/keys.py) — nigdy klucz
przyslany przez serwer ani zapisany w pliku `.beatproof`.

Cztery przypadki, kazdy z osobnym testem:

* klucz aktualny   -> PODPISANY/ZAKOTWICZONY;
* klucz wycofany   -> poprawny podpis, ale poziom najwyzej ZAREJESTROWANY
                      i ostrzezenie „odswiez online" (nigdy PODPISANY: ten
                      klucz podpisal tez inne korzenie dla 2026-W25/W30);
* klucz obcy       -> glosne zastrzezenie, dowod odrzucony;
* wlasny klucz     -> uznany, ale oznaczony jako 'override'.
"""
from __future__ import annotations

import base64
import copy
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from beatstamp import bundle, i18n, keys, proof  # noqa: E402
from beatstamp.config import Settings, settings_path  # noqa: E402
from beatstamp.history import Entry, History, entry_from_verification  # noqa: E402
from test_core import DIGEST, LIVE_PAYLOAD, RETIRED_KEY_PAYLOAD  # noqa: E402

# Jezyk interfejsu PRZYPIETY. Testy sprawdzaja ZNACZENIE napisu — oczekiwany
# tekst bierzemy z tego samego katalogu tlumaczen, ktorego uzywa program
# (`_('<msgid>')`), a nie z przepisanego recznie ciagu znakow. Bez przypiecia
# wynik suite zalezalby od jezyka interfejsu maszyny, na ktorej akurat sie ja
# uruchamia; bez katalogu — sprawdzalibysmy literowke, a nie tresc.
i18n.set_language('pl')
_ = i18n.gettext


RETIRED = keys.RETIRED_KEYS[0]['public_key']
CURRENT = keys.primary_key()


def _rogue_pair():
    """(klucz_prywatny, klucz_publiczny_b64) spoza listy BeatTime."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    pub = base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    return priv, pub


def _alias(key: str) -> str:
    """Ten sam klucz zapisany niekanonicznie: niezerowy bit dopelnienia.

    Ostatni znak przed `=` niesie 4 bity klucza i 2 nieuzywane bity, wiec
    `...yN0=` i `...yN1=` to te same 32 bajty. `b64decode(validate=True)`
    przyjmuje oba zapisy.
    """
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    assert key.endswith('=') and not key.endswith('==')
    alias = key[:-2] + alphabet[alphabet.index(key[-2]) ^ 1] + '='
    assert alias != key
    assert base64.b64decode(alias, validate=True) == base64.b64decode(key)
    return alias


def _signed_by(priv, pub, payload=LIVE_PAYLOAD) -> dict:
    """Odpowiedz z korzeniem podpisanym podanym kluczem."""
    out = copy.deepcopy(payload)
    message = f"beattime-proof-v1|{out['week']}|{out['week_root']}".encode()
    out['root_signature'] = base64.b64encode(priv.sign(message)).decode()
    out['public_key'] = pub
    return out


class KeyListTests(unittest.TestCase):
    """Niezmienniki samej listy — literowka tutaj wylaczylaby cala weryfikacje."""

    def test_every_key_is_a_raw_ed25519_public_key(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        for entry in keys.CURRENT_KEYS + keys.RETIRED_KEYS:
            raw = base64.b64decode(entry['public_key'], validate=True)
            self.assertEqual(len(raw), 32, entry)
            Ed25519PublicKey.from_public_bytes(raw)     # nie rzuca

    def test_builtin_keys_are_canonical(self):
        for entry in keys.CURRENT_KEYS + keys.RETIRED_KEYS:
            self.assertEqual(keys.canonical(entry['public_key']), entry['public_key'])
        self.assertEqual(keys.LEGACY_DEFAULT_PINNED_KEY,
                         keys.canonical(keys.LEGACY_DEFAULT_PINNED_KEY))

    def test_current_and_retired_are_disjoint(self):
        self.assertFalse(set(keys.current_public_keys()) & set(keys.retired_public_keys()))

    def test_dates_are_iso_and_ordered(self):
        from datetime import date
        for entry in keys.RETIRED_KEYS:
            start = date.fromisoformat(entry['active_from'])
            end = date.fromisoformat(entry['retired_on'])
            self.assertLessEqual(start, end, entry)
        for entry in keys.CURRENT_KEYS:
            date.fromisoformat(entry['active_from'])
        # Aktualny klucz zaczyna obowiazywac najpozniej w dniu wycofania
        # poprzedniego — inaczej w historii bylaby dziura bez klucza.
        self.assertLessEqual(keys.CURRENT_KEYS[0]['active_from'],
                             keys.RETIRED_KEYS[-1]['retired_on'])

    def test_known_values(self):
        self.assertEqual(CURRENT, 'e7y9THJIUKvNKOZHmdBjJ8E0bOKyBFVxxMpAJ8w574Y=')
        self.assertTrue(keys.is_retired('YNVYXDyg3hQGM3F+/ec+ZNmeN1JI/hZX+CxLqyJdyN0='))
        self.assertEqual(keys.retired_info(RETIRED)['retired_on'], '2026-09-21')
        self.assertEqual(proof.PINNED_PUBLIC_KEY, CURRENT)

    def test_classify(self):
        _priv, rogue = _rogue_pair()
        self.assertEqual(keys.classify(CURRENT), keys.SIGNER_CURRENT)
        self.assertEqual(keys.classify(RETIRED), keys.SIGNER_RETIRED)
        self.assertEqual(keys.classify(rogue), keys.SIGNER_UNKNOWN)
        self.assertEqual(keys.classify(''), keys.SIGNER_UNKNOWN)
        self.assertEqual(keys.classify(rogue, override=rogue), keys.SIGNER_OVERRIDE)
        self.assertTrue(keys.is_trusted(CURRENT))
        self.assertFalse(keys.is_trusted(RETIRED))
        self.assertFalse(keys.is_trusted(rogue))

    def test_override_never_revives_a_retired_key(self):
        self.assertEqual(keys.classify(RETIRED, override=RETIRED), keys.SIGNER_RETIRED)
        self.assertFalse(keys.is_trusted(RETIRED, override=RETIRED))

    def test_normalize_override(self):
        _priv, rogue = _rogue_pair()
        for quiet in ('', '   ', None, RETIRED, keys.LEGACY_DEFAULT_PINNED_KEY, CURRENT):
            self.assertEqual(keys.normalize_override(quiet), '', quiet)
        self.assertEqual(keys.normalize_override(f' {rogue} '), rogue)

    def test_format_date(self):
        self.assertEqual(keys.format_date('2026-09-21'), '21.09.2026')
        self.assertEqual(keys.format_date(''), '')


class NonCanonicalKeyTests(unittest.TestCase):
    """Regresja: alias klucza wycofanego omijal zakaz „przywrocenia" go.

    Porownanie napisow uznawalo `...yN1=` za inny klucz niz wycofany
    `...yN0=`, choc to te same 32 bajty. Alias wpisany jako wlasny klucz
    dawal podpisom YNVY (takze testowemu korzeniowi W25) poziom
    ZAKOTWICZONY.
    """

    ALIAS = _alias(RETIRED)

    def test_reviewer_alias_is_this_one(self):
        self.assertEqual(self.ALIAS, 'YNVYXDyg3hQGM3F+/ec+ZNmeN1JI/hZX+CxLqyJdyN1=')

    def test_canonical_rejects_every_non_canonical_form(self):
        for bad in (self.ALIAS, _alias(CURRENT), RETIRED.rstrip('='), RETIRED + '=',
                    'YWJj', 'x' * 44, '', None, 123, 'None'):
            self.assertEqual(keys.canonical(bad), '', bad)
        self.assertEqual(keys.canonical(f'  {CURRENT} '), CURRENT)

    def test_alias_is_neither_trusted_nor_an_override(self):
        self.assertEqual(keys.normalize_override(self.ALIAS), '')
        self.assertEqual(keys.classify(self.ALIAS), keys.SIGNER_UNKNOWN)
        self.assertEqual(keys.classify(self.ALIAS, override=self.ALIAS), keys.SIGNER_UNKNOWN)
        self.assertFalse(keys.is_trusted(self.ALIAS, override=self.ALIAS))
        self.assertFalse(keys.is_trusted(_alias(CURRENT)))

    def test_alias_payload_with_alias_override_is_rejected(self):
        payload = copy.deepcopy(RETIRED_KEY_PAYLOAD)
        payload['public_key'] = self.ALIAS
        r = proof.verify_payload(payload, expected_digest=DIGEST, key_override=self.ALIAS)
        self.assertTrue(r.signature_ok, 'te same bajty klucza — podpis sie zgadza')
        self.assertEqual(r.signer_status, keys.SIGNER_UNKNOWN)
        self.assertIs(r.level, proof.Level.RECORDED)
        self.assertFalse(r.trusted)
        self.assertTrue(r.problems)

    def test_alias_bundle_with_alias_override_is_rejected(self):
        data = bundle.build(proof.verify_payload(RETIRED_KEY_PAYLOAD, expected_digest=DIGEST))
        data['public_key'] = self.ALIAS
        check = bundle.check(data, document_digest=DIGEST, key_override=self.ALIAS)
        self.assertTrue(check.signature_ok)
        self.assertFalse(check.ok)
        self.assertEqual(check.signer_status, keys.SIGNER_UNKNOWN)

    def test_alias_in_settings_is_dropped(self):
        self.assertEqual(Settings(pinned_public_key=self.ALIAS).key_override, '')


class CurrentKeyTests(unittest.TestCase):

    def test_current_key_is_accepted(self):
        r = proof.verify_payload(LIVE_PAYLOAD, expected_digest=DIGEST)
        self.assertEqual(r.signer_status, keys.SIGNER_CURRENT)
        self.assertTrue(r.key_pinned_ok and r.signature_ok and r.trusted)
        self.assertFalse(r.needs_refresh)
        self.assertIs(r.level, proof.Level.ANCHORED)

    def test_current_key_without_anchor_is_signed(self):
        payload = copy.deepcopy(LIVE_PAYLOAD)
        payload['ots_status'] = 'pending'
        payload['anchors'] = []
        r = proof.verify_payload(payload, expected_digest=DIGEST)
        self.assertIs(r.level, proof.Level.SIGNED)
        self.assertTrue(r.trusted)


class RetiredKeyTests(unittest.TestCase):
    """Poprawny podpis WYCOFANYM kluczem: nie falszerstwo, ale i nie dowod."""

    def setUp(self):
        self.r = proof.verify_payload(RETIRED_KEY_PAYLOAD, expected_digest=DIGEST)

    def test_signature_is_mathematically_valid(self):
        self.assertTrue(self.r.signature_checked and self.r.signature_ok)
        self.assertTrue(self.r.inclusion_ok)

    def test_level_is_capped_at_recorded(self):
        self.assertIs(self.r.level, proof.Level.RECORDED,
                      'wycofany klucz nie może dawać poziomu PODPISANY ani ZAKOTWICZONY')
        self.assertLess(self.r.level.order, proof.Level.SIGNED.order)
        self.assertFalse(self.r.key_pinned_ok)
        self.assertFalse(self.r.trusted)

    def test_is_flagged_for_refresh_not_as_forgery(self):
        self.assertEqual(self.r.signer_status, keys.SIGNER_RETIRED)
        self.assertTrue(self.r.needs_refresh)
        self.assertEqual(self.r.problems, [], 'to nie jest dowód fałszerstwa')
        self.assertEqual(len(self.r.warnings), 1, self.r.warnings)
        warning = self.r.warnings[0]
        self.assertIn(keys.format_date('2026-09-21'), warning)
        self.assertIn('2026-W25', warning)
        self.assertIn(
            _('Refresh the proof online (History -> Refresh statuses, F5) to '
              'fetch a signature made with the current key.'), warning)

    def test_retired_key_as_settings_override_is_still_capped(self):
        r = proof.verify_payload(RETIRED_KEY_PAYLOAD, expected_digest=DIGEST,
                                 key_override=RETIRED)
        self.assertEqual(r.signer_status, keys.SIGNER_RETIRED)
        self.assertIs(r.level, proof.Level.RECORDED)

    def test_tampered_retired_signature_is_a_problem(self):
        payload = copy.deepcopy(RETIRED_KEY_PAYLOAD)
        sig = payload['root_signature']
        payload['root_signature'] = ('A' if sig[0] != 'A' else 'B') + sig[1:]
        r = proof.verify_payload(payload, expected_digest=DIGEST)
        self.assertFalse(r.signature_ok)
        self.assertFalse(r.needs_refresh)
        self.assertIn(_('The Ed25519 signature of the week root is invalid.'),
                      r.problems)
        self.assertIs(r.level, proof.Level.RECORDED)

    def test_retired_key_over_a_different_root_stays_recorded(self):
        """Scenariusz z audytu: wycofany klucz podpisal INNY korzen tego tygodnia.

        Atakujacy z tym kluczem sklada wlasne drzewo, w ktorym skrot wisi
        pod jego korzeniem, i podpisuje ten korzen. Wszystko sie zgadza
        matematycznie — ale poziom nie moze urosnac.
        """
        from beatstamp import merkle
        # Nie mamy prywatnego klucza YNVY, wiec symulujemy go wlasnym kluczem
        # dopisanym na chwile do listy wycofanych.
        priv, pub = _rogue_pair()
        sibling = 'ab' * 32
        root = merkle.fold_proof(DIGEST, [{'side': 'R', 'hash': sibling}])
        forged = copy.deepcopy(LIVE_PAYLOAD)
        forged.update(week_root=root, inclusion_proof=[{'side': 'R', 'hash': sibling}])
        forged = _signed_by(priv, pub, forged)
        original = keys.RETIRED_KEYS
        keys.RETIRED_KEYS = original + (
            {'public_key': pub, 'active_from': '2026-01-01', 'retired_on': '2026-02-01'},)
        try:
            r = proof.verify_payload(forged, expected_digest=DIGEST)
        finally:
            keys.RETIRED_KEYS = original
        self.assertTrue(r.inclusion_ok and r.signature_ok)
        self.assertIs(r.level, proof.Level.RECORDED)
        self.assertFalse(r.trusted)


class UnknownKeyTests(unittest.TestCase):

    def test_unknown_key_is_rejected_loudly(self):
        priv, pub = _rogue_pair()
        r = proof.verify_payload(_signed_by(priv, pub), expected_digest=DIGEST)
        self.assertTrue(r.signature_ok)
        self.assertEqual(r.signer_status, keys.SIGNER_UNKNOWN)
        self.assertFalse(r.key_pinned_ok)
        self.assertFalse(r.trusted)
        self.assertIs(r.level, proof.Level.RECORDED)
        self.assertIn(
            _('The server signed the root with a key OTHER than the BeatTime '
              'keys built into the application. The signature may be '
              'technically valid, but it does not prove it comes from '
              'BeatTime.'), r.problems)

    def test_missing_key_is_rejected(self):
        payload = copy.deepcopy(LIVE_PAYLOAD)
        payload['public_key'] = ''
        r = proof.verify_payload(payload, expected_digest=DIGEST)
        self.assertTrue(r.signature_ok, 'podpis sprawdzony aktualnym kluczem z listy')
        self.assertFalse(r.trusted)
        self.assertIn(_('The server did not give a public key for the '
                        'signature.'), r.problems)

    def test_server_cannot_vouch_for_its_own_key(self):
        """Nic w odpowiedzi nie dopisuje klucza do zaufanych."""
        priv, pub = _rogue_pair()
        payload = _signed_by(priv, pub)
        payload['trusted_keys'] = [pub]
        payload['key_status'] = 'active'
        payload['current_public_key'] = pub
        r = proof.verify_payload(payload, expected_digest=DIGEST)
        self.assertFalse(r.trusted)


class OverrideKeyTests(unittest.TestCase):

    def test_override_is_accepted_but_flagged(self):
        priv, pub = _rogue_pair()
        r = proof.verify_payload(_signed_by(priv, pub), expected_digest=DIGEST,
                                 key_override=pub)
        self.assertEqual(r.signer_status, keys.SIGNER_OVERRIDE)
        self.assertTrue(r.key_pinned_ok and r.trusted)
        self.assertIs(r.level, proof.Level.ANCHORED)
        self.assertEqual(r.problems, [])

    def test_override_does_not_disable_builtin_keys(self):
        _priv, other = _rogue_pair()
        r = proof.verify_payload(LIVE_PAYLOAD, expected_digest=DIGEST, key_override=other)
        self.assertEqual(r.signer_status, keys.SIGNER_CURRENT)
        self.assertTrue(r.trusted)

    def test_override_for_one_key_does_not_trust_another(self):
        priv, pub = _rogue_pair()
        _p2, other = _rogue_pair()
        r = proof.verify_payload(_signed_by(priv, pub), expected_digest=DIGEST,
                                 key_override=other)
        self.assertFalse(r.trusted)


class BundleKeyTests(unittest.TestCase):

    def _bundle(self, payload) -> dict:
        return bundle.build(proof.verify_payload(payload, expected_digest=DIGEST))

    def test_current_key_bundle_is_ok(self):
        check = bundle.check(self._bundle(LIVE_PAYLOAD), document_digest=DIGEST)
        self.assertTrue(check.ok, check.problems)
        self.assertEqual(check.signer_status, keys.SIGNER_CURRENT)
        self.assertFalse(check.needs_refresh)

    def test_retired_key_bundle_needs_refresh(self):
        check = bundle.check(self._bundle(RETIRED_KEY_PAYLOAD), document_digest=DIGEST)
        self.assertFalse(check.ok, 'wycofany klucz nie może dać „zweryfikowany offline"')
        self.assertTrue(check.signature_ok and check.inclusion_ok)
        self.assertFalse(check.key_pinned_ok)
        self.assertEqual(check.signer_status, keys.SIGNER_RETIRED)
        self.assertTrue(check.needs_refresh)
        self.assertEqual(check.problems, [])
        self.assertTrue(any('wycofanym 21.09.2026' in w for w in check.warnings))

    def test_retired_key_bundle_with_override_still_not_ok(self):
        check = bundle.check(self._bundle(RETIRED_KEY_PAYLOAD), document_digest=DIGEST,
                             key_override=RETIRED)
        self.assertFalse(check.ok)

    def test_unknown_key_bundle_is_rejected(self):
        priv, pub = _rogue_pair()
        check = bundle.check(self._bundle(_signed_by(priv, pub)), document_digest=DIGEST)
        self.assertFalse(check.ok)
        self.assertEqual(check.signer_status, keys.SIGNER_UNKNOWN)
        self.assertTrue(check.problems)

    def test_override_bundle_is_ok(self):
        priv, pub = _rogue_pair()
        data = self._bundle(_signed_by(priv, pub))
        check = bundle.check(data, document_digest=DIGEST, key_override=pub)
        self.assertTrue(check.ok, check.problems)
        self.assertEqual(check.signer_status, keys.SIGNER_OVERRIDE)

    def test_instructions_name_the_current_key(self):
        data = self._bundle(LIVE_PAYLOAD)
        self.assertIn(CURRENT, data['how_to_verify'])
        self.assertNotIn(RETIRED, data['how_to_verify'])
        self.assertIn('/spec/#keys', data['how_to_verify'])


class SettingsMigrationTests(unittest.TestCase):
    """Stare settings.json mialo YNVY jako przypiety klucz fabryczny."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._old = os.environ.get('BEATSTAMP_DATA_DIR')
        os.environ['BEATSTAMP_DATA_DIR'] = self._tmp

    def tearDown(self):
        if self._old is None:
            os.environ.pop('BEATSTAMP_DATA_DIR', None)
        else:
            os.environ['BEATSTAMP_DATA_DIR'] = self._old
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _load_with(self, value) -> Settings:
        settings_path().write_text(json.dumps(
            {'pinned_public_key': value, 'theme': 'dark'}), encoding='utf-8')
        return Settings.load()

    def test_default_is_builtin_list(self):
        self.assertEqual(Settings().pinned_public_key, '')
        self.assertEqual(Settings().key_override, '')

    def test_old_factory_default_is_migrated(self):
        loaded = self._load_with(keys.LEGACY_DEFAULT_PINNED_KEY)
        self.assertEqual(loaded.pinned_public_key, '')
        self.assertEqual(loaded.theme, 'dark', 'reszta ustawień zostaje')
        loaded.save()
        raw = json.loads(settings_path().read_text(encoding='utf-8'))
        self.assertEqual(raw['pinned_public_key'], '', 'zapisuje się już pusta wartość')

    def test_empty_and_retired_and_current_become_empty(self):
        for value in ('', RETIRED, CURRENT):
            self.assertEqual(self._load_with(value).pinned_public_key, '', value)

    def test_custom_override_is_kept(self):
        _priv, pub = _rogue_pair()
        loaded = self._load_with(pub)
        self.assertEqual(loaded.pinned_public_key, pub)
        self.assertEqual(loaded.key_override, pub)

    def test_migrated_settings_trust_the_current_key(self):
        """Sedno migracji: po aktualizacji swieze dowody NIE sa „obcym kluczem"."""
        loaded = self._load_with(keys.LEGACY_DEFAULT_PINNED_KEY)
        r = proof.verify_payload(LIVE_PAYLOAD, expected_digest=DIGEST,
                                 key_override=loaded.key_override)
        self.assertTrue(r.trusted)
        r = proof.verify_payload(RETIRED_KEY_PAYLOAD, expected_digest=DIGEST,
                                 key_override=loaded.key_override)
        self.assertIs(r.level, proof.Level.RECORDED)

    def test_key_override_property_filters_hand_edited_file(self):
        self.assertEqual(Settings(pinned_public_key=RETIRED).key_override, '')

    def test_null_and_garbage_do_not_become_a_custom_key(self):
        """Regresja: `null` zamienial sie w „wlasny klucz" o tresci 'None'.

        Zaufanie i tak nie rosnie (zaden podpis nie ma klucza 'None'), ale
        pasek stanu na stale ostrzegal o wlasnym kluczu, a Ustawienia nie
        daly sie zapisac bez recznego czyszczenia pola.
        """
        for value in (None, 'garbage', 123, 'None', ['x'], {'a': 1},
                      _alias(RETIRED), _alias(CURRENT)):
            with self.subTest(value=value):
                with self.assertLogs('beatstamp.config', level='WARNING'):
                    loaded = self._load_with(value)
                self.assertEqual(loaded.pinned_public_key, '')
                self.assertEqual(loaded.key_override, '')
                self.assertEqual(loaded.theme, 'dark', 'reszta ustawień zostaje')

    def test_quiet_values_are_not_logged(self):
        for value in ('', RETIRED, CURRENT, f' {CURRENT} '):
            with self.subTest(value=value):
                with self.assertNoLogs('beatstamp.config', level='WARNING'):
                    self.assertEqual(self._load_with(value).pinned_public_key, '')


class HistoryRetiredKeyTests(unittest.TestCase):
    """Wpisy zapisane, gdy wycofany klucz byl jeszcze uznawany."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / 'history.json'

    def tearDown(self):
        self._tmp.cleanup()

    def _stored(self, payload, level='anchored') -> Entry:
        # Symulujemy wpis zapisany przez stara wersje: poziom „zakotwiczony"
        # i verified_ok=True, niezaleznie od dzisiejszych zasad.
        entry = entry_from_verification(proof.verify_payload(payload, expected_digest=DIGEST))
        entry.level = level
        entry.verified_ok = True
        return entry

    def test_retired_entry_is_demoted_on_load(self):
        self.path.write_text(json.dumps([self._stored(RETIRED_KEY_PAYLOAD).to_dict()]),
                             encoding='utf-8')
        entry = History(self.path).load().entries[0]
        self.assertTrue(entry.signed_by_retired_key)
        self.assertEqual(entry.level, 'recorded')
        self.assertFalse(entry.verified_ok)

    def test_retired_entry_stored_as_signed_is_demoted_too(self):
        """Mutant M12: demotion tylko dla 'anchored' przechodzil testy."""
        self.path.write_text(json.dumps(
            [self._stored(RETIRED_KEY_PAYLOAD, level='signed').to_dict()]),
            encoding='utf-8')
        entry = History(self.path).load().entries[0]
        self.assertEqual(entry.level, 'recorded')
        self.assertFalse(entry.verified_ok)

    def test_current_entry_is_untouched(self):
        self.path.write_text(json.dumps([self._stored(LIVE_PAYLOAD).to_dict()]),
                             encoding='utf-8')
        entry = History(self.path).load().entries[0]
        self.assertFalse(entry.signed_by_retired_key)
        self.assertEqual(entry.level, 'anchored')
        self.assertTrue(entry.verified_ok)

    def test_level_without_signature_is_demoted(self):
        """Plik historii edytowany recznie: „zakotwiczony" bez podpisu korzenia."""
        entry = self._stored(LIVE_PAYLOAD)
        entry.root_signature = ''
        self.path.write_text(json.dumps([entry.to_dict()]), encoding='utf-8')
        loaded = History(self.path).load().entries[0]
        self.assertEqual(loaded.level, 'recorded')
        self.assertFalse(loaded.verified_ok)

    def test_backdated_entry_is_demoted(self):
        entry = self._stored(LIVE_PAYLOAD)
        entry.utc, entry.beat = '2019-01-01T00:00:00Z', '@041.66'
        self.path.write_text(json.dumps([entry.to_dict()]), encoding='utf-8')
        loaded = History(self.path).load().entries[0]
        self.assertEqual(loaded.level, 'recorded')
        self.assertFalse(loaded.verified_ok)

    def test_refresh_fetches_new_signature_for_retired_entries(self):
        os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
        from beatstamp import workers

        class FakeClient:
            def __init__(self):
                self.asked = []

            def verify(self, digest):
                self.asked.append(digest)
                return copy.deepcopy(LIVE_PAYLOAD)

        # Nawet wpis, ktory wciaz twierdzi „zakotwiczony" (np. przed
        # migracja w pamieci), musi zostac odpytany, bo jego klucz nie jest
        # na liscie aktualnych.
        stale = self._stored(RETIRED_KEY_PAYLOAD, level='anchored')
        fresh_current = self._stored(LIVE_PAYLOAD, level='anchored')
        client = FakeClient()
        task = workers.RefreshEntriesTask([stale, fresh_current], client)
        self.assertTrue(task._needs_refresh(stale))
        self.assertFalse(task._needs_refresh(fresh_current))

        updated = task.work()
        self.assertEqual(client.asked, [DIGEST], 'zakotwiczony wpis z aktualnym kluczem pomijamy')
        self.assertEqual(len(updated), 1)
        self.assertEqual(updated[0].public_key, CURRENT)
        self.assertEqual(updated[0].level, 'anchored')
        self.assertTrue(updated[0].verified_ok)

    def test_certificate_of_retired_entry_says_refresh(self):
        from beatstamp import certificate
        entry = self._stored(RETIRED_KEY_PAYLOAD, level='anchored')
        text, _color = certificate._level_line(entry)
        self.assertTrue(text.startswith('ZAREJESTROWANY'))
        self.assertIn('wycofanym', text)
        pdf = certificate.build_certificate(entry)
        self.assertTrue(pdf.startswith(b'%PDF'))


class HistoryOverrideTrustTests(unittest.TestCase):
    """Wpisy zweryfikowane WLASNYM kluczem, ktory potem usunieto z ustawien.

    Regresja: zapisany poziom „zakotwiczony" i verified_ok=True zostawaly po
    usunieciu klucza (takze podsunietego przez atakujacego) — zielone
    w historii i na certyfikacie PDF, choc swieza weryfikacja daje
    „Zarejestrowany".
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / 'history.json'
        priv, self.pub = _rogue_pair()
        result = proof.verify_payload(_signed_by(priv, self.pub), expected_digest=DIGEST,
                                      key_override=self.pub)
        self.assertIs(result.level, proof.Level.ANCHORED)
        self.entry = entry_from_verification(result)
        self.path.write_text(json.dumps([self.entry.to_dict()]), encoding='utf-8')

    def tearDown(self):
        self._tmp.cleanup()

    def test_kept_while_the_override_is_set(self):
        entry = History(self.path).load(key_override=self.pub).entries[0]
        self.assertEqual(entry.level, 'anchored')
        self.assertTrue(entry.verified_ok)

    def test_demoted_on_load_without_the_override(self):
        entry = History(self.path).load().entries[0]
        self.assertEqual(entry.level, 'recorded')
        self.assertFalse(entry.verified_ok)

    def test_demoted_in_memory_when_the_override_is_removed(self):
        history = History(self.path).load(key_override=self.pub)
        self.assertEqual(history.demote_untrusted(self.pub), 0)
        self.assertEqual(history.demote_untrusted(''), 1)
        self.assertEqual(history.entries[0].level, 'recorded')
        self.assertEqual(history.demote_untrusted(''), 0, 'drugi raz nie ma czego zmieniać')

    def test_certificate_recomputes_trust(self):
        from beatstamp import certificate
        text, _color = certificate._level_line(self.entry)
        self.assertEqual(text, _('UNCONFIRMED — root signed with a key outside '
                                 'the BeatTime list, signature not binding'))
        text, _color = certificate._level_line(self.entry, key_override=self.pub)
        self.assertEqual(text, _('ANCHORED — the week root is preserved outside '
                                 'BeatTime'))
        self.assertEqual(
            certificate._signature_text(self.entry, key_override=self.pub),
            _('Ed25519 — root signed with YOUR OWN key from the settings '
              '(outside the built-in list), checked locally'))

    def test_refresh_skips_anchored_override_entry_only_while_override_is_set(self):
        """Mutant M27: _needs_refresh ignorujacy key_override przechodzil testy."""
        os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
        from beatstamp import workers
        with_override = workers.RefreshEntriesTask([self.entry], client=None,
                                                   key_override=self.pub)
        self.assertFalse(with_override._needs_refresh(self.entry))
        without = workers.RefreshEntriesTask([self.entry], client=None)
        self.assertTrue(without._needs_refresh(self.entry))


if __name__ == '__main__':
    unittest.main(verbosity=2)
