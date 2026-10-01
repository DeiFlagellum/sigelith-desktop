"""
Zmiana nazwy BeatStamp -> Sigelith Desktop (3.0.0, 2026-09-27).

Infrastruktura dowodowa nazywa sie od 2026-09-27 Sigelith (sigelith.org),
a zapis czasu to po prostu .beat; BeatTime zostal tylko w nazwach aplikacji
zegarowych w Google Play (decyzja wlasciciela 2026-09-27 wieczorem).
sigelith.org i beattime.live obsluguje TA SAMA instancja — jedna baza, jeden
dziennik, jeden klucz — wiec zmiana dotyczy nazw i adresow, nie formatow.

Kazdy test pilnuje jednego miejsca, w ktorym stara nazwa albo stary adres
wrocilyby po cichu: adres API i naglowek User-Agent, adres weryfikacji
w kodzie QR, metadane pliku `.exe` i paczki MSIX, oraz STRAZNIK, ktory nie
pozwala zbudowac paczki MSIX z tozsamoscia BeatStampa.

Rzeczy, ktore sie NIE zmieniaja (identyfikatory formatow, `.beatproof`,
klucze), maja wlasne testy: `test_core.BundleAuthorityTests`,
`test_keys`, `test_server_parity`. Przeprowadzka danych
`%USERPROFILE%\\BeatStamp` -> `%USERPROFILE%\\Sigelith`:
`test_datadir.MigrationFromBeatStampTests`. Internet Archive pod obiema
domenami: `test_prestore.WaybackTests`.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))

from beatstamp import __app_name__, __version__, api, bundle, config, i18n, witness  # noqa: E402
from beatstamp.config import Settings  # noqa: E402

import licenses  # noqa: E402  (tools/)

PACKAGING = ROOT / 'packaging'
MANIFEST = PACKAGING / 'AppxManifest.xml'
NS = {'m': 'http://schemas.microsoft.com/appx/manifest/foundation/windows10',
      'uap': 'http://schemas.microsoft.com/appx/manifest/uap/windows10'}


def _powershell() -> str | None:
    if sys.platform != 'win32':
        return None
    return shutil.which('powershell.exe') or shutil.which('powershell')


class ProgramNameTests(unittest.TestCase):

    def test_the_program_is_sigelith_desktop_3(self):
        self.assertEqual(__app_name__, 'Sigelith Desktop')
        self.assertEqual(__version__.split('.')[0], '3')

    def test_the_user_agent_names_the_program_and_its_site(self):
        self.assertEqual(api.USER_AGENT, f'SigelithDesktop/{__version__} (+https://sigelith.org)')
        client = api.BeatTimeClient(Settings())
        try:
            # Ten sam naglowek dla API i dla osob trzecich (archiwa, eksploratory).
            for session in (client._session, client._session_once, client._external):
                self.assertEqual(session.headers['User-Agent'], api.USER_AGENT)
        finally:
            client.close()

    def test_every_window_title_ends_with_the_display_name(self):
        """Qt dokleja nazwe programu do tytulu, ktory sie nia nie konczy —
        tytul z BeatStampem dostalby „… — BeatStamp - Sigelith Desktop".
        `i18n.temporary` — jezyk calego procesu testow zostaje nietkniety."""
        for msgid in ('Settings — Sigelith Desktop', 'About — Sigelith Desktop',
                      'Thank you — Sigelith Desktop', 'Event log — Sigelith Desktop',
                      'Licences and notices — Sigelith Desktop',
                      'Application error — Sigelith Desktop'):
            with self.subTest(title=msgid):
                for language in i18n.SUPPORTED:
                    with i18n.temporary(language):
                        self.assertTrue(i18n.gettext(msgid).endswith(__app_name__),  # i18n: skip
                                        f'{language}: {i18n.gettext(msgid)!r}')  # i18n: skip


class NetworkAddressTests(unittest.TestCase):

    def test_the_api_goes_to_sigelith_with_unchanged_paths(self):
        client = api.BeatTimeClient(Settings())
        try:
            for path in ('/api/proof/stamp', '/api/proof/verify',
                         '/api/proof/cert/' + 'a' * 64, '/api/proof/checkpoints/latest',
                         '/checkpoints/000001.json', '/api/supporters/thanks'):
                with self.subTest(path=path):
                    self.assertEqual(client._url(path), 'https://sigelith.org' + path)
        finally:
            client.close()

    def test_tor_still_uses_the_existing_onion_service(self):
        client = api.BeatTimeClient(Settings(use_tor=True))
        try:
            self.assertEqual(client._url('/api/proof/stamp'),
                             config.ONION_BASE_URL + '/api/proof/stamp')
        finally:
            client.close()

    def test_legal_and_help_pages_are_under_sigelith(self):
        self.assertEqual(config.SITE_BASE, 'https://sigelith.org')
        self.assertEqual(config.IMPRESSUM_URL, 'https://sigelith.org/de/impressum/')
        self.assertEqual(config.privacy_policy_url('de'), 'https://sigelith.org/de/datenschutz/')
        self.assertEqual(config.privacy_policy_url('pl'), 'https://sigelith.org/privacy/')
        self.assertEqual(config.site_url('proof', 'pl'), 'https://sigelith.org/pl/proof/')

    def test_the_witness_reads_the_renamed_log_repository(self):
        self.assertEqual(witness.GITHUB_REPO, 'DeiFlagellum/sigelith-log')
        self.assertEqual(witness.CHECKPOINT_PUBLIC, 'https://sigelith.org/checkpoints/{name}')


class VerificationLinkTests(unittest.TestCase):
    """Adres weryfikacji w JEDNEJ stalej — kod QR ma dzialac latami."""

    DIGEST = 'ab' * 32

    def test_one_constant(self):
        self.assertEqual(config.VERIFY_URL, 'https://sigelith.org/proof/?h=')
        self.assertEqual(config.verify_url(self.DIGEST), config.VERIFY_URL + self.DIGEST)

    def test_the_window_button_uses_the_same_page_in_the_interface_language(self):
        self.assertEqual(config.verify_url(self.DIGEST, 'pl'),
                         'https://sigelith.org/pl/proof/?h=' + self.DIGEST)
        self.assertEqual(config.verify_url(self.DIGEST, 'en'), config.verify_url(self.DIGEST))

    def test_history_and_certificate_take_it_from_there(self):
        from beatstamp import certificate
        from beatstamp.history import Entry

        self.assertEqual(Entry(digest=self.DIGEST).verify_url, config.verify_url(self.DIGEST))
        seen = []
        real = certificate._qr

        def recording(url, *args, **kwargs):
            seen.append(url)
            return real(url, *args, **kwargs)

        entry = Entry(digest=self.DIGEST, file_name='a.pdf', beat='@500.00',
                      utc='2026-09-22T12:00:00Z', week='2026-W39', verified_ok=True)
        with mock.patch.object(certificate, '_qr', recording):
            certificate.build_certificate(entry)
        self.assertEqual(seen, [config.verify_url(self.DIGEST)])

    def test_the_pdf_metadata_names_the_new_program(self):
        from beatstamp import certificate
        from beatstamp.history import Entry

        data = certificate.build_certificate(Entry(digest=self.DIGEST))
        self.assertIn(b'/Author (Sigelith Desktop)', data)
        self.assertIn(f'/Creator (Sigelith Desktop {__version__})'.encode(), data)
        self.assertNotIn(b'BeatStamp', data)


class ExecutableMetadataTests(unittest.TestCase):
    """Plik `.exe`, katalog wydania, manifest i zasob wersji mowia jedno."""

    def test_the_spec_builds_sigelithdesktop_exe(self):
        spec = (ROOT / 'beatstamp.spec').read_text(encoding='utf-8')
        self.assertEqual(spec.count("name='SigelithDesktop'"), 2, 'EXE i COLLECT')
        manifest = re.search(r"manifest='([^']+)'", spec).group(1)
        self.assertTrue((ROOT / manifest).is_file(), manifest)
        self.assertEqual(licenses.EXECUTABLE, 'SigelithDesktop.exe')
        self.assertEqual(licenses.PACKAGE_DIRS[0].name, 'SigelithDesktop')

    def test_the_build_scripts_agree_with_the_spec(self):
        build = (ROOT / 'build.ps1').read_text(encoding='utf-8-sig')
        self.assertIn(r"'dist\SigelithDesktop\SigelithDesktop.exe'", build)
        msix = (PACKAGING / 'build_msix.ps1').read_text(encoding='utf-8-sig')
        self.assertIn(r"Join-Path $Desktop 'dist\SigelithDesktop'", msix)
        self.assertIn('SigelithDesktop-$packageVersion-x64.msix', msix)
        # Jedyny dozwolony `BeatStamp.exe`: sprzatanie pozostalosci po trybie
        # jednoplikowym wersji 2.1 (`dist\BeatStamp.exe`).
        old = [line for line in (build + msix).splitlines() if 'BeatStamp.exe' in line]
        self.assertTrue(all('$legacy' in line or 'jednoplikowym' in line for line in old), old)
        self.assertNotIn('BeatStamp.exe', msix)

    def test_the_version_resource_matches_the_code(self):
        text = (ROOT / 'version_info.txt').read_text(encoding='utf-8')
        numbers = tuple(int(p) for p in __version__.split('.')) + (0,)
        for field in ('filevers', 'prodvers'):
            with self.subTest(field=field):
                found = re.search(field + r'=\((\d+), (\d+), (\d+), (\d+)\)', text)
                self.assertEqual(tuple(int(g) for g in found.groups()), numbers)
        self.assertIn(f"StringStruct('ProductVersion', '{__version__}')", text)
        self.assertIn(f"StringStruct('FileVersion', '{__version__}.0')", text)
        self.assertIn("StringStruct('ProductName', 'Sigelith Desktop')", text)
        self.assertIn("StringStruct('OriginalFilename', 'SigelithDesktop.exe')", text)
        self.assertIn("StringStruct('CompanyName', 'Adam Koch')", text)
        self.assertNotIn('BeatStamp', text)


class MsixManifestTests(unittest.TestCase):
    """Tozsamosc z Partner Center (produkt „Sigelith Desktop", 9N5XK65GTF33)."""

    def setUp(self):
        self.root = ET.parse(MANIFEST).getroot()

    def test_the_identity_is_the_sigelith_desktop_product(self):
        identity = self.root.find('m:Identity', NS)
        self.assertEqual(identity.get('Name'), 'AdamKoch.SigelithDesktop')
        self.assertEqual(identity.get('Publisher'), 'CN=322BC472-4859-4579-991B-25EE879D3796')
        props = self.root.find('m:Properties', NS)
        self.assertEqual(props.find('m:PublisherDisplayName', NS).text, 'Adam Koch')

    def test_the_names_are_the_reserved_name(self):
        self.assertEqual(self.root.find('m:Properties/m:DisplayName', NS).text,
                         'Sigelith Desktop')
        app = self.root.find('m:Applications/m:Application', NS)
        visual = app.find('uap:VisualElements', NS)
        self.assertEqual(visual.get('DisplayName'), 'Sigelith Desktop')
        self.assertIn('Sigelith', visual.get('Description'))
        self.assertNotIn('BeatTime', visual.get('Description'))
        self.assertEqual(app.get('Executable'), licenses.EXECUTABLE)


@unittest.skipUnless(_powershell(), 'straznik MSIX to skrypt PowerShella (Windows)')
class MsixBuildGuardTests(unittest.TestCase):
    """`build_msix.ps1` ODMAWIA paczki z tozsamoscia BeatStampa.

    Placeholder w <Identity> dal juz kiedys paczke, ktora zbudowala sie bez
    bledu i byla bezuzyteczna. Tu sprawdzamy prawdziwe skrypty, bez budowania:
    straznik konczy prace, zanim cokolwiek zostanie skopiowane albo spakowane.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def _manifest(self, folder: Path, **replace: str) -> Path:
        text = MANIFEST.read_text(encoding='utf-8')
        for old, new in replace.items():
            self.assertIn(old, text)
            text = text.replace(old, new)
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / 'AppxManifest.xml'
        target.write_text(text, encoding='utf-8')
        return target

    def _run(self, script: Path, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [_powershell(), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
             '-File', str(script), *args],
            capture_output=True, timeout=120)

    @staticmethod
    def _text(result: subprocess.CompletedProcess) -> str:
        return (result.stdout + result.stderr).decode('utf-8', 'replace')

    def test_the_current_manifest_passes(self):
        result = self._run(PACKAGING / 'check_identity.ps1', '-Manifest', str(MANIFEST))
        self.assertEqual(result.returncode, 0, self._text(result))
        self.assertIn('AdamKoch.SigelithDesktop', self._text(result))

    def test_the_beatstamp_identity_is_refused(self):
        manifest = self._manifest(self.dir, **{
            'Name="AdamKoch.SigelithDesktop"': 'Name="AdamKoch.BeatStamp"'})
        result = self._run(PACKAGING / 'check_identity.ps1', '-Manifest', str(manifest))
        self.assertEqual(result.returncode, 1, self._text(result))
        self.assertIn('ODMOWA', self._text(result))
        self.assertIn('AdamKoch.BeatStamp', self._text(result))

    def test_the_beatstamp_display_name_is_refused(self):
        manifest = self._manifest(self.dir, **{
            '<DisplayName>Sigelith Desktop</DisplayName>': '<DisplayName>BeatStamp</DisplayName>'})
        result = self._run(PACKAGING / 'check_identity.ps1', '-Manifest', str(manifest))
        self.assertEqual(result.returncode, 1, self._text(result))

    def test_an_unreadable_manifest_is_an_error(self):
        result = self._run(PACKAGING / 'check_identity.ps1', '-Manifest',
                           str(self.dir / 'nie-ma.xml'))
        self.assertEqual(result.returncode, 2, self._text(result))

    def _layout(self, **replace: str) -> Path:
        """Kopia `packaging/` w katalogu tymczasowym — bez `dist/` i bez kodu."""
        packaging = self.dir / 'packaging'
        packaging.mkdir()
        for name in ('build_msix.ps1', 'check_identity.ps1'):
            shutil.copy2(PACKAGING / name, packaging / name)
        self._manifest(packaging, **replace)
        return packaging / 'build_msix.ps1'

    def test_build_msix_stops_before_doing_anything(self):
        script = self._layout(**{'Name="AdamKoch.SigelithDesktop"': 'Name="AdamKoch.BeatStamp"'})
        result = self._run(script)
        text = self._text(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn('ODMOWA', text)
        self.assertIn('Paczka NIE zostala zbudowana', text)
        self.assertNotIn('=== Narzedzia ===', text, 'straznik ma byc PIERWSZY')
        self.assertFalse((self.dir / 'dist').exists())

    def test_build_msix_lets_the_sigelith_identity_through(self):
        script = self._layout()
        result = self._run(script)
        text = self._text(result)
        # Dalej i tak sie nie zbuduje (brak dist/ i kodu w katalogu
        # tymczasowym), ale straznik przepuscil i skrypt poszedl dalej.
        self.assertNotIn('ODMOWA', text)
        self.assertIn('AdamKoch.SigelithDesktop', text)
        self.assertIn('=== Narzedzia ===', text)
        self.assertFalse(list(self.dir.glob('dist/*.msix')))


if __name__ == '__main__':
    unittest.main()
