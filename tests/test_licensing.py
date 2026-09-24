"""
Licencje: co lezy w ZBUDOWANEJ paczce i czy wolno to wydac.

Reszta testow dziala na kodzie zrodlowym. Ten zestaw jest jedynym, ktory
patrzy na wynik kompilacji — bo pytanie „czy wolno to komus dac" nie dotyczy
kodu, tylko tego, co uzytkownik naprawde dostaje na dysk.

Siedem awarii, ktorych nie widzi zaden inny test:

* **modul tylko-GPL w paczce.** Qt jest licencjonowane MODULAMI i nie kazdy
  modul jest na LGPL. Qt Virtual Keyboard (klawiatura ekranowa) wchodzil tu
  sam, jako zaleznosc wtyczki wejscia — nieuzywany, niewidoczny i wystarczajacy,
  zeby wydanie na Apache-2.0 bylo naruszeniem. Nic sie przy tym nie psuje,
  wiec zaden test funkcjonalny tego nie zlapie;
* **plik bez przypisanej licencji.** Aktualizacja zaleznosci dokłada pliki.
  Jesli zaden wzorzec ich nie obejmuje, nota licencyjna po cichu ich nie
  wymienia — i dopiero ktos z zewnatrz zauwaza, ze paczka zawiera cos,
  o czym nie napisano ani slowa;
* **`NOTICE` rozjechany z paczka.** Plik not jest generowany; recznie
  poprawiony albo niezregenerowany po zmianie zaleznosci klamie, a klamie
  cicho;
* **usuniecie, ktore cos zlamalo.** Razem z klawiatura wypadl caly stos QML.
  Test czyta tablice importow KAZDEGO pliku, ktory zostal, i sprawdza, ze
  nikt nie wola o to, czego juz nie ma;
* **biblioteka bez wlasnego pliku.** reportlab, requests, urllib3, idna
  i PySocks nie maja w paczce ani jednego pliku — ich kod lezy w archiwum
  wewnatrz `BeatStamp.exe`. Kontrola po nazwach plikow widziala komplet
  i nie zauwazala, ze paczka rozpowszechnia kod BSD/MIT/Apache bez noty;
* **nota FALSZYWA zamiast brakujacej.** Lapacz `Qt6*.dll -> qt (LGPL)`
  oglaszal kazdy nowy modul Qt jako LGPL, takze taki, ktory jest dostepny
  wylacznie na GPLv3. Test podklada nieznane nazwy i sprawdza, ze wpadaja
  do `unassigned`, zamiast dostac cudza licencje;
* **zaleznosc ladowana po NAZWIE, w czasie dzialania.** Tablica importow
  nie widzi `QLibrary`/`GetProcAddress`. Test czyta wiec takze NAPISY
  w pozostalych binarkach — tak zlapiemy plik, ktory wola o usunieta
  biblioteke, nie wymieniajac jej w zadnej tablicy.

Bez zbudowanej paczki (`.\\build.ps1`) czesc testow jest pomijana — nie ma
czego ogladac. Reszta, czyli komplet tekstow licencji i spojnosc adresow
zrodel z tym, co pokazuje okno „O programie", dziala zawsze.

CO JEST „PACZKA"

`licenses.built_packages()` zwraca katalog `dist/BeatStamp`, katalog
`dist/msix` ORAZ gotowy plik `dist/BeatStamp-*.msix` — bo do Sklepu jedzie
archiwum, a nie katalog, z ktorego je zlozono. Testy czytajace pliki PE
przez `pefile` dzialaja tylko na katalogach (`PACKAGE_DIRS`): zawartosc
archiwum jest sprawdzana na poziomie listy plikow, a jej zgodnosc
z katalogiem — osobnym testem.
"""
from __future__ import annotations

import os
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))

import licenses                                   # noqa: E402
import make_notice                                # noqa: E402
from beatstamp import config                      # noqa: E402

PACKAGES = licenses.built_packages()

#: Tylko paczki rozpakowane na dysku. `pefile` i skanowanie napisow
#: potrzebuja PLIKU, a nie wpisu w archiwum.
PACKAGE_DIRS = [path for path in PACKAGES if path.is_dir()]

#: Nazwy rozwiazywane przez mechanizm API sets Windows — nie sa plikami
#: i szukanie ich na dysku nic by nie dalo.
SYSTEM_PREFIXES = ('api-ms-win-', 'ext-ms-win-')

#: Katalog bibliotek systemowych. Sprawdzamy OBECNOSC PLIKU zamiast trzymac
#: wlasna liste nazw: lista „to nalezy do Windows" pisana recznie starzeje sie
#: z kazda wersja systemu i daje czerwony test na cudzej maszynie zamiast
#: pokazywac prawdziwy blad pakowania.
SYSTEM_DIR = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32'


def _text(blob: bytes) -> str:
    """Bajty z paczki jako tekst — z koncami wierszy jak przy `read_text`.

    `NOTICE` w repozytorium jest zapisywany `Path.write_text`, wiec na
    Windows ma `\\r\\n`; odczyt `read_text` zamienia je z powrotem na `\\n`.
    Porownanie bajt w bajt widzialoby tu roznice, ktorej nie ma.
    """
    return blob.decode('utf-8').replace('\r\n', '\n').replace('\r', '\n')


def _imports(path: Path) -> list[str]:
    """Nazwy bibliotek z tablicy importow pliku PE (male litery)."""
    import pefile

    names: list[str] = []
    pe = pefile.PE(str(path), fast_load=True)
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'],
        ])
        for attribute in ('DIRECTORY_ENTRY_IMPORT', 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            for entry in (getattr(pe, attribute, None) or []):
                if entry.dll:
                    names.append(entry.dll.decode('ascii', 'replace').lower())
    finally:
        pe.close()
    return names


class NoGplOnlyModuleIsShippedTests(unittest.TestCase):
    """Ani jednego pliku z listy „tylko GPL albo licencja komercyjna"."""

    @unittest.skipUnless(PACKAGES, 'brak zbudowanej paczki — uruchom .\\build.ps1')
    def test_the_package_has_no_forbidden_file(self):
        for package in PACKAGES:
            with self.subTest(package=package.name):
                report = licenses.audit(package)
                gpl = [(path, reason) for path, reason in report.forbidden
                       if reason.kind == 'gpl']
                self.assertEqual(
                    gpl, [],
                    'w paczce leza moduly dostepne wylacznie na GPL albo '
                    'komercyjnie — wydanie na Apache-2.0 bylo by naruszeniem: '
                    + ', '.join(f'{path} ({reason.subject})' for path, reason in gpl))

    @unittest.skipUnless(PACKAGES, 'brak zbudowanej paczki — uruchom .\\build.ps1')
    def test_the_package_has_nothing_we_decided_to_drop(self):
        """Takze „sieroty" i pliki z maszyny budujacej. Wroca po cichu, gdy
        ktos zmieni `beatstamp.spec` i nie zajrzy do `tools/licenses.py`."""
        for package in PACKAGES:
            with self.subTest(package=package.name):
                report = licenses.audit(package)
                self.assertEqual(
                    [path for path, _reason in report.forbidden], [],
                    'w paczce leza pliki, ktore mialy z niej wypasc: '
                    + ', '.join(f'{path} [{reason.kind}]'
                                for path, reason in report.forbidden))

    def test_a_forbidden_file_is_caught_wherever_it_lies(self):
        """Wzorzec zakazu dopasowuje NAZWE, nie sciezke.

        Qt przenosilo juz wtyczki miedzy katalogami. Zakaz zapisany jako
        pelna sciezka przestalby dzialac po takiej zmianie i nikt by tego
        nie zauwazyl, bo test dalej bylby zielony.
        """
        for path in ('_internal/PySide6/Qt6VirtualKeyboard.dll',
                     '_internal/PySide6/plugins/gdzieindziej/Qt6VirtualKeyboard.dll',
                     r'_internal\PySide6\Qt6VirtualKeyboard.dll'):
            with self.subTest(path=path):
                reason = licenses.excluded_reason(path)
                self.assertIsNotNone(reason)
                self.assertEqual(reason.kind, 'gpl')


class EveryFileHasALicenceTests(unittest.TestCase):
    """Kazdy plik paczki nalezy do jakiegos skladnika."""

    @unittest.skipUnless(PACKAGES, 'brak zbudowanej paczki — uruchom .\\build.ps1')
    def test_nothing_is_left_without_a_licence(self):
        for package in PACKAGES:
            with self.subTest(package=package.name):
                report = licenses.audit(package)
                self.assertEqual(
                    report.unassigned, [],
                    'te pliki nie maja przypisanej licencji — dopisz regule '
                    'w tools/licenses.py: ' + ', '.join(report.unassigned[:10]))

    @unittest.skipUnless(PACKAGES, 'brak zbudowanej paczki — uruchom .\\build.ps1')
    def test_every_component_used_is_described(self):
        """Regula nie moze wskazywac skladnika, ktorego nie ma w spisie."""
        for package in PACKAGES:
            report = licenses.audit(package)
            for key in report.assigned:
                with self.subTest(package=package.name, component=key):
                    self.assertIn(key, licenses.COMPONENTS)

    def test_a_star_does_not_cross_a_slash(self):
        """`_internal/*.pyd` to moduly CPythona, a nie wszystko, co ma `.pyd`.

        `fnmatch` traktuje `*` jako „cokolwiek", RAZEM z ukosnikiem — wzorzec
        dla katalogu glownego lapalby wtedy `_internal/PIL/_imaging.pyd`
        i przypisywal Pillow licencje PSF. Roznica jest niewidoczna, dopoki
        ktos nie przeczyta noty.
        """
        self.assertTrue(licenses.matches('_internal/*.pyd', '_internal/select.pyd'))
        self.assertFalse(licenses.matches('_internal/*.pyd',
                                          '_internal/PIL/_imaging.pyd'))
        self.assertTrue(licenses.matches('_internal/**',
                                         '_internal/PIL/_imaging.pyd'))

    def test_files_go_to_the_component_they_belong_to(self):
        cases = {
            'BeatStamp.exe': ('beatstamp', 'pyinstaller'),
            '_internal/PIL/_imaging.cp312-win_amd64.pyd': ('pillow',),
            '_internal/PySide6/Qt6Core.dll': ('qt',),
            '_internal/PySide6/Qt6Pdf.dll': ('qt', 'pdfium'),
            '_internal/PySide6/QtCore.pyd': ('pyside6',),
            '_internal/PySide6/MSVCP140.dll': ('msvc',),
            '_internal/PySide6/opengl32sw.dll': ('mesa',),
            '_internal/shiboken6/shiboken6.abi3.dll': ('shiboken6',),
            '_internal/shiboken6/VCRUNTIME140.dll': ('msvc',),
            '_internal/_ssl.pyd': ('cpython', 'openssl'),
            '_internal/select.pyd': ('cpython',),
            '_internal/libcrypto-3.dll': ('openssl',),
            '_internal/ucrtbase.dll': ('ucrt',),
            '_internal/api-ms-win-crt-heap-l1-1-0.dll': ('ucrt',),
            '_internal/locale/pl/LC_MESSAGES/beatstamp.mo': ('beatstamp',),
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(licenses.components_for(path), expected)


class WhatIsInsideTheExecutableTests(unittest.TestCase):
    """`BeatStamp.exe` to archiwum — i jego zawartosc tez ma licencje.

    Najwiekszy plik paczki (5,7 MB) przez dlugi czas byl opisany jako „nasz
    kod plus program rozruchowy PyInstallera". W srodku lezalo 619 modulow,
    z tego 159 reportlaba, 36 urllib3, 17 requests, 6 idny i PySocks —
    biblioteki, ktore w paczce NIE MAJA ANI JEDNEGO WLASNEGO PLIKU. Kontrola
    chodzaca po nazwach plikow meldowala komplet, a paczka rozpowszechniala
    kod na BSD, MIT i Apache bez wymaganej noty. Zaden inny test tego nie
    widzi, bo nic sie przy tym nie psuje.
    """

    @unittest.skipUnless(PACKAGES, 'brak zbudowanej paczki — uruchom .\\build.ps1')
    def test_every_package_inside_the_archive_has_a_component(self):
        for package in PACKAGES:
            report = licenses.audit(package)
            with self.subTest(package=package.name):
                self.assertEqual(
                    report.unassigned_modules, [],
                    'te pakiety leza w archiwum wewnatrz BeatStamp.exe '
                    'i nie opisuje ich zaden skladnik — dopisz je do '
                    'PYZ_COMPONENTS w tools/licenses.py: '
                    + ', '.join(report.unassigned_modules[:10]))

    @unittest.skipUnless(PACKAGES, 'brak zbudowanej paczki — uruchom .\\build.ps1')
    def test_the_libraries_without_a_file_of_their_own_are_found(self):
        """Nie „cokolwiek sie znajdzie", tylko te konkretne piec.

        Gdyby odczyt archiwum kiedys przestal dzialac — inny format, inna
        wersja PyInstallera, cicho zwrocona pusta lista — poprzedni test
        przeszedlby na zielono, bo pusty zbior nie ma nieprzypisanych
        pakietow. Ten test wymaga, zeby je NAPRAWDE widziec.
        """
        for package in PACKAGES:
            report = licenses.audit(package)
            for key in ('reportlab', 'requests', 'urllib3', 'idna', 'pysocks'):
                with self.subTest(package=package.name, component=key):
                    self.assertIn(
                        licenses.EXECUTABLE, report.assigned.get(key, []),
                        f'{key} lezy w archiwum wewnatrz BeatStamp.exe, ale '
                        f'nota nie wymienia tego pliku przy tym skladniku')

    @unittest.skipUnless(PACKAGES, 'brak zbudowanej paczki — uruchom .\\build.ps1')
    def test_the_notice_names_those_libraries(self):
        text = make_notice.NOTICE.read_text(encoding='utf-8')
        for name in ('ReportLab', 'requests', 'urllib3', 'idna', 'PySocks'):
            with self.subTest(component=name):
                self.assertIn(name, text)

    def test_the_standard_library_does_not_need_its_own_entry(self):
        """Stdlib rozpoznajemy po `sys.stdlib_module_names`, nie z listy.

        Lista nazw stdlib pisana recznie starzeje sie przy kazdym wydaniu
        Pythona i daje czerwony test zamiast pokazywac prawdziwy problem.
        """
        self.assertEqual(licenses.components_for_module('json'), ('cpython',))
        self.assertEqual(licenses.components_for_module('reportlab'),
                         ('reportlab',))
        self.assertEqual(licenses.components_for_module('socks'), ('pysocks',))
        self.assertEqual(licenses.components_for_module('nieznany_pakiet'), ())


class UnknownFilesAreStoppedNotLabelledTests(unittest.TestCase):
    """Nieznany plik ma wpadac w `unassigned`, a nie dostawac cudza licencje.

    `Qt6*.dll -> qt (LGPL-3.0-only)` chronil przed plikiem BEZ noty i nie
    chronil przed nota NIEPRAWDZIWA: modul Qt dostepny wylacznie na GPLv3
    albo komercyjnie, ktorego nie ma na czarnej liscie (Qt MQTT, Qt CoAP,
    Qt OPC UA, Qt Quick 3D...), wpadal w ten wzorzec i byl oglaszany jako
    LGPL. Jedynym sygnalem bylby czerwony test „NOTICE rozjechal sie
    z paczka", ktorego zalecana naprawa — uruchomienie generatora — wpisuje
    ten modul do noty i zazielenia caly zestaw.

    Czarna lista `GPL_ONLY` zostaje jako druga bariera. Ale lista zakazow
    starzeje sie z kazdym wydaniem Qt, a lista zezwolen nie.
    """

    def test_an_unknown_qt_library_is_not_declared_lgpl(self):
        for name in ('Qt6Mqtt.dll', 'Qt6Coap.dll', 'Qt6OpcUa.dll',
                     'Qt6Quick3D.dll', 'Qt6Lottie.dll'):
            with self.subTest(name=name):
                self.assertEqual(
                    licenses.components_for(f'_internal/PySide6/{name}'), (),
                    f'{name} dostal licencje, zamiast zatrzymac generator')

    def test_an_unknown_qt_plugin_is_not_declared_lgpl(self):
        for path in ('_internal/PySide6/plugins/imageformats/cokolwiek.dll',
                     '_internal/PySide6/plugins/platforminputcontexts/'
                     'qtvirtualkeyboardplugin2.dll',
                     '_internal/PySide6/plugins/nowykatalog/cos.dll'):
            with self.subTest(path=path):
                self.assertEqual(licenses.components_for(path), ())

    def test_an_unknown_extension_module_is_not_declared_psf(self):
        for path in ('_internal/nieznany_modul.pyd',
                     '_internal/nieznany_dodatek.dll',
                     '_internal/PySide6/QtMqtt.pyd',
                     '_internal/shiboken6/cos_nowego.pyd'):
            with self.subTest(path=path):
                self.assertEqual(licenses.components_for(path), ())

    def test_the_files_we_really_ship_are_still_covered(self):
        """Biala lista ma byc waska, ale nie za waska — inaczej nastepny
        audyt zaczyna sie od setki falszywych alarmow."""
        for package in PACKAGES:
            report = licenses.audit(package)
            with self.subTest(package=package.name):
                self.assertEqual(report.unassigned, [])


class DeclaredVersionsMatchTheBinariesTests(unittest.TestCase):
    """Wersja w nocie ma pochodzic z PLIKU, a nie z pamieci.

    `_rust.pyd` niesie WKOMPILOWANY OpenSSL 3.5.1, a nota przez dlugi czas
    deklarowala jeden OpenSSL w wersji 3.0.16 — tej z wydania CPythona.
    Zdanie w dokumencie prawnym bylo nieprawdziwe, a druga biblioteka
    Apache-2.0 jechala bez wymaganej atrybucji. Podbicie cryptography
    zmienia te wersje po cichu; ten test zglosi to sam.
    """

    #: `OPENSSL_VERSION_TEXT`, czyli baner wkompilowany w kazde wydanie
    #: OpenSSL-a: „OpenSSL 3.0.16 11 Feb 2025". Data w tym wzorcu nie jest
    #: ozdoba — bez niej lapiemy takze zwykle zdania z dokumentacji
    #: (`_hashlib.pyd` ma w sobie „OpenSSL 3.0.0 and newer it returns..."),
    #: czyli pliki, ktore zadnego OpenSSL-a nie niosa.
    VERSION = re.compile(
        rb'OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)\s+\d{1,2}\s+[A-Z][a-z]{2}\s+\d{4}')

    @unittest.skipUnless(PACKAGE_DIRS, 'brak zbudowanej paczki — uruchom .\\build.ps1')
    def test_every_openssl_in_the_package_is_declared(self):
        declared = {component.version.split()[0]
                    for key, component in licenses.COMPONENTS.items()
                    if key.startswith('openssl')}
        for package in PACKAGE_DIRS:
            found: dict[str, set[str]] = {}
            for relpath in licenses.package_files(package):
                if not relpath.lower().endswith(('.dll', '.pyd', '.exe')):
                    continue
                blob = (package / relpath).read_bytes()
                versions = {match.decode('ascii')
                            for match in self.VERSION.findall(blob)}
                if versions:
                    found[relpath] = versions
            for relpath, versions in found.items():
                with self.subTest(package=package.name, file=relpath):
                    self.assertTrue(
                        versions <= declared,
                        f'{relpath} niesie OpenSSL {sorted(versions)}, '
                        f'a NOTICE deklaruje {sorted(declared)}. Popraw '
                        f'wersje skladnika w tools/licenses.py — nota, ktora '
                        f'podaje inna wersje niz plik, jest nieprawdziwa.')
            with self.subTest(package=package.name):
                self.assertTrue(found, 'nie znalazlem w paczce ani jednego '
                                       'ciagu z wersja OpenSSL-a — to nie '
                                       'znaczy, ze go nie ma, tylko ze test '
                                       'przestal dzialac')


class TheShippedArchiveIsTheAuditedOneTests(unittest.TestCase):
    """Do Sklepu jedzie PLIK `.msix`, a nie katalog, z ktorego go zlozono.

    Dzis jedno zgadza sie z drugim. Zgodnosc jest jednak przypadkiem
    chwili: przepakowanie katalogu bez ponownego `MakeAppx` (albo odwrotnie)
    rozjezdza je, a kontrola patrzaca tylko na katalog tego nie zobaczy.
    """

    ARCHIVES = [path for path in PACKAGES if path.suffix.lower() == '.msix']

    @unittest.skipUnless(ARCHIVES, 'brak paczki .msix — uruchom '
                                   '.\\packaging\\build_msix.ps1')
    def test_the_archive_passes_the_same_audit(self):
        for archive in self.ARCHIVES:
            report = licenses.audit(archive)
            with self.subTest(archive=archive.name):
                self.assertEqual([path for path, _reason in report.forbidden],
                                 [])
                self.assertEqual(report.unassigned, [])
                self.assertEqual(report.unassigned_modules, [])

    @unittest.skipUnless(ARCHIVES, 'brak paczki .msix')
    def test_the_archive_holds_what_the_directory_holds(self):
        source = licenses.PACKAGE_DIRS[1]
        if not licenses.is_package(source):
            self.skipTest('brak dist/msix')
        #: Skladane przez `MakeAppx` z NASZEJ zawartosci, wiec w katalogu
        #: ich nie ma i byc nie moze.
        generated = {'AppxBlockMap.xml', '[Content_Types].xml',
                     'AppxSignature.p7x'}
        expected = set(licenses.package_files(source))
        for archive in self.ARCHIVES:
            inside = set(licenses.package_files(archive))
            with self.subTest(archive=archive.name):
                self.assertEqual(
                    sorted(expected - inside), [],
                    'w katalogu dist/msix sa pliki, ktorych nie ma '
                    'w archiwum — przepakuj je po tej samej zawartosci')
                extra = {path for path in inside - expected
                         if path not in generated
                         and not path.startswith('AppxMetadata/')}
                self.assertEqual(
                    sorted(extra), [],
                    'archiwum niesie pliki, ktorych nie ma w katalogu — '
                    'jedno z nich jest starsze niz drugie')


class NothingNeedsWhatWeRemovedTests(unittest.TestCase):
    """Dowod, ze usuniecie bylo bezpieczne — z tablic importow, nie z zalozenia.

    Razem z klawiatura ekranowa wypadl caly stos QML (`Qt6Quick`, `Qt6Qml*`,
    `Qt6OpenGL`), bo tylko ona go potrzebowala. „Tylko ona" to zdanie, ktore
    trzeba sprawdzac przy kazdym wydaniu Qt: wystarczy, ze nowa wersja
    dolozy zaleznosc, a program przestanie startowac u uzytkownika — i to
    w sposob, ktorego testy na kodzie zrodlowym nie zobacza, bo ze zrodel
    uzywany jest Qt z srodowiska, kompletny.
    """

    @unittest.skipUnless(PACKAGE_DIRS, 'brak zbudowanej paczki — uruchom .\\build.ps1')
    def test_no_remaining_file_imports_a_removed_library(self):
        try:
            import pefile                                    # noqa: F401
        except ImportError:                                  # pragma: no cover
            self.skipTest('brak `pefile` — jest zaleznoscia PyInstallera')

        removed = {licenses.normalise(item.pattern).lower()
                   for item in licenses.EXCLUDED if '/' not in item.pattern}
        for package in PACKAGE_DIRS:
            for relpath in licenses.package_files(package):
                if not relpath.lower().endswith(('.dll', '.pyd', '.exe')):
                    continue
                needed = set(_imports(package / relpath)) & removed
                with self.subTest(package=package.name, file=relpath):
                    self.assertEqual(
                        needed, set(),
                        f'{relpath} wola o biblioteke, ktorej juz nie ma '
                        f'w paczce: {sorted(needed)}. Albo wroc z nia '
                        f'(i sprawdz jej licencje), albo usun to, co jej uzywa.')

    @unittest.skipUnless(PACKAGE_DIRS, 'brak zbudowanej paczki — uruchom .\\build.ps1')
    def test_nothing_left_even_NAMES_a_removed_library(self):
        """To samo pytanie, ale bez zalozenia, ze zaleznosc widac w tablicy
        importow.

        Tablica importow opisuje WYLACZNIE wiazanie statyczne. Qt laduje
        czesc bibliotek przez `QLibrary`, czyli `LoadLibrary` po nazwie
        zapisanej w pliku jako zwykly napis — tak wlasnie robila wtyczka
        `tls/qopensslbackend.dll` z `libcrypto-3-x64.dll`. Ten sam plik
        przechodzil poprzedni test, bo w zadnej tablicy tych nazw nie mial.
        Dowod „nic tego nie potrzebuje" oparty na samych importach byl wiec
        wezszy, niz brzmial — i ta sama luka przepuscilaby w przyszlosci
        wtyczke Qt spod GPL, ladowana dokladnie tak samo.

        Szukamy nazwy BEZ rozszerzenia: Qt sklada `.dll` w czasie dzialania.
        """
        removed = {Path(item.pattern).stem.lower()
                   for item in licenses.EXCLUDED
                   if '/' not in item.pattern and '*' not in item.pattern}
        for package in PACKAGE_DIRS:
            for relpath in licenses.package_files(package):
                if not relpath.lower().endswith(('.dll', '.pyd', '.exe')):
                    continue
                blob = (package / relpath).read_bytes()
                named = {name for name in removed
                         if name.encode('ascii') in blob
                         or name.encode('utf-16-le') in blob}
                with self.subTest(package=package.name, file=relpath):
                    self.assertEqual(
                        named, set(),
                        f'{relpath} wymienia z nazwy biblioteke, ktorej juz '
                        f'nie ma w paczce: {sorted(named)}. Tablica importow '
                        f'tego nie pokazuje, bo Qt laduje ja dopiero w czasie '
                        f'dzialania. Albo wroc z ta biblioteka (i sprawdz jej '
                        f'licencje), albo usun plik, ktory jej szuka.')

    @unittest.skipUnless(PACKAGE_DIRS, 'brak zbudowanej paczki — uruchom .\\build.ps1')
    def test_every_library_the_package_needs_is_in_the_package(self):
        """Szerzej: kazda biblioteka z tablicy importow albo lezy w paczce,
        albo dostarcza ja Windows. To ta sama klasa awarii co wyzej, tyle ze
        bez zalozenia, ze winne jest akurat nasze wykluczenie — zlapie takze
        plik, ktory wypadl z paczki z zupelnie innego powodu."""
        try:
            import pefile                                    # noqa: F401
        except ImportError:                                  # pragma: no cover
            self.skipTest('brak `pefile` — jest zaleznoscia PyInstallera')

        for package in PACKAGE_DIRS:
            present = {Path(relpath).name.lower()
                       for relpath in licenses.package_files(package)}
            for relpath in licenses.package_files(package):
                if not relpath.lower().endswith(('.dll', '.pyd', '.exe')):
                    continue
                missing = {name for name in _imports(package / relpath)
                           if name not in present
                           and not name.startswith(SYSTEM_PREFIXES)
                           and not (SYSTEM_DIR / name).is_file()}
                with self.subTest(package=package.name, file=relpath):
                    self.assertEqual(
                        missing, set(),
                        f'{relpath} potrzebuje bibliotek, ktorych w paczce '
                        f'nie ma: {sorted(missing)}')


class NoticeMatchesThePackageTests(unittest.TestCase):
    """`NOTICE` jest generowany — wiec musi zgadzac sie z tym, co w paczce."""

    #: Noty skladamy z paczki PROGRAMU. Paczka MSIX to ta sama zawartosc plus
    #: manifest i logo — nasze wlasne pliki, opisane w spisie przy BeatStampie.
    PACKAGE = licenses.PACKAGE_DIRS[0]

    def test_the_notice_file_exists(self):
        self.assertTrue(make_notice.NOTICE.is_file(),
                        'brak pliku NOTICE — uruchom tools/make_notice.py')

    @unittest.skipUnless(licenses.is_package(licenses.PACKAGE_DIRS[0]),
                         'brak zbudowanej paczki — uruchom .\\build.ps1')
    def test_the_notice_is_what_the_generator_produces(self):
        current = make_notice.NOTICE.read_text(encoding='utf-8')
        self.assertEqual(
            current, make_notice.build(self.PACKAGE),
            'NOTICE rozjechal sie z paczka — uruchom tools/make_notice.py. '
            'Plik not poprawiony recznie klamie po cichu.')

    @unittest.skipUnless(PACKAGES, 'brak zbudowanej paczki — uruchom .\\build.ps1')
    def test_the_package_carries_the_current_notice(self):
        """Paczka niesie WLASNY egzemplarz not — i ten egzemplarz tez sie
        starzeje. Zregenerowany `NOTICE` bez ponownej kompilacji zostaje
        w repozytorium nowy, a u uzytkownika stary."""
        expected = make_notice.NOTICE.read_text(encoding='utf-8')
        relpath = f'{licenses.LEGAL_DIR_IN_PACKAGE}/NOTICE'
        for package in PACKAGES:
            with self.subTest(package=package.name):
                self.assertIn(relpath, licenses.package_files(package),
                              f'brak {relpath} w {package}')
                delivered = licenses.read_package_file(package, relpath)
                self.assertEqual(
                    _text(delivered), expected,
                    'paczka niesie STARE noty — przebuduj ja po '
                    'tools/make_notice.py')

    def test_the_notice_names_the_sources_of_the_lgpl_libraries(self):
        """Wymog LGPLv3 par. 4(d): zrodla SAMEJ biblioteki, dokladnie tej
        wersji. Do tego trwala pisemna oferta — adres moze zniknac."""
        text = make_notice.NOTICE.read_text(encoding='utf-8')
        self.assertIn(licenses.QT_SOURCE_URL, text)
        self.assertIn(licenses.PYSIDE_SOURCE_URL, text)
        self.assertIn(licenses.WRITTEN_OFFER_CONTACT, text)
        self.assertIn('Written offer', text)

    def test_the_notice_names_what_was_removed(self):
        text = make_notice.NOTICE.read_text(encoding='utf-8')
        for item in licenses.GPL_ONLY:
            with self.subTest(module=item.subject):
                self.assertIn(item.subject, text)


class LicenceTextsAreDeliveredTests(unittest.TestCase):
    """Teksty licencji leza w repozytorium I w paczce.

    LGPLv3 par. 4(c) mowi o DOSTARCZENIU kopii GNU GPL i LGPL razem z kodem
    wynikowym. Odnosnik do gnu.org tego nie spelnia — i praktycznie tez nie
    wystarcza, bo uzytkownik sprawdzajacy program sprzed lat zalezalby od
    cudzego serwera.
    """

    REQUIRED = ('GPL-3.0.txt', 'LGPL-3.0.txt', 'GPL-2.0.txt', 'Apache-2.0.txt')

    def test_the_gnu_licence_texts_are_in_the_repository(self):
        for name in self.REQUIRED:
            with self.subTest(text=name):
                path = licenses.LICENSES_DIR / name
                self.assertTrue(path.is_file(), f'brak {path}')
                self.assertGreater(len(path.read_text(encoding='utf-8')), 5_000)

    def test_the_texts_are_the_real_ones(self):
        expected = {
            'GPL-3.0.txt': 'GNU GENERAL PUBLIC LICENSE',
            'LGPL-3.0.txt': 'GNU LESSER GENERAL PUBLIC LICENSE',
            'GPL-2.0.txt': 'GNU GENERAL PUBLIC LICENSE',
            'Apache-2.0.txt': 'Apache License',
        }
        for name, marker in expected.items():
            with self.subTest(text=name):
                head = (licenses.LICENSES_DIR / name).read_text(
                    encoding='utf-8')[:400]
                self.assertIn(marker, head)

    def test_every_component_points_at_a_text_that_exists(self):
        for key, component in licenses.COMPONENTS.items():
            for name in component.texts:
                with self.subTest(component=key, text=name):
                    self.assertTrue((licenses.LICENSES_DIR / name).is_file(),
                                    f'{key} wskazuje na nieistniejacy '
                                    f'licenses/{name}')

    def test_the_lgpl_components_carry_both_gnu_texts(self):
        """LGPLv3 nie jest samodzielnym tekstem — to zestaw dodatkowych
        pozwolen do GPLv3. Bez GPLv3 nie da sie go przeczytac."""
        for key, component in licenses.COMPONENTS.items():
            if 'LGPL-3.0' not in component.spdx:
                continue
            with self.subTest(component=key):
                self.assertIn('LGPL-3.0.txt', component.texts)
                self.assertIn('GPL-3.0.txt', component.texts)

    def test_the_project_licence_is_apache_with_the_owner_named(self):
        text = (licenses.ROOT / 'LICENSE').read_text(encoding='utf-8')
        self.assertIn('Apache License', text[:400])
        self.assertIn('Version 2.0', text[:400])
        self.assertIn('Adam Koch', text)

    def test_the_licence_file_and_the_notes_say_the_same_copyright(self):
        """Nota copyright jest w DWOCH plikach i musi byc jedna.

        `LICENSE` niesie wypelniona formulke z zalacznika Apache-2.0,
        `tools/licenses.py` — te sama note dla skladnika `beatstamp`, z ktorej
        powstaje naglowek `NOTICE`. Rozjazd miedzy nimi (poprawiony rok w
        jednym miejscu, zapomniany w drugim) jest niewidoczny, dopoki ktos
        nie porowna obu dokumentow — czyli dokladnie wtedy, kiedy to boli.
        """
        text = (licenses.ROOT / 'LICENSE').read_text(encoding='utf-8')
        self.assertIn(licenses.COMPONENTS['beatstamp'].copyright, text)

    def test_no_licence_text_is_delivered_without_a_reason(self):
        """Tekst, na ktory nie wskazuje zaden skladnik, jest martwy.

        Znaczy jedno z dwojga: albo ktos dolozyl plik i zapomnial podpiac go
        pod skladnik (czyli nota dalej przemilcza biblioteke), albo skladnik
        zniknal, a tekst zostal. Oba przypadki wygladaja identycznie
        z zewnatrz: katalog pelen licencji, ktory niczego nie dowodzi.
        """
        pointed = {name for component in licenses.COMPONENTS.values()
                   for name in component.texts}
        present = {path.name for path in licenses.LICENSES_DIR.glob('*.txt')}
        self.assertEqual(
            sorted(present - pointed), [],
            'te teksty leza w licenses/ i jada do paczki, a zaden skladnik '
            'na nie nie wskazuje')

    @unittest.skipUnless(PACKAGES, 'brak zbudowanej paczki — uruchom .\\build.ps1')
    def test_the_package_carries_the_texts_too(self):
        for package in PACKAGES:
            delivered = set(licenses.package_files(package))
            with self.subTest(package=package.name):
                for name in (*self.REQUIRED, 'NOTICE', 'LICENSE'):
                    self.assertIn(f'{licenses.LEGAL_DIR_IN_PACKAGE}/{name}',
                                  delivered, f'brak {name} w {package}')

    @unittest.skipUnless(PACKAGES, 'brak zbudowanej paczki — uruchom .\\build.ps1')
    def test_every_text_a_component_points_at_is_in_the_package(self):
        """Nie tylko cztery teksty GNU: KAZDY, ktory wskazuje jakis skladnik.

        Nota wskazujaca `_internal/licenses/MPL-2.0.txt` w paczce, w ktorej
        tego pliku nie ma, jest gorsza niz brak wskazania — wysyla czytelnika
        pod adres, ktorego nie ma, i wyglada przy tym na spelniony obowiazek.
        """
        wanted = {name for component in licenses.COMPONENTS.values()
                  for name in component.texts}
        for package in PACKAGES:
            delivered = set(licenses.package_files(package))
            for name in sorted(wanted):
                with self.subTest(package=package.name, text=name):
                    self.assertIn(
                        f'{licenses.LEGAL_DIR_IN_PACKAGE}/{name}', delivered,
                        f'skladnik wskazuje na {name}, a paczka go nie niesie')


class TheApplicationAgreesWithTheNoticeTests(unittest.TestCase):
    """Okno „O programie" i noty musza mowic to samo.

    Adresy zrodel sa w dwoch miejscach, bo maja dwa zycia: `config.py` jest
    kodem aplikacji (pokazuje je uzytkownikowi i nie wolno mu zalezec od
    katalogu `tools/`, ktorego w paczce nie ma), `tools/licenses.py` jest
    czescia kompilacji. Rozjazd miedzy nimi znaczylby, ze program wysyla
    ludzi gdzie indziej, niz obiecuje plik not — czyli ze jedna z tych
    obietnic jest falszywa.
    """

    def test_the_source_urls_are_the_same(self):
        self.assertEqual(config.QT_SOURCE_URL, licenses.QT_SOURCE_URL)
        self.assertEqual(config.PYSIDE_SOURCE_URL, licenses.PYSIDE_SOURCE_URL)

    def test_the_source_urls_name_the_version_that_is_in_the_package(self):
        version = licenses.COMPONENTS['qt'].version
        self.assertIn(version, config.QT_SOURCE_URL)
        self.assertIn(licenses.COMPONENTS['pyside6'].version,
                      config.PYSIDE_SOURCE_URL)


class TheAboutWindowSaysWhatItMustTests(unittest.TestCase):
    """Okno „O programie" niesie to, czego wymaga LGPLv3 — i to naprawde.

    Akapit o Qt nie jest ozdoba ani grzecznoscia: LGPLv3 par. 4(a) mowi
    o WIDOCZNEJ informacji, ze program uzywa tej biblioteki, a par. 4(b)
    o nocie o jej prawach autorskich. Jedno i drugie da sie skasowac jednym
    ruchem przy porzadkach w kodzie i nic sie przy tym nie zepsuje — az do
    dnia, w ktorym ktos zapyta.

    Tu sprawdzamy ZLOZONE OKNO, a nie obecnosc napisu w katalogu tlumaczen:
    napis, ktory istnieje, ale nie zostal nigdzie wstawiony, spelnia wymog
    tak samo jak jego brak.
    """

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
        try:
            from PySide6.QtWidgets import QApplication
        except ImportError:                                  # pragma: no cover
            raise unittest.SkipTest('brak PySide6')
        cls._app = QApplication.instance() or QApplication(sys.argv)
        # Jezyk ustawiamy JAWNIE. Te testy sprawdzaja tresc zdan, a jezyk
        # w tym procesie zalezy od tego, ktory inny plik testowy zostal
        # zaimportowany wczesniej (`tests/test_i18n.py` wlacza polski przy
        # imporcie). Wynik testu nie moze zalezec od kolejnosci odkrywania.
        from beatstamp import i18n
        cls._language = i18n.current_language()
        i18n.set_language('en')

    @classmethod
    def tearDownClass(cls):
        from beatstamp import i18n
        i18n.set_language(cls._language)

    def _about_text(self) -> str:
        from PySide6.QtWidgets import QLabel

        from beatstamp.ui.dialogs import AboutDialog

        dialog = AboutDialog()
        try:
            return '\n'.join(label.text()
                             for label in dialog.findChildren(QLabel))
        finally:
            dialog.deleteLater()

    def test_it_names_the_libraries_and_their_licence(self):
        text = self._about_text()
        for needle in ('Qt', 'PySide6', 'Lesser General Public License'):
            with self.subTest(needle=needle):
                self.assertIn(needle, text)

    def test_it_carries_the_copyright_of_the_libraries(self):
        self.assertIn('The Qt Company Ltd.', self._about_text())

    def test_it_credits_freetype_the_way_its_licence_asks(self):
        """FTL prosi o JEDNO konkretne zdanie w dokumentacji programu.

        Zgodnosc z LGPL Qt nie zdejmuje obowiazkow z licencji kodu, ktory
        Qt wkompilowuje w siebie — a FreeType siedzi w `Qt6Gui.dll`
        i `Qt6Pdf.dll`.
        """
        text = ' '.join(self._about_text().split())
        self.assertIn('The FreeType Project', text)
        self.assertIn('copyright (c) 2025 The FreeType Project', text)

    def test_it_does_not_promise_swapping_files_in_a_store_install(self):
        """Zdanie o podmianie bibliotek jest prawda TYLKO w wersji
        przenosnej. Paczka MSIX instaluje sie do
        `C:\\Program Files\\WindowsApps`, gdzie plikow podmienic sie nie da:
        katalog nalezy do TrustedInstallera, a zawartosc jest zwiazana
        podpisem paczki. Obietnica w oknie „O programie" bylaby tam
        nieprawdziwa — i to w akapicie, ktory ma spelniac wymog licencji.
        """
        from unittest import mock

        with mock.patch('beatstamp.ui.dialogs.is_packaged', return_value=True):
            packaged = ' '.join(self._about_text().split())
        with mock.patch('beatstamp.ui.dialogs.is_packaged', return_value=False):
            portable = ' '.join(self._about_text().split())

        self.assertIn('may be replaced with your own build', portable)
        self.assertNotIn('may be replaced with your own build', packaged)
        self.assertIn('cannot be exchanged in place', packaged)

    def test_it_points_at_the_full_licence_texts(self):
        """Wymog par. 4(c) — kopia GNU GPL i LGPL. W oknie jest przycisk,
        ktory otwiera katalog z nimi; tekst ma o tym mowic wprost."""
        from PySide6.QtWidgets import QPushButton

        from beatstamp.ui.dialogs import AboutDialog

        dialog = AboutDialog()
        try:
            captions = [button.text() for button in
                        dialog.findChildren(QPushButton)]
            urls = [button.property('url') for button in
                    dialog.findChildren(QPushButton)]
        finally:
            dialog.deleteLater()
        self.assertIn(config.QT_SOURCE_URL, urls)
        self.assertIn(config.PYSIDE_SOURCE_URL, urls)
        self.assertTrue(
            any('licen' in caption.lower() or 'lizenz' in caption.lower()
                for caption in captions),
            f'brak przycisku do tekstow licencji; przyciski: {captions}')

    def test_it_names_the_earlier_product_of_the_same_author(self):
        self.assertIn('TimeVaultSecure', self._about_text())

    def test_the_readme_says_the_same_about_the_earlier_product(self):
        """Porownanie po NORMALIZACJI bialych znakow.

        Wczesniej test przypinal zdanie razem z konkretnym zlamaniem
        wiersza. Przeformatowanie akapitu — inna szerokosc lamania,
        dopisane slowo — zapalalo go na czerwono, mimo ze tresc byla ta
        sama; a najprostsza „naprawa" bylaby zmiana tego zdania, czyli
        odwrotnosc tego, czego test pilnuje.
        """
        readme = (licenses.ROOT / 'README.md').read_text(encoding='utf-8')
        # README jest PUBLICZNE i po angielsku (od 2026-09-24) — to ta wersja
        # czyta ktos, kto trafia na repozytorium. Polski dziennik decyzji
        # (ROZWOJ.md) zostaje wewnetrzny i do migawki nie trafia.
        self.assertIn(
            ' '.join('TimeVaultSecure (timevaultsecure.com) is an earlier '
                     'product by the same author'.split()),
            ' '.join(readme.split()))

    def test_the_readme_does_not_promote_the_old_entries(self):
        """Wpisy z TVS maja zostac oznaczone, a nie awansowane po cichu.

        To zdanie w README jest obietnica wobec czytelnika, ktory ma stare
        dowody: mowi, ze program ich nie podniesie do poziomu, na ktory nie
        zasluguja. Gdyby zniklo z opisu, zniklaby tez umowa.
        """
        readme = ' '.join((licenses.ROOT / 'README.md')
                          .read_text(encoding='utf-8').split())
        self.assertIn('TVS archive', readme)
        self.assertIn('not silently promoted', readme)


if __name__ == '__main__':
    unittest.main()
