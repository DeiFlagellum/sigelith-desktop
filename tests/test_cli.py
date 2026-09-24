"""
Wiersz polecen: nazwy flag i ich aliasy.

Flaga wiersza polecen jest INTERFEJSEM PUBLICZNYM. Po otwarciu kodu i po
wydaniu ze Sklepu wpisuja ja ludzie, ktorzy nie czytaja tego repozytorium,
i cytuja skrypty, ktorych nigdy nie zobaczymy. Zmiana nazwy flagi jest wiec
zmiana zrywajaca zgodnosc — i to taka, ktora nie daje zadnego bledu
kompilacji ani czerwonego testu u tego, kto ja wprowadzil. Objawia sie
u kogos innego, jako „przestalo dzialac".

Dlatego:

* nazwy GLOWNE sa angielskie (`--selftest`, `--offline`) — powstaly przed
  publikacja, a nie po niej, zeby nie trzeba bylo ich potem zmieniac;
* nazwy dotychczasowe (`--samokontrola`, `--bez-sieci`) zostaja jako
  rownoprawne aliasy NA ZAWSZE. Ten plik jest miejscem, w ktorym „na zawsze"
  jest zapisane tak, ze usuniecie aliasu zapala sie na czerwono.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from beatstamp import selftest                    # noqa: E402


class FlagNamesTests(unittest.TestCase):
    """Nazwy, ktore obiecalismy: glowne angielskie, stare jako aliasy."""

    def test_the_main_names_are_english(self):
        self.assertEqual(selftest.FLAG, '--selftest')
        self.assertEqual(selftest.OFFLINE_FLAG, '--offline')

    def test_the_main_name_comes_first(self):
        """Kolejnosc nie jest kosmetyczna: `FLAGS[0]` jest tym, co pokazuja
        komunikaty i dokumentacja."""
        self.assertEqual(selftest.FLAGS[0], selftest.FLAG)
        self.assertEqual(selftest.OFFLINE_FLAGS[0], selftest.OFFLINE_FLAG)

    def test_the_polish_names_are_still_accepted(self):
        self.assertIn('--samokontrola', selftest.FLAGS)
        self.assertIn('--bez-sieci', selftest.OFFLINE_FLAGS)


class FlagRecognitionTests(unittest.TestCase):
    """Kazda nazwa dziala tak samo — takze w towarzystwie innych argumentow."""

    def test_every_name_asks_for_the_selftest(self):
        for flag in selftest.FLAGS:
            with self.subTest(flag=flag):
                self.assertTrue(selftest.requested([flag]))
                self.assertTrue(selftest.requested(['dokument.txt', flag]))

    def test_every_offline_name_is_understood(self):
        for flag in selftest.OFFLINE_FLAGS:
            with self.subTest(flag=flag):
                self.assertTrue(selftest.offline_requested([flag]))

    def test_the_names_can_be_mixed(self):
        """Alias jednej flagi z glowna nazwa drugiej — bo tak wlasnie wyglada
        skrypt poprawiany po polowie."""
        self.assertTrue(selftest.requested(['--samokontrola', '--offline']))
        self.assertTrue(selftest.offline_requested(['--selftest', '--bez-sieci']))

    def test_nothing_else_triggers_the_selftest(self):
        for argv in ([], ['dokument.txt'], ['--selftests'], ['selftest'],
                     ['--offline'], ['--help']):
            with self.subTest(argv=argv):
                self.assertFalse(selftest.requested(argv))

    def test_the_selftest_is_online_unless_asked_otherwise(self):
        for argv in ([], ['--selftest'], ['--samokontrola'], ['--bez_sieci']):
            with self.subTest(argv=argv):
                self.assertFalse(selftest.offline_requested(argv))


class DocumentationMentionsTheFlagsTests(unittest.TestCase):
    """README ma wymieniac obie nazwy kazdej flagi.

    Alias, o ktorym nie napisano, jest aliasem tylko do czasu, az ktos zrobi
    porzadek w kodzie.
    """

    def test_readme_names_both_forms(self):
        readme = (ROOT / 'README.md').read_text(encoding='utf-8')
        for flag in (*selftest.FLAGS, *selftest.OFFLINE_FLAGS):
            with self.subTest(flag=flag):
                self.assertIn(flag, readme)


if __name__ == '__main__':
    unittest.main()
