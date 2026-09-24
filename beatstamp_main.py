"""
Punkt startowy dla PyInstallera.

PyInstaller potrzebuje zwyklego skryptu, a nie pakietu uruchamianego przez
`python -m beatstamp`. Ten plik jest wylacznie cienka warstwa: cala logika
startu siedzi w `beatstamp/__main__.py`, wiec uruchomienie ze zrodel
(`python -m beatstamp`) i uruchomienie z pliku .exe przechodza dokladnie te
sama sciezke kodu — bez osobnego wariantu „tylko dla wersji skompilowanej",
ktory z czasem rozjezdza sie z tym, co testujemy.
"""
import multiprocessing
import sys

if __name__ == '__main__':
    # Wymagane na Windows w programach zamrozonych: bez tego kazdy proces
    # potomny uruchamialby od nowa CALA aplikacje (nowe okno, i tak w kolko).
    # Nie tworzymy dzis procesow potomnych, ale biblioteki zaleznosciowe moga —
    # to jedna linia, ktora zamyka cala klase awarii.
    multiprocessing.freeze_support()

    from beatstamp.__main__ import main
    sys.exit(main())
