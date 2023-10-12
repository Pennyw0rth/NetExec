#!/usr/bin/env python3

from PyInstaller.utils.hooks import collect_all

datas, binaries, hiddenimports = collect_all("pypykatz")
