"""Собирает Obhod-v<версия>.zip для автообновления: папка «Обход для чайников v<версия>» с программой и ПРОЧТИ_МЕНЯ.txt.

Имена записываются с флагом UTF-8, чтобы Проводник Windows показывал их по-русски.
Использование: python3 tools/package.py 6.0.19 app.exe
"""
import os
import sys
import zipfile

ver, exe = sys.argv[1], sys.argv[2]
here = os.path.dirname(os.path.abspath(__file__))
root = f"Обход для чайников v{ver}"
readme = os.path.join(here, "..", "packaging", "ПРОЧТИ_МЕНЯ.txt")
with zipfile.ZipFile(f"Obhod-v{ver}.zip", "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    z.writestr(zipfile.ZipInfo(root + "/"), b"")
    z.write(exe, f"{root}/Обход для чайников.exe")
    z.write(readme, f"{root}/ПРОЧТИ_МЕНЯ.txt")
print(f"Obhod-v{ver}.zip")
