#!/bin/sh
# Сборка установщика: build.sh <версия> <app.exe> <папка-вывода>  (ядро sing-box встроено в app.exe)
# Нужен makensis (apt install nsis). Результат: <папка-вывода>/Obhod-Setup-v<версия>.exe
set -eu
V="$1"; APP="$2"; OUT="$3"
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
mkdir -p "$W/payload" "$OUT"
cp "$APP" "$W/payload/app.exe"
cp "$HERE/../../LICENSE" "$W/payload/LICENSE"
cp "$HERE/obhod.nsi" "$HERE/obhod.ico" "$HERE/wizard.bmp" "$HERE/header.bmp" "$W/"
OUTABS=$(cd "$OUT" && pwd)
(cd "$W" && makensis -V2 -INPUTCHARSET UTF8 -DVERSION="$V" -DPAYLOAD=payload -DOUTFILE="$OUTABS/Obhod-Setup-v$V.exe" obhod.nsi)
ls -la "$OUTABS/Obhod-Setup-v$V.exe"
