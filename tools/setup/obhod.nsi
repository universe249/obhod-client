; Установщик «Обхода для чайников» (NSIS 3, Unicode).
; Собирается на Linux: tools/setup/build.sh <версия> <app.exe> <папка-вывода>
; Ставит программу в профиль пользователя (туда же, куда ставил прежний установщик, поэтому обновление идёт поверх
; и настройки в папке data сохраняются), создаёт ярлыки, автозапуск и запись в «Установка и удаление программ».
; Ключи: /S — тихая установка (с ярлыком и автозапуском), /D=папка — другая папка (последним аргументом).

Target amd64-unicode   ; программа только 64-битная, установщик тоже (заодно его можно проверить под wine64)
ManifestDPIAware true
SetCompressor /SOLID lzma
SetCompressorDictSize 64
RequestExecutionLevel admin   ; программе всё равно нужны права администратора (туннель); так можно закрыть запущенную копию и создать автозапуск

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef PAYLOAD
  !define PAYLOAD "payload"
!endif
!ifndef OUTFILE
  !define OUTFILE "Obhod-Setup-v${VERSION}.exe"
!endif

!define APPNAME   "Обход для чайников"
!define EXENAME   "Obhod.exe"
!define REGKEY    "Software\Microsoft\Windows\CurrentVersion\Uninstall\ObhodDlyaChaynikov"
!define TASKNAME  "SingUI"          ; имя задачи автозапуска в программе (platform_windows.go: taskName)
!define SITE      "https://github.com/universe249/obhodch"

Name "${APPNAME}"
Caption "${APPNAME} ${VERSION} — установка"
UninstallCaption "${APPNAME} — удаление"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\Programs\${APPNAME}"
BrandingText "${APPNAME} ${VERSION}"
ShowInstDetails nevershow
ShowUninstDetails nevershow
SpaceTexts none

VIProductVersion "${VERSION}.0"
VIAddVersionKey /LANG=1049 "ProductName" "${APPNAME}"
VIAddVersionKey /LANG=1049 "FileDescription" "Установка программы «${APPNAME}»"
VIAddVersionKey /LANG=1049 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=1049 "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=1049 "CompanyName" "universe249"
VIAddVersionKey /LANG=1049 "LegalCopyright" "universe249"

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

!define MUI_ICON "obhod.ico"
!define MUI_UNICON "obhod.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "wizard.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "wizard.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT
!define MUI_HEADERIMAGE_BITMAP "header.bmp"
!define MUI_HEADERIMAGE_UNBITMAP "header.bmp"
!define MUI_ABORTWARNING
!define MUI_ABORTWARNING_TEXT "Прервать установку «${APPNAME}»?"
!define MUI_COMPONENTSPAGE_NODESC

; --- страницы установки ---
!define MUI_WELCOMEPAGE_TITLE "Установка «${APPNAME}» ${VERSION}"
!define MUI_WELCOMEPAGE_TEXT "Программа открывает заблокированные сайты и приложения через сервер, а всё остальное оставляет напрямую.$\r$\n$\r$\nЕсли программа уже стоит, она обновится, а настройки, серверы и подписка сохранятся.$\r$\n$\r$\nНажми «Далее»."
!insertmacro MUI_PAGE_WELCOME
!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipDirIfUpdate
!insertmacro MUI_PAGE_DIRECTORY
!define MUI_PAGE_HEADER_TEXT "Настройки установки"
!define MUI_PAGE_HEADER_SUBTEXT "Всё это можно поменять потом в самой программе."
!define MUI_COMPONENTSPAGE_TEXT_TOP "Отметь, что нужно, и нажми «Установить»."
!define MUI_COMPONENTSPAGE_TEXT_COMPLIST "Дополнительно:"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_TITLE "Готово"
!define MUI_FINISHPAGE_TEXT "«${APPNAME}» установлена.$\r$\n$\r$\nПри первом запуске Windows спросит права администратора — они нужны, чтобы программа могла пропускать трафик через сервер."
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Запустить программу"
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchApp
!define MUI_FINISHPAGE_LINK "Страница программы и все версии"
!define MUI_FINISHPAGE_LINK_LOCATION "${SITE}/releases"
!insertmacro MUI_PAGE_FINISH

; --- страницы удаления ---
!insertmacro MUI_UNPAGE_CONFIRM
!define MUI_PAGE_HEADER_TEXT "Что удалить"
!define MUI_PAGE_HEADER_SUBTEXT "Программа, ярлыки и автозапуск удаляются всегда."
!define MUI_COMPONENTSPAGE_TEXT_COMPLIST "Дополнительно:"
!define MUI_COMPONENTSPAGE_TEXT_TOP "Настройки можно оставить — при новой установке всё подхватится само."
!insertmacro MUI_UNPAGE_COMPONENTS
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "Russian"

; ---------------------------------------------------------------------------------------------------
Var Updating

!macro StopApp
  ; закрываем программу и ядро: иначе файлы заняты. Ядро запускает сама программа, его тоже гасим.
  nsExec::Exec 'taskkill /F /IM "${EXENAME}"'
  Pop $0
  nsExec::Exec 'taskkill /F /IM sing-box.exe'
  Pop $0
  nsExec::Exec 'taskkill /F /IM obhod-core.exe'
  Pop $0
  nsExec::Exec 'taskkill /F /IM xray.exe'
  Pop $0
  Sleep 800
!macroend

Function .onInit
  ; второй экземпляр установщика не нужен
  System::Call 'kernel32::CreateMutex(p 0, i 0, t "ObhodSetupMutex") p .r1 ?e'
  Pop $0
  ${If} $0 == 183
    MessageBox MB_OK|MB_ICONINFORMATION "Установка уже идёт." /SD IDOK
    Abort
  ${EndIf}
  ; уже стоит — ставим в ту же папку
  StrCpy $Updating "0"
  ReadRegStr $0 HKCU "${REGKEY}" "InstallLocation"
  ${If} $0 != ""
  ${AndIf} ${FileExists} "$0\${EXENAME}"
    StrCpy $INSTDIR $0
    StrCpy $Updating "1"
  ${EndIf}
FunctionEnd

; Старая копия из архива (например C:\SingUI, файл «Обход для чайников.exe»): её не знает ни реестр, ни этот
; установщик. Находим её по запущенному процессу, рядом с которым лежит data\settings.json, или по папке C:\SingUI.
; Закрываем, переносим настройки (если в новой папке их ещё нет) и убираем её автозапуск — иначе после входа
; в Windows стартовала бы старая копия.
Var OldDir
Function MigrateOld
  StrCpy $OldDir ""
  nsExec::ExecToStack `powershell -NoProfile -ExecutionPolicy Bypass -Command "$$p = Get-Process | Where-Object { $$_.Path -and (Test-Path (Join-Path (Split-Path $$_.Path) 'data\settings.json')) -and (Test-Path (Join-Path (Split-Path $$_.Path) 'data\sing-box.exe')) } | Select-Object -First 1; if ($$p) { [Console]::Out.Write((Split-Path $$p.Path)) }"`
  Pop $0
  Pop $1
  ${If} $0 == 0
  ${AndIf} $1 != ""
    StrCpy $OldDir $1
  ${EndIf}
  ${If} $OldDir == ""
  ${AndIf} ${FileExists} "C:\SingUI\data\settings.json"
    StrCpy $OldDir "C:\SingUI"
  ${EndIf}
  ${If} $OldDir == ""
  ${OrIf} $OldDir == $INSTDIR
    Return
  ${EndIf}
  DetailPrint "Найдена старая копия: $OldDir"
  ; закрываем её (по пути, а не по имени: файл может называться как угодно)
  nsExec::Exec `powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Process | Where-Object { $$_.Path -like '$OldDir\*' } | Stop-Process -Force; Get-Process sing-box -ErrorAction SilentlyContinue | Stop-Process -Force"`
  Pop $0
  Sleep 1000
  ${IfNot} ${FileExists} "$INSTDIR\data\settings.json"
    CreateDirectory "$INSTDIR\data"
    ; кеш окна (webview2*) не переносим: он большой и создастся заново
    nsExec::Exec `robocopy "$OldDir\data" "$INSTDIR\data" /E /XD webview2 webview2-mini /R:1 /W:1 /NFL /NDL /NJH /NJS /NP`
    Pop $0
    ${If} $0 == "error"
    ${OrIf} $0 >= 8
      CopyFiles /SILENT "$OldDir\data\*.*" "$INSTDIR\data"
    ${EndIf}
    DetailPrint "Настройки перенесены из $OldDir"
    MessageBox MB_OK|MB_ICONINFORMATION "Нашлась старая копия программы в папке:$\r$\n$OldDir$\r$\n$\r$\nНастройки, серверы и подписка перенесены в новую. Старую папку теперь можно удалить." /SD IDOK
  ${EndIf}
  nsExec::Exec 'schtasks /Delete /TN "${TASKNAME}" /F' ; автозапуск старой копии (секция «Автозапуск» создаст новый)
  Pop $0
FunctionEnd

Function SkipDirIfUpdate
  ${If} $Updating == "1"
    Abort ; обновление: папку не спрашиваем
  ${EndIf}
FunctionEnd

Function LaunchApp
  ; программа сама перезапустится с правами администратора
  Exec '"$INSTDIR\${EXENAME}"'
FunctionEnd

; ---------------------------------------------------------------------------------------------------
Section "-Программа" SecApp
  SectionIn RO
  SetOutPath "$INSTDIR"
  Call MigrateOld
  !insertmacro StopApp
  ; файл мог ещё держаться пару секунд после закрытия
  ClearErrors
  SetOverwrite try
  File "/oname=${EXENAME}" "${PAYLOAD}\app.exe"
  ${If} ${Errors}
    Sleep 2000
    !insertmacro StopApp
    SetOverwrite on
    File "/oname=${EXENAME}" "${PAYLOAD}\app.exe"
  ${EndIf}
  SetOverwrite on

  ; ядро sing-box встроено в программу (с 6.3): отдельный sing-box.exe прошлых версий больше не нужен
  CreateDirectory "$INSTDIR\data"
  Delete "$INSTDIR\data\sing-box.exe"
  Delete "$INSTDIR\data\libcronet.dll"
  Delete "$INSTDIR\data\obhod-core.exe"   ; ссылка на прошлую версию программы, пересоздастся при включении
  ReadEnvStr $1 ProgramData
  Delete "$1\Obhod\obhod-core.exe"
  Delete "$INSTDIR\sing-box-LICENSE.txt"
  Delete "$INSTDIR\data\sing-box-LICENSE.txt"
  File "/oname=LICENSE.txt" "${PAYLOAD}\LICENSE"
  SetOutPath "$INSTDIR"

  ; от прежнего установщика остался свой uninstall.exe — заменяем нашим
  Delete "$INSTDIR\uninstall.exe"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  CreateShortcut "$SMPROGRAMS\${APPNAME}.lnk" "$INSTDIR\${EXENAME}" "" "$INSTDIR\${EXENAME}" 0

  ; «Установка и удаление программ»
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  WriteRegStr   HKCU "${REGKEY}" "DisplayName"     "${APPNAME}"
  WriteRegStr   HKCU "${REGKEY}" "DisplayVersion"  "${VERSION}"
  WriteRegStr   HKCU "${REGKEY}" "Publisher"       "universe249"
  WriteRegStr   HKCU "${REGKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr   HKCU "${REGKEY}" "DisplayIcon"     "$INSTDIR\${EXENAME}"
  WriteRegStr   HKCU "${REGKEY}" "URLInfoAbout"    "${SITE}"
  WriteRegStr   HKCU "${REGKEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr   HKCU "${REGKEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKCU "${REGKEY}" "EstimatedSize"   $0
  WriteRegDWORD HKCU "${REGKEY}" "NoModify" 1
  WriteRegDWORD HKCU "${REGKEY}" "NoRepair" 1

  Call EnsureWebView2
SectionEnd

Section "Ярлык на рабочем столе" SecDesktop
  CreateShortcut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\${EXENAME}" "" "$INSTDIR\${EXENAME}" 0
SectionEnd

Section "Автозапуск с Windows" SecAutostart
  ; та же задача, что создаёт переключатель «Автозапуск» в программе
  nsExec::Exec 'schtasks /Create /TN "${TASKNAME}" /TR "\"$INSTDIR\${EXENAME}\" -background" /SC ONLOGON /RL HIGHEST /F'
  Pop $0
SectionEnd

; Окно программы рисует среда Microsoft Edge WebView2. В Windows 10/11 она обычно есть; в «облегчённых» сборках её
; вырезают — тогда скачиваем официальный установщик Microsoft. Без неё программа откроется в браузере.
Function EnsureWebView2
  StrCpy $1 ""
  ReadRegStr $1 HKLM "SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" "pv"
  ${If} $1 == ""
  ${OrIf} $1 == "0.0.0.0"
    ReadRegStr $1 HKCU "SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" "pv"
  ${EndIf}
  ${If} $1 != ""
  ${AndIf} $1 != "0.0.0.0"
    Return
  ${EndIf}
  DetailPrint "Скачиваю Microsoft Edge WebView2…"
  nsExec::Exec `powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol='Tls12'; Invoke-WebRequest -UseBasicParsing 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' -OutFile '$TEMP\MicrosoftEdgeWebview2Setup.exe'"`
  Pop $0
  ${If} ${FileExists} "$TEMP\MicrosoftEdgeWebview2Setup.exe"
    DetailPrint "Устанавливаю Microsoft Edge WebView2…"
    ExecWait '"$TEMP\MicrosoftEdgeWebview2Setup.exe" /silent /install'
    Delete "$TEMP\MicrosoftEdgeWebview2Setup.exe"
  ${EndIf}
FunctionEnd

; ---------------------------------------------------------------------------------------------------
Section "-un.Программа"
  SectionIn RO
  !insertmacro StopApp
  nsExec::Exec 'schtasks /Delete /TN "${TASKNAME}" /F'
  Pop $0
  nsExec::Exec 'schtasks /Delete /TN "${APPNAME}" /F'   ; так задачу (ошибочно) называл прежний удалятор
  Pop $0
  Delete "$DESKTOP\${APPNAME}.lnk"
  Delete "$SMPROGRAMS\${APPNAME}.lnk"
  DeleteRegKey HKCU "${REGKEY}"
  Delete "$INSTDIR\${EXENAME}"
  Delete "$INSTDIR\${EXENAME}.bak"   ; остаются после автообновления
  Delete "$INSTDIR\${EXENAME}.new"
  Delete "$INSTDIR\data\obhod-core.exe"   ; ядро (ссылка на программу)
  ReadEnvStr $1 ProgramData
  Delete "$1\Obhod\obhod-core.exe"
  RMDir "$1\Obhod"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
SectionEnd

Section /o "un.Настройки, серверы и подписку" UnSecData
  RMDir /r "$INSTDIR\data"
  RMDir /r "$INSTDIR"
SectionEnd

Function un.onInit
  ; тихое удаление (/S) настройки не трогает
FunctionEnd
