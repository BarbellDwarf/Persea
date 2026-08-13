; persea — NSIS installer for Windows
;
; Unsigned for now (SmartScreen warning is expected; a code-signing
; certificate is not available yet).
;
; Build (Linux or Windows):
;   makensis -DPROJECT_ROOT=<dir containing persea.exe, static/, README.md,
;            LICENSE, config.example.toml> persea.nsi
;
; What it does:
;   1. Copies persea.exe + docs into $PROGRAMFILES64\persea
;   2. Copies the static web assets into %ProgramData%\persea\static so they
;      survive upgrades (data layout matches --init / the service)
;   3. Runs `persea.exe --init` — creates the data layout, generates a
;      self-signed TLS certificate, writes the starter config
;   4. Registers the persea Windows service (LocalSystem, auto-start) and
;      starts it
;
; Data lives in %ProgramData%\persea (db/, recordings/, tls/, config.toml).
; Uninstalling leaves that data behind unless the user opts to remove it.

!include "MUI2.nsh"
!include "LogicLib.nsh"

!ifndef PROJECT_ROOT
  !define PROJECT_ROOT "..\.."
!endif

!ifndef VERSION
  !define VERSION "0.0.0"
!endif

!define SERVICE_NAME "persea"
!define APP_NAME "persea"
!define PUBLISHER "persea"

; %ProgramData% is not an NSIS constant — read it from the environment
; (always set on Vista+), falling back to the well-known default.
Var ProgramData

!macro ResolveProgramData
  ReadEnvStr $ProgramData "ProgramData"
  ${If} $ProgramData == ""
    StrCpy $ProgramData "C:\ProgramData"
  ${EndIf}
!macroend

Name "${APP_NAME}"
OutFile "persea-setup.exe"
InstallDir "$PROGRAMFILES64\${APP_NAME}"
InstallDirRegKey HKLM "Software\${PUBLISHER}\${APP_NAME}" "InstallDir"
RequestExecutionLevel admin

!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "Install"
  !insertmacro ResolveProgramData

  SetOutPath "$INSTDIR"
  File "${PROJECT_ROOT}\persea.exe"
  File "${PROJECT_ROOT}\README.md"
  File "${PROJECT_ROOT}\LICENSE"
  File "${PROJECT_ROOT}\config.example.toml"

  ; Static web assets go under %ProgramData%\persea\static — the same root
  ; the service uses for db/recordings/tls/config, and the path --init
  ; writes into the starter config.
  SetOutPath "$ProgramData\persea\static"
  File /r "${PROJECT_ROOT}\static\*.*"

  ; First-run bootstrap: data layout, self-signed cert, starter config.
  ; Idempotent — an upgrade over an existing %ProgramData%\persea leaves
  ; the config and certificate untouched.
  nsExec::ExecToLog '"$INSTDIR\persea.exe" --init'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONSTOP "persea --init failed (exit code $0). Setup aborted."
    Abort
  ${EndIf}

  ; Register the service (LocalSystem, auto-start) and start it.
  nsExec::ExecToLog '"$INSTDIR\persea.exe" --install-service'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONSTOP "Failed to register the ${SERVICE_NAME} service (exit code $0). Setup aborted."
    Abort
  ${EndIf}

  nsExec::ExecToLog 'net start ${SERVICE_NAME}'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONINFORMATION "The ${SERVICE_NAME} service was registered but could not be started (exit code $0). Start it later with: net start ${SERVICE_NAME}"
  ${EndIf}

  ; Add/Remove Programs entry
  WriteRegStr HKLM "Software\${PUBLISHER}\${APP_NAME}" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "NoRepair" 1

  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
  !insertmacro ResolveProgramData

  ; Stop and unregister the service (both commands tolerate the service
  ; already being stopped).
  nsExec::ExecToLog 'net stop ${SERVICE_NAME}'
  nsExec::ExecToLog '"$INSTDIR\persea.exe" --uninstall-service'

  Delete "$INSTDIR\uninstall.exe"
  RMDir /r "$INSTDIR"
  DeleteRegKey HKLM "Software\${PUBLISHER}\${APP_NAME}"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"

  ; Data is kept by default — offer removal explicitly.
  MessageBox MB_YESNO|MB_ICONQUESTION "Remove persea data (database, recordings, certificates, config) from %ProgramData%\persea?" IDNO keep_data
  RMDir /r "$ProgramData\persea"
  keep_data:
SectionEnd
