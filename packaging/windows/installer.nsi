Unicode True
!include "MUI2.nsh"

Name "Hart's Anti-Venom Desktop Guard"
OutFile "Harts-Anti-Venom-1.0.0-Windows-x64-Setup.exe"
InstallDir "$LOCALAPPDATA\Programs\HartsAntiVenom"
InstallDirRegKey HKCU "Software\HartsAntiVenom" "Install_Dir"
RequestExecutionLevel user

!define MUI_ICON "..\..\src-tauri\icons\icon.ico"
!define MUI_UNICON "..\..\src-tauri\icons\icon.ico"
!define MUI_ABORTWARNING

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetOutPath "$INSTDIR"
  File "..\..\src-tauri\target\x86_64-pc-windows-gnu\release\harts-anti-venom-windows.exe"

  WriteRegStr HKCU "Software\HartsAntiVenom" "Install_Dir" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HartsAntiVenom" "DisplayName" "Hart's Anti-Venom Desktop Guard"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HartsAntiVenom" "DisplayVersion" "1.0.0"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HartsAntiVenom" "Publisher" "Josh Hart"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HartsAntiVenom" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteUninstaller "$INSTDIR\uninstall.exe"

  CreateDirectory "$SMPROGRAMS\Hart's Anti-Venom"
  CreateShortcut "$SMPROGRAMS\Hart's Anti-Venom\Hart's Anti-Venom.lnk" "$INSTDIR\harts-anti-venom-windows.exe" "" "$INSTDIR\harts-anti-venom-windows.exe" 0
  CreateShortcut "$DESKTOP\Hart's Anti-Venom.lnk" "$INSTDIR\harts-anti-venom-windows.exe" "" "$INSTDIR\harts-anti-venom-windows.exe" 0
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\harts-anti-venom-windows.exe"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$SMPROGRAMS\Hart's Anti-Venom\Hart's Anti-Venom.lnk"
  RMDir "$SMPROGRAMS\Hart's Anti-Venom"
  Delete "$DESKTOP\Hart's Anti-Venom.lnk"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\HartsAntiVenom"
  DeleteRegKey HKCU "Software\HartsAntiVenom"
SectionEnd