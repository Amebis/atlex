#
#    Copyright 1991-2015 Amebis
#
#    This file is part of ArnesLink.
#
#    ArnesLink is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    ArnesLink is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with ArnesLink. If not, see <http://www.gnu.org/licenses/>.
#

OUTPUT_DIR=$(MAKEDIR)\output

!IF "$(PROCESSOR_ARCHITECTURE)" == "AMD64"
PLAT=x64
!ELSE
PLAT=Win32
!ENDIF


All ::

Clean ::
	cd "MSI\MSIBuild\Version"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean
	cd "$(MAKEDIR)"
	cd "MSI\ArnesLink"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean LANG=En PLAT=Win32 CFG=Release
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean LANG=En PLAT=Win32 CFG=Debug
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean LANG=En PLAT=x64   CFG=Release
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean LANG=En PLAT=x64   CFG=Debug
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean LANG=Sl PLAT=Win32 CFG=Release
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean LANG=Sl PLAT=Win32 CFG=Debug
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean LANG=Sl PLAT=x64   CFG=Release
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Clean LANG=Sl PLAT=x64   CFG=Debug
	cd "$(MAKEDIR)"
	devenv.com "ArnesLink.sln" /clean "Release|Win32"
	devenv.com "ArnesLink.sln" /clean "Debug|Win32"
	devenv.com "ArnesLink.sln" /clean "Release|x64"
	devenv.com "ArnesLink.sln" /clean "Debug|x64"
	-if exist "$(OUTPUT_DIR)\Setup\ArnesLinkEn32.msi"  del /f /q "$(OUTPUT_DIR)\Setup\ArnesLinkEn32.msi"
	-if exist "$(OUTPUT_DIR)\Setup\ArnesLinkEn32D.msi" del /f /q "$(OUTPUT_DIR)\Setup\ArnesLinkEn32D.msi"
	-if exist "$(OUTPUT_DIR)\Setup\ArnesLinkEn64.msi"  del /f /q "$(OUTPUT_DIR)\Setup\ArnesLinkEn64.msi"
	-if exist "$(OUTPUT_DIR)\Setup\ArnesLinkEn64D.msi" del /f /q "$(OUTPUT_DIR)\Setup\ArnesLinkEn64D.msi"
	-if exist "$(OUTPUT_DIR)\Setup\ArnesLinkSl32.msi"  del /f /q "$(OUTPUT_DIR)\Setup\ArnesLinkSl32.msi"
	-if exist "$(OUTPUT_DIR)\Setup\ArnesLinkSl32D.msi" del /f /q "$(OUTPUT_DIR)\Setup\ArnesLinkSl32D.msi"
	-if exist "$(OUTPUT_DIR)\Setup\ArnesLinkSl64.msi"  del /f /q "$(OUTPUT_DIR)\Setup\ArnesLinkSl64.msi"
	-if exist "$(OUTPUT_DIR)\Setup\ArnesLinkSl64D.msi" del /f /q "$(OUTPUT_DIR)\Setup\ArnesLinkSl64D.msi"

!IFNDEF HAS_VERSION

######################################################################
# 1st Phase
# - Version info parsing
######################################################################

All \
Setup \
SetupDebug \
Register \
Unregister \
StopServices \
StartServices :: "MSI\MSIBuild\Version\Version.mak"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) HAS_VERSION=1 $@

"MSI\MSIBuild\Version\Version.mak" ::
	cd "MSI\MSIBuild\Version"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) Version
	cd "$(MAKEDIR)"

RestartServices : \
	StopServices \
	StartServices

!ELSE

######################################################################
# 2nd Phase
# - The version is known, do the rest.
######################################################################

!INCLUDE "MSI\MSIBuild\Version\Version.mak"
!INCLUDE "MSI\include\MSIBuildCfg.mak"


######################################################################
# Main targets
######################################################################

All :: \
	Setup

Setup : \
	"$(OUTPUT_DIR)\Setup" \
	"$(OUTPUT_DIR)\Setup\ArnesLinkEn32.msi" \
	"$(OUTPUT_DIR)\Setup\ArnesLinkEn64.msi" \
	"$(OUTPUT_DIR)\Setup\ArnesLinkSl32.msi" \
	"$(OUTPUT_DIR)\Setup\ArnesLinkSl64.msi"

SetupDebug : \
	"$(OUTPUT_DIR)\Setup" \
	"$(OUTPUT_DIR)\Setup\ArnesLinkEn32D.msi" \
	"$(OUTPUT_DIR)\Setup\ArnesLinkEn64D.msi" \
	"$(OUTPUT_DIR)\Setup\ArnesLinkSl32D.msi" \
	"$(OUTPUT_DIR)\Setup\ArnesLinkSl64D.msi"

Register :: \
	StopServices \
	RegisterDLLs \
	StartServices \
	RegisterShortcuts \
	RegisterFileTypes

Unregister :: \
	UnregisterFileTypes \
	UnregisterShortcuts \
	StopServices \
	UnregisterDLLs \
	StartServices

StopServices ::
	-net.exe stop Wlansvc
	-net.exe stop dot3svc
	-net.exe stop EapHost

StartServices ::
	cmd.exe /c <<"$(TEMP)\start_EapHost.bat"
@echo off
net.exe start EapHost
if errorlevel 3 exit %errorlevel%
if errorlevel 2 exit 0
exit %errorlevel%
<<NOKEEP
# Enable dot3svc service (Wired AutoConfig) and start it
	sc.exe config dot3svc start= auto
	cmd.exe /c <<"$(TEMP)\start_dot3svc.bat"
@echo off
net.exe start dot3svc
if errorlevel 3 exit %errorlevel%
if errorlevel 2 exit 0
exit %errorlevel%
<<NOKEEP
# Enable Wlansvc service (WLAN AutoConfig) and start it
	sc.exe config Wlansvc start= auto
	cmd.exe /c <<"$(TEMP)\start_Wlansvc.bat"
@echo off
net.exe start Wlansvc
if errorlevel 3 exit %errorlevel%
if errorlevel 2 exit 0
exit %errorlevel%
<<NOKEEP

RegisterDLLs : \
	"$(OUTPUT_DIR)\$(PLAT).Debug\al_peap.dll" \
	"$(OUTPUT_DIR)\$(PLAT).Debug\al_ttls.dll"
	"%windir%\regedit.exe" /s <<"$(TEMP)\register-AL.reg"
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\EapHost\Methods\17236]
@="ArnesLink"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\EapHost\Methods\17236\21]
"PeerFriendlyName"="EAP-TTLS"
"PeerDllPath"="$(OUTPUT_DIR:\=\\)\\$(PLAT).Debug\\al_ttls.dll"
"Properties"=dword:173cf8bf
!IFDEF AL_GENERIC_CREDENTIAL_UI
"PeerInvokeUsernameDialog"=dword:00000001
"PeerInvokePasswordDialog"=dword:00000001
!ELSE
"PeerInvokeUsernameDialog"=dword:00000000
"PeerInvokePasswordDialog"=dword:00000000
!ENDIF

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\EapHost\Methods\17236\25]
"PeerFriendlyName"="EAP-PEAP"
"PeerDllPath"="$(OUTPUT_DIR:\=\\)\\$(PLAT).Debug\\al_peap.dll"
"Properties"=dword:173cf8bf
!IFDEF AL_GENERIC_CREDENTIAL_UI
"PeerInvokeUsernameDialog"=dword:00000001
"PeerInvokePasswordDialog"=dword:00000001
!ELSE
"PeerInvokeUsernameDialog"=dword:00000000
"PeerInvokePasswordDialog"=dword:00000000
!ENDIF

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\AL-EAPTTLS]
"EnableFileTracing"=dword:1
"FileTracingMask"=dword:00070000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\AL-EAPPEAP]
"EnableFileTracing"=dword:1
"FileTracingMask"=dword:00070000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\AL-MONITOR]
"EnableFileTracing"=dword:1
"FileTracingMask"=dword:00070000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\AL-WLANMANAGER]
"EnableFileTracing"=dword:1
"FileTracingMask"=dword:00070000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\AL-IMPORT]
"EnableFileTracing"=dword:1
"FileTracingMask"=dword:00070000

<<NOKEEP

UnregisterDLLs :
	"%windir%\regedit.exe" /s <<"$(TEMP)\unregister-AL.reg"
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\EapHost\Methods\17236]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\AL-EAPTTLS]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\AL-EAPPEAP]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\AL-MONITOR]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\AL-WLANMANAGER]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\AL-IMPORT]

<<NOKEEP

RegisterShortcuts : \
	"$(ALLUSERSPROFILE)\Microsoft\Windows\Start Menu\Programs\ArnesLink" \
	"$(ALLUSERSPROFILE)\Microsoft\Windows\Start Menu\Programs\ArnesLink\ArnesLink Monitor.lnk" \
	"$(ALLUSERSPROFILE)\Microsoft\Windows\Start Menu\Programs\ArnesLink\ArnesLink Configuration Import.lnk"

UnregisterShortcuts :
	-if exist "$(ALLUSERSPROFILE)\Microsoft\Windows\Start Menu\Programs\ArnesLink" rd /s /q "$(ALLUSERSPROFILE)\Microsoft\Windows\Start Menu\Programs\ArnesLink"

RegisterFileTypes :
	"%windir%\regedit.exe" /s <<"$(TEMP)\register-AL.reg"
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\.arneslink-config-xml]
"Content Type"="application/arneslink-config+xml"
@="ArnesLink.Configuration"

[HKEY_CLASSES_ROOT\ArnesLink.Configuration]
@="ArnesLink Configuration"

[HKEY_CLASSES_ROOT\ArnesLink.Configuration\DefaultIcon]
@="$(MAKEDIR:\=\\)\\MSI\\ArnesLink\\Main\\Icon\\arneslinkconfig.ico"

[HKEY_CLASSES_ROOT\ArnesLink.Configuration\shell]
@="open"

[HKEY_CLASSES_ROOT\ArnesLink.Configuration\shell\open]
@="&Import with ArnesLink"

[HKEY_CLASSES_ROOT\ArnesLink.Configuration\shell\open\command]
@="\"$(OUTPUT_DIR:\=\\)\\$(PLAT).Debug\\al_import.exe\" \"%1\""

<<NOKEEP

UnregisterFileTypes :
	"%windir%\regedit.exe" /s <<"$(TEMP)\unregister-AL.reg"
Windows Registry Editor Version 5.00

[-HKEY_CLASSES_ROOT\.arneslink-config-xml]

[-HKEY_CLASSES_ROOT\ArnesLink.Configuration]

<<NOKEEP


######################################################################
# Folder creation
######################################################################

"$(OUTPUT_DIR)" \
"$(OUTPUT_DIR)\Setup" \
"$(ALLUSERSPROFILE)\Microsoft\Windows\Start Menu\Programs\ArnesLink" :
	if not exist $@ md $@

"$(OUTPUT_DIR)\Setup" : "$(OUTPUT_DIR)"


######################################################################
# File copy
######################################################################

"$(OUTPUT_DIR)\Setup\ArnesLinkEn32.msi" \
$(REDIST_EN_WIN32) : "$(OUTPUT_DIR)\ArnesLinkEn32.3.msi"
	copy /y $** $@ > NUL

"$(OUTPUT_DIR)\Setup\ArnesLinkEn32D.msi" \
$(REDIST_EN_WIN32) : "$(OUTPUT_DIR)\ArnesLinkEn32D.3.msi"
	copy /y $** $@ > NUL

"$(OUTPUT_DIR)\Setup\ArnesLinkEn64.msi" \
$(REDIST_EN_X64) : "$(OUTPUT_DIR)\ArnesLinkEn64.3.msi"
	copy /y $** $@ > NUL

"$(OUTPUT_DIR)\Setup\ArnesLinkEn64D.msi" \
$(REDIST_EN_X64) : "$(OUTPUT_DIR)\ArnesLinkEn64D.3.msi"
	copy /y $** $@ > NUL

"$(OUTPUT_DIR)\Setup\ArnesLinkSl32.msi" \
$(REDIST_SL_WIN32) : "$(OUTPUT_DIR)\ArnesLinkSl32.3.msi"
	copy /y $** $@ > NUL

"$(OUTPUT_DIR)\Setup\ArnesLinkSl32D.msi" \
$(REDIST_SL_WIN32) : "$(OUTPUT_DIR)\ArnesLinkSl32D.3.msi"
	copy /y $** $@ > NUL

"$(OUTPUT_DIR)\Setup\ArnesLinkSl64.msi" \
$(REDIST_SL_X64) : "$(OUTPUT_DIR)\ArnesLinkSl64.3.msi"
	copy /y $** $@ > NUL

"$(OUTPUT_DIR)\Setup\ArnesLinkSl64D.msi" \
$(REDIST_SL_X64) : "$(OUTPUT_DIR)\ArnesLinkSl64D.3.msi"
	copy /y $** $@ > NUL


######################################################################
# Shortcut creation
######################################################################

"$(ALLUSERSPROFILE)\Microsoft\Windows\Start Menu\Programs\ArnesLink\ArnesLink Monitor.lnk" : "$(OUTPUT_DIR)\$(PLAT).Debug\al_monitor.exe"
	cscript.exe "bin\MkLnk.wsf" //Nologo $@ $**

"$(ALLUSERSPROFILE)\Microsoft\Windows\Start Menu\Programs\ArnesLink\ArnesLink Configuration Import.lnk" : "$(OUTPUT_DIR)\$(PLAT).Debug\al_import.exe"
	cscript.exe "bin\MkLnk.wsf" //Nologo $@ $**


######################################################################
# Building
######################################################################

"$(OUTPUT_DIR)\Win32.Release\al_peap.dll" \
"$(OUTPUT_DIR)\Win32.Release\al_ttls.dll" \
"$(OUTPUT_DIR)\Win32.Release\al_monitor.exe" \
"$(OUTPUT_DIR)\Win32.Release\al_import.exe" ::
	devenv.com "ArnesLink.sln" /build "Release|Win32"

"$(OUTPUT_DIR)\Win32.Debug\al_peap.dll" \
"$(OUTPUT_DIR)\Win32.Debug\al_ttls.dll" \
"$(OUTPUT_DIR)\Win32.Debug\al_monitor.exe" \
"$(OUTPUT_DIR)\Win32.Debug\al_import.exe" ::
	devenv.com "ArnesLink.sln" /build "Debug|Win32"

"$(OUTPUT_DIR)\x64.Release\al_peap.dll" \
"$(OUTPUT_DIR)\x64.Release\al_ttls.dll" \
"$(OUTPUT_DIR)\x64.Release\al_monitor.exe" \
"$(OUTPUT_DIR)\x64.Release\al_import.exe" ::
	devenv.com "ArnesLink.sln" /build "Release|x64"

"$(OUTPUT_DIR)\x64.Debug\al_peap.dll" \
"$(OUTPUT_DIR)\x64.Debug\al_ttls.dll" \
"$(OUTPUT_DIR)\x64.Debug\al_monitor.exe" \
"$(OUTPUT_DIR)\x64.Debug\al_import.exe" ::
	devenv.com "ArnesLink.sln" /build "Debug|x64"

"$(OUTPUT_DIR)\ArnesLinkEn32.3.msi" ::
	devenv.com "ArnesLink.sln" /build "Release|Win32"

"$(OUTPUT_DIR)\ArnesLinkEn32D.3.msi" ::
	devenv.com "ArnesLink.sln" /build "Debug|Win32"

"$(OUTPUT_DIR)\ArnesLinkEn64.3.msi" ::
	devenv.com "ArnesLink.sln" /build "Release|x64"

"$(OUTPUT_DIR)\ArnesLinkEn64D.3.msi" ::
	devenv.com "ArnesLink.sln" /build "Debug|x64"

"$(OUTPUT_DIR)\ArnesLinkSl32.3.msi" ::
	devenv.com "ArnesLink.sln" /build "Release|Win32"

"$(OUTPUT_DIR)\ArnesLinkSl32D.3.msi" ::
	devenv.com "ArnesLink.sln" /build "Debug|Win32"

"$(OUTPUT_DIR)\ArnesLinkSl64.3.msi" ::
	devenv.com "ArnesLink.sln" /build "Release|x64"

"$(OUTPUT_DIR)\ArnesLinkSl64D.3.msi" ::
	devenv.com "ArnesLink.sln" /build "Debug|x64"

"$(OUTPUT_DIR)\ArnesLinkEn32.3.msi" ::
	cd "MSI\ArnesLink"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) LANG=En PLAT=Win32 CFG=Release
	cd "$(MAKEDIR)"

"$(OUTPUT_DIR)\ArnesLinkEn32D.3.msi" ::
	cd "MSI\ArnesLink"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) LANG=En PLAT=Win32 CFG=Debug
	cd "$(MAKEDIR)"

"$(OUTPUT_DIR)\ArnesLinkEn64.3.msi" ::
	cd "MSI\ArnesLink"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) LANG=En PLAT=x64 CFG=Release
	cd "$(MAKEDIR)"

"$(OUTPUT_DIR)\ArnesLinkEn64D.3.msi" ::
	cd "MSI\ArnesLink"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) LANG=En PLAT=x64 CFG=Debug
	cd "$(MAKEDIR)"

"$(OUTPUT_DIR)\ArnesLinkSl32.3.msi" ::
	cd "MSI\ArnesLink"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) LANG=Sl PLAT=Win32 CFG=Release
	cd "$(MAKEDIR)"

"$(OUTPUT_DIR)\ArnesLinkSl32D.3.msi" ::
	cd "MSI\ArnesLink"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) LANG=Sl PLAT=Win32 CFG=Debug
	cd "$(MAKEDIR)"

"$(OUTPUT_DIR)\ArnesLinkSl64.3.msi" ::
	cd "MSI\ArnesLink"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) LANG=Sl PLAT=x64 CFG=Release
	cd "$(MAKEDIR)"

"$(OUTPUT_DIR)\ArnesLinkSl64D.3.msi" ::
	cd "MSI\ArnesLink"
	$(MAKE) /f "Makefile" /$(MAKEFLAGS) LANG=Sl PLAT=x64 CFG=Debug
	cd "$(MAKEDIR)"

!ENDIF
