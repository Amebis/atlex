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

!INCLUDE "..\..\include\MSIBuildCfg.mak"

MSIBUILD_IS_LOCALIZEABLE=1


######################################################################
# AppSearch

All :: "$(LANG).$(PLAT).$(CFG).AppSearch-1.idt"

"$(LANG).$(PLAT).$(CFG).AppSearch-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
Property	Signature_
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)
AppSearch	Property	Signature_
OLDALDIR	clal_peap.dll.$(PLAT)
OLDALDIR	clal_peap_manager.exe.$(PLAT)
<<NOKEEP


######################################################################
# CompLocator

All :: "$(LANG).$(PLAT).$(CFG).CompLocator-1.idt"

"$(LANG).$(PLAT).$(CFG).CompLocator-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
Signature_	ComponentId	Type
s$(MSIBUILD_LENGTH_ID)	s38	I2
CompLocator	Signature_
!IF "$(PLAT)" == "Win32"
clal_peap.dll.Win32	{22C1BA35-6DA4-4007-8157-D30C3572065D}	1
clal_peap_manager.exe.Win32	{0E1DD03C-AC82-4D8E-849F-B4A551159327}	1
!ENDIF
!IF "$(PLAT)" == "x64"
clal_peap.dll.x64	{F72EF7CF-EAD8-4443-8B65-3E6A67BD0452}	1
clal_peap_manager.exe.x64	{487081CA-F423-463C-AD19-F2640662FFF8}	1
!ENDIF
<<NOKEEP


######################################################################
# Component

All :: "$(LANG).$(PLAT).$(CFG).Component-1.idt"

"$(LANG).$(PLAT).$(CFG).Component-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
Component	ComponentId	Directory_	Attributes	Condition	KeyPath
s$(MSIBUILD_LENGTH_ID)	S38	s$(MSIBUILD_LENGTH_ID)	i2	S255	S$(MSIBUILD_LENGTH_ID)
Component	Component
!IF "$(PLAT)" == "Win32"
compal_peap.dll.Win32	{22C1BA35-6DA4-4007-8157-D30C3572065D}	ALBINDIR	0		fileal_peap.dll.Win32
!ENDIF
!IF "$(PLAT)" == "x64"
compal_peap.dll.x64	{F72EF7CF-EAD8-4443-8B65-3E6A67BD0452}	ALBINDIR	256		fileal_peap.dll.x64
!ENDIF
compEAPHostPEAPTracingEnable	{8A27D848-12E6-49C1-96A4-FA84652A3549}	ALBINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPHostPEAPTracingEnable
compEAPHostPEAPTracingMask	{889CDA3E-1586-416E-81F9-A95A4EB4B98E}	ALBINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPHostPEAPTracingMask
compEAPHostPEAPPeerDllPath	{A540B9B4-99A8-43AF-822B-0FA4C47714E8}	ALBINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPHostPEAPPeerDllPath
compEAPHostPEAPPeerFriendlyName	{A62CA819-42F7-4CA7-A179-E96F20EAC60E}	ALBINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPHostPEAPPeerFriendlyName
compEAPHostPEAPPeerInvokePasswordDialog	{A1CC26E1-05A3-4AA0-BFA9-38D3F6B78691}	ALBINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPHostPEAPPeerInvokePasswordDialog
compEAPHostPEAPPeerInvokeUsernameDialog	{49155D73-314E-403E-B041-4F1BD81E4A24}	ALBINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPHostPEAPPeerInvokeUsernameDialog
compEAPHostPEAPProperties	{B50C7705-EF77-46C0-9316-17B0AC937C22}	ALBINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPHostPEAPProperties
<<NOKEEP


######################################################################
# Feature

All :: "$(LANG).$(PLAT).$(CFG).Feature-2.idt"

"En.$(PLAT).$(CFG).Feature-2.idtx" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
Feature	Feature_Parent	Title	Description	Display	Level	Directory_	Attributes
s$(MSIBUILD_LENGTH_ID)	S$(MSIBUILD_LENGTH_ID)	L64	L255	I2	i2	S$(MSIBUILD_LENGTH_ID)	i2
1252	Feature	Feature
featPEAP	featArnesLink	PEAP	PEAP Authentication Plugin	1	1	ALDIR	8
<<NOKEEP

"De.$(PLAT).$(CFG).Feature-2.idt" : "En.$(PLAT).$(CFG).Feature-2.idtx" "..\L10N\de_DE.po"
	rcxgettext.exe idtp $@ $**

"En.$(PLAT).$(CFG).Feature-2.idt" : "En.$(PLAT).$(CFG).Feature-2.idtx"
	copy /y $** $@ > NUL

"It.$(PLAT).$(CFG).Feature-2.idt" : "En.$(PLAT).$(CFG).Feature-2.idtx" "..\L10N\it_IT.po"
	rcxgettext.exe idtp $@ $**

"Sl.$(PLAT).$(CFG).Feature-2.idt" : "En.$(PLAT).$(CFG).Feature-2.idtx" "..\L10N\sl_SI.po"
	rcxgettext.exe idtp $@ $**


######################################################################
# FeatureComponents

All :: "$(LANG).$(PLAT).$(CFG).FeatureComponents-1.idt"

"$(LANG).$(PLAT).$(CFG).FeatureComponents-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
Feature_	Component_
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)
FeatureComponents	Feature_	Component_
featPEAP	compal_res.dll.$(PLAT)
featPEAP	compEAPHostAuthor
featPEAP	compal_peap.dll.$(PLAT)
featPEAP	compEAPHostPEAPTracingEnable
featPEAP	compEAPHostPEAPTracingMask
featPEAP	compEAPHostPEAPPeerDllPath
featPEAP	compEAPHostPEAPPeerFriendlyName
featPEAP	compEAPHostPEAPPeerInvokePasswordDialog
featPEAP	compEAPHostPEAPPeerInvokeUsernameDialog
featPEAP	compEAPHostPEAPProperties
<<NOKEEP


######################################################################
# File

All :: "$(LANG).$(PLAT).$(CFG).File-1.idt"

"$(LANG).$(PLAT).$(CFG).File-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
File	Component_	FileName	FileSize	Version	Language	Attributes	Sequence
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)	l255	i4	S$(MSIBUILD_LENGTH_ID)	S20	I2	i2
File	File
fileal_peap.dll.$(PLAT)	compal_peap.dll.$(PLAT)	al_peap.dll|al_peap.dll	0		0	1536	1
<<NOKEEP


######################################################################
# Registry

All :: \
	"$(LANG).$(PLAT).$(CFG).Registry-1.idt" \
	"$(LANG).$(PLAT).$(CFG).Registry-2.idt"

"$(LANG).$(PLAT).$(CFG).Registry-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
Registry	Root	Key	Name	Value	Component_
s$(MSIBUILD_LENGTH_ID)	i2	l255	L255	L0	s$(MSIBUILD_LENGTH_ID)
Registry	Registry
regEAPHostPEAPTracingEnable	2	SOFTWARE\Microsoft\Tracing\AL-EAPPEAP	EnableFileTracing	#1	compEAPHostPEAPTracingEnable
regEAPHostPEAPTracingMask	2	SOFTWARE\Microsoft\Tracing\AL-EAPPEAP	FileTracingMask	#458752	compEAPHostPEAPTracingMask
regEAPHostPEAPPeerDllPath	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\17236\25	PeerDllPath	[#fileal_peap.dll.$(PLAT)]	compEAPHostPEAPPeerDllPath
!IFDEF AL_GENERIC_CREDENTIAL_UI
regEAPHostPEAPPeerInvokePasswordDialog	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\17236\25	PeerInvokePasswordDialog	#1	compEAPHostPEAPPeerInvokePasswordDialog
regEAPHostPEAPPeerInvokeUsernameDialog	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\17236\25	PeerInvokeUsernameDialog	#1	compEAPHostPEAPPeerInvokeUsernameDialog
!ELSE
regEAPHostPEAPPeerInvokePasswordDialog	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\17236\25	PeerInvokePasswordDialog	#0	compEAPHostPEAPPeerInvokePasswordDialog
regEAPHostPEAPPeerInvokeUsernameDialog	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\17236\25	PeerInvokeUsernameDialog	#0	compEAPHostPEAPPeerInvokeUsernameDialog
!ENDIF
regEAPHostPEAPProperties	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\17236\25	Properties	#389871807	compEAPHostPEAPProperties
<<NOKEEP

"En.$(PLAT).$(CFG).Registry-2.idtx" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
Registry	Root	Key	Name	Value	Component_
s$(MSIBUILD_LENGTH_ID)	i2	l255	L255	L0	s$(MSIBUILD_LENGTH_ID)
1252	Registry	Registry
regEAPHostPEAPPeerFriendlyName	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\17236\25	PeerFriendlyName	EAP-PEAP	compEAPHostPEAPPeerFriendlyName
<<NOKEEP

"De.$(PLAT).$(CFG).Registry-2.idt" : "En.$(PLAT).$(CFG).Registry-2.idtx" "..\L10N\de_DE.po"
	rcxgettext.exe idtp $@ $**

"En.$(PLAT).$(CFG).Registry-2.idt" : "En.$(PLAT).$(CFG).Registry-2.idtx"
	copy /y $** $@ > NUL

"It.$(PLAT).$(CFG).Registry-2.idt" : "En.$(PLAT).$(CFG).Registry-2.idtx" "..\L10N\it_IT.po"
	rcxgettext.exe idtp $@ $**

"Sl.$(PLAT).$(CFG).Registry-2.idt" : "En.$(PLAT).$(CFG).Registry-2.idtx" "..\L10N\sl_SI.po"
	rcxgettext.exe idtp $@ $**


######################################################################
# RemoveFile

All :: "$(LANG).$(PLAT).$(CFG).RemoveFile-1.idt"

"$(LANG).$(PLAT).$(CFG).RemoveFile-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
FileKey	Component_	FileName	DirProperty	InstallMode
s$(MSIBUILD_LENGTH_ID)	s$(MSIBUILD_LENGTH_ID)	L255	s$(MSIBUILD_LENGTH_ID)	i2
RemoveFile	FileKey
rmfiTRACINGEAPPEAPLOG	compal_peap.dll.$(PLAT)	AL-EAP~1.LOG|AL-EAPPEAP.LOG	TRACINGDIR	2
rmfiTRACINGEAPPEAPOLD	compal_peap.dll.$(PLAT)	AL-EAP~1.OLD|AL-EAPPEAP.OLD	TRACINGDIR	2
<<NOKEEP


######################################################################
# ServiceControl

All :: "$(LANG).$(PLAT).$(CFG)..ServiceControl-1.idt"

"$(LANG).$(PLAT).$(CFG)..ServiceControl-1.idt" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
ServiceControl	Name	Event	Arguments	Wait	Component_
s$(MSIBUILD_LENGTH_ID)	l255	i2	L255	I2	s$(MSIBUILD_LENGTH_ID)
ServiceControl	ServiceControl
scal_peap.dll.Wlansvc	Wlansvc	51			compal_peap.dll.$(PLAT)
scal_peap.dll.dot3svc	dot3svc	51			compal_peap.dll.$(PLAT)
scal_peap.dll.EapHost	EapHost	51			compal_peap.dll.$(PLAT)
<<NOKEEP


######################################################################
# Build MSM module!
######################################################################

!INCLUDE "..\..\MSIBuild\MSM.mak"
