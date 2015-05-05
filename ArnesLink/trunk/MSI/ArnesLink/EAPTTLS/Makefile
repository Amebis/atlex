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
OLDALDIR	clal_ttls.dll.$(PLAT)
OLDALDIR	clal_ttls_manager.exe.$(PLAT)
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
clal_ttls.dll.Win32	{6968B2C0-78F5-41D5-9EC7-4AE287428014}	1
clal_ttls_manager.exe.Win32	{602783E9-D6C4-43E5-B55B-C98505D76B04}	1
!ENDIF
!IF "$(PLAT)" == "x64"
clal_ttls.dll.x64	{5EC2039D-81CC-4A44-B5E4-40F1483F869D}	1
clal_ttls_manager.exe.x64	{1497D3DD-44D1-4094-89C4-C91F244F585A}	1
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
compal_ttls.dll.Win32	{6968B2C0-78F5-41D5-9EC7-4AE287428014}	ALBINDIR	0		fileal_ttls.dll.Win32
!ENDIF
!IF "$(PLAT)" == "x64"
compal_ttls.dll.x64	{5EC2039D-81CC-4A44-B5E4-40F1483F869D}	ALBINDIR	256		fileal_ttls.dll.x64
!ENDIF
compEAPHostTTLSTracingEnable	{C401FB56-C6AA-4807-97AC-0F975E091B16}	ALBINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPHostTTLSTracingEnable
compEAPHostTTLSTracingMask	{CCE0D215-9874-433B-85C9-68269CAB4894}	ALBINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPHostTTLSTracingMask
compEAPHostTTLSPeerDllPath	{B319D997-714C-4A38-B345-5AB384D6C6A0}	ALBINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPHostTTLSPeerDllPath
compEAPHostTTLSPeerFriendlyName	{8B7B7E4A-C83B-4E2E-B724-270B6359292E}	ALBINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPHostTTLSPeerFriendlyName
compEAPHostTTLSPeerInvokePasswordDialog	{C339C512-B089-407B-88F4-DA632F584C9E}	ALBINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPHostTTLSPeerInvokePasswordDialog
compEAPHostTTLSPeerInvokeUsernameDialog	{43910AC4-D406-4FFE-A2CC-E0964662C77D}	ALBINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPHostTTLSPeerInvokeUsernameDialog
compEAPHostTTLSProperties	{87F20FF4-B448-4B57-9D00-1ED66E074578}	ALBINDIR	$(MSIBUILD_COMPONENT_ATTRIB_REGISTRY)		regEAPHostTTLSProperties
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
featTTLS	featArnesLink	TTLS	TTLS Authentication Plugin	1	1	ALDIR	8
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
featTTLS	compal_res.dll.$(PLAT)
featTTLS	compEAPHostAuthor
featTTLS	compal_ttls.dll.$(PLAT)
featTTLS	compEAPHostTTLSTracingEnable
featTTLS	compEAPHostTTLSTracingMask
featTTLS	compEAPHostTTLSPeerDllPath
featTTLS	compEAPHostTTLSPeerFriendlyName
featTTLS	compEAPHostTTLSPeerInvokePasswordDialog
featTTLS	compEAPHostTTLSPeerInvokeUsernameDialog
featTTLS	compEAPHostTTLSProperties
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
fileal_ttls.dll.$(PLAT)	compal_ttls.dll.$(PLAT)	al_ttls.dll|al_ttls.dll	0		0	1536	1
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
regEAPHostTTLSTracingEnable	2	SOFTWARE\Microsoft\Tracing\AL-EAPTTLS	EnableFileTracing	#1	compEAPHostTTLSTracingEnable
regEAPHostTTLSTracingMask	2	SOFTWARE\Microsoft\Tracing\AL-EAPTTLS	FileTracingMask	#458752	compEAPHostTTLSTracingMask
regEAPHostTTLSPeerDllPath	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\17236\21	PeerDllPath	[#fileal_ttls.dll.$(PLAT)]	compEAPHostTTLSPeerDllPath
!IFDEF AL_GENERIC_CREDENTIAL_UI
regEAPHostTTLSPeerInvokePasswordDialog	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\17236\21	PeerInvokePasswordDialog	#1	compEAPHostTTLSPeerInvokePasswordDialog
regEAPHostTTLSPeerInvokeUsernameDialog	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\17236\21	PeerInvokeUsernameDialog	#1	compEAPHostTTLSPeerInvokeUsernameDialog
!ELSE
regEAPHostTTLSPeerInvokePasswordDialog	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\17236\21	PeerInvokePasswordDialog	#0	compEAPHostTTLSPeerInvokePasswordDialog
regEAPHostTTLSPeerInvokeUsernameDialog	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\17236\21	PeerInvokeUsernameDialog	#0	compEAPHostTTLSPeerInvokeUsernameDialog
!ENDIF
regEAPHostTTLSProperties	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\17236\21	Properties	#389871807	compEAPHostTTLSProperties
<<NOKEEP

"En.$(PLAT).$(CFG).Registry-2.idtx" : "Makefile" "..\..\include\MSIBuildCfg.mak"
	-if exist $@ del /f /q $@
	move /y << $@ > NUL
Registry	Root	Key	Name	Value	Component_
s$(MSIBUILD_LENGTH_ID)	i2	l255	L255	L0	s$(MSIBUILD_LENGTH_ID)
1252	Registry	Registry
regEAPHostTTLSPeerFriendlyName	2	SYSTEM\CurrentControlSet\services\EapHost\Methods\17236\21	PeerFriendlyName	EAP-TTLS	compEAPHostTTLSPeerFriendlyName
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
rmfiTRACINGEAPTTLSLOG	compal_ttls.dll.$(PLAT)	AL-EAP~2.LOG|AL-EAPTTLS.LOG	TRACINGDIR	2
rmfiTRACINGEAPTTLSOLD	compal_ttls.dll.$(PLAT)	AL-EAP~2.OLD|AL-EAPTTLS.OLD	TRACINGDIR	2
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
scal_ttls.dll.Wlansvc	Wlansvc	51			compal_ttls.dll.$(PLAT)
scal_ttls.dll.dot3svc	dot3svc	51			compal_ttls.dll.$(PLAT)
scal_ttls.dll.EapHost	EapHost	51			compal_ttls.dll.$(PLAT)
<<NOKEEP


######################################################################
# Build MSM module!
######################################################################

!INCLUDE "..\..\MSIBuild\MSM.mak"
