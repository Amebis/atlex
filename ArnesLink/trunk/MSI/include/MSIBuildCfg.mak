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

######################################################################
# MSI General Package Information (language dependant)

!IF "$(LANG)" == "Sl"
MSIBUILD_PRODUCT_NAME=ArnesLink
MSIBUILD_PRODUCT_DESC=Vtičnik za avtentifikacijo 802.1X
MSIBUILD_VENDOR_NAME=Amebis, d. o. o., Kamnik
MSIBUILD_VENDOR_URL=http://www.amebis.si/
MSIBUILD_VENDOR_ADDRESS=Amebis, p. p. 69, 1241 Kamnik
MSIBUILD_VENDOR_PHONE=(01) 8311 035
MSIBUILD_PRODUCT_URL=$(MSIBUILD_VENDOR_URL)
MSIBUILD_PRODUCT_UPGRADE_URL=$(MSIBUILD_VENDOR_URL)
MSIBUILD_LANGID=1060
MSIBUILD_CODEPAGE=1250
!ELSE
LANG=En
MSIBUILD_PRODUCT_NAME=ArnesLink
MSIBUILD_PRODUCT_DESC=802.1X Authentication Plugin
MSIBUILD_VENDOR_NAME=Amebis, Slovenia, E.U.
MSIBUILD_VENDOR_URL=http://www.amebis.si/
MSIBUILD_VENDOR_ADDRESS=Amebis, p. p. 69, SI-1241 Kamnik, Slovenia, E.U.
MSIBUILD_VENDOR_PHONE=+386 1 8311 035
MSIBUILD_PRODUCT_URL=$(MSIBUILD_VENDOR_URL)
MSIBUILD_PRODUCT_UPGRADE_URL=$(MSIBUILD_VENDOR_URL)
MSIBUILD_LANGID=1033
MSIBUILD_CODEPAGE=1252
!ENDIF


######################################################################
# The base name of the output MSI file

MSIBUILD_TARGET=ArnesLink$(LANG)
!IF "$(PLAT)" == "x64"
MSIBUILD_TARGET=$(MSIBUILD_TARGET)64
!ELSE
PLAT=Win32
MSIBUILD_TARGET=$(MSIBUILD_TARGET)32
!ENDIF
!IF "$(CFG)" == "Debug"
MSIBUILD_TARGET=$(MSIBUILD_TARGET)D
!ELSE
CFG=Release
!ENDIF


######################################################################
# Path to version file (relative from MSIBuild\Version folder)

MSIBUILD_VERSION_FILE=..\..\..\include\version.h


######################################################################
# Working/output folder for building MSI file (relative from ArnesLink
# folder)

MSIBUILD_OUTPUT_DIR=..\..\output


######################################################################
# Path to MSIBuild folder (relative from ArnesLink folder)

MSIBUILD_ROOT=..\MSIBuild


######################################################################
# GUID used to determine MSI upgrade logic

!IF "$(PLAT)" == "x64"
MSIBUILD_UPGRADE_GUID={95A9F4AD-7310-4747-8A97-F16FB70ABC1F}
!ELSE
MSIBUILD_UPGRADE_GUID={905D15B9-00E1-4846-89AC-85E3B0A12E0F}
!ENDIF


######################################################################
# Minimum MSI version required to install this package

MSIBUILD_MSI_VERSION_MIN=200


######################################################################
# Length of ID and help fields in MSI tables (in characters)

MSIBUILD_LENGTH_ID=128
MSIBUILD_LENGTH_HELP=256


######################################################################
# Should MSIBuild compress files into CAB itself?

MSIBUILD_COMPRESS=1


######################################################################
# Prevent installation of 32-bit MSI on 64-bit Windows

MSIBUILD_HAS_X64=1
MSIBUILD_NO_WOW64=1


######################################################################
# Component and registry settings (platform dependant)

!IF "$(PLAT)" == "x64"
MSIBUILD_COMPONENT_ATTRIB_FILE=256
MSIBUILD_COMPONENT_ATTRIB_REGISTRY=260
MSIBUILD_REG32_RELOCATION=\Wow6432Node
!ELSE
MSIBUILD_COMPONENT_ATTRIB_FILE=0
MSIBUILD_COMPONENT_ATTRIB_REGISTRY=4
MSIBUILD_REG32_RELOCATION=
!ENDIF


######################################################################
# List of modules to compile and include in link

MSIBUILD_MODULES=\
	"$(MSIBUILD_ROOT)\Core\$(LANG).$(PLAT).$(CFG).msm" \
	"$(MSIBUILD_ROOT)\Version\$(LANG).$(PLAT).$(CFG).msm" \
	"$(MSIBUILD_ROOT)\UI\$(LANG).$(PLAT).$(CFG).msm" \
	"..\MSICA\MSICALib\MSIBuild\$(LANG).$(PLAT).$(CFG).msm" \
	"..\MSICA\MSICA\MSIBuild\$(LANG).$(PLAT).$(CFG).msm" \
	"Main\$(LANG).$(PLAT).$(CFG).msm" \
	"EAPPEAP\$(LANG).$(PLAT).$(CFG).msm" \
	"EAPTTLS\$(LANG).$(PLAT).$(CFG).msm"

	
######################################################################
# Project specific settings

#AL_GENERIC_CREDENTIAL_UI=1
