/*
    SecureW2, Copyright (C) SecureW2 B.V.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  

    See the GNU General Public License for more details, included in the file 
    LICENSE which you should have received along with this program.

    If you did not receive a copy of the GNU General Public License, 
    write to the Free Software Foundation, Inc., 675 Mass Ave, 
    Cambridge, MA 02139, USA.

    SecureW2 B.V. can be contacted at http://www.securew2.com
*/

#include "stdafx.h"

DWORD		g_dwMajorVersion = 0;
DWORD		g_dwMinorVersion = 0;
HINSTANCE	g_hInstance = NULL;
HINSTANCE	g_hResource = NULL;
HINSTANCE	g_hLanguage = NULL;
#ifndef _WIN32_WCE
DWORD		g_dwSW2TraceId = INVALID_TRACEID;
#endif // _WIN32_WCE
HANDLE		g_localHeap = NULL;

PWCHAR		SW2_METHOD_PROFILE_LOCATION	= L"SOFTWARE\\SecureW2\\Methods\\Default\\Profiles";

BYTE		EAPTYPE = 25;
PWCHAR		EAPID = L"EAP-PEAP";

//
// External interface context pointer
//
PSW2_RES_CONTEXT		 g_ResContext = NULL;

int 
WINAPI 
WinMain(	HINSTANCE hInstance, 
			HINSTANCE hPrevInstance, 
			LPSTR lpCmdLine, 
			int nShowCmd	)
{
	return SW2RunManager();
}