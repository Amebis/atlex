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

HINSTANCE	g_hInstance = NULL;
DWORD		g_dwMajorVersion = 0;
DWORD		g_dwMinorVersion = 0;
WCHAR		g_pwcCSDVersion[128];
DWORD		g_dwSW2TraceId = INVALID_TRACEID;
HANDLE		g_localHeap = NULL;

BOOL WINAPI DllMain(IN HANDLE	hInstance,
					IN DWORD	dwReason,
					IN LPVOID	lpVoid )
{
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

    if (dwReason == DLL_PROCESS_ATTACH)
	{
		g_hInstance = (HINSTANCE) hInstance;

		dwReturnCode = SW2InitializeHeap();
	}
    else if (dwReason == DLL_PROCESS_DETACH)
	{
		SW2DeInitializeHeap();
	}

    return TRUE;
}