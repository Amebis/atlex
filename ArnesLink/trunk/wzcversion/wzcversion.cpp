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
#pragma comment(lib, "Version.lib")

//
// Global information
//
HINSTANCE	g_hInstance = NULL;
DWORD		g_dwMajorVersion = 0;
DWORD		g_dwMinorVersion = 0;
#ifndef _WIN32_WCE
DWORD		g_dwSW2TraceId = INVALID_TRACEID;
#endif // _WIN32_WCE
HANDLE		g_localHeap = NULL;

extern "C" void 
__declspec ( dllexport )
Get( HWND hwndParent, 
	int string_size, 
	char *variables, 
	stack_t **stacktop )
{
	VS_FIXEDFILEINFO*	pvsFileInfo;
	DWORD				dwvsFileInfoSize;
	PBYTE				pbVersion;
	DWORD				dwHandle = 0;
	DWORD				cbVersion;
	DWORD				dwWZCSDllVersion;
	CHAR				pcTemp[256];
	DWORD				dwRet;

	EXDLL_INIT();

	dwRet = NO_ERROR;

	cbVersion = GetFileVersionInfoSize( "wzcsapi.dll", &dwHandle );

	if ((dwRet = SW2AllocateMemory(cbVersion, (PVOID*) &pbVersion)) == NO_ERROR)
	{
		if( GetFileVersionInfo( "wzcsapi.dll",
								0,
								cbVersion,
								pbVersion ) )
		{
			dwvsFileInfoSize = 0;

			if( VerQueryValue( pbVersion, "\\", ( LPVOID*) &pvsFileInfo, (PUINT) &dwvsFileInfoSize ) )
			{
				if( pvsFileInfo->dwProductVersionLS == 143857554 )
				{
					dwWZCSDllVersion = WZCS_DLL_VERSION_5_0_6034; // Windows 2000 SP3 + hotfix
				}
				else if( pvsFileInfo->dwProductVersionLS == 143858124 )
				{
					dwWZCSDllVersion = WZCS_DLL_VERSION_5_0_6604; // Windows 2000 SP4
				}
				else if( pvsFileInfo->dwProductVersionLS == 170393600 )
				{
					dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600; // Windows XP SP0
				}
				else if( pvsFileInfo->dwProductVersionLS == 170394706 )
				{
					dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600_1106; // Windows XP SP1
				}
				else if( pvsFileInfo->dwProductVersionLS == 170394781 )
				{
					dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600_1181; // Windows XP SP1 + WPA
				}
				else if( pvsFileInfo->dwProductVersionLS == 170394876 )
				{
					dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600_1276; // Windows XP SP1 + WPA Rollup
				}				
				else if( pvsFileInfo->dwProductVersionLS >= 170395749 )
				{
					dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600_2149; // Windows XP SP2 Release candidate 2
				}
				else
				{
					dwRet = ERROR_NOT_SUPPORTED;
				}
			}
			else
				dwRet = ERROR_NOT_SUPPORTED;
		}
		else
		{
			dwRet = ERROR_NOT_SUPPORTED;
		}

		SW2FreeMemory((PVOID*)&pbVersion);
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	if( dwRet == NO_ERROR )
	{
		sprintf_s( pcTemp, sizeof( pcTemp ), "%ld", dwWZCSDllVersion );
	}
	else
	{
		sprintf_s( pcTemp, sizeof( pcTemp ), "%ld", dwRet );
	}

	pushstring( pcTemp );
}

BOOL WINAPI
DllMain(	IN HINSTANCE   hInstance,
			IN DWORD       dwReason,
			IN LPVOID		lpVoid )
{
	DWORD	dwVersion;
	DWORD	dwReturnCode = NO_ERROR;

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		g_hInstance = hInstance;

		// Create the heap we'll be using for memory allocations.
		if ((dwReturnCode = SW2InitializeHeap())==NO_ERROR)
		{
			// retrieve windows version, used to distinct between Vista and others
			dwVersion = GetVersion();
			 
			g_dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
			g_dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));
		}
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		// Clean up our internal heap.
		dwReturnCode = SW2DeInitializeHeap();
	}

	if (dwReturnCode != NO_ERROR)
		return FALSE;
	else
		return TRUE;
}