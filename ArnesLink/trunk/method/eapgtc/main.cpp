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

//
// Global information
//
HINSTANCE	g_hInstance = NULL;
HINSTANCE	g_hLanguage = NULL;
HINSTANCE	g_hResource = NULL;
HINSTANCE	g_hExternal = NULL;
DWORD		g_dwMajorVersion = 0;
DWORD		g_dwMinorVersion = 0;
WCHAR		g_pwcCSDVersion[128];
#ifndef _WIN32_WCE
DWORD		g_dwSW2TraceId = INVALID_TRACEID;
#endif // _WIN32_WCE
HANDLE		g_localHeap = NULL;

//
// External interface context pointer
//
PSW2_RES_CONTEXT		 g_ResContext = NULL;


//
// This information is used when installing the module via regsvr32.exe
//
DWORD		VERSION = 1;
BYTE		EAPTYPE = 6;
PWCHAR		EAPID = L"EAP-GTC";
PWCHAR		EAPFRIENDLYID = L"SecureW2 EAP-GTC";
PWCHAR		EAPDLLNAME = L"sw2_gtc.dll";
#ifndef _WIN32_WCE
DWORD		EAPPROPERTIES = eapPropSessionIndependence |
							eapPropStandalone |
							0x01000000 |
							0x02000000 |
							0x10000000;
#else
DWORD		EAPPROPERTIES = 0x200000;
#endif // _WIN32_WCE

DWORD		EAPUSERNAMEDLG = 0;
DWORD		EAPPWDDLG = 0;
DWORD		EAPMPPESUPPORTED = 0;
DWORD		EAPSTANDALONESUPPORTED = 1;

DWORD		AUTHOR_ID = 29114;
DWORD		VENDOR_ID = 29114;
DWORD		VENDOR_TYPE = 0;

PWCHAR		SW2_METHOD_REG_LOCATION = L"SOFTWARE\\SecureW2\\GTC\\";
PWCHAR		SW2_METHOD_PROFILE_LOCATION	= L"SOFTWARE\\SecureW2\\GTC\\Profiles";

//
// Main dll function
//
BOOL WINAPI DllMain(IN HANDLE	hInstance,
					IN DWORD	dwReason,
					IN LPVOID	lpVoid )
{
	OSVERSIONINFO	osvi;
	DWORD			dwReturnCode = NO_ERROR;

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		g_hInstance = (HINSTANCE) hInstance;

		g_hExternal = NULL;
		g_hLanguage = NULL;
		g_hResource = NULL;

		//
		// Create the heap we'll be using for memory allocations.
		//
		if ((dwReturnCode = SW2InitializeHeap())==NO_ERROR)
		{
			//
			// Check for extension library, if not available load default resources
			//
			if ((g_hExternal = LoadLibrary(L"sw2_ext.dll")))
			{
				//
				// Load external interface
				//
				if ((dwReturnCode = SW2AllocateMemory(sizeof(SW2_RES_CONTEXT), 
												(PVOID*)&g_ResContext))==NO_ERROR)
				{
					if ((dwReturnCode = SW2LoadExternalInterface(g_hExternal,
																g_ResContext)) == NO_ERROR)
					{
						if ((g_ResContext->pContext = g_ResContext->pSW2Initialize(EAPTYPE))==NULL)
							dwReturnCode = ERROR_DLL_INIT_FAILED;

						if (dwReturnCode != NO_ERROR)
						{
							if (g_hExternal)
							{
								FreeLibrary(g_hExternal);
								g_hExternal = NULL;
							}
						}
					}

					if (dwReturnCode != NO_ERROR)
					{
						SW2FreeMemory((PVOID*)&g_ResContext);
						g_ResContext = NULL;
					}
				}
			}
			else if ((g_hLanguage = LoadLibrary( L"sw2_lang.dll" )))
			{
				if (!(g_hResource = LoadLibrary(L"sw2_res_default.dll")))
					dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

				if (dwReturnCode != NO_ERROR)
				{
					if (g_hLanguage)
					{
						FreeLibrary(g_hLanguage);
						g_hLanguage = NULL;
					}
				}
			}
			else
				dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

			if (dwReturnCode != NO_ERROR)
			{
				SW2DeInitializeHeap();
			}
		}

		if (dwReturnCode == NO_ERROR)
		{
			memset(&osvi, 0, sizeof(OSVERSIONINFO));

			osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

			GetVersionEx(&osvi);

			// retrieve windows version, used to distinct between Vista and others
			g_dwMajorVersion = osvi.dwMajorVersion;
			g_dwMinorVersion = osvi.dwMinorVersion;
			wcscpy_s(g_pwcCSDVersion, sizeof(g_pwcCSDVersion), osvi.szCSDVersion);
		}
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		if (g_ResContext)
		{
			if (g_ResContext->pContext)
				g_ResContext->pSW2Uninitialize(g_ResContext->pContext);

			SW2FreeMemory((PVOID*)&g_ResContext);
		}

		if (g_hExternal)
			FreeLibrary(g_hExternal);

		if (g_hLanguage)
			FreeLibrary(g_hLanguage);

		if (g_hResource)
			FreeLibrary(g_hResource);

		SW2DeInitializeHeap();
	}

	if (dwReturnCode != NO_ERROR)
		return FALSE;
	else
		return TRUE;
}

//
// Call made by regsvr32.exe
//
STDAPI
DllRegisterServer( VOID )
{
#ifdef _WIN32_WCE
	return NO_ERROR;
#else
	DWORD dwReturnCode = NO_ERROR;

#ifndef _WIN32_WCE
	g_dwSW2TraceId = TraceRegister(EAPID);
#endif // _WIN32_WCE

	// set the default tracing levels
	SW2SetDefaultTraceLevel(EAPID);

/*
	// untill MS fixes broken EapHost GTC will remain a RASEAP method
	if (g_dwMajorVersion > 5)
		return SW2_RegisterEapHostDLL();
	else
*/
		dwReturnCode = SW2_RegisterRASEAPDLL();

#ifndef _WIN32_WCE
	TraceDeregister(g_dwSW2TraceId);
#endif // _WIN32_WCE

		return dwReturnCode;
#endif // _WIN32_WCE
}

//
// Call made by regsvr32.exe /u
//
STDAPI
DllUnregisterServer( VOID )
{
#ifdef _WIN32_WCE
	return NO_ERROR;
#else
	DWORD dwReturnCode = NO_ERROR;

#ifndef _WIN32_WCE
	g_dwSW2TraceId = TraceRegister(EAPID);
#endif // _WIN32_WCE

	/*
	// untill MS fixes broken EapHost GTC will remain a RASEAP method
	if (g_dwMajorVersion > 5)
		return SW2_UnregisterEapHostDLL();
	else
	*/
	dwReturnCode = SW2_UnregisterRASEAPDLL();

#ifndef _WIN32_WCE
	TraceDeregister(g_dwSW2TraceId);
#endif // _WIN32_WCE

	SW2RemoveTraceConfiguration(EAPID);

	return dwReturnCode;
#endif // _WIN32_WCE
}