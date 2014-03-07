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

HINSTANCE	g_hResource = NULL;
HINSTANCE	g_hLanguage = NULL;
#ifndef _WIN32_WCE
DWORD		g_dwSW2TraceId = INVALID_TRACEID;
#endif // _WIN32_WCE
PWCHAR		pwcIdentity = NULL;
PWCHAR		pwcResponse = NULL;

//
// initialize GTC responder, called once during DLL startup (DLLMain::DLL_PROCESS_ATTACH)
//
PVOID APIENTRY SW2Initialize()
{
	return (PVOID) malloc(10);
}

//
// initialize GTC responder, called once during DLL shutdown (DLLMain::DLL_PROCESS_DETACH)
//
VOID APIENTRY SW2Uninitialize(IN PVOID pContext)
{
	free(pContext);
}

//
// retrieve GTC identity without user interface. 
// If user interface is required, pfInvokeUI should be set to TRUE
//
DWORD APIENTRY SW2GetIdentity(IN PVOID pContext,
							  OUT BOOL *pfInvokeUI,
							  OUT PWCHAR *ppwcIdentity)
{
	DWORD dwReturnCode;

	dwReturnCode = NO_ERROR;

	pwcIdentity = NULL;

	*pfInvokeUI = TRUE;

	return dwReturnCode;
}

//
// retrieve GTC identity using user interface
//
DWORD APIENTRY SW2InvokeIdentityUI(IN PVOID		pContext, 
								   IN HWND		hWndParent,
								   OUT PWCHAR	*ppwcIdentity)
{
	DWORD			dwReturnCode;
	SW2_USER_DATA	userData;

	dwReturnCode = NO_ERROR;

	memset(&userData, 0, sizeof(SW2_USER_DATA));

	if (DialogBoxParam(g_hResource,
						MAKEINTRESOURCE(IDD_IDENTITY),
						hWndParent,
						SW2IdentityDlgProc,
						(LPARAM) &userData))
	{
		if ((pwcIdentity = (PWCHAR) malloc((wcslen(userData.pwcIdentity)+1)*sizeof(WCHAR))))
		{
			wcscpy_s(pwcIdentity, (wcslen(userData.pwcIdentity)+1)*sizeof(WCHAR), userData.pwcIdentity);

			*ppwcIdentity = pwcIdentity;
		}
	}
	else
		dwReturnCode = ERROR_CANCELLED;

	return dwReturnCode;
}

//
// free GTC identity
//
VOID APIENTRY SW2FreeIdentity(IN PVOID pContext)
{
	if (pwcIdentity)
		free(pwcIdentity);
}

//
// retrieve GTC response without user interface. 
// If user interface is required, pfInvokeUI should be set to TRUE
//
DWORD APIENTRY SW2GetResponse(IN PVOID		pContext,
							  IN PWCHAR		pwcIdentity,
							  IN PWCHAR		pwcChallenge,
							  OUT BOOL		*pfInvokeUI,
							  OUT PWCHAR	*ppwcResponse)
{
	DWORD dwReturnCode;

	dwReturnCode = NO_ERROR;

	*pfInvokeUI = TRUE;

	pwcResponse = NULL;

	return dwReturnCode;
}

//
// retrieve GTC response using user interface
//
DWORD APIENTRY SW2InvokeResponseUI(IN PVOID		pContext,
								   IN HWND		hWndParent,
								   IN PWCHAR	pwcIdentity,
								   IN PWCHAR	pwcChallenge,
								   OUT PWCHAR	*ppwcResponse)
{
	SW2_USER_DATA	userData;
	DWORD			dwReturnCode;

	dwReturnCode = NO_ERROR;

	memset(&userData, 0, sizeof(SW2_USER_DATA));

	if ((wcslen(pwcIdentity)+1)*sizeof(WCHAR)<=sizeof(userData.pwcIdentity))
		wcscpy_s(userData.pwcIdentity, (wcslen(pwcIdentity)+1)*sizeof(WCHAR), pwcIdentity);

	if ((wcslen(pwcChallenge)+1)*sizeof(WCHAR)<=sizeof(userData.pwcChallenge))
		wcscpy_s(userData.pwcChallenge, (wcslen(pwcChallenge)+1)*sizeof(WCHAR), pwcChallenge);

	if (DialogBoxParam(g_hResource,
				MAKEINTRESOURCE(IDD_RESPONSE),
				hWndParent,
				SW2ResponseDlgProc,
				(LPARAM) &userData))
	{
		if ((pwcResponse = (PWCHAR) malloc((wcslen(userData.pwcResponse)+1)*sizeof(WCHAR))))
		{
			wcscpy_s(pwcResponse, (wcslen(userData.pwcResponse)+1)*sizeof(WCHAR), userData.pwcResponse);

			*ppwcResponse = pwcResponse;
		}
	}
	else
		dwReturnCode = ERROR_CANCELLED;

	return dwReturnCode;
}

//
// free GTC reponse
//
VOID APIENTRY SW2FreeResponse(IN PVOID pContext)
{
	free(pwcResponse);
}

BOOL WINAPI DllMain(IN HANDLE	hInstance,
					IN DWORD	dwReason,
					IN LPVOID	lpVoid )
{
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

    if (dwReason == DLL_PROCESS_ATTACH)
	{
		if ((g_hResource = LoadLibrary(L"sw2_gtc_res.dll")))
		{
			if (!(g_hLanguage = LoadLibrary(L"sw2_lang.dll")))
			{
				dwReturnCode = ERROR_DLL_INIT_FAILED;
			}
		}
		else
			dwReturnCode = ERROR_DLL_INIT_FAILED;
	}
    else if (dwReason == DLL_PROCESS_DETACH)
	{
		if (g_hResource)
			FreeLibrary(g_hResource);
	}

    return TRUE;
}