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

#ifndef WINVER				// Allow use of features specific to Windows XP or later.
#define WINVER 0x0501		// Change this to the appropriate value to target other versions of Windows.
#endif

#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0501	// Change this to the appropriate value to target other versions of Windows.
#endif						

#ifndef _WIN32_WINDOWS		// Allow use of features specific to Windows 98 or later.
#define _WIN32_WINDOWS 0x0410 // Change this to the appropriate value to target Windows Me or later.
#endif

#ifndef _WIN32_IE			// Allow use of features specific to IE 6.0 or later.
#define _WIN32_IE 0x0600	// Change this to the appropriate value to target other versions of IE.
#endif

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers

#include <windows.h>
#include <stdlib.h>
#include <lmcons.h>

#include "..\..\lib\common\common.h"

#ifdef _WIN32_WCE
#include "resource_CE.h"
#else
#include "resource.h"
#endif // _WIN32_WCE

extern DWORD		g_dwSW2TraceId;
extern HANDLE		g_localHeap;
extern HINSTANCE	g_hInstance;
// OS version information
extern DWORD		g_dwMajorVersion;
extern DWORD		g_dwMinorVersion;

// resource user data
typedef struct _SW2_USER_DATA
{
	INT		iEapType;
	WCHAR	pwcIdentity[UNLEN];
	WCHAR	pwcPassword[PWLEN];
	WCHAR	pwcChallenge[UNLEN];
	WCHAR	pwcResponse[PWLEN];
	BOOL	bSaveUserCredentials;

} SW2_USER_DATA, *PSW2_USER_DATA;

// resource functions
INT_PTR CALLBACK SW2IdentityDlgProc(IN  HWND    hWndParent,
									IN  UINT    unMsg,
									IN  WPARAM  wParam,
									IN  LPARAM  lParam);

INT_PTR CALLBACK SW2ResponseDlgProc(IN  HWND    hWndParent,
									IN  UINT    unMsg,
									IN  WPARAM  wParam,
									IN  LPARAM  lParam);


INT_PTR CALLBACK SW2CredentialsDlgProc(IN  HWND    hWndParent,
										IN  UINT    unMsg,
										IN  WPARAM  wParam,
										IN  LPARAM  lParam);