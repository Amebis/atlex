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

#include "..\..\lib\common\common.h"

#ifdef _WIN32_WCE
#include "..\..\resource\eap_default\resource_CE.h"
#else
#include "..\..\resource\eap_default\resource.h"
#endif

#include "..\..\resource\include\reseap.h"

//
// GTC eap state
//
typedef enum _SW2_GTC_STATE
{
	SW2_GTC_STATE_None,
	SW2_GTC_STATE_Initial,
    SW2_GTC_STATE_Challenge,
	SW2_GTC_STATE_InteractiveUI,
    SW2_GTC_STATE_Done

} SW2_GTC_STATE;

//
// GTC user data
//
typedef struct _SW2_USER_DATA
{
	WCHAR	pwcIdentity[UNLEN];

	BYTE	pbChallenge[UNLEN];
	DWORD	cbChallenge;
	
	BYTE	pbResponse[PWLEN];
	DWORD	cbResponse;

	BOOL	bSaveIdentity;

} SW2_USER_DATA, *PSW2_USER_DATA;

//
// GTC config data
//
typedef struct _SW2_CONFIG_DATA
{
	WCHAR	pwcIdentity[UNLEN];

} SW2_CONFIG_DATA, *PSW2_CONFIG_DATA;

//
// GTC work buffer
//
typedef struct _SW2_WORK_BUFFER
{
    SW2_GTC_STATE		AuthState;

	BYTE				bReceivePacketId;

    PSW2_CONFIG_DATA	pConfigData;

    PSW2_USER_DATA		pUserData;

}	SW2_WORK_BUFFER, *PSW2_WORK_BUFFER;

// ERROR
VOID SW2_HandleError(IN DWORD dwError, 
					IN SW2_EAP_FUNCTION EapFunction,
					IN SW2_GTC_STATE	GTCState,
					IN BOOL				*pbInvokeUI);

// GTC resource functions
INT_PTR CALLBACK SW2IdentityDlgProc(IN  HWND    hWndParent,
									IN  UINT    unMsg,
									IN  WPARAM  wParam,
									IN  LPARAM  lParam);

INT_PTR CALLBACK SW2ResponseDlgProc(IN  HWND    hWndParent,
									IN  UINT    unMsg,
									IN  WPARAM  wParam,
									IN  LPARAM  lParam);