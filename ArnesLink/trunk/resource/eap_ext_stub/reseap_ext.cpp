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
// initialize interface, called once during DLL startup (DLLMain::DLL_PROCESS_ATTACH)
//
PVOID APIENTRY SW2Initialize(IN INT iEapType)
{
	PSW2_USER_DATA pUserData = NULL;

	g_dwSW2TraceId = TraceRegister(L"SW2_EXTERNAL_STUB");

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2Initialize:: %ld"), iEapType);

	if (iEapType != EAP_TYPE_TTLS &&
		iEapType != EAP_TYPE_GTC &&
		iEapType != EAP_TYPE_PEAP)
    {
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2Initialize::Incorrect EAP_TYPE: %ld"), iEapType);

		SetLastError(SW2_ERROR_NOT_SUPPORTED);

		return NULL;
    }

	if (SW2AllocateMemory(sizeof(SW2_USER_DATA), (PVOID*)&pUserData)!=NO_ERROR)
		pUserData = NULL;
	else
		pUserData->iEapType = iEapType;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2Initialize::returning"));

	TraceDeregister(g_dwSW2TraceId);

	return pUserData;
}

//
// uninitialize interface, called once during DLL shutdown (DLLMain::DLL_PROCESS_DETACH)
//
DWORD APIENTRY SW2Uninitialize(IN PVOID pContext)
{
	PSW2_USER_DATA	pUserData;
	DWORD			dwReturnCode;

	g_dwSW2TraceId = TraceRegister(L"SW2_EXTERNAL_STUB");

	dwReturnCode = NO_ERROR;

	pUserData = (PSW2_USER_DATA) pContext;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2Uninitialize:: %ld"), pUserData->iEapType);

	dwReturnCode = SW2FreeMemory(&pContext);

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2Uninitialize::returning: %ld"), dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// retrieve identity without user interface. 
// If user interface is required, pfInvokeUI should be set to TRUE
//
DWORD APIENTRY SW2GetIdentity(IN PVOID		pContext,
							  OUT PWCHAR	*ppwcIdentity,
							  OUT BOOL		*bInvokeUI,
							  OUT BOOL		*bSaveIdentity)
{
	PSW2_USER_DATA	pUserData;
	DWORD			dwReturnCode;

	g_dwSW2TraceId = TraceRegister(L"SW2_EXTERNAL_STUB");

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2GetIdentity"));

	if (pContext != NULL)
	{
		pUserData = (PSW2_USER_DATA) pContext;

		if (pUserData->iEapType == EAP_TYPE_GTC)
		{
			*ppwcIdentity = NULL;

			*bInvokeUI = TRUE;

			*bSaveIdentity = FALSE;
		}
		else
			dwReturnCode = SW2_ERROR_NOT_SUPPORTED;
	}
	else
		dwReturnCode = SW2_ERROR_NO_DATA;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2GetIdentity::returning: %ld"), dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}


//
// retrieve identity using user interface
//
DWORD APIENTRY SW2InvokeIdentityUI(IN PVOID		pContext, 
								   IN HWND		hWndParent,
								   OUT PWCHAR	*ppwcIdentity,
								   OUT BOOL		*bSaveIdentity)
{
	PSW2_USER_DATA	pUserData;
	PWCHAR			pwcIdentity;
	DWORD			dwReturnCode;

	g_dwSW2TraceId = TraceRegister(L"SW2_EXTERNAL_STUB");

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2InvokeIdentityUI"));

	if (pContext != NULL)
	{
		pUserData = (PSW2_USER_DATA) pContext;

		memset(pUserData->pwcIdentity, 0, sizeof(pUserData->pwcIdentity));
		memset(pUserData->pwcChallenge, 0, sizeof(pUserData->pwcChallenge));
		memset(pUserData->pwcResponse, 0, sizeof(pUserData->pwcResponse));

		if (pUserData->iEapType == EAP_TYPE_GTC)
		{
			*bSaveIdentity = FALSE;

			if (DialogBoxParam(g_hInstance,
								MAKEINTRESOURCE(IDD_IDENTITY),
								hWndParent,
								SW2IdentityDlgProc,
								(LPARAM) pUserData))
			{
				if ((dwReturnCode = SW2AllocateMemory((DWORD)(wcslen(pUserData->pwcIdentity)+1)*sizeof(WCHAR), 
									(PVOID*)&pwcIdentity))==NO_ERROR)
				{
					wcscpy_s(pwcIdentity, 
						(wcslen(pUserData->pwcIdentity)+1)*sizeof(WCHAR), 
						pUserData->pwcIdentity);

					*ppwcIdentity = pwcIdentity;
				}
			}
			else
				dwReturnCode = SW2_ERROR_CANCELLED;
		}
		else
			dwReturnCode = SW2_ERROR_NOT_SUPPORTED;
	}
	else
		dwReturnCode = SW2_ERROR_NO_DATA;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2InvokeIdentityUI::returning: %ld"), dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// free identity
//
DWORD APIENTRY SW2FreeIdentity(IN PWCHAR pwcIdentity)
{
	DWORD dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(L"SW2_EXTERNAL_STUB");

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2FreeIdentity"));

	dwReturnCode = SW2FreeMemory((PVOID*)&pwcIdentity);

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2FreeIdentity::returning: %ld"), dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// retrieve response without user interface. 
// If user interface is required, pfInvokeUI should be set to TRUE
//
DWORD APIENTRY SW2GetResponse(IN PVOID		pContext,
							  IN PWCHAR		pwcIdentity,
							  IN PBYTE		pbChallenge,
							  IN DWORD		cbChallenge,
							  OUT BOOL		*bInvokeUI,
							  OUT PBYTE		*ppbResponse,
							  OUT DWORD		*pcbResponse)
{
	PSW2_USER_DATA	pUserData;
	DWORD			dwReturnCode;

	g_dwSW2TraceId = TraceRegister(L"SW2_EXTERNAL_STUB");

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2GetResponse"));

	if (pContext != NULL)
	{
		pUserData = (PSW2_USER_DATA) pContext;

		if (pUserData->iEapType == EAP_TYPE_GTC)
		{
			*pcbResponse = 0;

			*ppbResponse = NULL;

			*bInvokeUI = TRUE;
		}
		else
			dwReturnCode = SW2_ERROR_NOT_SUPPORTED;
	}
	else
		dwReturnCode = SW2_ERROR_NO_DATA;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2GetResponse::returning: %ld"), dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// retrieve response using user interface
//
// cbChallenge contains the length of the pbChallenge
//
// the response should be returned using ppbResponse, the 
// length of the ppbResponse should be returned in pcbResponse
//
DWORD APIENTRY SW2InvokeResponseUI(IN PVOID		pContext,
								   IN HWND		hWndParent,
								   IN PWCHAR	pwcIdentity,
								   IN PBYTE		pbChallenge,
								   IN DWORD		cbChallenge,
								   OUT PBYTE	*ppbResponse,
								   OUT DWORD	*pcbResponse)
{
	PSW2_USER_DATA	pUserData;
	DWORD			dwReturnCode;

	g_dwSW2TraceId = TraceRegister(L"SW2_EXTERNAL_STUB");

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2InvokeResponseUI"));

	if (pContext != NULL)
	{
		pUserData = (PSW2_USER_DATA) pContext;

		memset(pUserData->pwcIdentity, 0, sizeof(pUserData->pwcIdentity));
		memset(pUserData->pwcChallenge, 0, sizeof(pUserData->pwcChallenge));
		memset(pUserData->pwcResponse, 0, sizeof(pUserData->pwcResponse));
		pUserData->bSaveUserCredentials = FALSE;

		if (pUserData->iEapType == EAP_TYPE_GTC)
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
				TEXT("SW2InvokeResponseUI::received challenge, %ld bytes"), cbChallenge);
			SW2Dump( SW2_TRACE_LEVEL_DEBUG, pbChallenge, cbChallenge );

			PCHAR	pcChallenge;
			DWORD	ccChallenge;
			PWCHAR	pwcChallenge;

			ccChallenge = cbChallenge + 1;

			if ((dwReturnCode = SW2AllocateMemory(ccChallenge, (PVOID*)&pcChallenge))==NO_ERROR)
			{
				memset( pcChallenge, 0, ccChallenge );

				memcpy_s(pcChallenge, 
						ccChallenge,
						pbChallenge, 
						ccChallenge);

				if ((dwReturnCode = SW2AllocateMemory(ccChallenge*sizeof(WCHAR), 
													(PVOID*)&pwcChallenge))==NO_ERROR)
				{
					if (MultiByteToWideChar( CP_ACP, 0, 
											pcChallenge, -1, 
											pwcChallenge, ccChallenge ) > 0 )
					{
						wcscpy_s(pUserData->pwcChallenge, 
								sizeof(pUserData->pwcChallenge),
								pwcChallenge);

						if ((wcslen(pwcIdentity)+1)*sizeof(WCHAR)<=sizeof(pUserData->pwcIdentity))
							wcscpy_s(pUserData->pwcIdentity, (wcslen(pwcIdentity)+1)*sizeof(WCHAR), pwcIdentity);

						if ((wcslen(pwcChallenge)+1)*sizeof(WCHAR)<=sizeof(pUserData->pwcChallenge))
							wcscpy_s(pUserData->pwcChallenge, (wcslen(pwcChallenge)+1)*sizeof(WCHAR), pwcChallenge);

						if (DialogBoxParam(g_hInstance,
									MAKEINTRESOURCE(IDD_RESPONSE),
									hWndParent,
									SW2ResponseDlgProc,
									(LPARAM) pUserData))
						{
							PCHAR	pcResponse;
							DWORD	ccResponse;

							ccResponse = (DWORD)  wcslen(pUserData->pwcResponse)+1;

							//
							// Convert WCHAR Response to PCHAR
							//
							if ((dwReturnCode = SW2AllocateMemory(ccResponse, 
												(PVOID*)&pcResponse))==NO_ERROR)
							{
								if ((WideCharToMultiByte(CP_ACP, 
														0, 
														pUserData->pwcResponse, -1, 
														pcResponse, ccResponse, 
														NULL, NULL)) > 0)
								{
									*ppbResponse = (PBYTE) pcResponse;
									*pcbResponse = ccResponse -1;
								}
							}
						}
						else
							dwReturnCode = SW2_ERROR_CANCELLED;
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT("SW2_TRACE_LEVEL_ERROR::SW2InvokeResponseUI::converting pcResponse to pwcResponse FAILED: %ld"), GetLastError());

						dwReturnCode = SW2_ERROR_INTERNAL;
					}

					SW2FreeMemory((PVOID*)&pwcChallenge);
				}

				SW2FreeMemory((PVOID*)&pcChallenge);
			}
		}
		else
			dwReturnCode = SW2_ERROR_NOT_SUPPORTED;
	}
	else
		dwReturnCode = SW2_ERROR_NO_DATA;

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT("SW2_TRACE_LEVEL_INFO::SW2InvokeResponseUI::returning: %ld"), dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// free reponse
//
DWORD APIENTRY SW2FreeResponse(IN PBYTE pbResponse)
{
	DWORD dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(L"SW2_EXTERNAL_STUB");

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2FreeResponse"));

	dwReturnCode = SW2FreeMemory((PVOID*)&pbResponse);

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT("SW2_TRACE_LEVEL_INFO::SW2FreeResponse::returning: %ld"), dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// retrieve response without user interface. 
// If user interface is required, pfInvokeUI should be set to TRUE
// If secureW2 should save the credentials for single logon, bSaveCredentials should be set to TRUE
//
DWORD APIENTRY SW2GetCredentials(IN PVOID		pContext,
								 OUT PWCHAR		*ppwcIdentity,
								 OUT PWCHAR		*ppwcPassword,
								 OUT BOOL		*bInvokeUI,
								 OUT BOOL		*bSaveCredentials)
{
	PSW2_USER_DATA	pUserData;
	DWORD			dwReturnCode;

	g_dwSW2TraceId = TraceRegister(L"SW2_EXTERNAL_STUB");

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2GetCredentials"));

	if (pContext != NULL)
	{

		pUserData = (PSW2_USER_DATA) pContext;

		if (pUserData->iEapType == EAP_TYPE_TTLS)
		{
			*ppwcIdentity = NULL;
			*ppwcPassword = NULL;

			*bInvokeUI = TRUE;

			*bSaveCredentials = FALSE;
		}
		else
			dwReturnCode = SW2_ERROR_NOT_SUPPORTED;
	}
	else
		dwReturnCode = SW2_ERROR_NO_DATA;

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT("SW2_TRACE_LEVEL_INFO::SW2GetCredentials::returning: %ld"), dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}


//
// retrieve response with user interface. 
// If secureW2 should save the credentials for single logon, bSaveCredentials should be set to TRUE
//
DWORD APIENTRY SW2InvokeCredentialsUI(IN PVOID		pContext, 
									IN HWND			hWndParent,
									OUT PWCHAR		*ppwcIdentity,
									OUT PWCHAR		*ppwcPassword,
									OUT BOOL		*bSaveCredentials)
{
	PSW2_USER_DATA	pUserData;
	PWCHAR			pwcIdentity;
	PWCHAR			pwcPassword;
	DWORD			dwReturnCode;

	g_dwSW2TraceId = TraceRegister(L"SW2_EXTERNAL_STUB");

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2InvokeCredentialsUI"));

	if (pContext == NULL)
		return SW2_ERROR_NO_DATA;

	dwReturnCode = NO_ERROR;

	pUserData = (PSW2_USER_DATA) pContext;

	if (pUserData->iEapType == EAP_TYPE_TTLS)
	{
		pUserData = (PSW2_USER_DATA) pContext;

		dwReturnCode = NO_ERROR;

		bSaveCredentials = FALSE;

		memset(pUserData->pwcIdentity, 0, sizeof(pUserData->pwcIdentity));
		memset(pUserData->pwcPassword, 0, sizeof(pUserData->pwcPassword));

		if (DialogBoxParam(g_hInstance,
							MAKEINTRESOURCE(IDD_CREDENTIALS),
							hWndParent,
							SW2CredentialsDlgProc,
							(LPARAM) pUserData))
		{
			if ((dwReturnCode = SW2AllocateMemory(((DWORD)wcslen(pUserData->pwcIdentity)+1)*sizeof(WCHAR), 
								(PVOID*)&pwcIdentity))==NO_ERROR)
			{
				wcscpy_s(pwcIdentity, 
					(wcslen(pUserData->pwcIdentity)+1)*sizeof(WCHAR), 
					pUserData->pwcIdentity);

				*ppwcIdentity = pwcIdentity;

				if ((dwReturnCode = SW2AllocateMemory((DWORD)(wcslen(pUserData->pwcPassword)+1)*sizeof(WCHAR), 
									(PVOID*)&pwcPassword))==NO_ERROR)
				{
					wcscpy_s(pwcPassword, 
						(wcslen(pUserData->pwcPassword)+1)*sizeof(WCHAR), 
						pUserData->pwcPassword);

					*ppwcPassword = pwcPassword;
				}

				if (dwReturnCode != NO_ERROR)
				{
					SW2FreeMemory((PVOID*)&pwcIdentity);
					*ppwcIdentity = NULL;
				}
			}
		}
		else
			dwReturnCode = SW2_ERROR_CANCELLED;
	}
	else
		dwReturnCode = SW2_ERROR_NOT_SUPPORTED;

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT("SW2_TRACE_LEVEL_INFO::SW2InvokeCredentialsUI::returning: %ld"), dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// free identity
//
DWORD APIENTRY SW2FreeCredentials(IN PWCHAR pwcIdentity,
								  IN PWCHAR pwcPassword)
{
	DWORD dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(L"SW2_EXTERNAL_STUB");
		
	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2FreeCredentials"));

	if ((dwReturnCode = SW2FreeMemory((PVOID*)&pwcIdentity)) != NO_ERROR)
	{
		SW2FreeMemory((PVOID*)&pwcPassword);
	}
	else
	{
		dwReturnCode = SW2FreeMemory((PVOID*)&pwcPassword);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT("SW2_TRACE_LEVEL_INFO::SW2FreeCredentials::returning: %ld"), dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// Handle authentication result
//
DWORD APIENTRY SW2HandleResult (IN PVOID			pContext, 
								IN SW2_EAP_REASON	eapReason)
{
	g_dwSW2TraceId = TraceRegister(L"SW2_EXTERNAL_STUB");

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT("SW2_TRACE_LEVEL_INFO::SW2HandleResult::SW2_EAP_REASON: %ld"), eapReason);

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT("SW2_TRACE_LEVEL_INFO::SW2HandleResult::returning: %ld"), SW2_ERROR_NO_ERROR);

	TraceDeregister(g_dwSW2TraceId);

	return SW2_ERROR_NO_ERROR;
}


//
// Handle error without user interaction
// If user interface is required, bInvokeUI should be set to TRUE
//
DWORD APIENTRY SW2HandleError(IN PVOID			pContext, 
							IN SW2_AUTH_STATE	AuthState, 
							IN SW2_ERROR		Error,
							OUT					BOOL *pbInvokeUI)
{
	g_dwSW2TraceId = TraceRegister(L"SW2_EXTERNAL_STUB");

	SW2Trace( SW2_TRACE_LEVEL_ERROR, 
		TEXT("SW2_TRACE_LEVEL_ERROR::SW2HandleError::SW2_AUTH_STATE: %ld, SW2_ERROR: %ld"), 
		AuthState,
		Error);

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT("SW2_TRACE_LEVEL_INFO::SW2HandleError::returning: %ld"), SW2_ERROR_NO_ERROR);

	*pbInvokeUI =  FALSE;

	TraceDeregister(g_dwSW2TraceId);

	return SW2_ERROR_NO_ERROR;
}

//
// Handle error with user interaction
//
DWORD APIENTRY SW2HandleInteractiveError(IN PVOID			pContext, 
										IN HWND				hWndParent,
										SW2_AUTH_STATE		AuthState, 
										SW2_ERROR			Error)
{
	g_dwSW2TraceId = TraceRegister(L"SW2_EXTERNAL_STUB");

	SW2Trace( SW2_TRACE_LEVEL_ERROR, 
		TEXT("SW2_TRACE_LEVEL_ERROR::SW2HandleInteractiveError::SW2_AUTH_STATE: %ld, SW2_ERROR: %ld"), 
		AuthState,
		Error);

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2HandleInteractiveError::returning: %ld"), SW2_ERROR_NOT_SUPPORTED);

	TraceDeregister(g_dwSW2TraceId);

	return SW2_ERROR_NO_ERROR;
}