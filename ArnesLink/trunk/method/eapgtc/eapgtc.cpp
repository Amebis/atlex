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
#include <stdlib.h>
#pragma comment(lib, "msxml6.lib")

//
// Initialize the module
//
DWORD SW2EapMethodInitialize()
{
	BOOL	bInvokeUI;
	DWORD	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInitialize()");
	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInitialize()::running on %ld - %ld", g_dwMajorVersion, g_dwMinorVersion);

	SW2_HandleError(dwReturnCode, 
				SW2_EAP_FUNCTION_Initialize,
				SW2_GTC_STATE_None,
				&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInitialize()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

//
// De-Initialize the module
//
DWORD SW2EapMethodDeInitialize()
{
	BOOL	bInvokeUI;
	DWORD	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodDeInitialize()");

	SW2_HandleError(dwReturnCode, 
				SW2_EAP_FUNCTION_DeInitialize,
				SW2_GTC_STATE_None,
				&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodDeInitialize()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

//
// Identity has been determined, begin an authentication session
//
DWORD SW2EapMethodBegin(IN DWORD	dwFlags,
						IN HANDLE	hTokenImpersonateUser,
						IN DWORD	dwSizeofConnectionData,
						IN PBYTE	pbConnectionData,
						IN DWORD	dwSizeofUserData,
						IN PBYTE	pbUserData,
						IN PWCHAR	pwcUsername,
						IN PWCHAR	pwcPassword,
						OUT PVOID	*ppWorkBuffer)
{
	BOOL				bInvokeUI;
	PSW2_WORK_BUFFER	pwb;
	PCHAR				pcResponse;
	DWORD				ccResponse;
	DWORD				dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodBegin()");

	//
	// Allocate memory for working buffer
	//
	if ((dwReturnCode = SW2AllocateMemory(sizeof(SW2_WORK_BUFFER), 
		(PVOID*)&pwb))==NO_ERROR)
	{
		memset(pwb, 0, sizeof(SW2_WORK_BUFFER));

		//
		// Allocate memory for user data
		//
		if ((dwReturnCode = SW2AllocateMemory(sizeof(SW2_USER_DATA), 
			(PVOID*)&(pwb->pUserData)))==NO_ERROR)
		{
			//
			// Copy user data provided by our interface (containing username)
			// or use username provided by MS interface
			//
			if (pbUserData && 
				(dwSizeofUserData == sizeof(SW2_USER_DATA)))
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodBegin()::using provided userdata");

				memcpy_s(pwb->pUserData, sizeof(SW2_USER_DATA),
					pbUserData, sizeof(SW2_USER_DATA));
			}
			else if(pwcUsername&&
				wcslen(pwcUsername)>0)
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodBegin()::using provided identity");

				if (((wcslen(pwcUsername)+1)*sizeof(WCHAR))<=sizeof(pwb->pUserData->pwcIdentity))
					wcscpy_s(pwb->pUserData->pwcIdentity, (wcslen(pwcUsername)+1)*sizeof(WCHAR), pwcUsername);

				if(pwcPassword&&
					wcslen(pwcPassword)>0)
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodBegin()::using provided password");

					ccResponse = (DWORD) wcslen(pwcPassword) + 1;

					if (ccResponse <= sizeof(pwb->pUserData->pbResponse))
					{
						if ((dwReturnCode = SW2AllocateMemory(ccResponse, 
															(PVOID*)&pcResponse))==NO_ERROR)
						{
							if ((WideCharToMultiByte(CP_ACP, 
													0, 
													pwcPassword, -1, 
													pcResponse, 
													ccResponse, 
													NULL, NULL)) > 0)
							{
								pwb->pUserData->cbResponse = ccResponse -1;

								memcpy_s(pwb->pUserData->pbResponse, 
										sizeof(pwb->pUserData->pbResponse),
										pcResponse, 
										pwb->pUserData->cbResponse);
							}

							SW2FreeMemory((PVOID*)&pcResponse);
						}
					}
					else
						dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
				}
			}
		}

		//
		// Return working buffer
		//
		if (dwReturnCode == NO_ERROR)			
			*ppWorkBuffer = pwb;
		else
			SW2FreeMemory((PVOID*)pwb);
	}

	SW2_HandleError(dwReturnCode, 
				SW2_EAP_FUNCTION_Begin,
				SW2_GTC_STATE_None,
				&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodBegin()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

//
// Authentication has finished (either succesfull or not), End authentication session (Cleanup)
//
DWORD SW2EapMethodEnd(IN PVOID pWorkBuffer)
{
	BOOL				bInvokeUI;
	PSW2_WORK_BUFFER	pwb;
	DWORD				dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodEnd()");

	//
	// Sanity check
	//
	if (pWorkBuffer)
	{
		pwb = (PSW2_WORK_BUFFER) pWorkBuffer;

		//
		// Free user data
		//
		if (pwb->pUserData)
			SW2FreeMemory((PVOID*)&(pwb->pUserData));

		SW2FreeMemory((PVOID*)&pwb);
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapMethodEnd()::invalid work buffer");

		dwReturnCode = ERROR_NO_DATA;
	}

	SW2_HandleError(dwReturnCode, 
				SW2_EAP_FUNCTION_End,
				SW2_GTC_STATE_None,
				&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodEnd()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

//
// Show Configuration User interface
//
DWORD  SW2EapMethodInvokeConfigUI(IN HWND		hwndParent,
								  IN DWORD		dwFlags,
								  IN DWORD		dwSizeOfConnectionDataIn,
								  IN PBYTE		pbConnectionDataIn,
								  OUT DWORD		*pdwSizeOfConnectionDataOut,
								  OUT PBYTE		*ppbConnectionDataOut)
{
	BOOL	bInvokeUI;
	DWORD	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeConfigUI()");

	MessageBox(hwndParent, L"SecureW2 EAP-GTC", L"SecureW2", MB_OK);

	SW2_HandleError(dwReturnCode, 
				SW2_EAP_FUNCTION_InvokeConfigUI,
				SW2_GTC_STATE_None,
				&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeConfigUI()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

//
// Show Interactive User interface (Balloon)
//
DWORD SW2EapMethodInvokeInteractiveUI(IN HWND		hWndParent,
									  IN DWORD		dwSizeofUIContextData,
									  IN PBYTE		pbUIContextData,
									  OUT DWORD		*pdwSizeOfDataFromInteractiveUI,
									  OUT PBYTE		*ppbDataFromInteractiveUI)
{
	BOOL				bInvokeUI;
	PSW2_USER_DATA		pUserData;
	PBYTE				pbResponse;
	DWORD				cbResponse;
	DWORD				dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeInteractiveUI()");

	//
	// Sanity check
	//
	if (pbUIContextData&&
		dwSizeofUIContextData == sizeof(SW2_USER_DATA))
	{
		pUserData = (PSW2_USER_DATA) pbUIContextData;

		//
		// If available call extension library providing the challenge and retrieve the user response
		//
		if (g_ResContext)
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeInteractiveUI()::using extension library");

			if ((dwReturnCode = g_ResContext->pSW2InvokeResponseUI(g_ResContext->pContext,
																	hWndParent,
																	pUserData->pwcIdentity,
																	pUserData->pbChallenge,
																	pUserData->cbChallenge,
																	&pbResponse,
																	&cbResponse))==NO_ERROR)
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
					L"SW2_TRACE_LEVEL_DEBUG::SW2EapMethodInvokeInteractiveUI()::extension library returned %ld bytes", cbResponse);

				if (pbResponse)
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"SW2_TRACE_LEVEL_DEBUG::SW2EapMethodInvokeInteractiveUI()::pbResponse valid");

				*pdwSizeOfDataFromInteractiveUI = cbResponse;

				//
				// Copy response to memory context returned by this function
				//
				if ((dwReturnCode = SW2AllocateMemory(*pdwSizeOfDataFromInteractiveUI, 
					(PVOID*)ppbDataFromInteractiveUI))==NO_ERROR)
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
						L"SW2_TRACE_LEVEL_DEBUG::SW2EapMethodInvokeInteractiveUI()::allocated memory");

					memcpy_s(*ppbDataFromInteractiveUI, 
							*pdwSizeOfDataFromInteractiveUI,
							pbResponse, 
							*pdwSizeOfDataFromInteractiveUI);
				}

				SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
					L"SW2_TRACE_LEVEL_DEBUG::SW2EapMethodInvokeInteractiveUI()::freeing response");

				//
				// Call extension library to free memory allocated for response
				//
				g_ResContext->pSW2FreeResponse(pbResponse);
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapMethodInvokeInteractiveUI()::extension library returned error: %ld", dwReturnCode);

				dwReturnCode = SW2ConvertExternalErrorCode(dwReturnCode);
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeInteractiveUI()::using builtin resource");

			//
			// Use builtin dialog handling
			//
			if (DialogBoxParam(g_hResource,
								MAKEINTRESOURCE(IDD_RESPONSE),
								hWndParent,
								SW2ResponseDlgProc,
								(LPARAM) pUserData))
			{
				*pdwSizeOfDataFromInteractiveUI = pUserData->cbResponse;

				//
				// Copy response to memory context returned by this function
				//
				if ((dwReturnCode = SW2AllocateMemory(*pdwSizeOfDataFromInteractiveUI, 
					(PVOID*)ppbDataFromInteractiveUI))==NO_ERROR)
				{
					memcpy_s(*ppbDataFromInteractiveUI, 
							*pdwSizeOfDataFromInteractiveUI,
							pUserData->pbResponse, 
							*pdwSizeOfDataFromInteractiveUI);
				}
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapMethodInvokeInteractiveUI()::user cancelled");

				dwReturnCode = ERROR_CANCELLED;
			}
		}
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapMethodInvokeInteractiveUI()::invalid ui context data (%ld)", dwSizeofUIContextData);

		dwReturnCode = ERROR_NO_DATA;
	}

	if (dwReturnCode != NO_ERROR)
	{
		*ppbDataFromInteractiveUI = NULL;
		*pdwSizeOfDataFromInteractiveUI = 0;
	}

	SW2_HandleError(dwReturnCode, 
				SW2_EAP_FUNCTION_InvokeInteractiveUI,
				SW2_GTC_STATE_None,
				&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeInteractiveUI()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

//
// Show Identity User interface (Balloon)
//
DWORD SW2EapMethodInvokeIdentityUI(IN HWND			hWndParent,
								   IN DWORD			dwFlags,
								   IN DWORD			dwSizeOfConnectionData,
								   IN const BYTE	*pbConnectionData,										
								   IN DWORD			dwSizeOfUserDataIn,
								   IN const BYTE	*pbUserDataIn,
								   OUT DWORD		*pdwSizeOfUserDataOut,
								   OUT PBYTE		*ppbUserDataOut,
								   OUT PWCHAR		*ppwcIdentity)
{
	BOOL				bInvokeUI;
	PSW2_USER_DATA		pUserData;
	PWCHAR				pwcIdentity;
	DWORD				cwcIdentity;
	DWORD				dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeIdentityUI()");

	//
	// Allocate memory for user data
	//
	if ((dwReturnCode = SW2AllocateMemory(sizeof(SW2_USER_DATA), 
										(PVOID*)&pUserData))==NO_ERROR)
	{
		memset(pUserData, 0, sizeof(SW2_USER_DATA));

		//
		// If available call extension library to invoke idenity user interface
		//
		if (g_ResContext)
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeIdentityUI()::using extension library");

			if ((dwReturnCode=g_ResContext->pSW2InvokeIdentityUI(g_ResContext->pContext,
																hWndParent, 
																&pwcIdentity,
																&pUserData->bSaveIdentity))==NO_ERROR)
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeIdentityUI()::returned identity: %s", pwcIdentity);

				cwcIdentity = (DWORD) wcslen(pwcIdentity)+1;

				//
				// Copy Identity over to memory context returned by this function
				//
				if (cwcIdentity <= (sizeof(pUserData->pwcIdentity)/sizeof(WCHAR)))
					wcscpy_s(pUserData->pwcIdentity, sizeof(pUserData->pwcIdentity)/sizeof(WCHAR), pwcIdentity);
				else
					dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

				if (dwReturnCode == NO_ERROR )
				{
					if ((dwReturnCode = SW2AllocateMemory(cwcIdentity*sizeof(WCHAR), 
						(PVOID*)ppwcIdentity))==NO_ERROR)
					{
						wcscpy_s(*ppwcIdentity, cwcIdentity, pwcIdentity);
					}
				}

				//
				// Call extension library to free memory allocated for response
				//
				g_ResContext->pSW2FreeIdentity(pwcIdentity);
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapMethodInvokeIdentityUI()::extension library returned error: %ld", dwReturnCode);

				dwReturnCode = SW2ConvertExternalErrorCode(dwReturnCode);
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeIdentityUI()::using builtin interface");

			//
			// Use builtin dialog
			//
			if (DialogBoxParam(g_hResource,
								MAKEINTRESOURCE(IDD_IDENTITY),
								hWndParent,
								SW2IdentityDlgProc,
								(LPARAM) pUserData))
			{
				if ((dwReturnCode = SW2AllocateMemory(((DWORD)wcslen(pUserData->pwcIdentity)+1)*sizeof(WCHAR), 
						(PVOID*)&pwcIdentity))==NO_ERROR)
				{
					wcscpy_s(pwcIdentity, (wcslen(pUserData->pwcIdentity)+1)*sizeof(WCHAR), pUserData->pwcIdentity);

					*ppwcIdentity = pwcIdentity;
				}
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapMethodInvokeIdentityUI()::user cancelled");

				dwReturnCode = ERROR_CANCELLED;
			}
		}

		if (dwReturnCode == NO_ERROR)
		{
			*ppbUserDataOut = (PBYTE) pUserData;
			*pdwSizeOfUserDataOut = sizeof(SW2_USER_DATA);
		}

		if (dwReturnCode != NO_ERROR )
			SW2FreeMemory((PVOID*)&pUserData);
	}
	else
		dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

	SW2_HandleError(dwReturnCode, 
				SW2_EAP_FUNCTION_InvokeIdentityUI,
				SW2_GTC_STATE_None,
				&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeIdentityUI()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

//
// Retrieve Identity without user interaction, return *pfInvokeUI = TRUE if
// User Interface is required
//
DWORD SW2EapMethodGetIdentity(IN DWORD		dwFlags,
							  IN DWORD		dwSizeofConnectionData,
							  IN const BYTE	*pbConnectionData,
							  IN DWORD		dwSizeofUserData,
							  IN const BYTE	*pbUserData,								
							  IN HANDLE		hTokenImpersonateUser,
							  OUT BOOL		*pfInvokeUI,
							  OUT DWORD		*pdwSizeOfUserDataOut,
							  OUT PBYTE		*ppbUserDataOut,
							  OUT PWCHAR	*ppwcIdentity)
{
	BOOL				bInvokeUI;
	SW2_CONFIG_DATA		configData;
	PSW2_USER_DATA		pUserData;
	PWCHAR				pwcIdentity;
	DWORD				cwcIdentity;
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity()");

	*pfInvokeUI = FALSE;

	//
	// Allocate memory
	//
	if ((dwReturnCode = SW2AllocateMemory(sizeof(SW2_USER_DATA), 
									(PVOID*)&pUserData))==NO_ERROR)
	{
		//
		// Use configuration data provided by EapHost/RASEAP
		//
		if (dwSizeofConnectionData==sizeof(SW2_CONFIG_DATA))
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity()::using provided configdata");

			memcpy(&configData, pbConnectionData, sizeof(SW2_CONFIG_DATA));

			cwcIdentity = (DWORD) wcslen(configData.pwcIdentity)+1;

			//
			// If available use the Identity provided by the configuration
			//
			if (cwcIdentity>0)
			{
				if (cwcIdentity <= (sizeof(pUserData->pwcIdentity)/sizeof(WCHAR)))
					wcscpy_s(pUserData->pwcIdentity, 
							sizeof(pUserData->pwcIdentity)/sizeof(WCHAR), 
							configData.pwcIdentity);
				else
					dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapMethodGetIdentity()::invalid config data (no user identity)");

				dwReturnCode = ERROR_NO_DATA;
			}
		}
		else if (dwSizeofUserData==sizeof(SW2_USER_DATA))
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity()::using provided userdata");

			//
			// User data is available, copy it over
			//
			memcpy_s(pUserData, sizeof(SW2_USER_DATA), pbUserData, dwSizeofUserData);
		}
		else
		{
			//
			// No data available
			//

			if (g_ResContext)
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity()::using extension library");

				//
				// call extension library to get User Identity (non interactive)
				//
				if ((dwReturnCode = g_ResContext->pSW2GetIdentity(g_ResContext->pContext,
																	&pwcIdentity,
																	pfInvokeUI,
																	&pUserData->bSaveIdentity))==NO_ERROR)
				{
					if (!*pfInvokeUI)
					{
						//
						// Copy Identity over to User Data struct
						//
						cwcIdentity = (DWORD) wcslen(pwcIdentity)+1;

						SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity()::extension library returned: %s", pwcIdentity);

						if (cwcIdentity > 0)
						{
							if (cwcIdentity <= (sizeof(pUserData->pwcIdentity)/sizeof(WCHAR)))
								wcscpy_s(pUserData->pwcIdentity, 
										sizeof(pUserData->pwcIdentity)/sizeof(WCHAR), 
										pwcIdentity);
							else
								dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
						}
					}
					else
						SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity()::extension library requested interactive UI");

					//
					// Call extension library to free memory allocated for Identity
					//
					g_ResContext->pSW2FreeIdentity(pwcIdentity);
					pwcIdentity = NULL;
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapMethodGetIdentity()::extension library returned error: %ld", dwReturnCode);

					dwReturnCode = SW2ConvertExternalErrorCode(dwReturnCode);
				}

			}
			else
			{
				//
				// Always call the user interface
				//
				*pfInvokeUI = TRUE;
			}
		}

		if (dwReturnCode == NO_ERROR
			&&!*pfInvokeUI)
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity()::returning identity: %s", pUserData->pwcIdentity);

			//
			// Copy Identity to memory context returned by this function
			//
			if ((dwReturnCode = SW2AllocateMemory(cwcIdentity*sizeof(WCHAR), 
				(PVOID*)ppwcIdentity))==NO_ERROR)
			{
				wcscpy_s(*ppwcIdentity, cwcIdentity, pUserData->pwcIdentity);
			}
		}

		if (dwReturnCode == NO_ERROR)
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity()::returning userdata");

			*ppbUserDataOut = (PBYTE) pUserData;
			*pdwSizeOfUserDataOut = sizeof(SW2_USER_DATA);
		}
		else
			SW2FreeMemory((PVOID*)&pUserData);
	}

	SW2_HandleError(dwReturnCode, 
				SW2_EAP_FUNCTION_GetIdentity,
				SW2_GTC_STATE_None,
				&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

//
// Process an EAP packet
//
DWORD SW2EapMethodProcess(IN PVOID				pWorkBuffer,										
						  IN PSW2EAPPACKET		pReceivePacket,
						  IN DWORD				cbSendPacket,
						  OUT PSW2EAPPACKET		pSendPacket,
						  OUT SW2EAPOUTPUT		*pEapOutput)	
{
	BOOL				bInvokeUI;
	PSW2_WORK_BUFFER	pwb;
	DWORD				dwSizeOfReceivePacket;
	DWORD				dwEapDataLength;
	PBYTE				pbResponse;
	DWORD				cbResponse;
	BOOL				fInvokeUI;
	DWORD				dwReturnExternalCode = NO_ERROR;
	DWORD				dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess()");

	pwb = (PSW2_WORK_BUFFER) pWorkBuffer;

	// set default action
	pEapOutput->eapAction = SW2EAPACTION_None;

	//
	// Act according to GTC Eap State
	//
	switch(pwb->AuthState)
	{
		case SW2_GTC_STATE_None:

			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::SW2_GTC_STATE_None");

		case SW2_GTC_STATE_Initial:

			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::SW2_GTC_STATE_Initial");

		case SW2_GTC_STATE_Challenge:

			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::SW2_GTC_STATE_Challenge");

			if (pReceivePacket)
			{
				//
				// Parse recieved EAP GTC packet
				//
				dwSizeOfReceivePacket = SW2_WireToHostFormat16(pReceivePacket->Length);

				pwb->bReceivePacketId = pReceivePacket->Id;
				dwEapDataLength = dwSizeOfReceivePacket-5;

				//
				// copy EAP GTC challenge to struct and show user interface
				//
				if ((dwEapDataLength)<=(sizeof(pwb->pUserData->pbChallenge)))
				{
					pwb->pUserData->cbChallenge = dwEapDataLength;

					memset(pwb->pUserData->pbChallenge,
							0,
							sizeof(pwb->pUserData->pbChallenge));

					memcpy_s(pwb->pUserData->pbChallenge, 
							sizeof(pwb->pUserData->pbChallenge),
							&(pReceivePacket->Data[1]),
							dwEapDataLength);

					if (pwb->pUserData->cbResponse > 0)
					{
						pSendPacket->Code		= 2;
						pSendPacket->Id			= pwb->bReceivePacketId;
						pSendPacket->Data[0]	= EAPTYPE;

						//
						// Set Length of EAP Packet
						//
						SW2_HostToWireFormat16(pwb->pUserData->cbResponse+5, 
												pSendPacket->Length);

						memcpy(&(pSendPacket->Data[1]), 
							pwb->pUserData->pbResponse, 
							pwb->pUserData->cbResponse);

						//
						// Send packet
						//
						pEapOutput->eapAction = SW2EAPACTION_Send;

						//
						// Keep going untill we receive an access accept ;)
						//
						pwb->AuthState = SW2_GTC_STATE_Challenge;
					}
					else if (g_ResContext)
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::using extension library" );

						//
						// Call extension library and retrieve response from user to
						// the challenge
						//
						if ((dwReturnExternalCode = g_ResContext->pSW2GetResponse(g_ResContext->pContext,
																		pwb->pUserData->pwcIdentity,
																		pwb->pUserData->pbChallenge,
																		pwb->pUserData->cbChallenge,
																		&fInvokeUI,
																		&pbResponse,
																		&cbResponse))==NO_ERROR)
						{
							//
							// Check to see if responder requires UI
							//
							if (fInvokeUI)
							{
								SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::extension library requested interactive UI" );

								pwb->AuthState = SW2_GTC_STATE_InteractiveUI;

								//
								// Fire up user interface to show challenge and ask for response
								//
								pEapOutput->eapAction = SW2EAPACTION_InvokeUI;
							}
							else
							{
									pSendPacket->Code		= 2;
									pSendPacket->Id			= pwb->bReceivePacketId;
									pSendPacket->Data[0]	= EAPTYPE;

									//
									// Set Length of EAP Packet
									//
									SW2_HostToWireFormat16(cbResponse+5, 
															pSendPacket->Length);

									memcpy(&(pSendPacket->Data[1]), 
										pbResponse, 
										cbResponse);

									//
									// Send packet
									//
									pEapOutput->eapAction = SW2EAPACTION_Send;

									//
									// We can receive more challenges
									//
									pwb->AuthState = SW2_GTC_STATE_Challenge;
							}

							//
							// Call extension library to free Memory allocated for response
							//
							g_ResContext->pSW2FreeResponse(pbResponse);
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapMethodProcess::extension library returned error: %ld", dwReturnExternalCode);

							dwReturnCode = SW2ConvertExternalErrorCode(dwReturnExternalCode);
						}
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::using builtin resource" );

						//
						// Fire up user interface to show challenge and ask for response
						//
						pwb->AuthState = SW2_GTC_STATE_InteractiveUI;

						pEapOutput->eapAction = SW2EAPACTION_InvokeUI;
					}
				}
				else
					dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
			}
			else
			{
				// ignore the data
				dwReturnCode = ERROR_NO_DATA;

				pEapOutput->eapAction = SW2EAPACTION_None;
			}

		break;

		//
		// Process information provided by Interactive UI (if any)
		//
		case SW2_GTC_STATE_InteractiveUI:

			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::SW2_GTC_STATE_InteractiveUI");

			pSendPacket->Code		= 2;
			pSendPacket->Id			= pwb->bReceivePacketId;
			pSendPacket->Data[0]	= EAPTYPE;

			//
			// Set Length of EAP Packet
			//
			SW2_HostToWireFormat16(pwb->pUserData->cbResponse+5, 
									pSendPacket->Length);

			memcpy(&(pSendPacket->Data[1]), 
				pwb->pUserData->pbResponse, 
				pwb->pUserData->cbResponse);

			//
			// Send packet
			//
			pEapOutput->eapAction = SW2EAPACTION_Send;

			//
			// Keep going untill we receive an access accept ;)
			//
			pwb->AuthState = SW2_GTC_STATE_Challenge;

		break;

		//
		// Unknown state (should not occur)
		//
		default:

			SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapMethodProcess::Invalid EAPSTATE: %d", pwb->AuthState);

			pEapOutput->eapAction = SW2EAPACTION_None;

			dwReturnCode = ERROR_INVALID_STATE;

		break;
	}


	SW2_HandleError(dwReturnCode, 
				SW2_EAP_FUNCTION_GetIdentity,
				pwb ? pwb->AuthState : SW2_GTC_STATE_None,
				&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

//
// Before the Interactive UI is called, this function is called in which the
// context data for the Interactive UI is returned
//
DWORD SW2EapMethodGetUIContext(IN PVOID pWorkBuffer,
							   IN DWORD *pdwSizeOfUIContextData,
							   IN PBYTE	*ppbUIContextData)
{
	BOOL				bInvokeUI;
	DWORD				dwReturnCode;
	PSW2_WORK_BUFFER	pwb;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetUIContext()");

	pwb = (PSW2_WORK_BUFFER) pWorkBuffer;

	//
	// Context data is User Data struct
	//
	*pdwSizeOfUIContextData = sizeof(SW2_USER_DATA);
    *ppbUIContextData = (PBYTE) pwb->pUserData;

	SW2_HandleError(dwReturnCode, 
				SW2_EAP_FUNCTION_GetUIContext,
				pwb ? pwb->AuthState : SW2_GTC_STATE_None,
				&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetUIContext()::returning %ld", dwReturnCode);

	return dwReturnCode;
}

//
// After the Interactive UI is called, this function is called in which the
// context data for the Interactive UI is provided
//
DWORD SW2EapMethodSetUIContext(IN PVOID pWorkBuffer,
							   IN DWORD dwSizeOfUIContextData,
							   IN PBYTE	pbUIContextData)
{
	BOOL				bInvokeUI;
	PSW2_WORK_BUFFER	pwb;
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodSetUIContext()");

	pwb = (PSW2_WORK_BUFFER) pWorkBuffer;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"SW2_TRACE_LEVEL_DEBUG::SW2EapMethodSetUIContext()::dwSizeOfUIContextData: %ld", dwSizeOfUIContextData);

	memset(pwb->pUserData->pbResponse, 0, sizeof(pwb->pUserData->pbResponse));	
			
	if (pbUIContextData &&
		dwSizeOfUIContextData > 0)
	{
		pwb = (PSW2_WORK_BUFFER) pWorkBuffer;

		//
		// Copy data returned from Interactive UI (User Response to Challenge)
		//
		if (dwSizeOfUIContextData<=sizeof(pwb->pUserData->pbResponse))
		{
			pwb->pUserData->cbResponse = dwSizeOfUIContextData;

			memset(pwb->pUserData->pbResponse, 0, sizeof(pwb->pUserData->pbResponse));
					
			memcpy_s(pwb->pUserData->pbResponse,
					sizeof(pwb->pUserData->pbResponse),
					pbUIContextData,
					dwSizeOfUIContextData);
		}
	}
	else
	{
		// NULL response
		pwb->pUserData->cbResponse = 0;
	}

	SW2_HandleError(dwReturnCode, 
				SW2_EAP_FUNCTION_SetUIContext,
				pwb ? pwb->AuthState : SW2_GTC_STATE_None,
				&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodSetUIContext()::returning %ld", dwReturnCode);

	return dwReturnCode;
}

//
// Free memory allocated by this module
//
DWORD SW2EapMethodFreeMemory(IN PVOID* ppMemory)
{
	BOOL	bInvokeUI;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodFreeMemory()");

	dwReturnCode = SW2FreeMemory(ppMemory);

	SW2_HandleError(dwReturnCode, 
				SW2_EAP_FUNCTION_FreeMemory,
				SW2_GTC_STATE_None,
				&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodFreeMemory()::returning %ld", dwReturnCode );

	return dwReturnCode;
}

//
// Return the authentication result. In this function the user data and/or
// configuration data is also returned to the upper layer to be stored
//
DWORD SW2EapMethodGetResult(IN PVOID				pWorkBuffer,
							IN SW2_EAP_REASON		eapReason,
							OUT	BOOL				*pfResult,
							OUT BOOL				*pfSaveUserData,
							OUT	DWORD				*pdwSizeofUserData,
							OUT PBYTE				*ppbUserData,
							OUT BOOL				*pfSaveConnectionData,
							OUT	DWORD				*pdwSizeofConnectionData,
							OUT PBYTE				*ppbConnectionData,
							OUT	DWORD				*pdwNumberOfAttributes,
							OUT PSW2EAPATTRIBUTE	*pAttributes)
{
	BOOL				bInvokeUI;
	PSW2_WORK_BUFFER	pwb;
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetResult()");

	pwb = (PSW2_WORK_BUFFER) pWorkBuffer;

	*pfResult = FALSE;

	if (eapReason==SW2_EAP_REASON_Success)
	{
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetResult()::received SUCCESS");
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetResult()::state: %ld", pwb->AuthState);

		//
		// Authentication was succesfull :)
		//
		if (pwb->AuthState == SW2_GTC_STATE_Challenge)
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetResult()::client done");

			*pdwNumberOfAttributes = 0;

			*pAttributes = NULL;

			// we set result to true as we are happy with the ACCESS-ACCEPT
			*pfResult = TRUE;
		}
	}

	// inform extension library of success/failure
	if (g_ResContext)
	{
		if (!*pfResult && eapReason == SW2_EAP_REASON_Success)
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetResult()::informing extension library of client FAILURE");

			// we did recieve a ACCESS-ACCEPT, but we failed on the client side
			g_ResContext->pSW2HandleResult(g_ResContext->pContext,
											SW2_EAP_REASON_Failure);
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetResult()::informing extension library of %ld", eapReason);

			g_ResContext->pSW2HandleResult(g_ResContext->pContext,
											eapReason);
		}
	}

	SW2_HandleError(dwReturnCode, 
				SW2_EAP_FUNCTION_GetResult,
				SW2_GTC_STATE_None,
				&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetResult()::returning %ld", dwReturnCode);

	return dwReturnCode;
}

#ifndef _WIN32_WCE
//
// Convert an XML structure to a byte blob, this blob is uses in
// the API function calls during authentication
//
DWORD SW2EapMethodConfigXml2Blob(IN DWORD				dwFlags,
								 IN IXMLDOMDocument2	*pXMLConfigDoc,
								 OUT PBYTE				*ppbConfigOut,
								 OUT DWORD				*pdwSizeOfConfigOut)
{
    DWORD				dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodConfigXml2Blob()");

	*ppbConfigOut = NULL;
	*pdwSizeOfConfigOut = 0;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodConfigXml2Blob()::returning: %ld", dwReturnCode);

    return dwReturnCode;
}


//
// Convert a configuration blob to an XML structure
//
DWORD SW2EapMethodConfigBlob2Xml(IN DWORD				dwFlags,
								 IN const BYTE			*pbConfig,
								 IN DWORD				dwSizeOfConfig,
								 OUT IXMLDOMDocument2	**ppXMLConfigDoc)
{
	HRESULT				hr;
	DWORD				dwReturnCode = NO_ERROR;
	IXMLDOMDocument2	*pXmlDoc = NULL;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapmethodConfigBlob2Xml()");

	//
	// Create a default XML struct (XML is not supported yet)
	//
	if (SUCCEEDED((hr = CoCreateInstance(CLSID_DOMDocument60,
								  NULL,
								  CLSCTX_INPROC_SERVER,
								  IID_IXMLDOMDocument2,
								  reinterpret_cast<void**>(&pXmlDoc)
								  ))))
	{
		if (SUCCEEDED((hr = pXmlDoc->put_async(VARIANT_FALSE))))
		{
			BSTR xml = L"<Config xmlns=\"http://www.microsoft.com/provisioning/EapHostConfig\">\
							<eap-gtc xmlns=\"http://schemas.securew2.com/eapconfig/eap-ttls/v0 /\">\
						</Config>";

			VARIANT_BOOL isSuccess = VARIANT_FALSE;
			
			if (SUCCEEDED((hr = pXmlDoc->loadXML(xml, &isSuccess))))
			{
				//
				// Set the output parameters.
				// 
				*ppXMLConfigDoc = pXmlDoc;

				pXmlDoc = NULL;
			}
			else
			{
				dwReturnCode = HRESULT_CODE(hr);
				SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::loadXML failed::error: %ld", dwReturnCode);
			}
		}
		else
		{
			dwReturnCode = HRESULT_CODE(hr);		
			SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::put_async failed::error: %ld", dwReturnCode);
		}

		if(pXmlDoc)
			pXmlDoc->Release();
	}
	else	
	{
		dwReturnCode = HRESULT_CODE(hr);
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::Unable to CoCreate XMLDOMDocument2::error: %ld", dwReturnCode);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapmethodConfigBlob2Xml()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

DWORD SW2EapMethodCredentialsXml2Blob(IN DWORD					dwFlags,
										IN IXMLDOMDocument2*	pXMLCredentialsDoc,
										IN 	const BYTE*			pbConfigIn,
										IN DWORD				dwSizeOfConfigIn,
										OUT	BYTE				** ppbCredentialsOut,
										OUT DWORD*				pdwSizeOfCredentialsOut)
{
	DWORD	dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodCredentialsXml2Blob()");

	dwReturnCode = ERROR_NOT_SUPPORTED;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodCredentialsXml2Blob()::returning %ld", dwReturnCode);

	return dwReturnCode;
}

DWORD	
SW2EapMethodQueryCredentialInputFields(IN  HANDLE							hUserToken,
									   IN  DWORD							dwFlags,
									   IN  DWORD							dwSizeofConnectionData,
									   IN  PBYTE							pbConnectionData,
									   OUT	EAP_CONFIG_INPUT_FIELD_ARRAY	*pEapConfigInputFieldArray)
{
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodQueryCredentialInputFields");
	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodQueryCredentialInputFields()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

DWORD	
SW2EapMethodQueryUserBlobFromCredentialInputFields(IN  HANDLE						hUserToken,
												   IN  DWORD						dwFlags,
												   IN  DWORD						dwEapConnDataSize,
												   IN  PBYTE						pbEapConnData,
												   IN  CONST EAP_CONFIG_INPUT_FIELD_ARRAY	*pEapConfigInputFieldArray,
												   OUT DWORD						*pdwUserBlobSize,
												   OUT PBYTE						*ppbUserBlob)
{
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodQueryUserBlobFromCredentialInputFields");
	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodQueryUserBlobFromCredentialInputFields()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

#endif // _WIN32_WCE
