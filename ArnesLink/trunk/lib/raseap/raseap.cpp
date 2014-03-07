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
#include <stdio.h>
#include <stdlib.h>

//
// Return struct containing function pointers
//
DWORD WINAPI RasEapGetInfo(IN  DWORD			dwEapTypeId,
						   OUT PPPP_EAP_INFO	pEapInfo )
{
	PPP_EAP_INFO	EapInfo;

#ifndef _WIN32_WCE
	g_dwSW2TraceId = TraceRegister(EAPID);
#endif // _WIN32_WCE

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::RasEapGetInfo"));

    if (dwEapTypeId != EAPTYPE)
    {
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			TEXT("SW2_TRACE_LEVEL_ERROR::RasEapGetInfo::Incorrect EAP_TYPE: %ld"), dwEapTypeId);

		return ERROR_NOT_SUPPORTED;
    }

    EapInfo.dwEapTypeId       = dwEapTypeId;
	EapInfo.RasEapInitialize  = RasEapInitialize; 
	EapInfo.RasEapBegin       = RasEapBegin;
	EapInfo.RasEapEnd         = RasEapEnd;
	EapInfo.RasEapMakeMessage = RasEapMakeMessage;

	EapInfo.dwSizeInBytes = sizeof(PPP_EAP_INFO);

	*pEapInfo = EapInfo;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::RasEapGetInfo::returning"));

#ifndef _WIN32_WCE
	TraceDeregister(g_dwSW2TraceId);
#endif // _WIN32_WCE

    return NO_ERROR;
}

//
// Initialize RASEAP module
//
DWORD WINAPI RasEapInitialize(BOOL fInitialize)
{
	DWORD		dwReturnCode;

	dwReturnCode = NO_ERROR;

#ifndef _WIN32_WCE
	g_dwSW2TraceId = TraceRegister(EAPID);
#endif // _WIN32_WCE
	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::RasEapInitialize"));

	if (fInitialize)
		dwReturnCode = SW2EapMethodInitialize();
	else
		dwReturnCode = SW2EapMethodDeInitialize();

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT("SW2_TRACE_LEVEL_INFO::RasEapInitialize::returning %ld"), dwReturnCode);

#ifndef _WIN32_WCE
	TraceDeregister(g_dwSW2TraceId);
#endif // _WIN32_WCE

	return dwReturnCode;
}

//
// Return user identity
//
DWORD WINAPI RasEapGetIdentity(IN DWORD				dwEapTypeId,
								IN HWND				hWndParent,
								IN DWORD			dwFlags,
								IN const WCHAR *	pwcPhonebook,
								IN const WCHAR *	pwcEntry,
								IN BYTE *			pbConnectionData,
								IN DWORD			dwSizeOfConnectionData,
								IN BYTE *			pbUserDataIn,
								IN DWORD			dwSizeOfUserDataIn,
								OUT PBYTE *			ppbUserDataOut,
								OUT DWORD *			pdwSizeOfUserDataOut,
								OUT WCHAR **		ppwcIdentity)
{
	DWORD		dwReturnCode;
	BOOL		fInvokeUI;

	dwReturnCode = NO_ERROR;

#ifndef _WIN32_WCE
	g_dwSW2TraceId = TraceRegister(EAPID);
#endif // _WIN32_WCE

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::RasEapGetIdentity"));

	*ppwcIdentity = NULL;
	*ppbUserDataOut = NULL;
	*pdwSizeOfUserDataOut = 0;

	//
	// This is a mapping of the RASEAP Identity functionality on to EapHost
	//
	// First try and retrieve user identity without user interaction
	//
	if ((dwReturnCode = SW2EapMethodGetIdentity(dwFlags,
												dwSizeOfConnectionData,
												pbConnectionData,
												dwSizeOfUserDataIn,
												pbUserDataIn,
												NULL,
												&fInvokeUI,
												pdwSizeOfUserDataOut,
												ppbUserDataOut,
												ppwcIdentity))==NO_ERROR)
	{
		//
		// Check to see if interactive user interface is required
		//
		if (fInvokeUI)
		{
			//
			// Free any info that might have been allocated
			//
			if (*ppbUserDataOut && 
				(*pdwSizeOfUserDataOut > 0))
			{
				SW2EapMethodFreeMemory((PVOID*)ppbUserDataOut);
				*ppbUserDataOut = NULL;
				*pdwSizeOfUserDataOut = 0;
			}

			//
			// Check for prohibited use interaction
			//
			if (dwFlags & RAS_EAP_FLAG_NON_INTERACTIVE)
			{
				dwReturnCode = ERROR_INTERACTIVE_MODE;
			}
			else
			{
				//
				// We can show a user interface, now get user identity WITH user interaction
				//
				dwReturnCode = SW2EapMethodInvokeIdentityUI(hWndParent,
															dwFlags,
															dwSizeOfConnectionData,
															pbConnectionData,
															dwSizeOfUserDataIn,
															pbUserDataIn,
															pdwSizeOfUserDataOut,
															ppbUserDataOut,
															ppwcIdentity);
			}
		}
	}

	//
	// Again, a workaround for bug in Vista, if their is no user data the Identity 
	// sent to the RADIUS server will be ""
	//
	if (dwReturnCode == NO_ERROR)
	{
		if (!*ppbUserDataOut)
		{
			//
			// need to return "fake" data or RASEAP chokes...
			//
			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT("SW2_TRACE_LEVEL_INFO::RasEapGetIdentity::no user data provided by eap method, returning fake userdata"));

			SW2AllocateMemory(10,(PVOID*)ppbUserDataOut);
			*pdwSizeOfUserDataOut = 10;
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT("SW2_TRACE_LEVEL_INFO::RasEapGetIdentity::returning %ld of userdata"), *pdwSizeOfUserDataOut);
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::RasEapGetIdentity::returning: %ld"), dwReturnCode);

#ifndef _WIN32_WCE
	TraceDeregister(g_dwSW2TraceId);
#endif //_WIN32_WCE

	return dwReturnCode;
}

//
// Call after identity has been determined to begin authentication session
//
DWORD WINAPI RasEapBegin(OUT PVOID			*ppWorkBuf,
						 IN PPP_EAP_INPUT	*pInput)
{
	DWORD dwReturnCode;

	dwReturnCode = NO_ERROR;

#ifndef _WIN32_WCE
	g_dwSW2TraceId = TraceRegister(EAPID);
#endif // _WIN32_WCE

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::RasEapBegin"));

	dwReturnCode = SW2EapMethodBegin(pInput->fFlags,
									pInput->hTokenImpersonateUser,
									pInput->dwSizeOfConnectionData,
									pInput->pConnectionData,
									pInput->dwSizeOfUserData,
									pInput->pUserData,
									pInput->pwszIdentity,
									pInput->pwszPassword,
									ppWorkBuf);

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::RasEapBegin::returning %ld"), dwReturnCode);

#ifndef _WIN32_WCE
	TraceDeregister(g_dwSW2TraceId);
#endif // _WIN32_WCE
    return dwReturnCode;
}

//
// Call after authentication to end authentication session (Cleanup)
//
DWORD WINAPI RasEapEnd(IN PVOID pWorkBuf)
{
	DWORD dwReturnCode;

	dwReturnCode = NO_ERROR;

#ifndef _WIN32_WCE
	g_dwSW2TraceId = TraceRegister(EAPID);
#endif // _WIN32_WCE

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::RasEapEnd"));

	dwReturnCode = SW2EapMethodEnd(pWorkBuf);

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::RasEapEnd::returning %ld"), dwReturnCode);

#ifndef _WIN32_WCE
	TraceDeregister(g_dwSW2TraceId);
#endif // _WIN32_WCE

    return dwReturnCode;
}

//
// Free memory allocated by this module
//
DWORD WINAPI RasEapFreeMemory(PBYTE pbMemory)
{
	DWORD dwReturnCode;

	dwReturnCode = NO_ERROR;

#ifndef _WIN32_WCE
	g_dwSW2TraceId = TraceRegister(EAPID);
#endif // _WIN32_WCE

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::RasEapFreeMemory"));

	dwReturnCode = SW2EapMethodFreeMemory((PVOID*)&pbMemory);

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::RasEapFreeMemory::returning %ld"), dwReturnCode);

#ifndef _WIN32_WCE
	TraceDeregister(g_dwSW2TraceId);
#endif // _WIN32_WCE

    return dwReturnCode;
}

//
// Show configuration interface
//
DWORD WINAPI RasEapInvokeConfigUI(IN  DWORD     dwEapTypeId,
								  IN  HWND      hWndParent,						
								  IN  DWORD     dwFlags,
								  IN  PBYTE		pbConnectionDataIn,
								  IN  DWORD     dwSizeOfConnectionDataIn,
								  OUT PBYTE		*ppbConnectionDataOut,
								  OUT DWORD		*pdwSizeOfConnectionDataOut)
{
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

#ifndef _WIN32_WCE
	g_dwSW2TraceId = TraceRegister(EAPID);
#endif // _WIN32_WCE

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::RasEapInvokeConfigUI"));

	dwReturnCode = SW2EapMethodInvokeConfigUI(hWndParent,
											dwFlags,
											dwSizeOfConnectionDataIn,
											pbConnectionDataIn,
											pdwSizeOfConnectionDataOut,
											ppbConnectionDataOut);

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::RasEapInvokeConfigUI::returning %ld"), dwReturnCode);

#ifndef _WIN32_WCE
	TraceDeregister(g_dwSW2TraceId);
#endif // _WIN32_WCE

    return dwReturnCode;
}

//
// Show interactive user interface (Balloon)
//
DWORD WINAPI RasEapInvokeInteractiveUI(IN DWORD	dwEapTypeId,
									   IN  HWND		hWndParent,
									   IN  PBYTE	pbUIContextData,
									   IN  DWORD	dwSizeofUIContextData,
									   OUT PBYTE*	ppbDataFromInteractiveUI,
									   OUT DWORD*	pdwSizeOfDataFromInteractiveUI)
{
	DWORD dwReturnCode;

	dwReturnCode = NO_ERROR;

#ifndef _WIN32_WCE
	g_dwSW2TraceId = TraceRegister(EAPID);
#endif // _WIN32_WCE

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::RasEapInvokeInteractiveUI"));

	//
	// Again, a workaround for Vista, handle passed by Vista looses focus...
	//
	dwReturnCode = SW2EapMethodInvokeInteractiveUI(GetForegroundWindow(),
												dwSizeofUIContextData,
												pbUIContextData,
												pdwSizeOfDataFromInteractiveUI,
												ppbDataFromInteractiveUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::RasEapInvokeInteractiveUI::returning %ld"), dwReturnCode);

#ifndef _WIN32_WCE
	TraceDeregister(g_dwSW2TraceId);
#endif // _WIN32_WCE

    return dwReturnCode;
}

//
// Process EAP packet
//
DWORD WINAPI RasEapMakeMessage(IN  VOID*			pWorkBuf,
							   IN  PPP_EAP_PACKET*	pReceivePacket,
							   OUT PPP_EAP_PACKET*	pSendPacket,
							   IN  DWORD			cbSendPacket,
							   OUT PPP_EAP_OUTPUT*	pEapOutput,
							   IN  PPP_EAP_INPUT*	pEapInput)
{
	SW2_EAP_REASON		eapReason;
	BOOL				fResult;
	DWORD				dwNumberOfAttributes;
	SW2EAPOUTPUT		eapOutput;
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

#ifndef _WIN32_WCE
	g_dwSW2TraceId = TraceRegister(EAPID);
#endif // _WIN32_WCE

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::RasEapMakeMessage"));

	//
	// Reset output
	//
	memset(&eapOutput, 0, sizeof(eapOutput));

	//
	// Received information from interactive ui, set this using EapHost style functionality
	//
	if (pEapInput->fDataReceivedFromInteractiveUI)
	{
		dwReturnCode = SW2EapMethodSetUIContext(pWorkBuf,
												pEapInput->dwSizeOfDataFromInteractiveUI,
												pEapInput->pDataFromInteractiveUI);
	}

	if (dwReturnCode == NO_ERROR )
	{
		//
		// We recieved a packet, if it is a success or failure act according
		// to new EapHost style functionality
		//
		if (pReceivePacket &&
			(pReceivePacket->Code == EAPCODE_Success || pReceivePacket->Code == EAPCODE_Failure))
		{
			if (pReceivePacket->Code == EAPCODE_Success)
				eapReason = SW2_EAP_REASON_Success;
			else
				eapReason = SW2_EAP_REASON_Failure;

			dwReturnCode = SW2EapMethodGetResult(pWorkBuf,
												eapReason,
												&fResult,
												&(pEapOutput->fSaveUserData),
												&(pEapOutput->dwSizeOfUserData),
												&(pEapOutput->pUserData),
												&(pEapOutput->fSaveConnectionData),
												&(pEapOutput->dwSizeOfConnectionData),
												&(pEapOutput->pConnectionData),
												&dwNumberOfAttributes,
												(PSW2EAPATTRIBUTE*)&(pEapOutput->pUserAttributes));

			pEapOutput->Action = EAPACTION_Done;
		}
		else
		{
			//
			// Process packet, then act accordingly
			//
			if ((dwReturnCode = SW2EapMethodProcess(pWorkBuf,
													(PSW2EAPPACKET) pReceivePacket,
													cbSendPacket,
													(PSW2EAPPACKET) pSendPacket,
													&eapOutput))==NO_ERROR)
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
					TEXT("SW2_TRACE_LEVEL_DEBUG::RasEapMakeMessage::eapOutput.eapAction: %ld"), 
					eapOutput.eapAction);

				switch (eapOutput.eapAction)
				{
					//
					// RASEAP only
					//
					case SW2EAPACTION_Done:

						pEapOutput->Action = EAPACTION_Done;

					break;

					case SW2EAPACTION_Discard:

						// FIXME: maybe we have to return INVALID PACKET for RASEAP?

					case SW2EAPACTION_None:

						pEapOutput->Action = EAPACTION_NoAction;

					break;

					case SW2EAPACTION_Send:

						pEapOutput->Action = EAPACTION_Send;

					break;

					case SW2EAPACTION_InvokeUI:

						//
						// Invoke Interactive UI
						//
						pEapOutput->fInvokeInteractiveUI = TRUE;

						SW2EapMethodGetUIContext(pWorkBuf,
							&(pEapOutput->dwSizeOfUIContextData),
							&(pEapOutput->pUIContextData));

						pEapOutput->Action = EAPACTION_NoAction;

					break;

					default:

						dwReturnCode = ERROR_NOT_SUPPORTED;

					break;
				}
			}
		}
	}


	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::RasEapMakeMessage::returning %ld"), dwReturnCode);

#ifndef _WIN32_WCE
	TraceDeregister(g_dwSW2TraceId);
#endif // _WIN32_WCE

    return dwReturnCode;
}

#ifndef _WIN32_WCE
//
// Register/Install the dll RASEAP style
//
DWORD SW2_RegisterRASEAPDLL()
{
	HKEY	hRasEapKey;
	HKEY	hEapMethodKey;
	WCHAR	pwcTemp[MAX_PATH];
	DWORD	dwReturnCode;
	DWORD	dwDisp = 0;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_RegisterRASEAPDLL()");

	if ((dwReturnCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
										L"System\\CurrentControlSet\\Services\\RasMan\\PPP\\EAP", 
										0, 
										KEY_ALL_ACCESS, 
										&hRasEapKey )) == NO_ERROR)
	{
		swprintf_s(pwcTemp, sizeof(pwcTemp)/sizeof(WCHAR), 
			L"%d", EAPTYPE);

		if ((dwReturnCode = RegCreateKeyExW(hRasEapKey, 
											pwcTemp, 
											0, NULL, 
											REG_OPTION_NON_VOLATILE,
											KEY_ALL_ACCESS, 
											NULL, 
											&hEapMethodKey, 
											&dwDisp))==NO_ERROR)
		{
			dwReturnCode = RegSetValueExW(hEapMethodKey,
										L"FriendlyName", 
										0,
										REG_SZ,
										(PBYTE)EAPFRIENDLYID,
										(DWORD)(wcslen(EAPFRIENDLYID)+1)*sizeof(WCHAR));

			if (dwReturnCode == NO_ERROR)
			{
				if (GetCurrentDirectory((sizeof(pwcTemp)-1-sizeof(EAPDLLNAME)-1)/sizeof(WCHAR), pwcTemp)>=0)
				{
					if (((wcslen(pwcTemp)+1+wcslen(EAPDLLNAME)+1)*sizeof(WCHAR))<=sizeof(pwcTemp))
					{
						wcscat_s(pwcTemp, sizeof(pwcTemp), L"\\");
						wcscat_s(pwcTemp, sizeof(pwcTemp), EAPDLLNAME);
					}
					else
						dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
				}
				else
					dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
			}

			if (dwReturnCode == NO_ERROR)
			{
				dwReturnCode = RegSetValueExW(hEapMethodKey,
											L"ConfigUIPath", 
											0,
											REG_SZ,
											(LPBYTE)pwcTemp,
											(DWORD)(wcslen(pwcTemp)+1)*sizeof(WCHAR));
			}

			if (dwReturnCode == NO_ERROR)
			{
				dwReturnCode = RegSetValueExW(hEapMethodKey,
												L"IdentityPath", 
												0,
												REG_SZ,
												(LPBYTE)pwcTemp,
												(DWORD)(wcslen(pwcTemp)+1)*sizeof(WCHAR));
			}

			if (dwReturnCode == NO_ERROR)
			{
				dwReturnCode = RegSetValueExW(hEapMethodKey,
												L"InteractiveUIPath", 
												0,
												REG_SZ,
												(LPBYTE)pwcTemp,
												(DWORD)(wcslen(pwcTemp)+1)*sizeof(WCHAR));
			}

			if (dwReturnCode == NO_ERROR)
			{
				dwReturnCode = RegSetValueExW(hEapMethodKey,
												L"Path", 
												0,
												REG_SZ,
												(LPBYTE)pwcTemp,
												(DWORD)(wcslen(pwcTemp)+1)*sizeof(WCHAR));
			}

			if (dwReturnCode == NO_ERROR)
			{
				dwReturnCode = RegSetValueExW(hEapMethodKey,
											L"InvokeUsernameDialog",
											0,
											REG_DWORD,
											(LPBYTE) &EAPUSERNAMEDLG, 
											sizeof(DWORD));
			}

			if (dwReturnCode == NO_ERROR)
			{
				dwReturnCode = RegSetValueExW(hEapMethodKey,
											L"InvokePasswordDialog",
											0,
											REG_DWORD,
											(LPBYTE) &EAPPWDDLG, 
											sizeof(DWORD));
			}

			if (dwReturnCode == NO_ERROR)
			{
				dwReturnCode = RegSetValueExW(hEapMethodKey,
											L"MPPEEncryptionSupported",
											0,
											REG_DWORD,
											(LPBYTE) &EAPMPPESUPPORTED, 
											sizeof(DWORD));
			}

			if (dwReturnCode == NO_ERROR)
			{
				dwReturnCode = RegSetValueExW(hEapMethodKey,
											L"StandaloneSupported",
											0,
											REG_DWORD,
											(LPBYTE) &EAPSTANDALONESUPPORTED, 
											sizeof(DWORD));
			}

			RegCloseKey(hEapMethodKey);
		}

		RegCloseKey(hRasEapKey);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_RegisterRASEAPDLL()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}
#endif // _WIN32_WCE

#ifndef _WIN32_WCE
//
// Unregister/De-Install the dll RASEAP style
//
DWORD SW2_UnregisterRASEAPDLL()
{
	WCHAR	pwcTemp[MAX_PATH];
	WCHAR	pwcTemp2[MAX_PATH];
	HKEY	hRasEapKey;
	HKEY	hEapMethodKey;
	DWORD	cwcTemp2;
	DWORD	dwType;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_UnregisterRASEAPDLL()");

	if ((dwReturnCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
										L"System\\CurrentControlSet\\Services\\RasMan\\PPP\\EAP", 
										0, 
										KEY_ALL_ACCESS, 
										&hRasEapKey )) == NO_ERROR)
	{
		memset(pwcTemp, 0, sizeof(pwcTemp));

		swprintf_s(pwcTemp,sizeof(pwcTemp)/sizeof(WCHAR),L"%d", EAPTYPE);

		if ((dwReturnCode = RegOpenKeyEx(hRasEapKey, 
											pwcTemp, 
											0, 
											KEY_ALL_ACCESS, 
											&hEapMethodKey )) == NO_ERROR)
		{
			cwcTemp2 = sizeof( pwcTemp2 );

			memset( pwcTemp2, 0, sizeof( pwcTemp2 ) );

			// read 
			if (RegQueryValueEx( hEapMethodKey,
								L"Path",
								0,
								&dwType,
								(PBYTE) pwcTemp2,
								&cwcTemp2 ) == ERROR_SUCCESS )
			{
				if (wcsstr(pwcTemp2, L"sw2_") == NULL)
					dwReturnCode = ERROR_INVALID_DATA;
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_UnregisterRASEAPDLL::RegQueryValueEx(Path) FAILED: %ld" ), 
					dwReturnCode );

				dwReturnCode = ERROR_CANTOPEN;
			}

			RegCloseKey(hEapMethodKey);
		}

		if (dwReturnCode == NO_ERROR)
		{
			dwReturnCode = RegDeleteKey(hRasEapKey, 
										pwcTemp);
		}
		else if (dwReturnCode == ERROR_INVALID_DATA)
		{
			SW2Trace( SW2_TRACE_LEVEL_WARNING, 
				TEXT( "SW2_TRACE_LEVEL_WARNING::SW2_UnregisterRASEAPDLL::Registred method is not a SecureW2 Eap Method" ) );

			// not a SecureW2 method, so discard error
			dwReturnCode = NO_ERROR;
		}

		RegCloseKey(hRasEapKey);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_UnregisterRASEAPDLL()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}
#endif // _WIN32_WCE