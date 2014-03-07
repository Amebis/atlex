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
// Return structure containing pointer to EapHost functions
//
DWORD WINAPI EapPeerGetInfo(
         IN EAP_TYPE* pEapType, 
         OUT EAP_PEER_METHOD_ROUTINES* pEapPeerMethodRoutines, 
         OUT EAP_ERROR** ppEapError
         )
{
    DWORD dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerGetInfo()");

    //Sanity Check
    if ((!pEapType) || (!pEapPeerMethodRoutines) || (!ppEapError))
    {
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::EapPeerGetInfo()::One/Some of the parameters is/are NULL");
        dwReturnCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		// Verify if pEapType passed by EapHost correctly matches the EapType of this DLL.
		if (pEapType->type != EAPTYPE)
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::EapPeerGetInfo()::Input Eap Type Info does not match the supported Eap Type");
			dwReturnCode = ERROR_NOT_SUPPORTED;
		}
		else
		{
			// Verify if pEapType passed by EapHost correctly matches the EapType of this DLL.
			ZeroMemory(pEapPeerMethodRoutines, sizeof(EAP_PEER_METHOD_ROUTINES));

			pEapPeerMethodRoutines->dwVersion = VERSION;
		    
			pEapPeerMethodRoutines->EapPeerInitialize = SW2EapPeerInitialize;
			pEapPeerMethodRoutines->EapPeerShutdown = SW2EapPeerShutdown;

			pEapPeerMethodRoutines->EapPeerBeginSession = SW2EapPeerBeginSession;
			pEapPeerMethodRoutines->EapPeerEndSession = SW2EapPeerEndSession;

			pEapPeerMethodRoutines->EapPeerGetIdentity = SW2EapPeerGetIdentity;

			pEapPeerMethodRoutines->EapPeerSetCredentials = NULL;
		    
			pEapPeerMethodRoutines->EapPeerProcessRequestPacket = SW2EapPeerProcessRequestPacket;
			pEapPeerMethodRoutines->EapPeerGetResponsePacket = SW2EapPeerGetResponsePacket;

			pEapPeerMethodRoutines->EapPeerGetResult = SW2EapPeerGetResult;

			pEapPeerMethodRoutines->EapPeerGetUIContext = SW2EapPeerGetUIContext;
			pEapPeerMethodRoutines->EapPeerSetUIContext = SW2EapPeerSetUIContext;

			pEapPeerMethodRoutines->EapPeerGetResponseAttributes = SW2EapPeerGetResponseAttributes;
			pEapPeerMethodRoutines->EapPeerSetResponseAttributes = SW2EapPeerSetResponseAttributes;
		}
	}
     
	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}
	
	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerGetInfo()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// Free memory allocated by this module
//
VOID WINAPI EapPeerFreeMemory(IN PVOID pbMemory)
{
	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerFreeMemory()");

	SW2EapMethodFreeMemory(&pbMemory);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerFreeMemory:: returning");

	TraceDeregister(g_dwSW2TraceId);
}

//
// Free EapError memory allocated by this module
//
VOID WINAPI EapPeerFreeErrorMemory(IN EAP_ERROR* pEapError)
{
	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerFreeErrorMemory()");

	//Sanity Check
    if (!pEapError)
    {
        // Nothing to do; exit cleanly.
		SW2Trace( SW2_TRACE_LEVEL_WARNING, 
			L"SW2_TRACE_LEVEL_WARNING::EapPeerFreeErrorMemory()::Input Parameter is NULL, returning.");
    }
	else
	{
		//
		//If RootCauseString in EapError, free it.
		//
		if (pEapError->pRootCauseString)
			SW2FreeMemory((PVOID*)&pEapError->pRootCauseString);

		//
		//If error string in EapError, free it.
		//
		if (pEapError->pRepairString)
			SW2FreeMemory((PVOID*)&pEapError->pRepairString);
		//
		//Finally, free the EapError structure.
		//
		SW2FreeMemory((PVOID*)&pEapError);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerFreeErrorMemory()::returning");

	TraceDeregister(g_dwSW2TraceId);

    return;
}

//
// Show Configuration interface
//
DWORD WINAPI EapPeerInvokeConfigUI(
         IN EAP_METHOD_TYPE*	pEapMethodType,
         IN HWND				hWndParent,
         IN DWORD				dwFlags,
         IN DWORD				dwSizeOfConnectionDataIn,
         IN PBYTE				pbConnectionDataIn,
         OUT DWORD				*pdwSizeOfConnectionDataOut,
         OUT PBYTE				*ppbConnectionDataOut,
         OUT EAP_ERROR			**ppEapError
         )
{
    DWORD	dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerInvokeConfigUI()");

    if (!pEapMethodType || !pdwSizeOfConnectionDataOut || !ppbConnectionDataOut || !ppEapError)
    {
        SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::EapPeerInvokeConfigUI()::One/Some of the parameters is/are NULL");
        dwReturnCode = ERROR_INVALID_PARAMETER;
    }
	else
	{
		if ((pEapMethodType->eapType.type != EAPTYPE) ||  
			 (pEapMethodType->dwAuthorId != AUTHOR_ID))
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				L"SW2_TRACE_LEVEL_ERROR::EapPeerInvokeConfigUI()::Input Eap Type Info does not match the supported Eap Type");
			dwReturnCode = ERROR_NOT_SUPPORTED;
		}
		else
		{
			dwReturnCode = SW2EapMethodInvokeConfigUI(hWndParent,
													dwFlags,
													dwSizeOfConnectionDataIn,
													pbConnectionDataIn,
													pdwSizeOfConnectionDataOut,
													ppbConnectionDataOut);
		}
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		L"SW2_TRACE_LEVEL_INFO::EapPeerInvokeConfigUI()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

    return dwReturnCode;
}

//
// Show Interactive User interface (Balloon)
//
DWORD WINAPI EapPeerInvokeInteractiveUI(
         IN EAP_METHOD_TYPE*	pEapMethodType,
         IN HWND				hWndParent,
         IN DWORD				dwSizeofUIContextData,
         IN BYTE*				pbUIContextData,
         OUT DWORD*				pdwSizeOfDataFromInteractiveUI,
         OUT BYTE**				ppbDataFromInteractiveUI,
         OUT EAP_ERROR**		ppEapError
         )
{
    DWORD	dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerInvokeInteractiveUI()");

	if (!pEapMethodType || 
		!pbUIContextData || 
		!ppbDataFromInteractiveUI || 
		!pdwSizeOfDataFromInteractiveUI || 
		!ppEapError)
    {
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::EapPeerInvokeInteractiveUI()::One/Some of the parameters is/are NULL");
		dwReturnCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		if ((pEapMethodType->eapType.type != EAPTYPE) ||  
			 (pEapMethodType->dwAuthorId != AUTHOR_ID))
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				L"SW2_TRACE_LEVEL_ERROR::EapPeerInvokeInteractiveUI()::Input Eap Type Info does not match the supported Eap Type");
			dwReturnCode = ERROR_NOT_SUPPORTED;
			// Need to fill the EapError.
		}
		else
		{
			// call eap method specific function
			dwReturnCode = SW2EapMethodInvokeInteractiveUI(hWndParent,
														dwSizeofUIContextData,
														pbUIContextData,
														pdwSizeOfDataFromInteractiveUI,
														ppbDataFromInteractiveUI);
		}
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		L"SW2_TRACE_LEVEL_INFO::EapPeerInvokeInteractiveUI()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// Show Identity User interface (Balloon)
//
DWORD WINAPI EapPeerInvokeIdentityUI(
         IN EAP_METHOD_TYPE		*pEapMethodType,
         IN DWORD				dwFlags,
         IN HWND				hWndParent,
         IN DWORD				dwSizeOfConnectionData,
         IN const BYTE			*pbConnectionData,
         IN DWORD				dwSizeOfUserDataIn,
         IN const BYTE			*pbUserDataIn,
         OUT DWORD				*pdwSizeOfUserDataOut,
         OUT PBYTE				*ppbUserDataOut,
         OUT __out LPWSTR		*ppwszIdentity,
         OUT EAP_ERROR			**ppEapError
         )
{
    DWORD	dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		L"SW2_TRACE_LEVEL_INFO::EapPeerInvokeIdentityUI()");

    if (!pEapMethodType || !pdwSizeOfUserDataOut || !ppbUserDataOut || !ppwszIdentity || !ppEapError)
    {
        SW2Trace( SW2_TRACE_LEVEL_ERROR,
			L"SW2_TRACE_LEVEL_ERROR::EapPeerInvokeIdentityUI()::One/Some of the parameters is/are NULL");
        dwReturnCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		if ((pEapMethodType->eapType.type != EAPTYPE) ||  
			 (pEapMethodType->dwAuthorId != AUTHOR_ID))
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				L"SW2_TRACE_LEVEL_ERROR::EapPeerInvokeIdentityUI()::Input Eap Type Info does not match the supported Eap Type");
			dwReturnCode = ERROR_NOT_SUPPORTED;

		}
		else
		{
			dwReturnCode = SW2EapMethodInvokeIdentityUI(hWndParent,
														dwFlags,
														dwSizeOfConnectionData,
														pbConnectionData,         
														dwSizeOfUserDataIn,
														pbUserDataIn,
														pdwSizeOfUserDataOut,
														ppbUserDataOut,
														ppwszIdentity );
		}
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		L"SW2_TRACE_LEVEL_INFO::EapPeerInvokeIdentityUI()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

    return dwReturnCode;
}

// eaphost runtime functions

//
// Initialize the module
//
DWORD WINAPI SW2EapPeerInitialize(OUT EAP_ERROR** ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerInitialize()");

    //Sanity Check
    if (!ppEapError)
    {
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2EapPeerInitialize()::One/Some of the parameters is/are NULL");
        dwReturnCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		dwReturnCode = SW2EapMethodInitialize();
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		L"SW2_TRACE_LEVEL_INFO::SW2EapPeerInitialize()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

    return dwReturnCode;
}

//
// De-Initialize the module
//
DWORD WINAPI SW2EapPeerShutdown(OUT EAP_ERROR** ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerShutdown()");

    if (!ppEapError)
    {
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2EapPeerShutdown()::One/Some of the parameters is/are NULL");
        dwReturnCode = ERROR_INVALID_PARAMETER;
    }
	else
	{
		dwReturnCode = SW2EapMethodDeInitialize();
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerShutdown()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

    return dwReturnCode;
}

//
// Identity has been determined, begin an authentication session
//
DWORD WINAPI SW2EapPeerBeginSession(
         IN DWORD						dwFlags,
         IN const EapAttributes*		pAttributeArray,
         IN HANDLE						hTokenImpersonateUser,
         IN DWORD						dwSizeofConnectionData,
         IN BYTE*						pbConnectionData,
         IN DWORD						dwSizeofUserData,
         IN BYTE*						pbUserData,
         IN DWORD						dwMaxSendPacketSize,
         OUT EAP_SESSION_HANDLE*		ppEapSessionHandle,
         OUT EAP_ERROR**				ppEapError
         )
{
	PSW2_EAPHOST_WB			pwb;
    DWORD					dwReturnCode;
	
	dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerBeginSession()");

	//Sanity Check
    if (!ppEapSessionHandle || !ppEapError)
    {
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2EapPeerBeginSession()::One/Some of the parameters is/are NULL");
        dwReturnCode = ERROR_INVALID_PARAMETER;
    }
	else
	{
		//
		// allocate work buffer for eaphost
		//
		if ((dwReturnCode = SW2AllocateMemory(sizeof(SW2_EAPHOST_WB), (PVOID*)&pwb))==NO_ERROR)
		{
			//
			// Allocate memory for send packet
			//
			pwb->dwMaxSendPacketSize = dwMaxSendPacketSize;

			if ((dwReturnCode = SW2AllocateMemory(pwb->dwMaxSendPacketSize, (PVOID*)&pwb->pSendPacket))==NO_ERROR)
			{
				//
				// Call eap method specific function, this will allocate common work buffer
				//
				if ((dwReturnCode = SW2EapMethodBegin(dwFlags,
													hTokenImpersonateUser,
													dwSizeofConnectionData,
													pbConnectionData,
													dwSizeofUserData,
													pbUserData,
													NULL,
													NULL,
													(PVOID*) &(pwb->pCommonWorkBuffer)))==NO_ERROR)
				{
					*ppEapSessionHandle = pwb;
				}
			}
		}
		else
			dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

		if (dwReturnCode != NO_ERROR)
			SW2FreeMemory((PVOID*)&pwb);
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		L"SW2_TRACE_LEVEL_INFO::SW2EapPeerBeginSession()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// Authentication has finished (either succesfull or not), End authentication session (Cleanup)
//
DWORD WINAPI SW2EapPeerEndSession(
        IN EAP_SESSION_HANDLE eapSessionHandle, 
        OUT EAP_ERROR** ppEapError
		)
{
    DWORD	dwReturnCode = NO_ERROR;
	PSW2_EAPHOST_WB pwb = NULL;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerEndSession()");

	// Sanity check.
	if (!eapSessionHandle || !ppEapError)
    {
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2EapPeerEndSession()::One/Some of the parameters is/are NULL");
        dwReturnCode = ERROR_INVALID_PARAMETER;
    }
	else
	{
	    pwb = (PSW2_EAPHOST_WB)eapSessionHandle;

		SW2EapMethodEnd(pwb->pCommonWorkBuffer);

		if (pwb->pSendPacket)
			SW2FreeMemory((PVOID*)&(pwb->pSendPacket));

		SecureZeroMemory(pwb, sizeof(SW2_EAPHOST_WB));

		dwReturnCode = SW2FreeMemory((PVOID*)&pwb);
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerEndSession()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// Retrieve the user identity (non-interactive)
//
DWORD WINAPI SW2EapPeerGetIdentity(
	IN DWORD			dwFlags,
	IN DWORD			dwSizeofConnectionData,
	IN const BYTE		*pbConnectionData,
	IN DWORD			dwSizeofUserDataIn,
	IN const BYTE		*pbUserDataIn,
	IN HANDLE			hTokenImpersonateUser,
	OUT BOOL			*pfInvokeUI,
	IN OUT DWORD		*pdwSizeOfUserDataOut,
	OUT PBYTE			*ppbUserDataOut,
	OUT PWCHAR			*ppwcIdentity,
	OUT EAP_ERROR		**ppEapError
	)
{
    DWORD dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerGetIdentity()");

    if (!pfInvokeUI || !ppwcIdentity || !ppEapError)
    {
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2EapPeerGetIdentity()::One/Some of the parameters is/are NULL");
        dwReturnCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		// call eap method specific function
		dwReturnCode=SW2EapMethodGetIdentity(dwFlags,
												dwSizeofConnectionData,
												pbConnectionData,
												dwSizeofUserDataIn,
												pbUserDataIn,
												hTokenImpersonateUser,
												pfInvokeUI,
												pdwSizeOfUserDataOut,
												ppbUserDataOut,
												ppwcIdentity);
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerGetIdentity()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

    return dwReturnCode;
}

//
// Process a recieved request packet
//
DWORD WINAPI SW2EapPeerProcessRequestPacket(
         IN EAP_SESSION_HANDLE		eapSessionHandle,
         IN DWORD					cbReceivePacket,
         IN EapPacket*				pReceivePacket,
         OUT EapPeerMethodOutput*	pEapPeerMethodOutput,
         OUT EAP_ERROR**			ppEapError
         )
{
	SW2EAPOUTPUT		eapOutput;
    PSW2_EAPHOST_WB		pwb = NULL;
    DWORD				dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerProcessRequestPacket()");

	if(!eapSessionHandle || !pReceivePacket || !pEapPeerMethodOutput  || !ppEapError)
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2EapPeerProcessRequestPacket()::One/Some of the parameters is/are NULL");
		dwReturnCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		pwb = (PSW2_EAPHOST_WB) eapSessionHandle;

		memset(&eapOutput, 0, sizeof(eapOutput));

		// set default eapOutput options
		eapOutput.bAllowNotifications = TRUE;

		if ((dwReturnCode = SW2EapMethodProcess(pwb->pCommonWorkBuffer,
												(PSW2EAPPACKET) pReceivePacket,
												pwb->dwMaxSendPacketSize,
												pwb->pSendPacket,
												&eapOutput))==NO_ERROR)
		{
			switch (eapOutput.eapAction)
			{
				case SW2EAPACTION_Discard:

					pEapPeerMethodOutput->action = EapPeerMethodResponseActionDiscard;

				break;

				case SW2EAPACTION_Send:

					pEapPeerMethodOutput->action = EapPeerMethodResponseActionSend;

				break;

				case SW2EAPACTION_InvokeUI:

					SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
						L"SW2_TRACE_LEVEL_DEBUG::SW2EapPeerProcessRequestPacket()::EAP method requested interactive UI" );

					pEapPeerMethodOutput->action = EapPeerMethodResponseActionInvokeUI;

				break;

				case SW2EAPACTION_Done:

					// used for RASEAP, EapHost sees this as "none"

				case SW2EAPACTION_None:

					pEapPeerMethodOutput->action = EapPeerMethodResponseActionNone;

				break;

				default:

					dwReturnCode = ERROR_NOT_SUPPORTED;

				break;
			}
			//FIXME: fill eap error
		}
	}

	pEapPeerMethodOutput->fAllowNotifications = eapOutput.bAllowNotifications;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
		L"SW2_TRACE_LEVEL_DEBUG::SW2EapPeerProcessRequestPacket()::notifications: %ld", 
		pEapPeerMethodOutput->fAllowNotifications);

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerProcessRequestPacket()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// Retrieve a response packet to send
//
DWORD WINAPI SW2EapPeerGetResponsePacket(IN EAP_SESSION_HANDLE	eapSessionHandle,
										 IN OUT DWORD*			pcbSendPacket,
										 OUT EapPacket*			pSendPacket,
										 OUT EAP_ERROR**		ppEapError)
{
	DWORD	dwSizeOfSendPacket;
    DWORD	dwReturnCode = NO_ERROR;
	PSW2_EAPHOST_WB	pwb = NULL;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerGetResponsePacket()");

    //Sanity Check
    if (!eapSessionHandle || !pcbSendPacket  || !pSendPacket || !ppEapError)
    {
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2EapPeerGetResponsePacket()::One/Some of the parameters is/are NULL");
        dwReturnCode = ERROR_INVALID_PARAMETER;
    }
	else
	{
		pwb = (PSW2_EAPHOST_WB)eapSessionHandle;

		dwSizeOfSendPacket = SW2_WireToHostFormat16(pwb->pSendPacket->Length);
		
		//
		// sanity check
		//
		if (*pcbSendPacket < dwSizeOfSendPacket)
			dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
		else
		{
			memcpy_s(pSendPacket, *pcbSendPacket, pwb->pSendPacket, dwSizeOfSendPacket);
			*pcbSendPacket = dwSizeOfSendPacket;
		}
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerGetResponsePacket()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

    return dwReturnCode;
}

//
// Return the authentication result. In this function the user data and/or
// configuration data is also returned to the upper layer to be stored
//
DWORD WINAPI SW2EapPeerGetResult(IN EAP_SESSION_HANDLE			eapSessionHandle,
								 IN EapPeerMethodResultReason	eapPeerMethodResultReason,
								 OUT EapPeerMethodResult		*pEapPeerMethodResult, 
								 OUT EAP_ERROR					**ppEapError)
{
	EAP_ATTRIBUTES	*pAttribArray;
    PSW2_EAPHOST_WB	pwb = NULL;
    DWORD			dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerGetResult()");

    if (!eapSessionHandle || !pEapPeerMethodResult || !ppEapError)
    {
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapPeerGetResult():: One/Some of the parameters is/are NULL");
        dwReturnCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		pwb = (PSW2_EAPHOST_WB)eapSessionHandle;

		pEapPeerMethodResult->fIsSuccess = FALSE;

		if ((dwReturnCode = SW2AllocateMemory(sizeof(EAP_ATTRIBUTES), (PVOID*)&pAttribArray))==NO_ERROR)
		{
			if ((dwReturnCode = SW2EapMethodGetResult(pwb->pCommonWorkBuffer,
												(SW2_EAP_REASON)eapPeerMethodResultReason,
												&(pEapPeerMethodResult->fIsSuccess),
												&(pEapPeerMethodResult->fSaveUserData),
												&(pEapPeerMethodResult->dwSizeofUserData),
												&(pEapPeerMethodResult->pUserData),
												&(pEapPeerMethodResult->fSaveConnectionData),
												&(pEapPeerMethodResult->dwSizeofConnectionData),
												&(pEapPeerMethodResult->pConnectionData),
												&(pAttribArray->dwNumberOfAttributes),
												(PSW2EAPATTRIBUTE*)&(pAttribArray->pAttribs)))==NO_ERROR)
			{
				if(pEapPeerMethodResult->fIsSuccess)
					pEapPeerMethodResult->pAttribArray = pAttribArray;
			}

			if (dwReturnCode!=NO_ERROR||
				!pEapPeerMethodResult->fIsSuccess)
			{
				SW2FreeMemory((PVOID*)&pAttribArray);

				pEapPeerMethodResult->pAttribArray = NULL;
			}
		}
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerGetResult()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

    return dwReturnCode;
}

//
// Before the Interactive UI is called, this function is called in which the
// context data for the Interactive UI is returned
//
DWORD WINAPI SW2EapPeerGetUIContext(IN EAP_SESSION_HANDLE	eapSessionHandle,
									OUT DWORD				*pdwSizeOfUIContextData,         
									OUT BYTE				**ppbUIContextData,
									OUT EAP_ERROR			**ppEapError)
{
    DWORD	dwReturnCode = NO_ERROR;
    PSW2_EAPHOST_WB	pwb = NULL;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerGetUIContext()");

    //Sanity Check
    if (!eapSessionHandle || !pdwSizeOfUIContextData || !ppbUIContextData || !ppEapError)
    {
		SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerGetUIContext()::One/Some of the parameters is/are NULL");
        dwReturnCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		pwb = (PSW2_EAPHOST_WB)eapSessionHandle;

		dwReturnCode = SW2EapMethodGetUIContext(pwb->pCommonWorkBuffer,
												pdwSizeOfUIContextData,
												ppbUIContextData);
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerGetUIContext()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// After the Interactive UI is called, this function is called in which the
// context data for the Interactive UI is provided
//
DWORD WINAPI SW2EapPeerSetUIContext(
        IN EAP_SESSION_HANDLE		eapSessionHandle,
        IN DWORD					dwSizeOfUIContextData,
        IN const BYTE*				pbUIContextData,
        OUT EapPeerMethodOutput*	pEapPeerMethodOutput,
        OUT EAP_ERROR**				ppEapError
		)
{
	SW2EAPOUTPUT		eapOutPut;
    DWORD				dwReturnCode = NO_ERROR;
	PSW2_EAPHOST_WB		pwb = NULL;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerSetUIContext()");

	//
    // Sanity Check
	//
    if(!eapSessionHandle || !pEapPeerMethodOutput || !ppEapError)
    {
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapPeerSetUIContext()::One/Some of the parameters is/are NULL");
        dwReturnCode = ERROR_INVALID_PARAMETER;
    }
	else
	{
		pwb = (PSW2_EAPHOST_WB)eapSessionHandle;

		if ((dwReturnCode = SW2EapMethodSetUIContext(pwb->pCommonWorkBuffer,
													dwSizeOfUIContextData,
													(PBYTE)pbUIContextData))==NO_ERROR)
		{
			//
			// Make call to SW2EapMethodProccessRequestPacket one more time to retrieve action
			// based on current status
			//
			if ((dwReturnCode = SW2EapMethodProcess(pwb->pCommonWorkBuffer,
													NULL,
													pwb->dwMaxSendPacketSize,
													pwb->pSendPacket,
													&eapOutPut))==NO_ERROR)
			{
				switch (eapOutPut.eapAction)
				{
					case SW2EAPACTION_Discard:

						pEapPeerMethodOutput->action = EapPeerMethodResponseActionDiscard;

					break;

					case SW2EAPACTION_Send:

						pEapPeerMethodOutput->action = EapPeerMethodResponseActionSend;

					break;

					case SW2EAPACTION_InvokeUI:

						pEapPeerMethodOutput->action = EapPeerMethodResponseActionInvokeUI;

					break;

					case SW2EAPACTION_None:

						pEapPeerMethodOutput->action = EapPeerMethodResponseActionNone;

					break;

					default:

						dwReturnCode = ERROR_NOT_SUPPORTED;

					break;
				}
			}
		}
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerSetUIContext()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// Set any attributes from response
// NOT IMPLEMENTED
//
DWORD WINAPI SW2EapPeerSetResponseAttributes(IN EAP_SESSION_HANDLE		eapSessionHandle,
											 IN EapAttributes			*pAttribs,
											 OUT EapPeerMethodOutput	*pEapOutput,
											 OUT EAP_ERROR				**ppEapError)
{
	DWORD dwReturnCode;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerSetResponseAttributes()");

    dwReturnCode = NO_ERROR;

	if (!eapSessionHandle || !pAttribs || !ppEapError)
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapPeerSetResponseAttributes()::One/Some of the parameters is/are NULL");
		dwReturnCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		pEapOutput->action = EapPeerMethodResponseActionNone;

		pAttribs->dwNumberOfAttributes = 0;
		pAttribs->pAttribs = NULL;
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerSetResponseAttributes()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// Return any attributes from response
// NOT IMPLEMENTED
//
DWORD WINAPI SW2EapPeerGetResponseAttributes(IN EAP_SESSION_HANDLE	eapSessionHandle,
											 OUT EapAttributes*		pAttribs,
											 OUT EAP_ERROR**		ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerGetResponseAttributes()::returning: %ld", dwReturnCode);

	if (!eapSessionHandle || !pAttribs || !ppEapError)
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapPeerGetResponseAttributes()::One/Some of the parameters is/are NULL");
		dwReturnCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		pAttribs->dwNumberOfAttributes = 0;
		pAttribs->pAttribs = NULL;
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapPeerGetResponseAttributes()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// Free any atrributes allocated by this module
//
DWORD
SW2FreeAttributes(IN OUT EapAttributes **ppEapAttributes)
{
	DWORD			dwReturnCode = NO_ERROR;
	DWORD			dwAttribCount = 0;
	EapAttribute	*pEapAttrib = NULL;
	DWORD			i = 0;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2FreeAttributes()::returning: %ld", dwReturnCode);

	if (!ppEapAttributes)
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2FreeAttributes()::One/Some of the parameters is/are NULL");
		dwReturnCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		if (*ppEapAttributes)
		{
			dwAttribCount = (*ppEapAttributes)->dwNumberOfAttributes;

			//
			// Free all the Value pointers in each EAP attribute.
			//
			for (i = 0; i < dwAttribCount; i++)
			{
				pEapAttrib = &(((*ppEapAttributes)->pAttribs)[i]);
				dwReturnCode = SW2FreeMemory((PVOID*)&(pEapAttrib->pValue));
				if (dwReturnCode != NO_ERROR)
					break;
			}

			if (dwReturnCode == NO_ERROR)
			{
				if ((dwReturnCode = SW2FreeMemory((PVOID *)&((*ppEapAttributes)->pAttribs))) == NO_ERROR)
					dwReturnCode = SW2FreeMemory((PVOID*)ppEapAttributes);
			}
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2FreeAttributes()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

// configuration functions

//
// Convert an XML structure to a configuration blob
//
DWORD WINAPI EapPeerConfigXml2Blob(IN DWORD									dwFlags,
								   IN EAP_METHOD_TYPE						eapMethodType,
								   IN IXMLDOMDocument2*						pXMLConfigDoc,
								   OUT __out_ecount(*pdwSizeOfConfigOut)	BYTE** ppbConfigOut,
								   OUT DWORD*								pdwSizeOfConfigOut,
								   OUT EAP_ERROR**							ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerConfigXml2Blob()");

    if(!ppbConfigOut || !pdwSizeOfConfigOut || !pXMLConfigDoc || !ppEapError)
    {
        SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::EapPeerConfigXml2Blob()::One/Some of the parameters is/are NULL");
        dwReturnCode = ERROR_INVALID_PARAMETER;
    }
	else
	{
	    if ((eapMethodType.eapType.type != EAPTYPE) ||  
			 (eapMethodType.dwAuthorId != AUTHOR_ID))
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::EapPeerConfigXml2Blob()::Input Eap Type Info does not match the supported Eap Type");
			dwReturnCode = ERROR_NOT_SUPPORTED;
		}
		else
		{
			dwReturnCode = SW2EapMethodConfigXml2Blob(dwFlags,
													pXMLConfigDoc,
													ppbConfigOut,
													pdwSizeOfConfigOut);
		}
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerConfigXml2Blob()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

    return dwReturnCode;
}

//
// Convert a configuration blob to an XML structure
//
DWORD WINAPI EapPeerConfigBlob2Xml(IN DWORD										dwFlags,
								   IN EAP_METHOD_TYPE							eapMethodType,
								   IN __in_ecount(dwSizeOfConfigIn)	const BYTE	*pbConfigIn,
								   IN DWORD										dwSizeOfConfigIn,
								   OUT IXMLDOMDocument2							**ppXMLConfigDoc,
								   OUT EAP_ERROR								**ppEapError)
{
	DWORD				dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerConfigBlob2Xml()");

	// pConfigIn can be NULL. If it is, use the default configuration of the method.
	if (!ppXMLConfigDoc || !ppEapError)
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::EapPeerConfigBlob2Xml()::One/Some of the parameters is/are NULL");
		dwReturnCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		if ((eapMethodType.eapType.type != EAPTYPE) ||
			(eapMethodType.dwAuthorId != AUTHOR_ID))
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::EapPeerConfigBlob2Xml()::Input Eap Type Info does not match the supported Eap Type");
			dwReturnCode = ERROR_NOT_SUPPORTED;
		}
		else
		{
			dwReturnCode = SW2EapMethodConfigBlob2Xml(dwFlags,
														pbConfigIn,
														dwSizeOfConfigIn,
														ppXMLConfigDoc);
		}
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerConfigBlob2Xml()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// Function to convert XML containing credentials to credentials blob
//
DWORD WINAPI EapPeerCredentialsXml2Blob(IN DWORD									dwFlags,
										IN EAP_METHOD_TYPE							eapMethodType,
										IN IXMLDOMDocument2*						pXMLCredentialsDoc,
										IN __in_ecount(dwSizeOfConfigIn)			const BYTE* pbConfigIn,
										IN DWORD									dwSizeOfConfigIn,
										OUT __out_ecount(*pdwSizeOfCredentialsOut)	BYTE** ppbCredentialsOut,
										OUT DWORD*									pdwSizeOfCredentialsOut,
										OUT EAP_ERROR**								ppEapError)
{
    DWORD	dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerCredentialsXml2Blob()");

    if(!ppbCredentialsOut || !pdwSizeOfCredentialsOut || !pXMLCredentialsDoc || !ppEapError)
    {
        SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::EapPeerCredentialsXml2Blob()::One/Some of the parameters is/are NULL");
        dwReturnCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		if ((eapMethodType.eapType.type != EAPTYPE) ||  
			 (eapMethodType.dwAuthorId != AUTHOR_ID))
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::EapPeerCredentialsXml2Blob()::Input Eap Type Info does not match the supported Eap Type");
			dwReturnCode = ERROR_NOT_SUPPORTED;
		}
		else
		{
			dwReturnCode = SW2EapMethodCredentialsXml2Blob(dwFlags,
															pXMLCredentialsDoc,
															pbConfigIn,
															dwSizeOfConfigIn,
															ppbCredentialsOut,
															pdwSizeOfCredentialsOut);
		}
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerCredentialsXml2Blob()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

    return dwReturnCode;
}

//
// Function to return Inputfields
//
DWORD WINAPI EapPeerQueryCredentialInputFields(IN  HANDLE						hUserToken,
											   IN  EAP_METHOD_TYPE				eapMethodType,
											   IN  DWORD						dwFlags,
											   IN  DWORD						dwEapConnDataSize,
											   IN  PBYTE						pbEapConnData,
											   OUT EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldArray,
											   OUT EAP_ERROR					**ppEapError) 
{
	DWORD	dwReturnCode;

	g_dwSW2TraceId = TraceRegister(EAPID);

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerQueryCredentialInputFields()");

    if (!pEapConfigInputFieldArray ||
        !ppEapError)
    {
        SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::EapPeerQueryCredentialInputFields()::One/Some of the parameters is/are NULL");
        dwReturnCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		//
		// Verify if eapType passed by EapHost correctly matches the EapType of this DLL.
		//
		if ((eapMethodType.eapType.type != EAPTYPE) ||  
			 (eapMethodType.dwAuthorId != AUTHOR_ID))
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				L"SW2_TRACE_LEVEL_ERROR::EapPeerQueryCredentialInputFields()::Input Eap Type Info (%ld, %ld) does not match the supported Eap Type",
				eapMethodType.eapType.type,
				eapMethodType.dwAuthorId);
			dwReturnCode = ERROR_NOT_SUPPORTED;
		}
		else
		{
			dwReturnCode = SW2EapMethodQueryCredentialInputFields(hUserToken,
																	dwFlags,
																	dwEapConnDataSize,
																	pbEapConnData,
																	pEapConfigInputFieldArray);

			
		}
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerQueryCredentialInputFields()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

    return dwReturnCode;
}

//
// Function to return user blob according to Inputfields provided by EapHost
//
DWORD WINAPI EapPeerQueryUserBlobFromCredentialInputFields(IN  HANDLE						hUserToken,
														   IN  EAP_METHOD_TYPE				eapMethodType,
														   IN  DWORD						dwFlags,
														   IN  DWORD						dwEapConnDataSize,
														   IN  PBYTE						pbEapConnData,
														   IN  CONST EAP_CONFIG_INPUT_FIELD_ARRAY	*pEapConfigInputFieldArray,
														   OUT DWORD						*pdwUserBlobSize,
														   OUT PBYTE						*ppbUserBlob,
														   OUT EAP_ERROR					**ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerQueryUserBlobFromCredentialInputFields()");

    if (!pEapConfigInputFieldArray ||
        !pdwUserBlobSize ||
        !ppbUserBlob ||
        !ppEapError)
    {
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::QueryUserBlobFromCredentialInputFields()::One/Some of the parameters is/are NULL");
        dwReturnCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		//
		// Verify if eapType passed by EapHost correctly matches the EapType of this DLL.
		//
		if ((eapMethodType.eapType.type != EAPTYPE) ||  
			 (eapMethodType.dwAuthorId != AUTHOR_ID))
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::EapPeerQueryUserBlobFromCredentialInputFields()::Input Eap Type Info does not match the supported Eap Type");
			dwReturnCode = ERROR_NOT_SUPPORTED;
		}
		else
		{
			//
			// convert fields into user blob
			//
			dwReturnCode = SW2EapMethodQueryUserBlobFromCredentialInputFields(hUserToken,
																			dwFlags,
																			dwEapConnDataSize,
																			pbEapConnData,
																			pEapConfigInputFieldArray,
																			pdwUserBlobSize,
																			ppbUserBlob);
		}
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerQueryUserBlobFromCredentialInputFields()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// The EapPeerQueryInteractiveUIInputFields function obtains 
// the input fields for interactive UI components to be raised on the supplicant.
//
DWORD WINAPI EapPeerQueryInteractiveUIInputFields(
		IN DWORD dwVersion,
		IN DWORD dwFlags,
		IN DWORD dwSizeofUIContextData,
		IN __in_ecount(dwSizeofUIContextData) const BYTE* pUIContextData,
		OUT EAP_INTERACTIVE_UI_DATA* pEapInteractiveUIData,
		OUT EAP_ERROR** ppEapError,
		IN OUT LPVOID *pvReserved)
{
    DWORD dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerQueryInteractiveUIInputFields()");

    if (!pUIContextData ||
        !pEapInteractiveUIData ||
        !ppEapError)
    {
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::EapPeerQueryInteractiveUIInputFields()::One/Some of the parameters is/are NULL");
        dwReturnCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		dwReturnCode = ERROR_NOT_SUPPORTED;
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerQueryInteractiveUIInputFields()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// The EapPeerQueryUIBlobFromInteractiveUIInputFields function converts user 
// information into a user BLOB that can be consumed by EAPHost run-time functions.
//
DWORD WINAPI EapPeerQueryUIBlobFromInteractiveUIInputFields(
		IN DWORD dwVersion,
        IN DWORD dwFlags,
        IN DWORD dwSizeofUIContextData,
        IN __in_ecount(dwSizeofUIContextData) const BYTE* pUIContextData,
        IN const EAP_INTERACTIVE_UI_DATA *pEapInteractiveUIData,
        OUT DWORD * pdwSizeOfDataFromInteractiveUI,
        OUT __deref_out_ecount(*pdwSizeOfDataFromInteractiveUI) BYTE ** ppDataFromInteractiveUI,
        OUT EAP_ERROR** ppEapError,
        IN OUT LPVOID *pvReserved)
{
    DWORD dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerQueryUIBlobFromInteractiveUIInputFields()");

    if (!pUIContextData ||
        !pEapInteractiveUIData ||
		!ppDataFromInteractiveUI ||
        !ppEapError)
    {
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::EapPeerQueryUIBlobFromInteractiveUIInputFields()::One/Some of the parameters is/are NULL");
        dwReturnCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		//
		// Verify if eapType passed by EapHost correctly matches the EapType of this DLL.
		//
		dwReturnCode = ERROR_NOT_SUPPORTED;
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2AllocateandFillEapError(ppEapError,
									dwReturnCode, 
									0,
									NULL, 
									NULL, 
									NULL,
									NULL, 
									NULL);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::EapPeerQueryUIBlobFromInteractiveUIInputFields()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

// util functions

//
// Allocate a EapError and fill it according to dwErrorCode
//
DWORD SW2AllocateandFillEapError(IN OUT EAP_ERROR	**ppEapError,
								 IN DWORD			dwErrorCode,  
								 IN DWORD			dwReasonCode,
								 IN LPCGUID			pRootCauseGuid,
								 IN LPCGUID			pRepairGuid,
								 IN LPCGUID			pHelpLinkGuid,
								 IN __in LPWSTR		pRootCauseString,
								 IN __in LPWSTR		pRepairString)
{
	DWORD	dwReturnCode = NO_ERROR;
	GUID	guidDefaultRootCause = {0x9612fc67, 0x6150, 0x4209, {0xa8, 0x5e, 0xa8, 0xd8, 0, 0, 1, 4}};

	//Sanity Check
	if (!ppEapError)
	{
		dwReturnCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		//
		// Allocate memory for EAP_ERROR.
		//
		if ((dwReturnCode = SW2AllocateMemory(sizeof(EAP_ERROR), (PVOID *)ppEapError))==NO_ERROR)
		{
			ZeroMemory(*ppEapError, sizeof(EAP_ERROR));

			//
			// Assign the Win32 Error Code
			//
			(*ppEapError)->dwWinError = dwErrorCode;

			//
			// Assign the EAP_METHOD_TYPE to indicate which EAP Method send the error.
			//
			(*ppEapError)->type.eapType.type = EAPTYPE;
			(*ppEapError)->type.eapType.dwVendorId = VENDOR_ID;
			(*ppEapError)->type.eapType.dwVendorType = VENDOR_TYPE;
			(*ppEapError)->type.dwAuthorId = AUTHOR_ID;

			//
			// Assign the reason code
			//
			(*ppEapError)->dwReasonCode = dwReasonCode;

			//
			// Assign the RootCause GUID
			//
			if (pRootCauseGuid == NULL)
			{
				memcpy(&((*ppEapError)->rootCauseGuid), 
						&guidDefaultRootCause, 
						sizeof(GUID));
			}
			else
				memcpy(&((*ppEapError)->rootCauseGuid), 
						pRootCauseGuid, 
						sizeof(GUID));

			//
			// Assign the Repair GUID
			//
			if(pRepairGuid != NULL)
				memcpy(&((*ppEapError)->repairGuid), pRepairGuid, sizeof(GUID));

			//
			// Assign the HelpLink GUID
			//
			if(pHelpLinkGuid!= NULL)
				memcpy(&((*ppEapError)->helpLinkGuid), pHelpLinkGuid, sizeof(GUID));
			
			// FIXME:
			//
			// Assign the Root Cause String
			//
			//dwReturnCode = CopyWideString(pRootCauseString, &((*pEapError)->pRootCauseString));
			//if(dwReturnCode != NO_ERROR)
			//	goto Cleanup;

			//
			// Assign the Repair String
			//
			//dwReturnCode = CopyWideString(pRepairString, &((*pEapError)->pRepairString));
			//if(retCode != NO_ERROR)
			//	goto Cleanup;
		}
	}

	//FIXME: free memory correctly!

	if (dwReturnCode != NO_ERROR)
		SW2FreeMemory((PVOID*)ppEapError);
	
	return dwReturnCode;
}

//
// Register/Install the dll EapHost style
//
DWORD SW2_RegisterEapHostDLL()
{
	HKEY	hEapHostKey;
	HKEY	hEapAuthorKey;
	HKEY	hEapMethodKey;
	WCHAR	pwcTemp[MAX_PATH];
	DWORD	dwReturnCode;
	DWORD	dwDisp = 0;

	dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_RegisterEapHostDLL()");

	if ((dwReturnCode = RegCreateKeyEx(HKEY_LOCAL_MACHINE, 
										L"System\\CurrentControlSet\\Services\\EapHost\\Methods", 
										0, NULL, 
										REG_OPTION_NON_VOLATILE,
										KEY_ALL_ACCESS, 
										NULL, 
										&hEapHostKey, 
										&dwDisp)) == NO_ERROR)
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_RegisterEapHostDLL::RegOpenKeyEx() on \"System\\CurrentControlSet\\Services\\EapHost\\Methods\" succeeded");

		memset(pwcTemp, 0, sizeof(pwcTemp));

		swprintf_s(pwcTemp, sizeof(pwcTemp)/sizeof(WCHAR), 
			L"%ld", AUTHOR_ID);

		dwDisp = 0;

		// add author ID
		if ((dwReturnCode = RegCreateKeyExW(hEapHostKey, 
											pwcTemp, 
											0, NULL, 
											REG_OPTION_NON_VOLATILE,
											KEY_ALL_ACCESS, 
											NULL, 
											&hEapAuthorKey, 
											&dwDisp))==NO_ERROR)
		{
			if ((dwReturnCode = RegSetValueExW(hEapAuthorKey,
											NULL, 
											0,
											REG_SZ,
											(PBYTE)EAPVENDOR,
											(DWORD)(wcslen(EAPVENDOR)+1)*sizeof(WCHAR)))!=NO_ERROR)
			{
				SW2Trace( SW2_TRACE_LEVEL_WARNING, 
							L"SW2_TRACE_LEVEL_WARNING::SW2_RegisterEapHostDLL::could not set EAPVENDOR: %ld", dwReturnCode);
			}

			RegCloseKey(hEapAuthorKey);
		}

		memset(pwcTemp, 0, sizeof(pwcTemp));

		swprintf_s(pwcTemp, sizeof(pwcTemp)/sizeof(WCHAR), 
			L"%ld\\%d", AUTHOR_ID, EAPTYPE);

		dwDisp = 0;

		if ((dwReturnCode = RegCreateKeyExW(hEapHostKey, 
											pwcTemp, 
											0, NULL, 
											REG_OPTION_NON_VOLATILE,
											KEY_ALL_ACCESS, 
											NULL, 
											&hEapMethodKey, 
											&dwDisp))==NO_ERROR)
		{
			dwReturnCode = RegSetValueExW(hEapMethodKey,
											L"PeerFriendlyName", 
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

						dwReturnCode = RegSetValueExW(hEapMethodKey,
													L"PeerDllPath", 
													0,
													REG_EXPAND_SZ,
													(LPBYTE)pwcTemp,
													(DWORD)(wcslen(pwcTemp)+1)*sizeof(WCHAR));
					}
					else
						dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
				}
				else
					dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							L"SW2_TRACE_LEVEL_ERROR::SW2_RegisterEapHostDLL::could not set \"PeerFriendlyName\": %ld", dwReturnCode);
			}

			if (dwReturnCode == NO_ERROR)
			{
				dwReturnCode = RegSetValueExW(hEapMethodKey,
											L"Properties",
											0,
											REG_DWORD,
											(LPBYTE) &EAPPROPERTIES, 
											sizeof(DWORD));
			}

			if (dwReturnCode == NO_ERROR)
			{
				dwReturnCode = RegSetValueExW(hEapMethodKey,
											L"PeerInvokeUsernameDialog",
											0,
											REG_DWORD,
											(LPBYTE) &EAPUSERNAMEDLG, 
											sizeof(DWORD));
			}

			if (dwReturnCode == NO_ERROR)
			{
				dwReturnCode = RegSetValueExW(hEapMethodKey,
											L"PeerInvokePasswordDialog",
											0,
											REG_DWORD,
											(LPBYTE) &EAPPWDDLG, 
											sizeof(DWORD));
			}

			RegCloseKey(hEapMethodKey);
		}

		RegCloseKey(hEapHostKey);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		L"SW2_TRACE_LEVEL_INFO::SW2_RegisterEapHostDLL::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// Register/Install the dll EapHost extended style 
//
DWORD SW2_RegisterEapHostExtendedDLL()
{
	HKEY	hEapHostKey;
	HKEY	hEapMethodKey;
	WCHAR	pwcTemp[MAX_PATH];
	DWORD	dwReturnCode;
	DWORD	dwDisp = 0;

	dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(EAPID);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_RegisterEapHostExtendedDLL()");

	if ((dwReturnCode = RegCreateKeyEx(HKEY_LOCAL_MACHINE, 
										L"System\\CurrentControlSet\\Services\\EapHost\\Methods", 
										0, NULL, 
										REG_OPTION_NON_VOLATILE,
										KEY_ALL_ACCESS, 
										NULL, 
										&hEapHostKey, 
										&dwDisp)) == NO_ERROR)
	{
		swprintf_s(pwcTemp, sizeof(pwcTemp)/sizeof(WCHAR), 
			L"%ld\\254\\%ld\\%d", AUTHOR_ID, VENDOR_ID, EAPTYPE);

		dwDisp = 0;

		if ((dwReturnCode = RegCreateKeyExW(hEapHostKey, 
											pwcTemp, 
											0, NULL, 
											REG_OPTION_NON_VOLATILE,
											KEY_ALL_ACCESS, 
											NULL, 
											&hEapMethodKey, 
											&dwDisp))==NO_ERROR)
		{
			dwReturnCode = RegSetValueExW(hEapMethodKey,
											L"PeerFriendlyName", 
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

						dwReturnCode = RegSetValueExW(hEapMethodKey,
													L"PeerDllPath", 
													0,
													REG_SZ,
													(LPBYTE)pwcTemp,
													(DWORD)(wcslen(pwcTemp)+1)*sizeof(WCHAR));
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
											L"Properties",
											0,
											REG_DWORD,
											(LPBYTE) &EAPPROPERTIES, 
											sizeof(DWORD));
			}

			if (dwReturnCode == NO_ERROR)
			{
				dwReturnCode = RegSetValueExW(hEapMethodKey,
											L"PeerInvokeUsernameDialog",
											0,
											REG_DWORD,
											(LPBYTE) &EAPUSERNAMEDLG, 
											sizeof(DWORD));
			}

			if (dwReturnCode == NO_ERROR)
			{
				dwReturnCode = RegSetValueExW(hEapMethodKey,
											L"PeerInvokePasswordDialog",
											0,
											REG_DWORD,
											(LPBYTE) &EAPPWDDLG, 
											sizeof(DWORD));
			}

			RegCloseKey(hEapMethodKey);
		}

		RegCloseKey(hEapHostKey);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_RegisterEapHostExtendedDLL()::returning: %ld", dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}

//
// Unregister/De-Install the dll EapHost style
//
DWORD SW2_UnregisterEapHostDLL()
{
	WCHAR	pwcTemp1[MAX_PATH];
	WCHAR	pwcTemp2[MAX_PATH];
	HKEY	hEapHostKey;
	HKEY	hAuthorKey;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_UnregisterEapHostDLL()");

	if ((dwReturnCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
										L"System\\CurrentControlSet\\Services\\EapHost\\Methods", 
										0, 
										KEY_ALL_ACCESS, 
										&hEapHostKey )) == NO_ERROR)
	{
		swprintf_s(pwcTemp1,sizeof(pwcTemp1)/sizeof(WCHAR),L"%ld", AUTHOR_ID);

		if ((dwReturnCode = RegOpenKeyEx(hEapHostKey, 
										pwcTemp1, 
										0, 
										KEY_ALL_ACCESS, 
										&hAuthorKey )) == NO_ERROR)
		{
			memset(pwcTemp2, 0, sizeof(pwcTemp2));

			swprintf_s(pwcTemp2,sizeof(pwcTemp2)/sizeof(WCHAR),L"%ld", EAPTYPE);

			dwReturnCode = RegDeleteKey(hAuthorKey, 
										pwcTemp2);

			RegCloseKey(hAuthorKey);
		}

		RegCloseKey(hEapHostKey);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_UnregisterEapHostDLL()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

//
// Unregister/De-Install the dll EapHost Extended style
//
DWORD SW2_UnregisterEapHostExtendedDLL()
{
	WCHAR	pwcTemp1[MAX_PATH];
	WCHAR	pwcTemp2[MAX_PATH];
	HKEY	hEapHostKey;
	HKEY	hAuthorKey;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_UnregisterEapHostExtendedDLL()");

	if ((dwReturnCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
										L"System\\CurrentControlSet\\Services\\EapHost\\Methods", 
										0, 
										KEY_ALL_ACCESS, 
										&hEapHostKey )) == NO_ERROR)
	{
		swprintf_s(pwcTemp1,sizeof(pwcTemp1)/sizeof(WCHAR),L"%ld\\254\\%ld", AUTHOR_ID, VENDOR_ID);

		if ((dwReturnCode = RegOpenKeyEx(hEapHostKey, 
										pwcTemp1, 
										0, 
										KEY_ALL_ACCESS, 
										&hAuthorKey )) == NO_ERROR)
		{
			memset(pwcTemp2, 0, sizeof(pwcTemp2));

			swprintf_s(pwcTemp2,sizeof(pwcTemp2)/sizeof(WCHAR),L"%ld", EAPTYPE);

			dwReturnCode = RegDeleteKey(hAuthorKey, 
										pwcTemp2);

			RegCloseKey(hAuthorKey);
		}

		RegCloseKey(hEapHostKey);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_UnregisterEapHostExtendedDLL()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}