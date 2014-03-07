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

#include "..\common\common.h"

// eaphost work buffer
typedef struct _SW2_EAPHOST_WB
{
	PVOID				pCommonWorkBuffer;

	PSW2EAPPACKET		pSendPacket;
	DWORD				dwMaxSendPacketSize;

}	SW2_EAPHOST_WB, *PSW2_EAPHOST_WB;

DWORD WINAPI SW2EapPeerGetUIContext(
         IN EAP_SESSION_HANDLE	eapSessionHandle,
         OUT DWORD				*dwSizeOfUIContextData,         
         OUT BYTE				**ppbUIContextData,
         OUT EAP_ERROR			**ppEapError
		 );

DWORD WINAPI SW2EapPeerSetUIContext(
        IN EAP_SESSION_HANDLE		eapSessionHandle,
        IN DWORD					dwSizeOfUIContextData,
        IN const BYTE*				pbUIContextData,
        OUT EapPeerMethodOutput*	pEapPeerMethodOutput,
        OUT EAP_ERROR**				ppEapError
		);

// eaphost runtime functions

DWORD WINAPI SW2EapPeerInitialize(OUT EAP_ERROR** ppEapError);

DWORD WINAPI SW2EapPeerShutdown(OUT EAP_ERROR** ppEapError);

DWORD WINAPI SW2EapPeerBeginSession(
         IN DWORD						dwFlags,
         IN const EapAttributes*		pAttributeArray,
         IN HANDLE						hTokenImpersonateUser,
         IN DWORD						dwSizeofConnectionData,
         IN BYTE*						pbConnectionData,
         IN DWORD						dwSizeofUserData,
         IN BYTE*						pbUserData,
         IN DWORD						dwMaxSendPacketSize,
         OUT EAP_SESSION_HANDLE*		pEapSessionHandle,
         OUT EAP_ERROR**				ppEapError
         );

DWORD WINAPI SW2EapPeerEndSession(
        IN EAP_SESSION_HANDLE eapSessionHandle, 
        OUT EAP_ERROR** ppEapError
		);

DWORD WINAPI SW2EapPeerSetResponseAttributes(
         IN EAP_SESSION_HANDLE sessionHandle,
         IN EapAttributes* pAttribs,
         OUT EapPeerMethodOutput* pEapOutput,
         OUT EAP_ERROR** ppEapError
		 );

DWORD WINAPI SW2EapPeerGetResponseAttributes(
        IN EAP_SESSION_HANDLE sessionHandle,
        OUT EapAttributes* pAttribs,
        OUT EAP_ERROR** ppEapError         
		);

DWORD WINAPI SW2EapPeerGetResult(
	IN EAP_SESSION_HANDLE			eapSessionHandle,
	IN EapPeerMethodResultReason	eapPeerMethodResultReason,
	OUT EapPeerMethodResult*		pEapPeerMethodResult, 
	OUT EAP_ERROR**					ppEapError         
	);

DWORD WINAPI SW2EapPeerGetIdentity(
	IN DWORD			dwFlags,
	IN DWORD			dwSizeofConnectionData,
	IN const BYTE		*pbConnectionData,
	IN DWORD			dwSizeofUserData,
	IN const BYTE		*pUserData,
	IN HANDLE			hTokenImpersonateUser,
	OUT BOOL			*pfInvokeUI,
	IN OUT DWORD		*pdwSizeOfUserDataOut,
	OUT PBYTE			*ppUserDataOut,
	OUT __out PWCHAR	*ppwszIdentity,
	OUT EAP_ERROR		**	ppEapError
	);

DWORD WINAPI SW2EapPeerGetResponsePacket(
         IN EAP_SESSION_HANDLE	eapSessionHandle,
         IN OUT DWORD*			pcbSendPacket,
         OUT EapPacket*			pSendPacket,
         OUT EAP_ERROR**		ppEapError
         );

DWORD WINAPI SW2EapPeerProcessRequestPacket(
         IN EAP_SESSION_HANDLE		eapSessionHandle,
         IN DWORD					cbReceivePacket,
         IN EapPacket*				pReceivePacket,
         OUT EapPeerMethodOutput*	pEapPeerMethodOutput,
         OUT EAP_ERROR**			ppEapError
         );

// util functions
DWORD SW2AllocateandFillEapError(
	IN OUT EAP_ERROR** ppEapError,
	IN DWORD dwErrorCode,  
	IN DWORD dwReasonCode,
	IN LPCGUID pRootCauseGuid,
	IN LPCGUID pRepairGuid,
	IN LPCGUID pHelpLinkGuid,
	IN __in LPWSTR pRootCauseString,
	IN __in LPWSTR pRepairString
	);

DWORD	SW2FreeAttributes(
    IN OUT EapAttributes **ppEapAttributes
	);

DWORD SW2_RegisterEapHostDLL();
DWORD SW2_UnregisterEapHostDLL();
