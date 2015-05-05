/*
    ArnesLink, Copyright 1991-2015 Amebis
    SecureW2, Copyright (C) SecureW2 B.V.

    ArnesLink is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ArnesLink is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ArnesLink. If not, see <http://www.gnu.org/licenses/>.
*/

#include "stdafx.h"


//
// Internal function declarations
//
static DWORD _MakeClientPAPMessage(_In_ const AL::TLS::CSessionData *pSessionData, _Out_bytecap_(*pdwMessageSize) LPBYTE *ppbMessage, DWORD *pdwMessageSize);


//
// This function is called when the TLS tunnel has been setup and the inner authentication must be done
//
DWORD AuthHandleInnerPAPAuthentication(_Inout_ AL::TLS::CSessionData *pSessionData, _Out_ AL::EAP::CPacket &pktSend, _Out_ EapPeerMethodOutput* pEapPeerMethodOutput)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // If the authentication has failed simply return no error when using PAP
    // no need to de-initialize anything as with EAP
    //
    LPBYTE pbMessage;
    DWORD dwMessageSize;
    if ((dwReturnCode = _MakeClientPAPMessage(pSessionData, &pbMessage, &dwMessageSize)) == NO_ERROR) {
        LPBYTE pbRecord;
        DWORD dwRecordSize;
        if ((dwReturnCode = AL::TLS::Record::MakeApplication(&(pSessionData->m_TLSSession), pbMessage, dwMessageSize, &pbRecord, &dwRecordSize, TRUE)) == NO_ERROR) {
            dwReturnCode = pktSend.Append(pbRecord, dwRecordSize, dwRecordSize);

            pEapPeerMethodOutput->action = EapPeerMethodResponseActionSend;

            SecureZeroMemory(pbRecord, dwRecordSize);
            AL::Heap::Free((LPVOID*)&pbRecord);
        }

        SecureZeroMemory(pbMessage, dwMessageSize);
        AL::Heap::Free((LPVOID*)&pbMessage);
    }

    return dwReturnCode;
}


//
// This function is called when we want to use PAP as the Inner Authentication
//
static DWORD _MakeClientPAPMessage(_In_ const AL::TLS::CSessionData *pSessionData, _Out_bytecap_(*pdwMessageSize) LPBYTE *ppbMessage, DWORD *pdwMessageSize)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // Build user ID
    //
    ATL::CW2A sIdentity(pSessionData->m_user.m_sIdentity, CP_UTF8);

    //
    // Build password
    //
    ATL::CW2AParanoid sPassword(pSessionData->m_user.m_sPassword, CP_UTF8);

    //
    // Build the AVPS for PAP
    //
    LPBYTE pbUsernameAVP;
    DWORD dwUsernameAVPSize;
    if ((dwReturnCode = AL::TLS::AuthMakeDiameterAttribute(0x01, (LPCBYTE)(LPCSTR)sIdentity, (DWORD)strlen(sIdentity), &pbUsernameAVP, &dwUsernameAVPSize)) == NO_ERROR) {
        LPBYTE pbPasswordAVP;
        DWORD dwPasswordAVPSize;
        if ((dwReturnCode = AL::TLS::AuthMakeDiameterAttribute(0x02, (LPCBYTE)(LPCSTR)sPassword, (DWORD)strlen(sPassword), &pbPasswordAVP, &dwPasswordAVPSize)) == NO_ERROR) {
            *pdwMessageSize = dwUsernameAVPSize + dwPasswordAVPSize;
            if ((dwReturnCode = AL::Heap::Alloc(*pdwMessageSize, (LPVOID*)ppbMessage)) == NO_ERROR) {
                memcpy(   *ppbMessage,                      pbUsernameAVP, dwUsernameAVPSize);
                memcpy(&((*ppbMessage)[dwUsernameAVPSize]), pbPasswordAVP, dwPasswordAVPSize);
            }

            SecureZeroMemory(pbPasswordAVP, dwPasswordAVPSize);
            AL::Heap::Free((LPVOID*)&pbPasswordAVP);
        }

        AL::Heap::Free((LPVOID*)&pbUsernameAVP);
    }

    return dwReturnCode;
}
