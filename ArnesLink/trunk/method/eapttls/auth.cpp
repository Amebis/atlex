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
// This function is called when the TLS tunnel has been setup and the inner authentication must be done
//
DWORD AL::TLS::AuthHandleInnerAuthentication(_Inout_ CSessionData *pSessionData, _Out_ AL::EAP::CPacket &pktSend, _Out_ EapPeerMethodOutput* pEapPeerMethodOutput)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    {
        WCHAR pszTemp[1024];
        if (AL::System::FormatMsg(IDS_AL_MSG_INNER_AUTH, pszTemp, _countof(pszTemp)) == NO_ERROR)
            pSessionData->m_pMonitor->SendMsg(L"info", pszTemp, NULL);
    }

    switch (pSessionData->m_TLSSession.m_TLSState) {
        case AL::TLS::STATE_CHANGE_CIPHER_SPEC:
        case AL::TLS::STATE_INNER_AUTHENTICATION:
            if (pSessionData->m_cfg.m_InnerAuth == AL::TLS::INNERMETHOD_EAP) {
                AL_TRACE_INFO(_T("Using EAP..."));
                dwReturnCode = AuthHandleInnerEAPAuthentication(pSessionData, pktSend, pEapPeerMethodOutput);
#ifdef AL_EAPHOST
            } else if (wcscmp(L"EAPHOST", pSessionData->m_cfg.m_pwcInnerAuth) == 0) {
                AL_TRACE_INFO(_T("Using EAPHOST..."));
                dwReturnCode = AuthHandleInnerEAPHOSTAuthentication(pSessionData, pktSend, pEapPeerMethodOutput);
#endif
            } else {
                AL_TRACE_INFO(_T("Using PAP..."));
                dwReturnCode = AuthHandleInnerPAPAuthentication(pSessionData, pktSend, pEapPeerMethodOutput);
            }

            pSessionData->m_TLSSession.m_TLSState = AL::TLS::STATE_INNER_AUTHENTICATION;
            break;

        default:
            AL_TRACE_ERROR(_T("Unknown authentication state."));
            dwReturnCode = ERROR_PPP_INVALID_PACKET;
    }

    return dwReturnCode;
}

//
// Name: AL::TLS::AuthMakeDiameterAttribute
// Description: This function builds a diameter attribute
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD AL::TLS::AuthMakeDiameterAttribute(DWORD dwType, LPCBYTE pbData, DWORD cbData, LPBYTE *ppbDiameter, DWORD *pcbDiameter)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // length of AVP must be multiple of 4 octets
    //
    DWORD dwPadding = (0x08 + cbData) % 4;
    if (dwPadding != 0)
        dwPadding = 4 - dwPadding;

    *pcbDiameter = 0x08 + cbData + dwPadding;
    if ((dwReturnCode = AL::Heap::Alloc(*pcbDiameter, (LPVOID*)ppbDiameter)) == NO_ERROR) {
        AL::Convert::H2N32(dwType, &((*ppbDiameter)[0]));

        //
        // Not vendor specific and important so
        // set the M bit
        // 01000000
        //
        (*ppbDiameter)[4] = 0x40;

        //
        // Length of AVP (3 bytes)
        // avp_header(7) + lenght of Password
        //
        AL::Convert::H2N24(cbData + 0x08, &((*ppbDiameter)[5]));

        memcpy(&((*ppbDiameter)[8]), pbData, cbData);
    }

    return dwReturnCode;
}
