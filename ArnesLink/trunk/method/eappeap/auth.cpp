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
DWORD AL::TLS::AuthHandleInnerAuthentication(_Inout_ AL::TLS::CSessionData *pSessionData, _Out_ AL::EAP::CPacket &pktSend, _Out_ EapPeerMethodOutput* pEapPeerMethodOutput)
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
        case AL::TLS::STATE_RESUME_SESSION_ACK:
        case AL::TLS::STATE_INNER_AUTHENTICATION:
            if (pSessionData->m_cfg.m_InnerAuth == AL::TLS::INNERMETHOD_EAP) {
                AL_TRACE_INFO(_T("EAP"));
                dwReturnCode = AuthHandleInnerEAPAuthentication(pSessionData, pktSend, pEapPeerMethodOutput);
#ifdef AL_EAPHOST
            } else if (wcscmp(L"EAPHOST", pSessionData->m_cfg.m_pwcInnerAuth) == 0) {
                AL_TRACE_INFO(_T("EAPHOST"));
                dwReturnCode = AuthHandleInnerEAPHOSTAuthentication(pSessionData, pktSend, pEapPeerMethodOutput);
#endif
            } else
                dwReturnCode = ERROR_NOT_SUPPORTED;

            pSessionData->m_TLSSession.m_TLSState = AL::TLS::STATE_INNER_AUTHENTICATION;
            break;

        default:
            AL_TRACE_ERROR(_T("Unknown authentication state."));
            dwReturnCode = ERROR_PPP_INVALID_PACKET;
    }

    return dwReturnCode;
}
