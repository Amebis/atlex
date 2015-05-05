/*
    Copyright 1991-2015 Amebis

    This file is part of ArnesLink.

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


AL::TLS::CSessionData::CSessionData(_In_opt_ HANDLE hTokenImpersonateUser, _In_opt_ LPCBYTE pbConnectionData, _In_opt_ LPCBYTE pbUserData, _In_opt_ const AL::CMonitor *pMonitor) :
    m_bCurrentMethodVersion(0),
    m_bNewMethodVersion(0),
    m_fFlags(0),
    m_hTokenImpersonateUser(hTokenImpersonateUser),
    m_bPacketId(0),
    m_fSaveConfigData(FALSE),
    m_pMonitor(pMonitor),
    m_fSentEapExtensionSuccess(FALSE)
{
    //
    // MemUnpack connection data.
    //
    if (pbConnectionData)
        MemUnpack(&pbConnectionData, m_cfg);

    //
    // MemUnpack user data.
    //
    if (pbUserData)
        MemUnpack(&pbUserData, m_user);

    //
    // Initialize inner data.
    //
    m_Inner.m_pbSessionData        = NULL;
    m_Inner.m_fHandledAccessReject = FALSE;
    ZeroMemory(&(m_Inner.m_EapInput),  sizeof(m_Inner.m_EapInput ));
    m_Inner.m_EapState             = AL::EAP::INNERSTATE_Unknown;
#ifdef AL_EAPHOST
    m_Inner.m_eapSessionId         = NULL;
#endif
}


AL::TLS::CSessionData::~CSessionData()
{
    DWORD dwReturnCode = NO_ERROR;

    //
    // Cleanup Inner Data
    //
    if (AL::EAP::g_bType == AL_EAP_TYPE_PEAP || m_cfg.m_InnerAuth == AL::TLS::INNERMETHOD_EAP) {
        AL_TRACE_INFO(_T("Cleaning inner RASEAP data..."));
        if ((dwReturnCode = m_Inner.m_eap.m_info.RasEapEnd(m_Inner.m_pbSessionData)) == NO_ERROR) {
            m_Inner.m_eap.m_info.RasEapInitialize(FALSE);
        } else
            AL_TRACE_ERROR(_T("Inner method RasEapEnd failed (%ld)."), dwReturnCode);
#ifdef AL_EAPHOST
    } else if (wcscmp(m_cfg.m_pwcInnerAuth, L"EAPHOST") == 0) {
        EAP_ERROR *pEapError = NULL;

        AL_TRACE_INFO(_T("cleaning inner EAPHOST data"));

        if ((dwReturnCode = EapHostPeerEndSession(m_Inner.m_eapSessionId, &pEapError)) == NO_ERROR) {
            EapHostPeerUninitialize();
        } else {
            AL_TRACE_ERROR(_T("EapHostPeerEndSession Failed"));

            if (pEapError)
                EapHostPeerFreeEapError(pEapError);
        }

        if (m_Inner.pEapPeerData)
            AL::Heap::Free((LPVOID*)&m_Inner.pEapPeerData);
#endif // AL_EAPHOST
    }
}
