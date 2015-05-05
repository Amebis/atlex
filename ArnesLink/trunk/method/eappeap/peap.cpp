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
// This function parses a application data message (DIAMETER AVPs) and acts accordingly
//
DWORD AL::TLS::ParseApplicationDataRecord(_Inout_ AL::TLS::CSessionData *pSessionData, _In_bytecount_(dwRecordSize) LPCBYTE pbRecord, _In_ DWORD dwRecordSize)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // When in MS mode then we must add the (stripped) EAP headers.
    //
    AL_DUMP_DEBUG(pbRecord, dwRecordSize);

    if (pSessionData->m_bCurrentMethodVersion == 0) {
        //
        // When in MS PEAPv0 mode then we must add the (stripped) EAP headers
        //

        //
        // But of course extensions are not stripped... so we skip them
        //
        if (dwRecordSize >= 5 && pbRecord[4] == 0x21) {
            //
            // Handle normally
            //
            if (!pSessionData->m_TLSSession.m_pktInnerEAPMsg.DuplicateAndAttach((EapPacket*)pbRecord)) {
                AL_TRACE_ERROR(_T("Error duplicating EAP packet."));
                dwReturnCode = ERROR_OUTOFMEMORY;
            }
        } else {
            AL_TRACE_DEBUG(_T("PEAPV0, adding stripped EAP headers"));

            //
            // Request
            //
            if ((dwReturnCode = pSessionData->m_TLSSession.m_pktInnerEAPMsg.CreateRequest(pSessionData->m_bPacketId, pbRecord[0], pbRecord[1], (WORD)dwRecordSize + 4)) == NO_ERROR)
                memcpy(pSessionData->m_TLSSession.m_pktInnerEAPMsg->Data + 2, pbRecord + 2, dwRecordSize - 2);
        }
    } else {
        if (!pSessionData->m_TLSSession.m_pktInnerEAPMsg.DuplicateAndAttach((EapPacket*)pbRecord)) {
            AL_TRACE_ERROR(_T("Error duplicating EAP packet."));
            dwReturnCode = ERROR_OUTOFMEMORY;
        }
    }

    return dwReturnCode;
}
