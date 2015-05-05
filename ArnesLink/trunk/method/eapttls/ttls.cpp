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

    if (dwRecordSize == 0)
        return NO_ERROR;

    //
    // Loop through message
    //
    for (DWORD dwCursor = 0; dwCursor < dwRecordSize && dwReturnCode == NO_ERROR; ) {
        DWORD dwCode = AL::Convert::N2H32(&(pbRecord[dwCursor]));
        dwCursor += 4;
        if (dwCursor > dwRecordSize) {
            AL_TRACE_ERROR(_T("Unexpected end of record."));
            dwReturnCode = ERROR_PPP_INVALID_PACKET;
            break;
        }

        //BYTE bFlags = pbRecord[dwCursor];
        dwCursor++;
        if (dwCursor > dwRecordSize) {
            AL_TRACE_ERROR(_T("Unexpected end of record."));
            dwReturnCode = ERROR_PPP_INVALID_PACKET;
            break;
        }

        //
        // Length of total AVP
        //
        DWORD dwAVPLength = AL::Convert::N2H24(&(pbRecord[dwCursor]));
        dwCursor += 3;
        if (dwCursor > dwRecordSize) {
            AL_TRACE_ERROR(_T("Unexpected end of record."));
            dwReturnCode = ERROR_PPP_INVALID_PACKET;
            break;
        }

        //
        // TODO: if AVP FLags contains the V (Vendor bit) then the following 4 bytes are
        // the vendor field
        //

        //
        // Calculate padding
        //
        // length of AVP must be multiple of 4 octets
        //
        DWORD dwPadding = (dwAVPLength) % 4;
        if (dwPadding != 0)
            dwPadding = 4 - dwPadding;

        //
        // Length of rest of packet is
        //
        // dwDataLength = dwAVPLength - code (4) - Flags(1) - Length of msg (3)
        //
        DWORD dwDataLength = dwAVPLength - 4 - 1 - 3;

        switch (dwCode) {
            case 0x4F: // Eap-Message
                if (!pSessionData->m_TLSSession.m_pktInnerEAPMsg.DuplicateAndAttach((EapPacket*)&(pbRecord[dwCursor]))) {
                    AL_TRACE_ERROR(_T("Error duplicating EAP packet."));
                    dwReturnCode = ERROR_OUTOFMEMORY;
                }
                break;

            case 0x50: // Message-Authenticator
                //
                // Is ignored
                //
                AL_TRACE_DEBUG(_T("Message-Authenticator(%ld)"), dwDataLength);
                AL_DUMP_DEBUG(&(pbRecord[dwCursor]), dwDataLength);
                break;

            case 0x18: // State
                AL_TRACE_DEBUG(_T("State(%ld)"), dwDataLength);
                AL_DUMP_DEBUG(&(pbRecord[dwCursor]), dwDataLength);
                if (pSessionData->m_TLSSession.m_aState.SetCount(dwDataLength))
                    memcpy(pSessionData->m_TLSSession.m_aState.GetData(), &(pbRecord[dwCursor]), dwDataLength);
                else
                    AL_TRACE_ERROR(_T("Error allocating memory for state attribute."));
                break;

            default:
                AL_TRACE_WARNING(_T("Unknown record (0x%x)."), pbRecord[dwCursor]);
        }

        dwCursor += dwDataLength + dwPadding;
    }

    return dwReturnCode;
}
