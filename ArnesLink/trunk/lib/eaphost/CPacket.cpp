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


AL::EAP::CPacket::~CPacket() throw()
{
    if (m_h)
        free(m_h);
}


DWORD AL::EAP::CPacket::Create(_In_ EapCode Code, _In_ BYTE bId, _In_ WORD wLength) throw()
{
    ATLASSERT(wLength >= 4);

    EapPacket *pPacket = (EapPacket*)malloc(wLength);
    if (!pPacket) {
        AL_TRACE_ERROR(_T("Error allocating memory for packet."));
        return ERROR_OUTOFMEMORY;
    }

    //
    // Initialize packet.
    //
    pPacket->Code = (BYTE)Code;
    pPacket->Id   = bId;
    AL::Convert::H2N16(wLength, pPacket->Length);

    //
    // Attach.
    //
    Attach(pPacket);
    return NO_ERROR;
}


DWORD AL::EAP::CPacket::CreateRequest(_In_ BYTE bId, _In_ BYTE bProtocolId, _In_ BYTE bFlags, _In_opt_ WORD wLength)
{
    ATLASSERT(wLength >= 6);

    DWORD dwReturnCode;
    if ((dwReturnCode = Create(EapCodeRequest, bId, wLength)) != NO_ERROR)
        return dwReturnCode;

    m_h->Data[0] = bProtocolId;
    m_h->Data[1] = bFlags;

    return NO_ERROR;
}


DWORD AL::EAP::CPacket::CreateResponse(_In_ BYTE bId, _In_ BYTE bProtocolId, _In_ BYTE bFlags, _In_opt_ WORD wLength)
{
    ATLASSERT(wLength >= 6);

    DWORD dwReturnCode;
    if ((dwReturnCode = Create(EapCodeResponse, bId, wLength)) != NO_ERROR)
        return dwReturnCode;

    m_h->Data[0] = bProtocolId;
    m_h->Data[1] = bFlags;

    return NO_ERROR;
}


DWORD AL::EAP::CPacket::Append(_In_bytecount_(nSize) LPCVOID pBuf, _In_ SIZE_T nSize, _In_ SIZE_T nSizeTotal)
{
    ATLASSERT(m_h);

    SIZE_T
        nPacketSizeNew,
        nRecordSizeNew = 0;
    WORD
        wPacketSize = AL::Convert::N2H16(&m_h->Length[0]),
        wCursor;
    BOOL
        fLengthInc = wPacketSize >= 6 && (m_h->Data[1] & AL_TLS_REQUEST_LENGTH_INC);

    // The packet must be at least 4 bytes.
    ATLASSERT(wPacketSize >= 4);

    if (fLengthInc) {
        DWORD dwRecordSize = wPacketSize >= 10 ? AL::Convert::N2H32(m_h->Data + 2) : 0;
        if (dwRecordSize == 0) {
            // This is the initial packet.
            nPacketSizeNew = nSize + wPacketSize + 4;
            wCursor        = wPacketSize;
        } else {
            nPacketSizeNew = nSize + wPacketSize;
            wCursor        = wPacketSize - 4;
        }
        nRecordSizeNew = nSizeTotal + dwRecordSize;
    } else {
        nPacketSizeNew = nSize + wPacketSize;
        wCursor        = wPacketSize - 4;
    }

    // Sanity check
    if (nPacketSizeNew > MAXWORD) {
        AL_TRACE_ERROR(_T("Packet (%ldB) too big."), nPacketSizeNew);
        return ERROR_INSUFFICIENT_BUFFER;
    }

    // Realloc packet memory.
    EapPacket *pPacket = (EapPacket*)realloc(m_h, nPacketSizeNew);
    if (!pPacket) {
        AL_TRACE_ERROR(_T("Error reallocating memory for packet."));
        return ERROR_OUTOFMEMORY;
    }

    // Update packet length.
    AL::Convert::H2N16((WORD)nPacketSizeNew, pPacket->Length);

    if (fLengthInc) {
        // Update total length of packet.
        AL::Convert::H2N32((DWORD)nRecordSizeNew, pPacket->Data + 2);
    }

    // Copy data.
    memcpy(pPacket->Data + wCursor, pBuf, nSize);
    m_h = pPacket;

    return NO_ERROR;
}


void AL::EAP::CPacket::InternalFree()
{
    free(m_h);
}


EapPacket* AL::EAP::CPacket::InternalDuplicate(EapPacket* h) const
{
    WORD wLength = AL::Convert::N2H16(h->Length);
    EapPacket *pPacketDst = (EapPacket*)malloc(wLength);
    if (pPacketDst) memcpy(pPacketDst, h, wLength);
    return pPacketDst;
}
