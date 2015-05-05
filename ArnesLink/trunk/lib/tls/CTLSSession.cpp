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


AL::TLS::CTLSSession::CTLSSession() :
    m_TLSState(STATE_START),
    m_algEncKey(0),
    m_dwEncKeySize(0),
    m_algMacKey(0),
    m_dwMacKeySize(0),
    m_bCompression(0),
    m_nReceiveCursor(0),
    m_dwSeqNum((DWORD)-1),
    m_fCipherSpec(FALSE),
    m_fServerFinished(FALSE),
    m_fFoundAlert(FALSE),
    m_fSentFinished(FALSE),
    m_fCertRequest(FALSE),
    m_tTLSSessionID(0)
{
    ZeroMemory(m_pbPMS         , sizeof(m_pbPMS         ));
    ZeroMemory(m_pbMacWrite    , sizeof(m_pbMacWrite    ));
    ZeroMemory(m_pbMacRead     , sizeof(m_pbMacRead     ));
    ZeroMemory(m_pbRandomClient, sizeof(m_pbRandomClient));
    ZeroMemory(m_pbRandomServer, sizeof(m_pbRandomServer));
    ZeroMemory(m_pbCipher      , sizeof(m_pbCipher      ));
    ZeroMemory(m_pbMS          , sizeof(m_pbMS          ));
}


void AL::TLS::CTLSSession::Reset()
{
    m_dwSeqNum = (DWORD)-1;

    m_TLSState = AL::TLS::STATE_START;

    ZeroMemory(m_pbPMS, sizeof(m_pbPMS));

    m_algEncKey = 0;
    m_dwEncKeySize = 0;

    m_algMacKey = 0;
    m_dwMacKeySize = 0;
    ZeroMemory(m_pbMacWrite, sizeof(m_pbMacWrite));
    ZeroMemory(m_pbMacRead , sizeof(m_pbMacRead ));

    m_keyRead.Free();
    m_keyWrite.Free();

    m_lCertificateChain.RemoveAll();

    ZeroMemory(m_pbRandomClient, sizeof(m_pbRandomClient));
    ZeroMemory(m_pbRandomServer, sizeof(m_pbRandomServer));
    ZeroMemory(m_pbCipher      , sizeof(m_pbCipher      ));

    m_bCompression = 0;

    m_lHandshakeMsgs.RemoveAll();

    ResetReceiveMsg();

    m_fCipherSpec     = FALSE;
    m_fServerFinished = FALSE;
    m_fSentFinished   = FALSE;
    m_fCertRequest    = FALSE;

    m_aState.RemoveAll();
}


void AL::TLS::CTLSSession::ResetReceiveMsg()
{
    m_aReceiveMsg.RemoveAll();
    m_nReceiveCursor = 0;
}


DWORD AL::TLS::CTLSSession::AddHandshakeMessage(_In_bytecount_(dwMessageSize) LPCBYTE pbMessage, _In_ SIZE_T nMessageSize)
{
    ATL::CAtlArray<BYTE> &aMsg = m_lHandshakeMsgs.GetAt(m_lHandshakeMsgs.AddTail());
    if (aMsg.SetCount(nMessageSize)) {
        memcpy(aMsg.GetData(), pbMessage, nMessageSize);
        return NO_ERROR;
    } else {
        AL_TRACE_ERROR(_T("Error allocating memory for TLS message."));
        return ERROR_OUTOFMEMORY;
    }
}
