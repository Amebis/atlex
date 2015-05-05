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


AL::TLS::CUserData::CUserData() :
    m_sPassword(&AL::Heap::g_stringMgrParanoid),
    m_fSaveCredentials(FALSE),
    m_fPromptForCredentials(FALSE),
    m_tTLSSessionID(0),
    m_EapReasonLast(EapPeerMethodResultUnknown)
{
    ZeroMemory(&m_pbMS, sizeof(m_pbMS));
}


VOID MemPack(_Inout_ BYTE **ppbCursor, _In_ const AL::TLS::CUserData &user)
{
    ::MemPack(ppbCursor, user.m_sIdentity                     );
    {
        int iCount = user.m_sPassword.GetLength();
        ATL::CAtlStringW sEncrypted;
        LPWSTR szBuffer = sEncrypted.GetBuffer(iCount);
        AL::Buffer::XORData((LPCWSTR)user.m_sPassword, szBuffer, sizeof(WCHAR)*iCount, AL_SECUREW2_XORPATTERN, sizeof(AL_SECUREW2_XORPATTERN) - sizeof(CHAR));
        sEncrypted.ReleaseBuffer(iCount);
        ::MemPack(ppbCursor, sEncrypted);
    }
    ::MemPack(ppbCursor, (BYTE)user.m_fSaveCredentials     );
    ::MemPack(ppbCursor, (BYTE)user.m_fPromptForCredentials);
    ::MemPack(ppbCursor, user.m_aTLSSessionID              );
    ::MemPack(ppbCursor, user.m_tTLSSessionID              );
    ::MemPack(ppbCursor, user.m_pbMS                       );
    ::MemPack(ppbCursor, (BYTE)user.m_EapReasonLast        );
    ::MemPack(ppbCursor, user.m_aEAPUserData               );
}


SIZE_T MemGetPackedSize(_In_ const AL::TLS::CUserData &user)
{
    return 
        ::MemGetPackedSize(user.m_sIdentity                  ) +
        ::MemGetPackedSize(user.m_sPassword                  ) +
        ::MemGetPackedSize((BYTE)user.m_fSaveCredentials     ) +
        ::MemGetPackedSize((BYTE)user.m_fPromptForCredentials) +
        ::MemGetPackedSize(user.m_aTLSSessionID              ) +
        ::MemGetPackedSize(user.m_tTLSSessionID              ) +
        ::MemGetPackedSize(user.m_pbMS                       ) +
        ::MemGetPackedSize((BYTE)user.m_EapReasonLast        ) +
        ::MemGetPackedSize(user.m_aEAPUserData               );
}


VOID MemUnpack(_Inout_ const BYTE **ppbCursor, _Out_ AL::TLS::CUserData &user)
{
    BYTE bTemp;

    ::MemUnpack(ppbCursor, user.m_sIdentity    );
    {
        ATL::CAtlStringW sEncrypted;
        ::MemUnpack(ppbCursor, sEncrypted);
        int iCount = sEncrypted.GetLength();
        LPWSTR szBuffer = user.m_sPassword.GetBuffer(iCount);
        AL::Buffer::XORData((LPCWSTR)sEncrypted, szBuffer, sizeof(WCHAR)*iCount, AL_SECUREW2_XORPATTERN, sizeof(AL_SECUREW2_XORPATTERN) - sizeof(CHAR));
        user.m_sPassword.ReleaseBuffer(iCount);
    }
    ::MemUnpack(ppbCursor, bTemp               ); user.m_fSaveCredentials      = bTemp;
    ::MemUnpack(ppbCursor, bTemp               ); user.m_fPromptForCredentials = bTemp;
    ::MemUnpack(ppbCursor, user.m_aTLSSessionID);
    ::MemUnpack(ppbCursor, user.m_tTLSSessionID);
    ::MemUnpack(ppbCursor, user.m_pbMS         );
    ::MemUnpack(ppbCursor, bTemp               ); user.m_EapReasonLast = (EapPeerMethodResultReason)bTemp;
    ::MemUnpack(ppbCursor, user.m_aEAPUserData );
}
