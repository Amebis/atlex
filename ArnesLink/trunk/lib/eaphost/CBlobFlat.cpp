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


AL::EAP::CBlobFlat::CBlobFlat() : CBlobBase()
{
}


AL::EAP::CBlobFlat::~CBlobFlat()
{
    if (m_pData)
        AL::Heap::Free((LPVOID*)&m_pData);
}


DWORD AL::EAP::CBlobFlat::Create(_In_ SIZE_T nSize)
{
    if (m_pData)
        AL::Heap::Free((LPVOID*)&m_pData);

    DWORD dwReturnCode;
    if ((dwReturnCode = AL::Heap::Alloc(sizeof(BLOBCOOKIEHDR) + nSize, (LPVOID*)&m_pData)) != NO_ERROR)
        return dwReturnCode;

    m_nSize = nSize;

    return NO_ERROR;
}


VOID AL::EAP::CBlobFlat::Free()
{
    if (m_pData)
        AL::Heap::Free((LPVOID*)&m_pData);

    m_nSize = 0;
}


DWORD AL::EAP::CBlobFlat::Attach(_In_ LPVOID p)
{
    if (m_pData)
        AL::Heap::Free((LPVOID*)&m_pData);

    m_pData = p;
    AL::Heap::GetSize(p, &m_nSize);

    return NO_ERROR;
}


LPVOID AL::EAP::CBlobFlat::Detach()
{
    if (m_pData) {
        LPVOID p = m_pData;

        m_pData = NULL;
        m_nSize = 0;

        return p;
    } else
        return NULL;
}
