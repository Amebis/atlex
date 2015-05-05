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


AL::EAP::CBlobReader::CBlobReader() :
    m_pData(NULL),
    m_nSize(0),
    m_pCookie(NULL),
    m_bIsLastConsumer(FALSE)
{
}


AL::EAP::CBlobReader::~CBlobReader()
{
    if (m_pCookie) {
        switch (m_pCookie->type) {
        case BLOBCOOKIEHDR::BLOBTYPE_Heap:
            break;

        case BLOBCOOKIEHDR::BLOBTYPE_File:
            UnmapViewOfFile(m_pData);
            CloseHandle(m_hMapping);
            CloseHandle(m_hFile   );
            if (m_bIsLastConsumer) DeleteFile((LPTSTR)(m_pCookie + 1));
            break;

        default:
            AL_TRACE_ERROR(_T("Invalid BLOB type %ld."), m_pCookie->type);
        }
    }
}



DWORD AL::EAP::CBlobReader::Mount(_In_ LPCVOID p, _In_ SIZE_T nSize, _In_opt_ BOOL bIsLastConsumer)
{
    ATLASSERT(!m_pCookie);

    if (p == NULL || nSize < sizeof(BLOBCOOKIEHDR)) {
        // NULL data is OK too.
        return NO_ERROR;
    }

    DWORD dwReturnCode;
    m_pCookie = (BLOBCOOKIEHDR*)p;
    switch (m_pCookie->type) {
    case BLOBCOOKIEHDR::BLOBTYPE_Heap:
        m_pData = m_pCookie + 1;
        m_nSize = nSize - sizeof(BLOBCOOKIEHDR);
        return NO_ERROR;

    case BLOBCOOKIEHDR::BLOBTYPE_File: {
        // Open the file.
        LPTSTR pszName = (LPTSTR)(m_pCookie + 1);
        m_hFile = CreateFile(pszName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (m_hFile != INVALID_HANDLE_VALUE) {
            // Get data size.
            LARGE_INTEGER liSize;
            GetFileSizeEx(m_hFile, &liSize);

            // Create file mapping.
            m_hMapping = CreateFileMapping(m_hFile, NULL, PAGE_READONLY, liSize.HighPart, liSize.LowPart, NULL);
            if (m_hMapping) {
                // Map content into process address space.
                m_pData = MapViewOfFile(m_hMapping, FILE_MAP_READ, 0, 0, (SIZE_T)liSize.QuadPart);
                if (m_pData) {
                    m_nSize = (SIZE_T)liSize.QuadPart;
                    m_bIsLastConsumer = bIsLastConsumer;
                    return NO_ERROR;
                } else
                    AL_TRACE_ERROR(_T("Error mapping content into process address space (%ld)."), dwReturnCode = GetLastError());

                CloseHandle(m_hMapping);
            } else
                AL_TRACE_ERROR(_T("Error creating file mapping %s (%ld)."), pszName, dwReturnCode = GetLastError());

            CloseHandle(m_hFile);
        } else
            AL_TRACE_ERROR(_T("Error opening file %s (%ld)."), pszName, dwReturnCode = GetLastError());
        break;
    }

    default:
        AL_TRACE_ERROR(_T("Invalid BLOB type %ld."), m_pCookie->type);
        dwReturnCode = ERROR_INVALID_PARAMETER;
    }

    m_pCookie = NULL;
    return dwReturnCode;
}
