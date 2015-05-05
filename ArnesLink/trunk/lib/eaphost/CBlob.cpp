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


AL::EAP::CBlob::CBlob() :
    m_pCookie(NULL),
    CBlobBase()
{
}


AL::EAP::CBlob::~CBlob()
{
    Free();
}



DWORD AL::EAP::CBlob::Create(_In_ SIZE_T nSize)
{
    DWORD dwReturnCode;

    Free();

    //
    //  Windows 8 introduced a built-in limitation of IPC BLOB maximum size of 4kB. BLOBs equal or larger of 4kB
    //  will make COM Surrogate (DllHost.exe) not being invoked for UI prompts and EAP session silently stalls.
    //  This limitation is overcomed by using temporary files for IPC BLOBs. Unfortunately, there is no exact way
    //  to schedule a temporary file delete. However, we did our best to minimize and limit this leak as much
    //  as possible.
    //
    SIZE_T nCookieSize = sizeof(BLOBCOOKIEHDR) + nSize;
    if (   nCookieSize <= 3*1024
        || AL::System::g_uliVerEap3Host.HighPart <  0x00060002
#ifdef AL_WIN10_DISABLE_INTERACTIONS
        || AL::System::g_uliVerEap3Host.HighPart >= 0x000a0000
#endif
        )
    {
        //
        //    BLOB size is small enough that Windows 8 EAP shouldn't choke on it.
        // Or this is a pre Windows 8 machine, where BLOBs can be any size.
        // Or this is a Windows 10 machine, where UI and IPC won't work any way.
        // => BLOB will be kept on the heap.
        //
        if ((dwReturnCode = AL::Heap::Alloc(nCookieSize, (LPVOID*)&m_pCookie)) == NO_ERROR) {
            // Set BLOB type.
            m_pCookie->type = BLOBCOOKIEHDR::BLOBTYPE_Heap;
            m_pData = m_pCookie + 1;
            m_nSize = nSize;
            return NO_ERROR;
        }
    } else {
        //
        // This is Windows 8 and BLOB size is big enough to cause problems launching DllHost.exe (COM Surrogate).
        // Data will be saved to file.
        //

#ifdef _DEBUG
        //Sleep(10000);
#endif

        // Generate a file name and create a temporary file.
        ATL::CAtlString sFilename;
        {
            LPTSTR szBuffer = sFilename.GetBuffer(MAX_PATH);
            ::GetTempPath(MAX_PATH, szBuffer);
            _tcscat_s(szBuffer, MAX_PATH, _T("ArnesLink\\"));

            // Create a subfolder as other process will need Read&Browse access to read the files and we do not want to tamper the Temp folder permissions.
            CreateDirectory(szBuffer, NULL);
            {
                // Create security descriptor, allowing: Everybody: read, delete, Administrators: full, SYSTEM: full.
                ATL::CDacl dacl;
                dacl.AddAllowedAce(ATL::Sids::World() , GENERIC_READ | DELETE, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
                dacl.AddAllowedAce(ATL::Sids::Admins(), GENERIC_ALL          , OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
                dacl.AddAllowedAce(ATL::Sids::System(), GENERIC_ALL          , OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);

                // Set folder permissions.
                dwReturnCode = SetNamedSecurityInfo(
                    szBuffer,
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    (PSID)ATL::Sids::Admins().GetPSID(),
                    NULL,
                    (PACL)dacl.GetPACL(),
                    NULL);
            }

            ::GetTempFileName(szBuffer, _T("BLOB"), 0, szBuffer);
            sFilename.ReleaseBuffer();
        }
        int iFilenameLenZ = sFilename.GetLength() + 1;
        nCookieSize = sizeof(BLOBCOOKIEHDR) + sizeof(TCHAR)*iFilenameLenZ;

        // m_pCookie will contain BLOB type (BLOBCOOKIEHDR) and the file name (LPCTSTR).
        if ((dwReturnCode = AL::Heap::Alloc(nCookieSize, (LPVOID*)&m_pCookie)) == NO_ERROR) {
            // Set BLOB type.
            m_pCookie->type = BLOBCOOKIEHDR::BLOBTYPE_File;

            // Set file name.
            LPTSTR pszName = (LPTSTR)(m_pCookie + 1);
            memcpy(pszName, (LPCTSTR)sFilename, sizeof(TCHAR)*iFilenameLenZ);

            // Open the file (GetTempFileName() already created it).
            m_hFile = CreateFile(pszName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (m_hFile != INVALID_HANDLE_VALUE) {
                // Create file mapping.
                m_hMapping = CreateFileMapping(m_hFile, NULL, PAGE_READWRITE,
#ifdef _WIN64
                    (DWORD)(nSize >> 32), (DWORD)(nSize & 0xffffffff),
#else
                    0, nSize,
#endif
                    NULL);
                if (m_hMapping) {
                    // Map content into process address space.
                    m_pData = MapViewOfFile(m_hMapping, FILE_MAP_ALL_ACCESS, 0, 0, nSize);
                    if (m_pData) {
                        // Memory must be zeroed for an AL::Heap::Alloc() consistent experience.
                        ZeroMemory(m_pData, nSize);
                        m_nSize = nSize;
                        return NO_ERROR;
                    } else
                        AL_TRACE_ERROR(_T("Error mapping content into process address space (%ld)."), dwReturnCode = GetLastError());

                    CloseHandle(m_hMapping);
                } else
                    AL_TRACE_ERROR(_T("Error creating file mapping %s (%ld)."), pszName, dwReturnCode = GetLastError());

                CloseHandle(m_hFile);
            } else
                AL_TRACE_ERROR(_T("Error opening file %s (%ld)."), pszName, dwReturnCode = GetLastError());

            AL::Heap::Free((LPVOID*)&m_pCookie);
        }
    }

    return dwReturnCode;
}


VOID AL::EAP::CBlob::Free()
{
    if (m_pCookie) {
        switch (m_pCookie->type) {
        case BLOBCOOKIEHDR::BLOBTYPE_Heap:
            break;

        case BLOBCOOKIEHDR::BLOBTYPE_File:
            UnmapViewOfFile(m_pData);
            CloseHandle(m_hMapping);
            CloseHandle(m_hFile   );
            DeleteFile((LPCTSTR)(m_pCookie + 1));
            break;

        default:
            AL_TRACE_ERROR(_T("Invalid BLOB type %ld."), m_pCookie->type);
        }

        m_pData = NULL;
        m_nSize = 0;
        AL::Heap::Free((LPVOID*)&m_pCookie);
    }
}


DWORD AL::EAP::CBlob::Attach(_In_ LPVOID p)
{
    DWORD dwReturnCode;

    Free();

    m_pCookie = (BLOBCOOKIEHDR*)p;
    switch (m_pCookie->type) {
    case BLOBCOOKIEHDR::BLOBTYPE_Heap:
        if ((dwReturnCode = AL::Heap::GetSize(p, &m_nSize)) == NO_ERROR) {
            m_pData  = m_pCookie + 1;
            m_nSize -= sizeof(BLOBCOOKIEHDR);
            return NO_ERROR;
        } else
            m_nSize = 0;
        break;

    case BLOBCOOKIEHDR::BLOBTYPE_File: {
        // Open the file.
        LPTSTR pszName = (LPTSTR)(m_pCookie + 1);
        m_hFile = CreateFile(pszName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (m_hFile != INVALID_HANDLE_VALUE) {
            // Get data size.
            LARGE_INTEGER liSize;
            GetFileSizeEx(m_hFile, &liSize);

            // Create file mapping.
            m_hMapping = CreateFileMapping(m_hFile, NULL, PAGE_READWRITE, liSize.HighPart, liSize.LowPart, NULL);
            if (m_hMapping) {
                // Map content into process address space.
                m_pData = MapViewOfFile(m_hMapping, FILE_MAP_ALL_ACCESS, 0, 0, (SIZE_T)liSize.QuadPart);
                if (m_pData) {
                    m_nSize = (SIZE_T)liSize.QuadPart;
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


LPVOID AL::EAP::CBlob::Detach()
{
    if (m_pCookie) {
        switch (m_pCookie->type) {
        case BLOBCOOKIEHDR::BLOBTYPE_Heap:
            break;

        case BLOBCOOKIEHDR::BLOBTYPE_File:
            UnmapViewOfFile(m_pData);
            CloseHandle(m_hMapping);
            CloseHandle(m_hFile   );
            break;

        default:
            AL_TRACE_ERROR(_T("Invalid BLOB type %ld."), m_pCookie->type);
        }

        m_pData = NULL;
        m_nSize = 0;

        LPVOID p = m_pCookie;
        m_pCookie = NULL;
        return p;
    } else
        return NULL;
}
