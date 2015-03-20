/*
    Copyright 1991-2015 Amebis

    This file is part of libatl.

    Setup is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Setup is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Setup. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <atlstr.h>
#include <WinCrypt.h>


inline DWORD CertGetNameStringA(PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void *pvTypePara, ATL::CAtlStringA &sNameString)
{
    // Query the final string length first.
    DWORD dwSize = ::CertGetNameStringA(pCertContext, dwType, dwFlags, pvTypePara, NULL, 0);

    // Prepare the buffer to format the string data into and read it.
    LPSTR szBuffer = sNameString.GetBuffer(dwSize);
    if (!szBuffer) return ERROR_OUTOFMEMORY;
    dwSize = ::CertGetNameStringA(pCertContext, dwType, dwFlags, pvTypePara, szBuffer, dwSize);
    sNameString.ReleaseBuffer(dwSize);
    return dwSize;
}


inline DWORD CertGetNameStringW(PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void *pvTypePara, ATL::CAtlStringW &sNameString)
{
    // Query the final string length first.
    DWORD dwSize = ::CertGetNameStringW(pCertContext, dwType, dwFlags, pvTypePara, NULL, 0);

    // Prepare the buffer to format the string data into and read it.
    LPWSTR szBuffer = sNameString.GetBuffer(dwSize);
    if (!szBuffer) return ERROR_OUTOFMEMORY;
    dwSize = ::CertGetNameStringW(pCertContext, dwType, dwFlags, pvTypePara, szBuffer, dwSize);
    sNameString.ReleaseBuffer(dwSize);
    return dwSize;
}
