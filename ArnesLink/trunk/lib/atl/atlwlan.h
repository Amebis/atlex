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
#include <wlanapi.h>


inline DWORD WlanReasonCodeToString(__in DWORD dwReasonCode, __out ATL::CAtlStringW &sValue, __reserved PVOID pReserved)
{
    DWORD dwSize = 0;

    for (;;) {
        // Increment size and allocate buffer.
        LPWSTR szBuffer = sValue.GetBuffer(dwSize += 1024);
        if (!szBuffer) return ERROR_OUTOFMEMORY;

        // Try!
        DWORD dwResult = ::WlanReasonCodeToString(dwReasonCode, dwSize, szBuffer, pReserved);
        if (dwResult == NO_ERROR) {
            DWORD dwLength = (DWORD)wcsnlen(szBuffer, dwSize);
            sValue.ReleaseBuffer(dwLength);
            if (dwLength < dwSize - 1) {
                // Buffer was long enough to get entire string.
                sValue.FreeExtra();
                return NO_ERROR;
            }
        } else {
            // Return error code.
            sValue.ReleaseBuffer(0);
            return dwResult;
        }
    }
}
