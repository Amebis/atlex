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

///
/// \defgroup ATLWLANAPI WLAN API
/// Integrates ATL classes with Microsoft WLAN API
///
/// @{

///
/// Retrieves a string that describes a specified reason code and stores it in a ATL::CAtlStringW string.
///
/// \sa [WlanReasonCodeToString function](https://msdn.microsoft.com/en-us/library/windows/desktop/ms706768.aspx)
///
inline DWORD WlanReasonCodeToString(_In_ DWORD dwReasonCode, _Out_ ATL::CAtlStringW &sValue, __reserved PVOID pReserved)
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
            sValue.ReleaseBuffer(dwLength++);
            if (dwLength == dwSize) {
                // Buffer was long exactly enough.
                return NO_ERROR;
            } else if (dwLength < dwSize) {
                // Buffer was long enough to get entire string, and has some extra space left.
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

/// @}
