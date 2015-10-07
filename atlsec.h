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

#include <Security.h>


BOOLEAN GetUserNameExA(__in EXTENDED_NAME_FORMAT NameFormat, __out ATL::CAtlStringA &sName)
{
    ULONG ulSize = 0;

    // Query the final string length first.
    if (!::GetUserNameExA(NameFormat, NULL, &ulSize)) {
        if (::GetLastError() == ERROR_MORE_DATA) {
            // Prepare the buffer and retry.
            LPSTR szBuffer = sName.GetBuffer(ulSize - 1);
            if (!szBuffer) {
                SetLastError(ERROR_OUTOFMEMORY);
                return FALSE;
            }
            if (::GetUserNameExA(NameFormat, szBuffer, &ulSize)) {
                sName.ReleaseBuffer(ulSize);
                return TRUE;
            } else {
                sName.ReleaseBuffer(0);
                return FALSE;
            }
        } else {
            // Return error.
            return FALSE;
        }
    } else {
        // The result is empty.
        sName.Empty();
        return NO_ERROR;
    }
}


BOOLEAN GetUserNameExW(__in EXTENDED_NAME_FORMAT NameFormat, __out ATL::CAtlStringW &sName)
{
    ULONG ulSize = 0;

    // Query the final string length first.
    if (!::GetUserNameExW(NameFormat, NULL, &ulSize)) {
        if (::GetLastError() == ERROR_MORE_DATA) {
            // Prepare the buffer and retry.
            LPWSTR szBuffer = sName.GetBuffer(ulSize - 1);
            if (!szBuffer) {
                SetLastError(ERROR_OUTOFMEMORY);
                return FALSE;
            }
            if (::GetUserNameExW(NameFormat, szBuffer, &ulSize)) {
                sName.ReleaseBuffer(ulSize);
                return TRUE;
            } else {
                sName.ReleaseBuffer(0);
                return FALSE;
            }
        } else {
            // Return error.
            return FALSE;
        }
    } else {
        // The result is empty.
        sName.Empty();
        return NO_ERROR;
    }
}
