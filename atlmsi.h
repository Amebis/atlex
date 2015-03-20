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

#include <atlcoll.h>
#include <atlstr.h>
#include <MsiQuery.h>


inline UINT MsiGetPropertyA(MSIHANDLE hInstall, LPCSTR szName, ATL::CAtlStringA &sValue)
{
    DWORD dwSize = 0;
    UINT uiResult;

    // Query the actual string length first.
    uiResult = ::MsiGetPropertyA(hInstall, szName, "", &dwSize);
    if (uiResult == ERROR_MORE_DATA) {
        // Prepare the buffer to read the string data into and read it.
        LPSTR szBuffer = sValue.GetBuffer(dwSize++);
        if (!szBuffer) return ERROR_OUTOFMEMORY;
        uiResult = ::MsiGetPropertyA(hInstall, szName, szBuffer, &dwSize);
        sValue.ReleaseBuffer(uiResult == NO_ERROR ? dwSize : 0);
        return uiResult;
    } else if (uiResult == NO_ERROR) {
        // The string in database is empty.
        sValue.Empty();
        return NO_ERROR;
    } else {
        // Return error code.
        return uiResult;
    }
}


inline UINT MsiGetPropertyW(MSIHANDLE hInstall, LPCWSTR szName, ATL::CAtlStringW &sValue)
{
    DWORD dwSize = 0;
    UINT uiResult;

    // Query the actual string length first.
    uiResult = ::MsiGetPropertyW(hInstall, szName, L"", &dwSize);
    if (uiResult == ERROR_MORE_DATA) {
        // Prepare the buffer to read the string data into and read it.
        LPWSTR szBuffer = sValue.GetBuffer(dwSize++);
        if (!szBuffer) return ERROR_OUTOFMEMORY;
        uiResult = ::MsiGetPropertyW(hInstall, szName, szBuffer, &dwSize);
        sValue.ReleaseBuffer(uiResult == NO_ERROR ? dwSize : 0);
        return uiResult;
    } else if (uiResult == NO_ERROR) {
        // The string in database is empty.
        sValue.Empty();
        return NO_ERROR;
    } else {
        // Return error code.
        return uiResult;
    }
}


inline UINT MsiRecordGetStringA(MSIHANDLE hRecord, unsigned int iField, ATL::CAtlStringA &sValue)
{
    DWORD dwSize = 0;
    UINT uiResult;

    // Query the actual string length first.
    uiResult = ::MsiRecordGetStringA(hRecord, iField, "", &dwSize);
    if (uiResult == ERROR_MORE_DATA) {
        // Prepare the buffer to read the string data into and read it.
        LPSTR szBuffer = sValue.GetBuffer(dwSize++);
        if (!szBuffer) return ERROR_OUTOFMEMORY;
        uiResult = ::MsiRecordGetStringA(hRecord, iField, szBuffer, &dwSize);
        sValue.ReleaseBuffer(uiResult == NO_ERROR ? dwSize : 0);
        return uiResult;
    } else if (uiResult == NO_ERROR) {
        // The string in database is empty.
        sValue.Empty();
        return NO_ERROR;
    } else {
        // Return error code.
        return uiResult;
    }
}


inline UINT MsiRecordGetStringW(MSIHANDLE hRecord, unsigned int iField, ATL::CAtlStringW &sValue)
{
    DWORD dwSize = 0;
    UINT uiResult;

    // Query the actual string length first.
    uiResult = ::MsiRecordGetStringW(hRecord, iField, L"", &dwSize);
    if (uiResult == ERROR_MORE_DATA) {
        // Prepare the buffer to read the string data into and read it.
        LPWSTR szBuffer = sValue.GetBuffer(dwSize++);
        if (!szBuffer) return ERROR_OUTOFMEMORY;
        uiResult = ::MsiRecordGetStringW(hRecord, iField, szBuffer, &dwSize);
        sValue.ReleaseBuffer(uiResult == NO_ERROR ? dwSize : 0);
        return uiResult;
    } else if (uiResult == NO_ERROR) {
        // The string in database is empty.
        sValue.Empty();
        return NO_ERROR;
    } else {
        // Return error code.
        return uiResult;
    }
}


inline UINT MsiFormatRecordA(MSIHANDLE hInstall, MSIHANDLE hRecord, ATL::CAtlStringA &sValue)
{
    DWORD dwSize = 0;
    UINT uiResult;

    // Query the final string length first.
    uiResult = ::MsiFormatRecordA(hInstall, hRecord, "", &dwSize);
    if (uiResult == ERROR_MORE_DATA) {
        // Prepare the buffer to format the string data into and read it.
        LPSTR szBuffer = sValue.GetBuffer(dwSize++);
        if (!szBuffer) return ERROR_OUTOFMEMORY;
        uiResult = ::MsiFormatRecordA(hInstall, hRecord, szBuffer, &dwSize);
        sValue.ReleaseBuffer(uiResult == NO_ERROR ? dwSize : 0);
        return uiResult;
    } else if (uiResult == NO_ERROR) {
        // The result is empty.
        sValue.Empty();
        return NO_ERROR;
    } else {
        // Return error code.
        return uiResult;
    }
}


inline UINT MsiFormatRecordW(MSIHANDLE hInstall, MSIHANDLE hRecord, ATL::CAtlStringW &sValue)
{
    DWORD dwSize = 0;
    UINT uiResult;

    // Query the final string length first.
    uiResult = ::MsiFormatRecordW(hInstall, hRecord, L"", &dwSize);
    if (uiResult == ERROR_MORE_DATA) {
        // Prepare the buffer to format the string data into and read it.
        LPWSTR szBuffer = sValue.GetBuffer(dwSize++);
        if (!szBuffer) return ERROR_OUTOFMEMORY;
        uiResult = ::MsiFormatRecordW(hInstall, hRecord, szBuffer, &dwSize);
        sValue.ReleaseBuffer(uiResult == NO_ERROR ? dwSize : 0);
        return uiResult;
    } else if (uiResult == NO_ERROR) {
        // The result is empty.
        sValue.Empty();
        return NO_ERROR;
    } else {
        // Return error code.
        return uiResult;
    }
}


inline UINT MsiRecordReadStream(MSIHANDLE hRecord, unsigned int iField, ATL::CAtlArray<BYTE> &binData)
{
    DWORD dwSize = 0;
    UINT uiResult;

    // Query the actual data length first.
    uiResult = ::MsiRecordReadStream(hRecord, iField, NULL, &dwSize);
    if (uiResult == NO_ERROR) {
        if (!binData.SetCount(dwSize)) return ERROR_OUTOFMEMORY;
        return ::MsiRecordReadStream(hRecord, iField, (char*)binData.GetData(), &dwSize);
    } else {
        // Return error code.
        return uiResult;
    }
}


inline UINT MsiGetTargetPathA(MSIHANDLE hInstall, LPCSTR szFolder, ATL::CAtlStringA &sValue)
{
    DWORD dwSize = 0;
    UINT uiResult;

    // Query the final string length first.
    uiResult = ::MsiGetTargetPathA(hInstall, szFolder, "", &dwSize);
    if (uiResult == ERROR_MORE_DATA) {
        // Prepare the buffer to format the string data into and read it.
        LPSTR szBuffer = sValue.GetBuffer(dwSize++);
        if (!szBuffer) return ERROR_OUTOFMEMORY;
        uiResult = ::MsiGetTargetPathA(hInstall, szFolder, szBuffer, &dwSize);
        sValue.ReleaseBuffer(uiResult == NO_ERROR ? dwSize : 0);
        return uiResult;
    } else if (uiResult == NO_ERROR) {
        // The result is empty.
        sValue.Empty();
        return NO_ERROR;
    } else {
        // Return error code.
        return uiResult;
    }
}


inline UINT MsiGetTargetPathW(MSIHANDLE hInstall, LPCWSTR szFolder, ATL::CAtlStringW &sValue)
{
    DWORD dwSize = 0;
    UINT uiResult;

    // Query the final string length first.
    uiResult = ::MsiGetTargetPathW(hInstall, szFolder, L"", &dwSize);
    if (uiResult == ERROR_MORE_DATA) {
        // Prepare the buffer to format the string data into and read it.
        LPWSTR szBuffer = sValue.GetBuffer(dwSize++);
        if (!szBuffer) return ERROR_OUTOFMEMORY;
        uiResult = ::MsiGetTargetPathW(hInstall, szFolder, szBuffer, &dwSize);
        sValue.ReleaseBuffer(uiResult == NO_ERROR ? dwSize : 0);
        return uiResult;
    } else if (uiResult == NO_ERROR) {
        // The result is empty.
        sValue.Empty();
        return NO_ERROR;
    } else {
        // Return error code.
        return uiResult;
    }
}
