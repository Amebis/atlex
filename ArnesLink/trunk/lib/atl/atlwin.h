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
#include <Windows.h>


inline DWORD GetModuleFileNameA(__in_opt HMODULE hModule, __out ATL::CAtlStringA &sValue)
{
    DWORD dwSize = 0;

    for (;;) {
        // Increment size and allocate buffer.
        LPSTR szBuffer = sValue.GetBuffer(dwSize += 1024);
        if (!szBuffer) {
            ::SetLastError(ERROR_OUTOFMEMORY);
            return 0;
        }

        // Try!
        DWORD dwResult = ::GetModuleFileNameA(hModule, szBuffer, dwSize);
        if (dwResult == 0) {
            // Error.
            sValue.ReleaseBuffer(0);
            return 0;
        } else if (dwResult < dwSize) {
            DWORD dwLength = (DWORD)strnlen(szBuffer, dwSize);
            sValue.ReleaseBuffer(dwLength++);
            if (dwLength == dwSize) {
                // Buffer was long exactly enough.
                return dwResult;
            } if (dwLength < dwSize) {
                // Buffer was long enough to get entire string, and has some extra space left.
                sValue.FreeExtra();
                return dwResult;
            }
        }
    }
}


inline DWORD GetModuleFileNameW(__in_opt HMODULE hModule, __out ATL::CAtlStringW &sValue)
{
    DWORD dwSize = 0;

    for (;;) {
        // Increment size and allocate buffer.
        LPWSTR szBuffer = sValue.GetBuffer(dwSize += 1024);
        if (!szBuffer) {
            ::SetLastError(ERROR_OUTOFMEMORY);
            return 0;
        }

        // Try!
        DWORD dwResult = ::GetModuleFileNameW(hModule, szBuffer, dwSize);
        if (dwResult == 0) {
            // Error.
            sValue.ReleaseBuffer(0);
            return 0;
        } else if (dwResult < dwSize) {
            DWORD dwLength = (DWORD)wcsnlen(szBuffer, dwSize);
            sValue.ReleaseBuffer(dwLength++);
            if (dwLength == dwSize) {
                // Buffer was long exactly enough.
                return dwResult;
            } if (dwLength < dwSize) {
                // Buffer was long enough to get entire string, and has some extra space left.
                sValue.FreeExtra();
                return dwResult;
            }
        }
    }
}


inline int GetWindowTextA(__in HWND hWnd, __out ATL::CAtlStringA &sValue)
{
    int iResult;

    // Query the final string length first.
    iResult = ::GetWindowTextLengthA(hWnd);
    if (iResult > 0) {
        // Prepare the buffer and read the string data into it.
        LPSTR szBuffer = sValue.GetBuffer(iResult++);
        if (!szBuffer) return 0;
        iResult = ::GetWindowTextA(hWnd, szBuffer, iResult);
        sValue.ReleaseBuffer(iResult);
        return iResult;
    } else {
        // The result is empty.
        sValue.Empty();
        return 0;
    }
}


inline int GetWindowTextW(__in HWND hWnd, __out ATL::CAtlStringW &sValue)
{
    int iResult;

    // Query the final string length first.
    iResult = ::GetWindowTextLengthW(hWnd);
    if (iResult > 0) {
        // Prepare the buffer and read the string data into it.
        LPWSTR szBuffer = sValue.GetBuffer(iResult++);
        if (!szBuffer) return 0;
        iResult = ::GetWindowTextW(hWnd, szBuffer, iResult);
        sValue.ReleaseBuffer(iResult);
        return iResult;
    } else {
        // The result is empty.
        sValue.Empty();
        return 0;
    }
}


inline BOOL GetFileVersionInfoA(__in LPCSTR lptstrFilename, __reserved DWORD dwHandle, __out ATL::CAtlArray<BYTE> &aValue)
{
    // Get version info size.
    DWORD dwVerInfoSize = ::GetFileVersionInfoSizeA(lptstrFilename, &dwHandle);
    if (dwVerInfoSize != 0) {
        if (aValue.SetCount(dwVerInfoSize)) {
            // Read version info.
            return ::GetFileVersionInfoA(lptstrFilename, dwHandle, dwVerInfoSize, aValue.GetData());
        } else {
            ::SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }
    } else
        return FALSE;
}


inline BOOL GetFileVersionInfoW(__in LPCWSTR lptstrFilename, __reserved DWORD dwHandle, __out ATL::CAtlArray<BYTE> &aValue)
{
    // Get version info size.
    DWORD dwVerInfoSize = ::GetFileVersionInfoSizeW(lptstrFilename, &dwHandle);
    if (dwVerInfoSize != 0) {
        if (aValue.SetCount(dwVerInfoSize)) {
            // Read version info.
            return ::GetFileVersionInfoW(lptstrFilename, dwHandle, dwVerInfoSize, aValue.GetData());
        } else {
            ::SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }
    } else
        return FALSE;
}


inline DWORD ExpandEnvironmentStringsA(__in LPCSTR lpSrc, ATL::CAtlStringA &sValue)
{
    DWORD dwBufferSizeEst = (DWORD)strlen(lpSrc) + 0x100; // Initial estimate

    for (;;) {
        DWORD dwBufferSize = dwBufferSizeEst;
        LPSTR szBuffer = sValue.GetBuffer(dwBufferSize);
        if (!szBuffer) {
            ::SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }
        dwBufferSizeEst = ::ExpandEnvironmentStringsA(lpSrc, szBuffer, dwBufferSize);
        if (dwBufferSizeEst > dwBufferSize) {
            // The buffer was to small. Repeat with a bigger one.
            sValue.ReleaseBuffer(0);
        } else if (dwBufferSizeEst == 0) {
            // Error.
            sValue.ReleaseBuffer(0);
            return 0;
        } else {
            // The buffer was sufficient. Break.
            sValue.ReleaseBuffer();
            sValue.FreeExtra();
            return dwBufferSizeEst;
        }
    }
}


inline DWORD ExpandEnvironmentStringsW(__in LPCWSTR lpSrc, ATL::CAtlStringW &sValue)
{
    DWORD dwBufferSizeEst = (DWORD)wcslen(lpSrc) + 0x100; // Initial estimate

    for (;;) {
        DWORD dwBufferSize = dwBufferSizeEst;
        LPWSTR szBuffer = sValue.GetBuffer(dwBufferSize);
        if (!szBuffer) {
            ::SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }
        dwBufferSizeEst = ::ExpandEnvironmentStringsW(lpSrc, szBuffer, dwBufferSize);
        if (dwBufferSizeEst > dwBufferSize) {
            // The buffer was to small. Repeat with a bigger one.
            sValue.ReleaseBuffer(0);
        } else if (dwBufferSizeEst == 0) {
            // Error.
            sValue.ReleaseBuffer(0);
            return 0;
        } else {
            // The buffer was sufficient. Break.
            sValue.ReleaseBuffer();
            sValue.FreeExtra();
            return dwBufferSizeEst;
        }
    }
}



inline BOOL RegQueryStringValue(_In_ HKEY hReg, _In_z_ LPCSTR pszName, _Out_ ATL::CAtlStringA &sValue)
{
    DWORD dwSize = 0;
    DWORD dwType;

    // Determine the type and size first.
    if (::RegQueryValueExA(hReg, pszName, NULL, &dwType, NULL, &dwSize) == ERROR_SUCCESS) {
        if (dwType == REG_SZ || dwType == REG_MULTI_SZ) {
            // The value is REG_SZ or REG_MULTI_SZ. Read it now.
            LPSTR szTemp = sValue.GetBuffer(dwSize / sizeof(TCHAR));
            if (!szTemp) {
                ::SetLastError(ERROR_OUTOFMEMORY);
                return FALSE;
            }
            if (::RegQueryValueExA(hReg, pszName, NULL, NULL, (LPBYTE)szTemp, &dwSize) == ERROR_SUCCESS) {
                sValue.ReleaseBuffer();
                return TRUE;
            } else {
                // Reading of the value failed.
                sValue.ReleaseBuffer(0);
                return FALSE;
            }
        } else if (dwType == REG_EXPAND_SZ) {
            // The value is REG_EXPAND_SZ. Read it and expand environment variables.
            ATL::CTempBuffer<CHAR> sTemp(dwSize / sizeof(CHAR));
            return
                ::RegQueryValueExA(hReg, pszName, NULL, NULL, (LPBYTE)(CHAR*)sTemp, &dwSize) == ERROR_SUCCESS &&
                ::ExpandEnvironmentStringsA((const CHAR*)sTemp, sValue) != 0;
        } else {
            // The value is not a string type.
            return FALSE;
        }
    } else {
        // The value with given name doesn't exist in this key.
        return FALSE;
    }
}


inline BOOL RegQueryStringValue(_In_ HKEY hReg, _In_z_ LPCWSTR pszName, _Out_ ATL::CAtlStringW &sValue)
{
    DWORD dwSize = 0;
    DWORD dwType;

    // Determine the type and size first.
    if (::RegQueryValueExW(hReg, pszName, NULL, &dwType, NULL, &dwSize) == ERROR_SUCCESS) {
        if (dwType == REG_SZ || dwType == REG_MULTI_SZ) {
            // The value is REG_SZ or REG_MULTI_SZ. Read it now.
            LPWSTR szTemp = sValue.GetBuffer(dwSize / sizeof(TCHAR));
            if (!szTemp) {
                ::SetLastError(ERROR_OUTOFMEMORY);
                return FALSE;
            }
            if (::RegQueryValueExW(hReg, pszName, NULL, NULL, (LPBYTE)szTemp, &dwSize) == ERROR_SUCCESS) {
                sValue.ReleaseBuffer();
                return TRUE;
            } else {
                // Reading of the value failed.
                sValue.ReleaseBuffer(0);
                return FALSE;
            }
        } else if (dwType == REG_EXPAND_SZ) {
            // The value is REG_EXPAND_SZ. Read it and expand environment variables.
            ATL::CTempBuffer<WCHAR> sTemp(dwSize / sizeof(WCHAR));
            return
                ::RegQueryValueExW(hReg, pszName, NULL, NULL, (LPBYTE)(WCHAR*)sTemp, &dwSize) == ERROR_SUCCESS &&
                ::ExpandEnvironmentStringsW((const WCHAR*)sTemp, sValue) != 0;
        } else {
            // The value is not a string type.
            return FALSE;
        }
    } else {
        // The value with given name doesn't exist in this key.
        return FALSE;
    }
}
