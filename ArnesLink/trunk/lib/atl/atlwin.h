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
#include <Windows.h>


inline int GetWindowTextA(__in HWND hWnd, __out ATL::CAtlStringA &sValue)
{
    int iResult;

    // Query the final string length first.
    iResult = ::GetWindowTextLengthA(hWnd);
    if (iResult > 0) {
        // Prepare the buffer to format the string data into and read it.
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
        // Prepare the buffer to format the string data into and read it.
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


inline BOOL RegQueryStringValue(_In_ HKEY hReg, _In_z_ LPCSTR pszName, _Inout_ ATL::CAtlStringA &sValue)
{
    DWORD dwSize = 0;
    DWORD dwType;

    // Determine the type and size first.
    if (::RegQueryValueExA(hReg, pszName, NULL, &dwType, NULL, &dwSize) == ERROR_SUCCESS) {
        if (dwType == REG_SZ || dwType == REG_MULTI_SZ) {
            // The value is REG_SZ or REG_MULTI_SZ. Read it now.
            LPSTR szTemp = sValue.GetBuffer(dwSize / sizeof(TCHAR));
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
            LPSTR szTemp = (LPSTR)::LocalAlloc(LMEM_FIXED, dwSize);
            if (!szTemp) AtlThrow(E_OUTOFMEMORY);
            if (::RegQueryValueExA(hReg, pszName, NULL, NULL, (LPBYTE)szTemp, &dwSize) == ERROR_SUCCESS) {
                // The value was read successfully. Now, expand the environment variables.
                DWORD cCharFinal = dwSize / sizeof(TCHAR) + 0x100; // Initial estimate

                for (;;) {
                    DWORD cCharEx = cCharFinal;
                    LPSTR szTempEx = sValue.GetBuffer(cCharEx);
                    cCharFinal = ::ExpandEnvironmentStringsA(szTemp, szTempEx, cCharEx);
                    if (cCharFinal > cCharEx) {
                        // The buffer was to small. Repeat with a bigger one.
                        sValue.ReleaseBuffer(0);
                    } else {
                        // The buffer was sufficient. Break.
                        sValue.ReleaseBuffer();
                        break;
                    }
                }

                ::LocalFree(szTemp);
                return TRUE;
            } else {
                // Reading of the value failed.
                ::LocalFree(szTemp);
                return FALSE;
            }
        } else {
            // The value is not a string type.
            return FALSE;
        }
    } else {
        // The value with given name doesn't exist in this key.
        return FALSE;
    }
}


inline BOOL RegQueryStringValue(_In_ HKEY hReg, _In_z_ LPCWSTR pszName, _Inout_ ATL::CAtlStringW &sValue)
{
    DWORD dwSize = 0;
    DWORD dwType;

    // Determine the type and size first.
    if (::RegQueryValueExW(hReg, pszName, NULL, &dwType, NULL, &dwSize) == ERROR_SUCCESS) {
        if (dwType == REG_SZ || dwType == REG_MULTI_SZ) {
            // The value is REG_SZ or REG_MULTI_SZ. Read it now.
            LPWSTR szTemp = sValue.GetBuffer(dwSize / sizeof(TCHAR));
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
            LPWSTR szTemp = (LPWSTR)::LocalAlloc(LMEM_FIXED, dwSize);
            if (!szTemp) AtlThrow(E_OUTOFMEMORY);
            if (::RegQueryValueExW(hReg, pszName, NULL, NULL, (LPBYTE)szTemp, &dwSize) == ERROR_SUCCESS) {
                // The value was read successfully. Now, expand the environment variables.
                DWORD cCharFinal = dwSize / sizeof(TCHAR) + 0x100; // Initial estimate

                for (;;) {
                    DWORD cCharEx = cCharFinal;
                    LPWSTR szTempEx = sValue.GetBuffer(cCharEx);
                    cCharFinal = ::ExpandEnvironmentStringsW(szTemp, szTempEx, cCharEx);
                    if (cCharFinal > cCharEx) {
                        // The buffer was to small. Repeat with a bigger one.
                        sValue.ReleaseBuffer(0);
                    } else {
                        // The buffer was sufficient. Break.
                        sValue.ReleaseBuffer();
                        break;
                    }
                }

                ::LocalFree(szTemp);
                return TRUE;
            } else {
                // Reading of the value failed.
                ::LocalFree(szTemp);
                return FALSE;
            }
        } else {
            // The value is not a string type.
            return FALSE;
        }
    } else {
        // The value with given name doesn't exist in this key.
        return FALSE;
    }
}
