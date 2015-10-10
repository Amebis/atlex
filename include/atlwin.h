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

#include "atlex.h"
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
        if (!szBuffer) {
            SetLastError(ERROR_OUTOFMEMORY);
            return 0;
        }
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
        if (!szBuffer) {
            SetLastError(ERROR_OUTOFMEMORY);
            return 0;
        }
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


inline VOID GuidToString(_In_ LPCGUID lpGuid, ATL::CAtlStringA &str)
{
    str.Format("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        lpGuid->Data1,
        lpGuid->Data2,
        lpGuid->Data3,
        lpGuid->Data4[0], lpGuid->Data4[1],
        lpGuid->Data4[2], lpGuid->Data4[3], lpGuid->Data4[4], lpGuid->Data4[5], lpGuid->Data4[6], lpGuid->Data4[7]);
}


inline VOID GuidToString(_In_ LPCGUID lpGuid, ATL::CAtlStringW &str)
{
    str.Format(L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        lpGuid->Data1,
        lpGuid->Data2,
        lpGuid->Data3,
        lpGuid->Data4[0], lpGuid->Data4[1],
        lpGuid->Data4[2], lpGuid->Data4[3], lpGuid->Data4[4], lpGuid->Data4[5], lpGuid->Data4[6], lpGuid->Data4[7]);
}


inline LSTATUS RegQueryStringValue(_In_ HKEY hReg, _In_z_ LPCSTR pszName, _Out_ ATL::CAtlStringA &sValue)
{
    LSTATUS lResult;
    DWORD dwSize = 0, dwType;

    // Determine the type and size first.
    if ((lResult = ::RegQueryValueExA(hReg, pszName, NULL, &dwType, NULL, &dwSize)) == ERROR_SUCCESS) {
        if (dwType == REG_SZ || dwType == REG_MULTI_SZ) {
            // The value is REG_SZ or REG_MULTI_SZ. Read it now.
            LPSTR szTemp = sValue.GetBuffer(dwSize / sizeof(CHAR));
            if (!szTemp) return ERROR_OUTOFMEMORY;
            if ((lResult = ::RegQueryValueExA(hReg, pszName, NULL, NULL, (LPBYTE)szTemp, &dwSize)) == ERROR_SUCCESS) {
                sValue.ReleaseBuffer();
            } else {
                // Reading of the value failed.
                sValue.ReleaseBuffer(0);
            }
        } else if (dwType == REG_EXPAND_SZ) {
            // The value is REG_EXPAND_SZ. Read it and expand environment variables.
            ATL::CTempBuffer<CHAR> sTemp(dwSize / sizeof(CHAR));
            if ((lResult = ::RegQueryValueExA(hReg, pszName, NULL, NULL, (LPBYTE)(CHAR*)sTemp, &dwSize)) == ERROR_SUCCESS)
                if (::ExpandEnvironmentStringsA((const CHAR*)sTemp, sValue) == 0)
                    lResult = ::GetLastError();
        } else {
            // The value is not a string type.
            lResult = ERROR_INVALID_DATA;
        }
    }

    return lResult;
}


inline LSTATUS RegQueryStringValue(_In_ HKEY hReg, _In_z_ LPCWSTR pszName, _Out_ ATL::CAtlStringW &sValue)
{
    LSTATUS lResult;
    DWORD dwSize = 0, dwType;

    // Determine the type and size first.
    if ((lResult = ::RegQueryValueExW(hReg, pszName, NULL, &dwType, NULL, &dwSize)) == ERROR_SUCCESS) {
        if (dwType == REG_SZ || dwType == REG_MULTI_SZ) {
            // The value is REG_SZ or REG_MULTI_SZ. Read it now.
            LPWSTR szTemp = sValue.GetBuffer(dwSize / sizeof(WCHAR));
            if (!szTemp) return ERROR_OUTOFMEMORY;
            if ((lResult = ::RegQueryValueExW(hReg, pszName, NULL, NULL, (LPBYTE)szTemp, &dwSize)) == ERROR_SUCCESS) {
                sValue.ReleaseBuffer();
            } else {
                // Reading of the value failed.
                sValue.ReleaseBuffer(0);
            }
        } else if (dwType == REG_EXPAND_SZ) {
            // The value is REG_EXPAND_SZ. Read it and expand environment variables.
            ATL::CTempBuffer<WCHAR> sTemp(dwSize / sizeof(WCHAR));
            if ((lResult = ::RegQueryValueExW(hReg, pszName, NULL, NULL, (LPBYTE)(WCHAR*)sTemp, &dwSize)) == ERROR_SUCCESS)
                if (::ExpandEnvironmentStringsW((const WCHAR*)sTemp, sValue) == 0)
                    lResult = ::GetLastError();
        } else {
            // The value is not a string type.
            lResult = ERROR_INVALID_DATA;
        }
    }

    return lResult;
}


inline LSTATUS RegQueryValueExA(__in HKEY hKey, __in_opt LPCSTR lpValueName, __reserved LPDWORD lpReserved, __out_opt LPDWORD lpType, __out ATL::CAtlArray<BYTE> &aData)
{
    LSTATUS lResult;
    DWORD dwDataSize;

    if ((lResult = RegQueryValueExA(hKey, lpValueName, lpReserved, NULL, NULL, &dwDataSize)) == ERROR_SUCCESS) {
        if (!aData.SetCount(dwDataSize)) return ERROR_OUTOFMEMORY;
        if ((lResult = RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, aData.GetData(), &dwDataSize)) != ERROR_SUCCESS)
            aData.SetCount(0);
    }

    return lResult;
}


inline LSTATUS RegQueryValueExW(__in HKEY hKey, __in_opt LPCWSTR lpValueName, __reserved LPDWORD lpReserved, __out_opt LPDWORD lpType, __out ATL::CAtlArray<BYTE> &aData)
{
    LSTATUS lResult;
    DWORD dwDataSize;

    if ((lResult = RegQueryValueExW(hKey, lpValueName, lpReserved, NULL, NULL, &dwDataSize)) == ERROR_SUCCESS) {
        if (!aData.SetCount(dwDataSize)) return ERROR_OUTOFMEMORY;
        if ((lResult = RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, aData.GetData(), &dwDataSize)) != ERROR_SUCCESS)
            aData.SetCount(0);
    }

    return lResult;
}


#if _WIN32_WINNT >= _WIN32_WINNT_VISTA

inline LSTATUS RegLoadMUIStringA(__in HKEY hKey, __in_opt LPCSTR pszValue, __out ATL::CAtlStringA &sOut, __in DWORD Flags, __in_opt LPCSTR pszDirectory)
{
    LSTATUS lResult;
    DWORD dwSize;

    Flags &= ~REG_MUI_STRING_TRUNCATE;

    lResult = RegLoadMUIStringA(hKey, pszValue, NULL, 0, &dwSize, Flags, pszDirectory);
    if (lResult == ERROR_MORE_DATA) {
        LPSTR szBuffer = sOut.GetBuffer(dwSize - 1);
        if (!szBuffer) return ERROR_OUTOFMEMORY;
        sOut.ReleaseBuffer((lResult = RegLoadMUIStringA(hKey, pszValue, szBuffer, dwSize, &dwSize, Flags, pszDirectory)) == ERROR_SUCCESS ? dwSize - 1 : 0);
    } else if (lResult == ERROR_SUCCESS)
        sOut.Empty();

    return lResult;
}


inline LSTATUS RegLoadMUIStringW(__in HKEY hKey, __in_opt LPCWSTR pszValue, __out ATL::CAtlStringW &sOut, __in DWORD Flags, __in_opt LPCWSTR pszDirectory)
{
    LSTATUS lResult;
    DWORD dwSize;

    Flags &= ~REG_MUI_STRING_TRUNCATE;

    lResult = RegLoadMUIStringW(hKey, pszValue, NULL, 0, &dwSize, Flags, pszDirectory);
    if (lResult == ERROR_MORE_DATA) {
        LPWSTR szBuffer = sOut.GetBuffer(dwSize - 1);
        if (!szBuffer) return ERROR_OUTOFMEMORY;
        sOut.ReleaseBuffer((lResult = RegLoadMUIStringW(hKey, pszValue, szBuffer, dwSize, &dwSize, Flags, pszDirectory)) == ERROR_SUCCESS ? dwSize - 1 : 0);
    } else if (lResult == ERROR_SUCCESS)
        sOut.Empty();

    return lResult;
}

#endif


namespace ATL
{
    class CAtlLibrary : public CObjectWithHandleT<HMODULE>
    {
    public:
        virtual ~CAtlLibrary() throw()
        {
            if (m_h)
                FreeLibrary(m_h);
        }

        inline BOOL Load(__in LPCTSTR lpFileName, __reserved HANDLE hFile, __in DWORD dwFlags) throw()
        {
            HANDLE h = LoadLibraryEx(lpFileName, hFile, dwFlags);
            if (h) {
                Attach(h);
                return TRUE;
            } else
                return FALSE;
        }

    protected:
        virtual void InternalFree()
        {
            FreeLibrary(m_h);
        }
    };
}
