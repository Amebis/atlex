/*
    ArnesLink, Copyright 1991-2015 Amebis
    SecureW2, Copyright (C) SecureW2 B.V.

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
#pragma comment(lib, "Shlwapi.lib")



DWORD AL::System::GetModulePath(_In_ HMODULE hInstance, _In_z_ LPCTSTR pszLibraryFilename, _Out_ ATL::CAtlString &sModulePath)
{
    DWORD dwResult = NO_ERROR;

    if (GetModuleFileName(hInstance, sModulePath)) {
        LPTSTR pszFilename = PathFindFileName(sModulePath);
        if (pszFilename)
            sModulePath.Truncate((int)(pszFilename - (LPCTSTR)sModulePath));
        else
            sModulePath.Empty();

        sModulePath += pszLibraryFilename;
    } else
        AL_TRACE_ERROR(_T("GetModuleFileName failed (%ld)."), dwResult = GetLastError());

    return dwResult;
}


HMODULE AL::System::LoadLibrary(_In_ HMODULE hInstance, _In_z_ LPCTSTR pszLibraryFilename, _In_ DWORD dwFlags)
{
    DWORD dwResult;
    ATL::CAtlString sLibraryPath;

    if ((dwResult = GetModulePath(hInstance, pszLibraryFilename, sLibraryPath)) == NO_ERROR) {
        HMODULE hInstanceDLL = ::LoadLibraryEx(sLibraryPath, NULL, dwFlags);
        if (!hInstanceDLL) {
            dwResult = GetLastError();
            AL_TRACE_ERROR(_T("LoadLibraryEx(%s) failed (%ld)."), (LPCTSTR)sLibraryPath, dwResult);
        }
        return hInstanceDLL;
    }

    return NULL;
}


DWORD AL::System::FormatMsg(_In_ DWORD dwMessageId, _Out_z_cap_(dwBufferLen) LPTSTR pszBuffer, _In_ DWORD dwBufferLen, ...)
{
    DWORD dwResult = NO_ERROR;
    TCHAR pszTemp[2048];

    if (LoadString(AL::System::g_hResource, dwMessageId, pszTemp, _countof(pszTemp)) != 0) {
        va_list arglist;
        va_start(arglist, dwBufferLen);
        if (FormatMessage(FORMAT_MESSAGE_FROM_STRING, pszTemp, dwMessageId, 0, pszBuffer, dwBufferLen, &arglist) == 0)
            AL_TRACE_ERROR(_T("FormatMessage failed (%ld)."), dwResult = GetLastError());
        va_end(arglist);
    } else
        AL_TRACE_ERROR(_T("LoadString(0x%x) failed (%ld)."), dwMessageId, dwResult = GetLastError());

    return dwResult;
}
