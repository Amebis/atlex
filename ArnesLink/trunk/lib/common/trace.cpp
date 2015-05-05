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
#pragma comment(lib, "Rtutils.lib")

static DWORD g_dwID = INVALID_TRACEID;


DWORD AL::Trace::Init(_In_z_ LPCTSTR pszTraceId)
{
    // Sanity checks
    if (g_dwID != INVALID_TRACEID)
        return NO_ERROR;

    if ((g_dwID = TraceRegister(pszTraceId)) == INVALID_TRACEID)
        return GetLastError();

    return NO_ERROR;
}


DWORD AL::Trace::Done()
{
    // Sanity checks
    if (g_dwID == INVALID_TRACEID)
        return NO_ERROR;

    if (!TraceDeregister(g_dwID)) {
        g_dwID = INVALID_TRACEID;
        return NO_ERROR;
    } else
        return GetLastError();
}


VOID AL::Trace::Dump(_In_ LEVEL_T level, _In_bytecount_(cbData) LPCVOID pData, _In_ DWORD cbData, _In_opt_z_ LPCTSTR pszPrefix)
{
    // Sanity checks
    if (g_dwID == INVALID_TRACEID)
        return;

    ATL::CAtlString sTemp(
        (level & LEVEL_ERROR  ) ? _T("E ") :
        (level & LEVEL_WARNING) ? _T("W ") :
        (level & LEVEL_INFO   ) ? _T("I ") :
        (level & LEVEL_DEBUG  ) ? _T("D ") : _T("? "));
    sTemp += pszPrefix;

    /// The default level assigned to each trace message.
    TraceDumpEx(g_dwID, (DWORD)level | TRACE_USE_MASK | TRACE_USE_MSEC, (LPBYTE)pData, cbData, 1, FALSE, sTemp);
}


VOID AL::Trace::Output(_In_ LEVEL_T level, _In_z_ LPCTSTR pszFormat, ...)
{
    ATL::CAtlString sTemp(
        (level & LEVEL_ERROR  ) ? _T("E ") :
        (level & LEVEL_WARNING) ? _T("W ") :
        (level & LEVEL_INFO   ) ? _T("I ") :
        (level & LEVEL_DEBUG  ) ? _T("D ") : _T("? "));
    sTemp += pszFormat;

    va_list arglist;
    va_start(arglist, pszFormat);

#ifdef _DEBUG
    {
        ATL::CAtlString sTemp2;
        sTemp2.FormatV(sTemp, arglist);
        sTemp2 += _T('\n');
        OutputDebugString(sTemp2);
    }
#endif

    if (g_dwID != INVALID_TRACEID)
        TraceVprintfEx(g_dwID, (DWORD)level | TRACE_USE_MASK | TRACE_USE_MSEC, sTemp, arglist);

    va_end(arglist);
}


DWORD AL::Trace::GetFilePath(_In_z_ LPCTSTR pszTraceId, _Out_ ATL::CAtlString &sFilePath)
{
    DWORD dwReturnCode = NO_ERROR;

    ATL::CAtlString sTemp;
    sTemp.Format(_T("Software\\Microsoft\\Tracing\\%s"), pszTraceId);

    ATL::CRegKey reg;
    if ((dwReturnCode = reg.Open(HKEY_LOCAL_MACHINE, sTemp, KEY_READ)) == NO_ERROR) {
        dwReturnCode = RegQueryStringValue(reg, _T("FileDirectory"), sFilePath);
    } else {
        //
        // Assume default tracelog file location.
        //
        sTemp.Format(_T("%%windir%%\\tracing\\%s.LOG"), pszTraceId);
        dwReturnCode = ExpandEnvironmentStrings(sTemp, sFilePath) != 0 ? NO_ERROR : GetLastError();
    }

    return dwReturnCode;
}


DWORD AL::Trace::RemoveConfiguration(_In_z_ LPCTSTR pszTraceId)
{
    DWORD dwReturnCode = NO_ERROR;

    ATL::CRegKey reg;
    if ((dwReturnCode = reg.Open(HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Tracing"), KEY_ALL_ACCESS)) == NO_ERROR) {
        dwReturnCode = reg.RecurseDeleteKey(pszTraceId);
    }

    return dwReturnCode;
}
