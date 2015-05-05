/*
    Copyright 1991-2015 Amebis

    This file is part of ArnesLink.

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
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Userenv.lib")


AL::CMonitor::CMonitor() :
    m_hSession(NULL),
    m_hTokenImpersonateUser(NULL),
    m_hProfileUser(NULL)
{
}


AL::CMonitor::~CMonitor()
{
    if (m_hTokenImpersonateUser)
        InternalDone();
}


DWORD AL::CMonitor::Init(_In_ HANDLE hTokenImpersonateUser, _In_ HANDLE hSession)
{
    DWORD dwReturnCode = NO_ERROR;

    if (m_hTokenImpersonateUser)
        Done();

    m_hSession = hSession;

    if (DuplicateTokenEx(hTokenImpersonateUser, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, NULL, SecurityIdentification, TokenPrimary, &(m_hTokenImpersonateUser))) {
        //
        // Get user identity.
        //
        TCHAR szIdentity[UNLEN + 3] = _T("\\\\");
        if (ImpersonateLoggedOnUser(m_hTokenImpersonateUser)) {
            ULONG ulSize = _countof(szIdentity) - 2;
            if (!GetUserNameEx(NameDnsDomain, szIdentity + 2, &ulSize)) {
                AL_TRACE_WARNING(_T("GetUserNameEx failed (%ld)."), dwReturnCode = GetLastError());
                szIdentity[2] = 0;
            }
            RevertToSelf();
        } else {
            AL_TRACE_WARNING(_T("ImpersonateLoggedOnUser failed (%ld)."), dwReturnCode = GetLastError());
            szIdentity[2] = 0;
        }

        //
        // Prepare to load user's profile.
        //
        PROFILEINFO ProfileInfo = { sizeof(ProfileInfo) };
        ProfileInfo.dwFlags = PI_NOUI; // Assume process has no UI available.
        LPTSTR pszUserName = _tcschr(szIdentity + 2, _T('\\'));
        if (pszUserName) *pszUserName = 0;
        ProfileInfo.lpUserName   = pszUserName ? pszUserName + 1 : szIdentity + 2;
        ProfileInfo.lpServerName = pszUserName ? szIdentity  + 2 : NULL;

        //
        // If user has a roaming profile, we must handle that too.
        //
        USER_INFO_4 *pUI4 = NULL;
        if ((dwReturnCode = NetUserGetInfo(pszUserName ? szIdentity : NULL, ProfileInfo.lpUserName, 4, (LPBYTE*)&pUI4)) == NERR_Success) {
            ProfileInfo.lpProfilePath = pUI4->usri4_profile;
            dwReturnCode = NO_ERROR;
        } else {
            AL_TRACE_WARNING(_T("NetUserGetInfo failed (%ld)."), dwReturnCode);
            pUI4 = NULL;
        }

        //
        // Load user profile.
        //
        if (LoadUserProfile(m_hTokenImpersonateUser, &(ProfileInfo))) {
            m_hProfileUser = ProfileInfo.hProfile;
        } else
            AL_TRACE_ERROR(_T("LoadUserProfile failed (%ld)."), dwReturnCode = GetLastError());

        if (pUI4)
            NetApiBufferFree(pUI4);

        if ((dwReturnCode = AL::System::GetModulePath(AL::System::g_hInstance, _T("al_monitor.exe"), m_sMonitorFile)) == NO_ERROR) {
            //
            // Start the monitor.
            //
            ATL::CAtlString sTemp;
            sTemp.Format(_T("begin \"%s\""), AL::Trace::g_pszID);
            Send(sTemp, FALSE);
        } else {
            //
            // Free memory.
            //
            if (m_hProfileUser) {
                UnloadUserProfile(m_hTokenImpersonateUser, m_hProfileUser);
                m_hProfileUser = NULL;
            }
            CloseHandle(m_hTokenImpersonateUser);
            m_hTokenImpersonateUser = NULL;
        }
    } else {
        AL_TRACE_ERROR(_T("DuplicateTokenEx failed (%ld)."), dwReturnCode = GetLastError());
        m_hTokenImpersonateUser = NULL;
    }

    return dwReturnCode;
}


void AL::CMonitor::Done()
{
    if (m_hTokenImpersonateUser) {
        InternalDone();

        m_hSession              = NULL;
        m_hProfileUser          = NULL;
        m_hTokenImpersonateUser = NULL;
        m_sMonitorFile.Empty();
    }
}


VOID AL::CMonitor::InternalDone()
{
    //
    // Send monitor end message.
    //
    Send(_T("end"));

    //
    // Free memory
    //
    if (m_hProfileUser)
        UnloadUserProfile(m_hTokenImpersonateUser, m_hProfileUser);

    CloseHandle(m_hTokenImpersonateUser);
}


DWORD AL::CMonitor::Send(_In_z_ LPCTSTR pszParameters, _In_ BOOL bSynchronous) const
{
    DWORD dwReturnCode = NO_ERROR;

    // Sanity check
    if (m_sMonitorFile.IsEmpty()) {
        AL_TRACE_ERROR(_T("m_sMonitorFile is NULL."));
        dwReturnCode = ERROR_INVALID_STATE;
    } else if (m_hTokenImpersonateUser == NULL) {
        AL_TRACE_ERROR(_T("m_hTokenImpersonateUser is NULL."));
        dwReturnCode = ERROR_INVALID_STATE;
    } else {
        ATL::CAtlString sCommandLine;
        STARTUPINFO si;
        PROCESS_INFORMATION pi;

        sCommandLine.Format(_T("\"%s\" %ld-%p %s"), (LPCTSTR)m_sMonitorFile, GetCurrentProcessId(), m_hSession, pszParameters);

        ZeroMemory(&si, sizeof(si));
        si.cb          = sizeof(si);
        si.dwFlags     = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOW;
        si.lpDesktop   = _T("");

        ZeroMemory(&pi, sizeof(pi));

        //
        // Prepare the environment. We want to have the monitor process as comfortable as possible.
        //
        LPVOID pEnv;
        if (!CreateEnvironmentBlock(&pEnv, m_hTokenImpersonateUser, FALSE)) {
            AL_TRACE_ERROR(_T("CreateEnvironmentBlock failed (%ld)."), dwReturnCode = GetLastError());
            pEnv = NULL;
        }

        //
        // Start the monitor process.
        //
        if (CreateProcessAsUser(m_hTokenImpersonateUser, NULL, sCommandLine.GetBuffer(), NULL, NULL, FALSE, pEnv ? CREATE_UNICODE_ENVIRONMENT : NULL, pEnv, NULL, &si, &pi)) {
            sCommandLine.ReleaseBuffer();
            if (bSynchronous) {
                //
                // Wait for process to finish.
                //
                WaitForSingleObject(pi.hProcess, INFINITE);
            }
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        } else {
            sCommandLine.ReleaseBuffer();
            AL_TRACE_ERROR(_T("CreateProcessAsUser failed (%ld)."), dwReturnCode = GetLastError());
        }
    }

    return dwReturnCode;
}


DWORD AL::CMonitor::SendMsg(_In_z_ LPCWSTR pszMessage, _In_z_ LPCWSTR pszTitle, _In_z_ LPCWSTR pszDetails, _In_ BOOL bSynchronous) const
{
    DWORD dwReturnCode = NO_ERROR;

    // Sanity check
    if (pszMessage == NULL) {
        AL_TRACE_ERROR(_T("pszMessage is NULL."));
        dwReturnCode = ERROR_INVALID_PARAMETER;
    } else if (pszTitle == NULL) {
        AL_TRACE_ERROR(_T("pszTitle is NULL."));
        dwReturnCode = ERROR_INVALID_PARAMETER;
    } else {
        //
        // Prepare command line.
        //
        ATL::CAtlStringW sCommandLine, sTemp;
        sCommandLine += L'"';
        AL::Buffer::CommandLine::Encode(pszMessage, sTemp);
        sCommandLine += sTemp;
        sCommandLine += L"\" \"";
        AL::Buffer::CommandLine::Encode(pszTitle, sTemp);
        sCommandLine += sTemp;
        sCommandLine += L"\" \"";

        if (pszDetails && pszDetails[0]) {
            AL::Buffer::CommandLine::Encode(pszDetails, sTemp);
            sCommandLine += sTemp;
        }
        sCommandLine += L'"';

        //
        // Send the message.
        //
        Send(sCommandLine, bSynchronous);
    }

    return dwReturnCode;
}


DWORD AL::CMonitor::SendError(_In_ const EAP_ERROR* pEapError, _In_ BOOL bSynchronous) const
{
    DWORD dwReturnCode = NO_ERROR;

    // Sanity check
    if (pEapError == NULL) {
        AL_TRACE_ERROR(_T("pEapError is NULL."));
        dwReturnCode = ERROR_INVALID_PARAMETER;
    } else if (pEapError->pRootCauseString == NULL) {
        AL_TRACE_ERROR(_T("pEapError->pRootCauseString is NULL."));
        dwReturnCode = ERROR_INVALID_PARAMETER;
    } else {
        if (pEapError->pRepairString && pEapError->pRepairString[0])
            dwReturnCode = SendMsg(L"error", pEapError->pRootCauseString, pEapError->pRepairString, bSynchronous);
        else {
            //
            // Fill repair string with generic instructions.
            //
            WCHAR szTemp[1024];
            AL::System::FormatMsg(IDS_AL_MSGERR_GENERIC_INSTRUCTION, szTemp, _countof(szTemp));
            dwReturnCode = SendMsg(L"error", pEapError->pRootCauseString, szTemp);
        }
    }

    return dwReturnCode;
}
