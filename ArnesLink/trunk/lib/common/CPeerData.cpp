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


AL::RASEAP::CPeerData::CPeerData() :
    m_dwType(0),
    m_dwInvokeUsernameDlg(0),
    m_dwInvokePasswordDlg(0)
{
}


//
// Read the inner EAP information from the registry
//
DWORD AL::RASEAP::CPeerData::Load(_In_ DWORD dwType)
{
    DWORD dwReturnCode;

    //
    // Initialize to default.
    //
    m_dwType = dwType;

    ATL::CAtlString sTemp;
    sTemp.Format(_T("SYSTEM\\CurrentControlSet\\Services\\RasMan\\PPP\\EAP\\%ld"), dwType);

    ATL::CRegKey reg;
    if ((dwReturnCode = reg.Open(HKEY_LOCAL_MACHINE, sTemp, KEY_QUERY_VALUE)) != NO_ERROR) {
        AL_TRACE_ERROR(_T("Error opening RASEAP peer key %s in registry (%ld)."), (LPCTSTR)sTemp, dwReturnCode);
        return ERROR_CANTOPEN;
    }

    //
    // Read friendly name.
    //
    if ((dwReturnCode = RegLoadMUIString(reg, _T("FriendlyName"), m_sFriendlyName, 0, NULL)) != NO_ERROR) {
        AL_TRACE_ERROR(_T("Error reading RASEAP peer %ld name from registry (%ld)."), dwType, dwReturnCode);
        return ERROR_NOT_FOUND;
    }

    //
    // Read Path.
    //
    if ((dwReturnCode = RegQueryStringValue(reg, L"Path", m_sPath)) != NO_ERROR) {
        AL_TRACE_ERROR(_T("Error reading RASEAP peer %ld path from registry (%ld)."), dwType, dwReturnCode);
        return ERROR_NOT_FOUND;
    }

    //
    // Read ConfigUIPath.
    //
    if (RegQueryStringValue(reg, L"ConfigUIPath", m_sPathConfigUI) != NO_ERROR) {
        AL_TRACE_WARNING(_T("ConfigUIPath not defined for RASEAP peer %ls, cannot configure EAP method."), dwType);
        m_sPathConfigUI.Empty();
    }

    //
    // Read IdentityPath.
    //
    if (RegQueryStringValue(reg, L"IdentityPath", m_sPathIdentity) != NO_ERROR) {
        AL_TRACE_WARNING(_T("IdentityPath not defined for RASEAP peer %ls, EAP method not used for identity."), dwType);
        m_sPathIdentity.Empty();
    }

    //
    // Read InteractiveUIPath.
    //
    if (RegQueryStringValue(reg, L"InteractiveUIPath", m_sPathInteractiveUI) != NO_ERROR) {
        AL_TRACE_WARNING(_T("InteractiveUIPath not defined for RASEAP peer %ls, EAP method not used for interactive UI."), dwType);
        m_sPathIdentity.Empty();
    }

    if (reg.QueryDWORDValue(L"InvokeUsernameDialog", m_dwInvokeUsernameDlg) != NO_ERROR)
        m_dwInvokeUsernameDlg = 0;

    if (reg.QueryDWORDValue(L"InvokePasswordDialog", m_dwInvokePasswordDlg) != NO_ERROR)
        m_dwInvokePasswordDlg = 0;

    return NO_ERROR;
}
