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


AL::RASEAP::CPeerInstance::CPeerInstance() :
    RasEapGetInfo(NULL),
    CPeerInstanceBase()
{
    ZeroMemory(&m_info, sizeof(m_info));
    m_info.dwSizeInBytes = sizeof(m_info);
}


DWORD AL::RASEAP::CPeerInstance::Load(_In_ const CPeerData *pCfg)
{
    DWORD dwReturnCode;
    if ((dwReturnCode = CPeerInstanceBase::Load(pCfg->m_sPath)) != NO_ERROR)
        return dwReturnCode;

    //
    // Get functions.
    //
    if ((RasEapGetInfo = (PINNERGETINFO)GetProcAddress(m_h, "RasEapGetInfo")) == NULL) {
        AL_TRACE_ERROR(_T("RasEapGetInfo not found in %s."), (LPCTSTR)pCfg->m_sPath);
        return ERROR_NOT_SUPPORTED;
    }

    //
    // Get other RASEAP module info.
    //
    if ((dwReturnCode = RasEapGetInfo(pCfg->m_dwType, &m_info)) != NO_ERROR) {
        AL_TRACE_ERROR(_T("RasEapGetInfo failed (%ld)."), dwReturnCode);
        return dwReturnCode;
    }

    return NO_ERROR;
}
