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


AL::RASEAP::CPeerIdentity::CPeerIdentity() :
    RasEapGetIdentity(NULL),
    CPeerInstanceBase()
{
}


DWORD AL::RASEAP::CPeerIdentity::Load(_In_ const CPeerData *pCfg)
{
    DWORD dwReturnCode;
    if ((dwReturnCode = CPeerInstanceBase::Load(pCfg->m_sPathIdentity)) != NO_ERROR)
        return dwReturnCode;

    //
    // Get functions.
    //
    if ((RasEapGetIdentity = (PINNERGETIDENTITY)GetProcAddress(m_h, "RasEapGetIdentity")) == NULL) {
        AL_TRACE_ERROR(_T("RasEapGetIdentity not found in %s."), (LPCTSTR)pCfg->m_sPathIdentity);
        return ERROR_NOT_SUPPORTED;
    }

    return NO_ERROR;
}
