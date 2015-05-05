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


AL::RASEAP::CPeerInstanceBase::CPeerInstanceBase() :
    RasEapFreeMemory(NULL),
    ATL::CAtlLibrary()
{
}


DWORD AL::RASEAP::CPeerInstanceBase::Load(_In_ LPCTSTR lpFileName)
{
    DWORD dwReturnCode;
    if (!ATL::CAtlLibrary::Load(lpFileName, NULL, 0)) {
        AL_TRACE_ERROR(_T("LoadLibrary(%s) failed (%ld)."), lpFileName, dwReturnCode = GetLastError());
        return dwReturnCode;
    }

    //
    // Get functions.
    //
    if ((RasEapFreeMemory = (PINNERFREEMEMORY)GetProcAddress(m_h, "RasEapFreeMemory")) == NULL) {
        AL_TRACE_ERROR(_T("RasEapFreeMemory not found in %s."), lpFileName);
        return ERROR_NOT_SUPPORTED;
    }

    return NO_ERROR;
}
