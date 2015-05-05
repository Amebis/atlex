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

#pragma once

#include "..\..\lib\common\common.h"

#include <IPHlpApi.h>
#include <RasError.h>
#include <Shlwapi.h>
#include <tchar.h>

DWORD AuthHandleInnerPAPAuthentication(_Inout_ AL::TLS::CSessionData *pSessionData, _Out_ AL::EAP::CPacket &pktSend, _Out_ EapPeerMethodOutput* pEapPeerMethodOutput);
#ifdef AL_EAPHOST
DWORD AuthHandleInnerEAPHOSTAuthentication(_Inout_ AL::TLS::CSessionData *pSessionData, _Out_ AL::EAP::CPacket &pktSend, _Out_ EapPeerMethodOutput* pEapPeerMethodOutput);
#endif
DWORD AuthHandleInnerEAPAuthentication(_Inout_ AL::TLS::CSessionData *pSessionData, _Out_ AL::EAP::CPacket &pktSend, _Out_ EapPeerMethodOutput* pEapPeerMethodOutput);
