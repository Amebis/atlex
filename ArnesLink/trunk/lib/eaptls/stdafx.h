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

//
// Use Windows XP visual styles
//
#define ISOLATION_AWARE_ENABLED 1

#include "..\common\common.h"
#include "..\atl\atlwin.h"

#include <atlbase.h>
#include <atlfile.h>
#include <CommCtrl.h>
#include <cryptuiapi.h>
#include <IPHlpApi.h>
#include <RasError.h>
#include <Shlwapi.h>
#include <ShObjIdl.h>
#include <tchar.h>
#ifdef USE_WINXP_THEMES
#include <Uxtheme.h>
#endif
