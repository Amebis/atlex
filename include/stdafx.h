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

#include "atlwin.h"

#include "atlcrypt.h"
#include "atleap.h"
#include "atlex.h"
#include "atlmsi.h"
#if defined(SECURITY_WIN32) || defined(SECURITY_KERNEL) || defined(SECURITY_MAC)
#include "atlsec.h"
#endif
#include "atlshlwapi.h"
#include "atlwlan.h"
