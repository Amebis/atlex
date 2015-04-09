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

#include <eaptypes.h>


namespace ATL
{
    namespace EAP
    {
        class CEAPAttribute : public EAP_ATTRIBUTE
        {
        public:
            CEAPAttribute()
            {
                eaType   = eatReserved;
                dwLength = 0;
                pValue   = NULL;
            }

            ~CEAPAttribute()
            {
                if (pValue)
                    delete pValue;
            }
        };
    }
}
