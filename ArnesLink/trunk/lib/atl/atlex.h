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

#include <atldef.h>


namespace ATL
{
    //
    // CObjectWithHandleT
    //
    template <class T>
    class CObjectWithHandleT
    {
    public:
        typedef T HANDLE;

        inline CObjectWithHandleT() throw() : m_h(NULL)
        {
        }

        inline CObjectWithHandleT(T h) throw() : m_h(h)
        {
        }

        inline operator T() const throw()
        {
            return m_h;
        }

        inline T*& operator*() const
        {
            ATLENSURE(m_h != NULL);
            return *m_h;
        }

        inline T* operator&() throw()
        {
            ATLASSERT(m_h == NULL);
            return &m_h;
        }

        inline T operator->() const throw()
        {
            ATLASSERT(m_h != NULL);
            return m_h;
        }

        inline bool operator!() const throw()
        {
            return m_h == NULL;
        }

        inline bool operator<(_In_opt_ T h) const throw()
        {
            return m_h < h;
        }

        inline bool operator!=(_In_opt_ T h) const
        {
            return !operator==(h);
        }

        inline bool operator==(_In_opt_ T h) const throw()
        {
            return m_h == h;
        }

        inline void Attach(_In_opt_ T h) throw()
        {
            if (m_h)
                InternalFree();
            m_h = h;
        }

        inline T Detach() throw()
        {
            T h = m_h;
            m_h = NULL;
            return h;
        }

        inline void Free() throw()
        {
            if (m_h) {
                InternalFree();
                m_h = NULL;
            }
        }

    protected:
        virtual void InternalFree() = 0;

    protected:
        T m_h;
    };
}
