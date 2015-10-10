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

#include <atlconv.h>
#include <atldef.h>
#include <atlstr.h>


namespace ATL
{
    /**
     * Base abstract template class to support generic object handle keeping
     * It provides basic operators and methods to ease the replacement of native object handle type with this template class and its descendands.
     */
    template <class T> class CObjectWithHandleT
    {
    public:
        /**
         * Datatype of the object handle this template class handles
         */
        typedef T HANDLE;

        /**\name Constructors */
        /**@{*/
        /**
         * The default constructor
         * Sets the object handle to NULL.
         */
        inline CObjectWithHandleT() throw() : m_h(NULL)
        {
        }

        /**
         *\param h Initial object handle value
         */
        inline CObjectWithHandleT(_In_opt_ HANDLE h) throw() : m_h(h)
        {
        }
        /**@}*/

        /**\name Operators to allow transparent use of this class */
        /**@{*/
        /**
         * Auto-typecasting operator
         *\return Object handle
         */
        inline operator HANDLE() const throw()
        {
            return m_h;
        }

        /**
         * Operator to return object handle value when the object handle is a pointer to a value (class, struct, etc.)
         *\return Object handle value
         */
        inline HANDLE*& operator*() const
        {
            ATLENSURE(m_h != NULL);
            return *m_h;
        }

        /**
         * Operator to return object handle reference
         *\return Object handle reference
         */
        inline HANDLE* operator&() throw()
        {
            ATLASSERT(m_h == NULL);
            return &m_h;
        }

        /**
         * Operator for object handle member access when the object handle is a pointer to a class or struct
         *\return Object handle
         */
        inline HANDLE operator->() const throw()
        {
            ATLASSERT(m_h != NULL);
            return m_h;
        }
        /**@}*/

        /**
         * Test if the object handle is NULL
         *\return
         * - Non zero when object handle is NULL;
         * - Zero otherwise.
         */
        inline bool operator!() const throw()
        {
            return m_h == NULL;
        }

        /**\name Comparison operators */
        /**@{*/
        /**
         * Is less than
         *\param h Object handle value to compare against
         *\return
         * - Non zero when object handle is less than h;
         * - Zero otherwise.
         */
        inline bool operator<(_In_opt_ HANDLE h) const throw()
        {
            return m_h < h;
        }

        /**
         * Is less than or equal to
         *\param h Object handle value to compare against
         *\return
         * - Non zero when object handle is less than or equal to h;
         * - Zero otherwise.
         */
        inline bool operator<=(_In_opt_ HANDLE h) const throw()
        {
            return m_h <= h;
        }

        /**
         * Is greater than or equal to
         *\param h Object handle value to compare against
         *\return
         * - Non zero when object handle is greater than or equal to h;
         * - Zero otherwise.
         */
        inline bool operator>=(_In_opt_ HANDLE h) const throw()
        {
            return m_h >= h;
        }

        /**
         * Is greater than
         *\param h Object handle value to compare against
         *\return
         * - Non zero when object handle is greater than h;
         * - Zero otherwise.
         */
        inline bool operator>(_In_opt_ HANDLE h) const throw()
        {
            return m_h > h;
        }

        /**
         * Is not equal to
         *\param h Object handle value to compare against
         *\return
         * - Non zero when object handle is not equal to h;
         * - Zero otherwise.
         */
        inline bool operator!=(_In_opt_ HANDLE h) const
        {
            return !operator==(h);
        }

        /**
         * Is equal to
         *\param h Object handle value to compare against
         *\return
         * - Non zero when object handle is equal to h;
         * - Zero otherwise.
         */
        inline bool operator==(_In_opt_ HANDLE h) const throw()
        {
            return m_h == h;
        }
        /**@}*/

        /**
         * Set a new object handle for the class
         * When the current object handle of the class is non NULL, the object is destroyed first.
         *\param h New object handle
         */
        inline void Attach(_In_opt_ HANDLE h) throw()
        {
            if (m_h)
                InternalFree();
            m_h = h;
        }

        /**
         * Dismiss the object handle from this class
         *\return Object handle
         */
        inline HANDLE Detach() throw()
        {
            HANDLE h = m_h;
            m_h = NULL;
            return h;
        }

        /**
         * Destroys the object
         */
        inline void Free() throw()
        {
            if (m_h) {
                InternalFree();
                m_h = NULL;
            }
        }

    protected:
        /**
         * Abstract method that must be implemented by child classes to do the actual object destruction
         */
        virtual void InternalFree() = 0;

    protected:
        /*** Object handle */
        HANDLE m_h;
    };


    //
    // CObjectWithHandleDuplT
    //
    template <class T>
    class CObjectWithHandleDuplT : public CObjectWithHandleT<T>
    {
    public:
        inline HANDLE GetDuplicate() const
        {
            return m_h ? InternalDuplicate(m_h) : NULL;
        }

        inline BOOL DuplicateAndAttach(_In_opt_ HANDLE h) throw()
        {
            if (m_h)
                InternalFree();

            return h ? (m_h = InternalDuplicate(h)) != NULL : (m_h = NULL, TRUE);
        }

        //
        // Do not allow = operators. They are semantically ambigious:
        // Do they attach the class to the existing instance of object, or do they duplicate it?
        // To avoid confusion, user should use Attach() and Duplicate() methods explicitly.
        //
        //inline const CObjectWithHandleDuplT<T>& operator=(_In_ const HANDLE src)
        //{
        //    Attach(src ? InternalDuplicate(src) : NULL);
        //    return *this;
        //}

        //inline const CObjectWithHandleDuplT<T>& operator=(_In_ const CObjectWithHandleDuplT<T> &src)
        //{
        //    Attach(src.m_h ? InternalDuplicate(src.m_h) : NULL);
        //    return *this;
        //}

    protected:
        virtual HANDLE InternalDuplicate(HANDLE h) const = 0;
    };


    //
    // CStrFormatT, CStrFormatW, CStrFormatA, CStrFormat
    //
    template<typename BaseType, class StringTraits>
    class CStrFormatT : public CStringT<BaseType, StringTraits>
    {
    public:
        CStrFormatT(_In_z_ _FormatMessage_format_string_ PCXSTR pszFormat, ...)
        {
            ATLASSERT(AtlIsValidString(pszFormat));

            va_list argList;
            va_start(argList, pszFormat);
            FormatV(pszFormat, argList);
            va_end(argList);
        }

        CStrFormatT(_In_ _FormatMessage_format_string_ UINT nFormatID, ...)
        {
            CStringT strFormat(GetManager());
            ATLENSURE(strFormat.LoadString(nFormatID));

            va_list argList;
            va_start(argList, nFormatID);
            FormatV(strFormat, argList);
            va_end(argList);
        }

        CStrFormatT(_In_ HINSTANCE hInstance, _In_ _FormatMessage_format_string_ UINT nFormatID, ...)
        {
            CStringT strFormat(GetManager());
            ATLENSURE(strFormat.LoadString(hInstance, nFormatID));

            va_list argList;
            va_start(argList, nFormatID);
            FormatV(strFormat, argList);
            va_end(argList);
        }

        CStrFormatT(_In_ HINSTANCE hInstance, _In_ WORD wLanguageID, _In_ _FormatMessage_format_string_ UINT nFormatID, ...)
        {
            CStringT strFormat(GetManager());
            ATLENSURE(strFormat.LoadString(hInstance, nFormatID, wLanguageID));

            va_list argList;
            va_start(argList, nFormatID);
            FormatV(strFormat, argList);
            va_end(argList);
        }
    };

    typedef CStrFormatT< wchar_t, StrTraitATL< wchar_t, ChTraitsCRT< wchar_t > > > CStrFormatW;
    typedef CStrFormatT< char, StrTraitATL< char, ChTraitsCRT< char > > > CStrFormatA;
    typedef CStrFormatT< TCHAR, StrTraitATL< TCHAR, ChTraitsCRT< TCHAR > > > CStrFormat;


    //
    // CStrFormatMsgT, CStrFormatMsgW, CStrFormatMsgA, CStrFormatMsg
    //
    template<typename BaseType, class StringTraits>
    class CStrFormatMsgT : public CStringT<BaseType, StringTraits>
    {
    public:
        CStrFormatMsgT(_In_z_ _FormatMessage_format_string_ PCXSTR pszFormat, ...)
        {
            ATLASSERT(AtlIsValidString(pszFormat));

            va_list argList;
            va_start(argList, pszFormat);
            FormatMessageV(pszFormat, &argList);
            va_end(argList);
        }

        CStrFormatMsgT(_In_ _FormatMessage_format_string_ UINT nFormatID, ...)
        {
            CStringT strFormat(GetManager());
            ATLENSURE(strFormat.LoadString(nFormatID));

            va_list argList;
            va_start(argList, nFormatID);
            FormatMessageV(strFormat, &argList);
            va_end(argList);
        }

        CStrFormatMsgT(_In_ HINSTANCE hInstance, _In_ _FormatMessage_format_string_ UINT nFormatID, ...)
        {
            CStringT strFormat(GetManager());
            ATLENSURE(strFormat.LoadString(hInstance, nFormatID));

            va_list argList;
            va_start(argList, nFormatID);
            FormatMessageV(strFormat, &argList);
            va_end(argList);
        }

        CStrFormatMsgT(_In_ HINSTANCE hInstance, _In_ WORD wLanguageID, _In_ _FormatMessage_format_string_ UINT nFormatID, ...)
        {
            CStringT strFormat(GetManager());
            ATLENSURE(strFormat.LoadString(hInstance, nFormatID, wLanguageID));

            va_list argList;
            va_start(argList, nFormatID);
            FormatMessageV(strFormat, &argList);
            va_end(argList);
        }
    };

    typedef CStrFormatMsgT< wchar_t, StrTraitATL< wchar_t, ChTraitsCRT< wchar_t > > > CStrFormatMsgW;
    typedef CStrFormatMsgT< char, StrTraitATL< char, ChTraitsCRT< char > > > CStrFormatMsgA;
    typedef CStrFormatMsgT< TCHAR, StrTraitATL< TCHAR, ChTraitsCRT< TCHAR > > > CStrFormatMsg;


    //
    // CParanoidHeap
    //
    template <class BaseHeap>
    class CParanoidHeap : public BaseHeap {
    public:
        virtual void Free(_In_opt_ void* p) throw()
        {
            // Sanitize then free.
            SecureZeroMemory(p, GetSize(p));
            BaseHeap::Free(p);
        }

        _Ret_opt_bytecap_(nBytes) virtual void* Reallocate(_In_opt_ void* p, _In_ size_t nBytes) throw()
        {
            // Create a new sized copy.
            void *pNew = Allocate(nBytes);
            size_t nSizePrev = GetSize(p);
            memcpy(pNew, p, nSizePrev);

            // Sanitize the old data then free.
            SecureZeroMemory(p, nSizePrev);
            Free(p);

            return pNew;
        }
    };


    //
    // CW2AParanoidEX
    //
    template<int t_nBufferLength = 128>
    class CW2AParanoidEX : public CW2AEX<t_nBufferLength> {
    public:
        CW2AParanoidEX(_In_z_ LPCWSTR psz) throw(...) : CW2AEX<t_nBufferLength>(psz) {}
        CW2AParanoidEX(_In_z_ LPCWSTR psz, _In_ UINT nCodePage) throw(...) : CW2AEX<t_nBufferLength>(psz, nCodePage) {}
        ~CW2AParanoidEX() throw()
        {
            // Sanitize before free.
            if (m_psz != m_szBuffer)
                SecureZeroMemory(m_psz, _msize(m_psz));
            else
                SecureZeroMemory(m_szBuffer, sizeof(m_szBuffer));
        }
    };

    //
    // CW2AParanoid
    //
    typedef CW2AParanoidEX<> CW2AParanoid;
}
