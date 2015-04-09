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
#include <atlstr.h>


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

        inline CObjectWithHandleT(HANDLE h) throw() : m_h(h)
        {
        }

        inline operator HANDLE() const throw()
        {
            return m_h;
        }

        inline HANDLE*& operator*() const
        {
            ATLENSURE(m_h != NULL);
            return *m_h;
        }

        inline HANDLE* operator&() throw()
        {
            ATLASSERT(m_h == NULL);
            return &m_h;
        }

        inline HANDLE operator->() const throw()
        {
            ATLASSERT(m_h != NULL);
            return m_h;
        }

        inline bool operator!() const throw()
        {
            return m_h == NULL;
        }

        inline bool operator<(_In_opt_ HANDLE h) const throw()
        {
            return m_h < h;
        }

        inline bool operator!=(_In_opt_ HANDLE h) const
        {
            return !operator==(h);
        }

        inline bool operator==(_In_opt_ HANDLE h) const throw()
        {
            return m_h == h;
        }

        inline void Attach(_In_opt_ HANDLE h) throw()
        {
            if (m_h)
                InternalFree();
            m_h = h;
        }

        inline HANDLE Detach() throw()
        {
            HANDLE h = m_h;
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
}
