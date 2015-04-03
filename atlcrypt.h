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

#include "atlex.h"
#include <atlcoll.h>
#include <atlstr.h>
#include <WinCrypt.h>


inline DWORD CertGetNameStringA(PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void *pvTypePara, ATL::CAtlStringA &sNameString)
{
    // Query the final string length first.
    DWORD dwSize = ::CertGetNameStringA(pCertContext, dwType, dwFlags, pvTypePara, NULL, 0);

    // Prepare the buffer to format the string data into and read it.
    LPSTR szBuffer = sNameString.GetBuffer(dwSize);
    if (!szBuffer) return ERROR_OUTOFMEMORY;
    dwSize = ::CertGetNameStringA(pCertContext, dwType, dwFlags, pvTypePara, szBuffer, dwSize);
    sNameString.ReleaseBuffer(dwSize);
    return dwSize;
}


inline DWORD CertGetNameStringW(PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void *pvTypePara, ATL::CAtlStringW &sNameString)
{
    // Query the final string length first.
    DWORD dwSize = ::CertGetNameStringW(pCertContext, dwType, dwFlags, pvTypePara, NULL, 0);

    // Prepare the buffer to format the string data into and read it.
    LPWSTR szBuffer = sNameString.GetBuffer(dwSize);
    if (!szBuffer) return ERROR_OUTOFMEMORY;
    dwSize = ::CertGetNameStringW(pCertContext, dwType, dwFlags, pvTypePara, szBuffer, dwSize);
    sNameString.ReleaseBuffer(dwSize);
    return dwSize;
}


inline BOOL CryptGetHashParam(__in HCRYPTHASH  hHash, __in DWORD dwParam, __out ATL::CAtlArray<BYTE> &aData, __in DWORD dwFlags)
{
    DWORD dwHashSize;

    if (CryptGetHashParam(hHash, dwParam, NULL, &dwHashSize, dwFlags)) {
        if (aData.SetCount(dwHashSize)) {
            if (CryptGetHashParam(hHash, dwParam, aData.GetData(), &dwHashSize, dwFlags)) {
                return TRUE;
            } else {
                aData.SetCount(0);
                return FALSE;
            }
        } else {
            SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }
    } else
        return FALSE;
}


namespace ATL
{
    namespace Crypt
    {
        //
        // CCertContext
        //
        class CCertContext : public ATL::CHandleT<PCCERT_CONTEXT>
        {
        public:
            virtual ~CCertContext() throw()
            {
                if (m_h)
                    CertFreeCertificateContext(m_h);
            }

            inline BOOL Create(_In_  DWORD dwCertEncodingType, _In_  const BYTE *pbCertEncoded, _In_  DWORD cbCertEncoded) throw()
            {
                HANDLE h = CertCreateCertificateContext(dwCertEncodingType, pbCertEncoded, cbCertEncoded);
                if (h) {
                    Attach(h);
                    return TRUE;
                } else
                    return FALSE;
            }

        protected:
            virtual void InternalFree()
            {
                CertFreeCertificateContext(m_h);
            }
        };


        //
        // CCertStore
        //
        class CCertStore : public ATL::CHandleT<HCERTSTORE>
        {
        public:
            virtual ~CCertStore() throw()
            {
                if (m_h)
                    CertCloseStore(m_h, 0);
            }

            inline BOOL Create(__in LPCSTR lpszStoreProvider, __in DWORD dwEncodingType, __in_opt HCRYPTPROV_LEGACY hCryptProv, __in DWORD dwFlags, __in_opt const void *pvPara) throw()
            {
                HANDLE h = CertOpenStore(lpszStoreProvider, dwEncodingType, hCryptProv, dwFlags, pvPara);
                if (h) {
                    Attach(h);
                    return TRUE;
                } else
                    return FALSE;
            }

        protected:
            virtual void InternalFree()
            {
                CertCloseStore(m_h, 0);
            }
        };


        //
        // CContext
        //
        class CContext : public ATL::CHandleT<HCRYPTPROV>
        {
        public:
            virtual ~CContext() throw()
            {
                if (m_h)
                    CryptReleaseContext(m_h, 0);
            }

            inline BOOL Create(__in_opt LPCTSTR szContainer, __in_opt LPCTSTR szProvider, __in DWORD dwProvType, __in DWORD dwFlags) throw()
            {
                HANDLE h;
                if (CryptAcquireContext(&h, szContainer, szProvider, dwProvType, dwFlags)) {
                    Attach(h);
                    return TRUE;
                } else
                    return FALSE;
            }

        protected:
            virtual void InternalFree()
            {
                CryptReleaseContext(m_h, 0);
            }
        };


        //
        // CHash
        //
        class CHash : public ATL::CHandleT<HCRYPTHASH>
        {
        public:
            virtual ~CHash() throw()
            {
                if (m_h)
                    CryptDestroyHash(m_h);
            }

            inline BOOL Create(__in HCRYPTPROV  hProv, __in ALG_ID Algid, __in HCRYPTKEY hKey, __in DWORD dwFlags) throw()
            {
                HANDLE h;
                if (CryptCreateHash(hProv, Algid, hKey, dwFlags, &h)) {
                    Attach(h);
                    return TRUE;
                } else
                    return FALSE;
            }

        protected:
            virtual void InternalFree()
            {
                CryptDestroyHash(m_h);
            }
        };
    }
}
