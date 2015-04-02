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


namespace ATL
{
    namespace Crypt
    {

        //
        // CCertContext
        //
        class CCertContext
        {
        public:
            inline CCertContext() throw() : m_pCertContext(NULL)
            {
            }

            inline CCertContext(PCCERT_CONTEXT p) throw() : m_pCertContext(p)
            {
            }

            inline ~CCertContext() throw()
            {
                if (m_pCertContext)
                    CertFreeCertificateContext(m_pCertContext);
            }

            inline operator PCCERT_CONTEXT() const throw()
            {
                return m_pCertContext;
            }

            inline const CERT_CONTEXT& operator*() const
            {
                ATLENSURE(m_pCertContext != NULL);
                return *m_pCertContext;
            }

            inline PCCERT_CONTEXT* operator&() throw()
            {
                ATLASSERT(m_pCertContext == NULL);
                return &m_pCertContext;
            }

            inline PCCERT_CONTEXT operator->() const throw()
            {
                ATLASSERT(m_pCertContext != NULL);
                return m_pCertContext;
            }

            inline bool operator!() const throw()
            {
                return m_pCertContext == NULL;
            }

            inline bool operator<(_In_opt_ PCCERT_CONTEXT p) const throw()
            {
                return m_pCertContext < p;
            }

            inline bool operator!=(_In_opt_ PCCERT_CONTEXT p) const
            {
                return !operator==(p);
            }

            inline bool operator==(_In_opt_ PCCERT_CONTEXT p) const throw()
            {
                return m_pCertContext == p;
            }

            inline void Attach(_In_opt_ PCCERT_CONTEXT p) throw()
            {
                if (m_pCertContext)
                    CertFreeCertificateContext(m_pCertContext);
                m_pCertContext = p;
            }

            inline PCCERT_CONTEXT Detach() throw()
            {
                PCCERT_CONTEXT p = m_pCertContext;
                m_pCertContext = NULL;
                return p;
            }

            inline BOOL Create(_In_  DWORD dwCertEncodingType, _In_  const BYTE *pbCertEncoded, _In_  DWORD cbCertEncoded) throw()
            {
                PCCERT_CONTEXT p;

                p = CertCreateCertificateContext(dwCertEncodingType, pbCertEncoded, cbCertEncoded);
                if (!p) return FALSE;

                if (m_pCertContext)
                    CertFreeCertificateContext(m_pCertContext);
                m_pCertContext = p;
                return TRUE;
            }

            inline BOOL Free() throw()
            {
                if (m_pCertContext) {
                    BOOL bResult = CertFreeCertificateContext(m_pCertContext);
                    m_pCertContext = NULL;
                    return bResult;
                } else
                    return TRUE;
            }

        protected:
            PCCERT_CONTEXT m_pCertContext;
        };
    }
}
