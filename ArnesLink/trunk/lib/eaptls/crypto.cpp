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

#include "stdafx.h"


//
// Verifies the certificate chain starting with pCertContext
//
DWORD AL::TLS::Cert::VerifyChain(_In_ const ATL::CAtlList<ATL::Crypt::CCertContext> *plTrustedRootCAs, _In_ const ATL::CAtlList<ATL::Crypt::CCertContext> *plCertificateChain, _In_ POSITION posStart)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // Create temporary store to help verification of sub CA and root CA not globally trusted.
    //
    ATL::Crypt::CCertStore csTemp;
    if (csTemp.Create(CERT_STORE_PROV_MEMORY, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, (HCRYPTPROV)NULL, 0, NULL)) {
        //
        // Dump all trusted CA certificates to the temp store.
        //
        for (POSITION pos = plTrustedRootCAs->GetHeadPosition(); pos; plTrustedRootCAs->GetNext(pos)) {
            const ATL::Crypt::CCertContext &cc = plTrustedRootCAs->GetAt(pos);
            if (!CertAddCertificateContextToStore(csTemp, cc, CERT_STORE_ADD_REPLACE_EXISTING, NULL))
                AL_TRACE_ERROR(_T("CertAddCertificateContextToStore failed (%ld)."), GetLastError());
        }

        //
        // Dump all certificates, except first server (or self signed) certificate to the temp store.
        //
        {
            POSITION pos = posStart;
            plCertificateChain->GetNext(pos);
            for (; pos; plCertificateChain->GetNext(pos)) {
                const ATL::Crypt::CCertContext &cc = plCertificateChain->GetAt(pos);
                if (!CertAddCertificateContextToStore(csTemp, cc, CERT_STORE_ADD_REPLACE_EXISTING, NULL))
                    AL_TRACE_ERROR(_T("CertAddCertificateContextToStore failed (%ld)."), GetLastError());
            }
        }

        //
        // Initialize the certificate chain validation.
        //
        CERT_ENHKEY_USAGE EnhkeyUsage;
        EnhkeyUsage.cUsageIdentifier = 0;
        EnhkeyUsage.rgpszUsageIdentifier = NULL;

        CERT_USAGE_MATCH UsageMatch;
        UsageMatch.dwType = USAGE_MATCH_TYPE_AND;
        UsageMatch.Usage  = EnhkeyUsage;

        //
        // Set all options to 0 but set the ChainParams.dwUrlRetrievalTimeout to 1
        // If ChainParams.dwUrlRetrievalTimeout is not set to 1 then url checking will take forever!
        //
        CERT_CHAIN_PARA ChainParams = { sizeof(ChainParams) };
        ChainParams.dwUrlRetrievalTimeout = 1;
        ChainParams.RequestedUsage = UsageMatch;

        //
        // Check the certificate chain.
        // Do not check urls as we probably do not have any network connectivity.
        //
        const ATL::Crypt::CCertContext &cc = plCertificateChain->GetAt(posStart);
        ATL::Crypt::CCertChainContext ccc;
        if (ccc.Create(NULL, cc, NULL, csTemp, &ChainParams, 0, NULL)) {
            //
            // Check chain validation error flags. Ignore CERT_TRUST_IS_UNTRUSTED_ROOT flag when we check root CA explicitly.
            //
            if (ccc->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR ||
                !plTrustedRootCAs->IsEmpty() && (ccc->TrustStatus.dwErrorStatus & ~CERT_TRUST_IS_UNTRUSTED_ROOT) == CERT_TRUST_NO_ERROR)
            {
                //
                // If required, verify Root CA against ArnesLink Trusted Root CA List
                //
                if (!plTrustedRootCAs->IsEmpty()) {
                    if (ccc->cChain == 1) {
                        if (ccc->rgpChain[0]->cElement > 0) {
                            PCCERT_CONTEXT pRootCACertContext = ccc->rgpChain[0]->rgpElement[ccc->rgpChain[0]->cElement-1]->pCertContext;

                            //
                            // Connect to help CSP
                            //
                            ATL::Crypt::CContext ctx;
                            if ((dwReturnCode = AL::Crypto::AcquireContext(&ctx, NULL)) == NO_ERROR) {
                                ATL::CAtlArray<BYTE> aSHA1;
                                if ((dwReturnCode = AL::Crypto::GetHash(ctx, CALG_SHA1, pRootCACertContext->pbCertEncoded, pRootCACertContext->cbCertEncoded, aSHA1)) == NO_ERROR) {
                                    ATLASSERT(aSHA1.GetCount() == 20);
                                    for (POSITION pos = plTrustedRootCAs->GetHeadPosition(); ; plTrustedRootCAs->GetNext(pos)) {
                                        if (pos) {
                                            const ATL::Crypt::CCertContext &cc = plTrustedRootCAs->GetAt(pos);
                                            ATL::CAtlArray<BYTE> aSHA1Temp;
                                            if ((dwReturnCode = AL::Crypto::GetHash(ctx, CALG_SHA1, cc->pbCertEncoded, cc->cbCertEncoded, aSHA1Temp)) == NO_ERROR) {
                                                ATLASSERT(aSHA1Temp.GetCount() == 20);
                                                if (memcmp(aSHA1Temp.GetData(), aSHA1.GetData(), 20) == 0) {
                                                    //
                                                    // Found!
                                                    //
                                                    AL_TRACE_INFO(_T("Server certificate is signed by a trusted CA."));
                                                    break;
                                                }
                                            }
                                        } else {
                                            //
                                            // End of list reached, not found.
                                            //
                                            AL_TRACE_ERROR(_T("Server certificate is not signed by any of trusted CAs."));
                                            dwReturnCode = ERROR_FILE_NOT_FOUND;
                                            break;
                                        }
                                    }
                                }
                            }
                        } else {
                            AL_TRACE_ERROR(_T("Number of chain elements is zero."));
                            dwReturnCode = ERROR_INTERNAL_ERROR;
                        }
                    } else {
                        AL_TRACE_ERROR(_T("Single chain supported only."));
                        dwReturnCode = ERROR_NOT_SUPPORTED;
                    }
                }
            } else {
                AL_TRACE_ERROR(_T("Chain could not be validated (%ld)."), dwReturnCode = ccc->TrustStatus.dwErrorStatus);
                dwReturnCode = (DWORD)CERT_E_UNTRUSTEDROOT;
            }
        } else
            AL_TRACE_ERROR(_T("CertGetCertificateChain failed (%ld)."), dwReturnCode = GetLastError());
    } else
        AL_TRACE_ERROR(_T("CertOpenStore failed (%ld)."), dwReturnCode = GetLastError());

    return dwReturnCode;
}


//
// Verifies if the certificate pCertContext is installed
// in the local computer store
//
DWORD AL::TLS::Cert::VerifyInStore(_In_ PCCERT_CONTEXT pCertContext)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // Connect to help CSP
    //
    ATL::Crypt::CContext ctx;
    if ((dwReturnCode = AL::Crypto::AcquireContext(&ctx, NULL)) == NO_ERROR) {
        //
        // Retrieve Subject name of certificate
        //
        ATL::CAtlString sSubjectName;
        if (CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, sSubjectName) > 0) {
            //
            // Get HASH of certificate
            //
            ATL::CAtlArray<BYTE> aMD5;
            if ((dwReturnCode = AL::Crypto::GetHash(ctx, CALG_MD5, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, aMD5)) == NO_ERROR) {
                ATLASSERT(aMD5.GetCount() == 16);
                ATL::Crypt::CCertStore cs;
                if (cs.Create(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, (HCRYPTPROV)NULL, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"MY")) {
                    for (PCCERT_CONTEXT pCertContext2 = NULL;;) {
                        pCertContext2 = CertEnumCertificatesInStore(cs, pCertContext2);
                        if (pCertContext2) {
                            ATL::CAtlString sSubjectName2;
                            if (CertGetNameString(pCertContext2, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, sSubjectName2) > 0) {
                                if (_tcscmp(sSubjectName, sSubjectName2) == 0) {
                                    //
                                    // Verify HASH of certificate
                                    //
                                    ATL::CAtlArray<BYTE> aMD5Temp;
                                    if ((dwReturnCode = AL::Crypto::GetHash(ctx, CALG_MD5, pCertContext2->pbCertEncoded, pCertContext2->cbCertEncoded, aMD5Temp)) == NO_ERROR) {
                                        ATLASSERT(aMD5Temp.GetCount() == 16);
                                        if (memcmp(aMD5.GetData(), aMD5Temp.GetData(), 16) == 0) {
                                            CertFreeCertificateContext(pCertContext2);

                                            // We might have hit some errors along the way. So reset return code now, as we found what we were looking for.
                                            dwReturnCode = NO_ERROR;
                                            break;
                                        }
                                    }
                                }
                            } else
                                AL_TRACE_ERROR(_T("CertGetNameString failed (%ld)."), dwReturnCode = GetLastError());
                        } else {
                            AL_TRACE_ERROR(_T("Could not find certificate."));
                            dwReturnCode = ERROR_FILE_NOT_FOUND;
                            break;
                        }
                    }
                } else
                    AL_TRACE_ERROR(_T("CertOpenStore failed (%ld)."), dwReturnCode = GetLastError());
            }
        } else
            AL_TRACE_ERROR(_T("CertGetNameString failed (%ld)."), dwReturnCode = GetLastError());
    }

    return dwReturnCode;
}


//
// Verify if servername conforms with configured substring
//
DWORD AL::TLS::Cert::VerifyServerName(_In_ const CConfigData *pConfigData, _In_ PCCERT_CONTEXT pCertContext)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    ATL::CAtlStringA sSubjectName;
    if (CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, sSubjectName) > 0) {
        int iLenZ = pConfigData->m_sServerName.GetLength() + 1;
        ATL::CTempBuffer<CHAR> pszServerName(iLenZ);
        static const CHAR pszSeperators[]= ";";
        SIZE_T nSubjectNameLen = sSubjectName.GetLength();

        memcpy(pszServerName, (LPCSTR)(pConfigData->m_sServerName), sizeof(CHAR)*iLenZ);
        for (LPSTR pszTokenNext = NULL, pszToken = strtok_s((char*)pszServerName, pszSeperators, &pszTokenNext); ; pszToken = strtok_s(NULL, pszSeperators, &pszTokenNext)) {
            if (pszToken != NULL) {
                SIZE_T nTokenLen = strlen(pszToken);

                if (_stricmp(pszToken, sSubjectName) == 0 || // Direct match
                    pszToken[0] == '*' && nSubjectNameLen >= nTokenLen - 1 && _stricmp(pszToken + 1, (LPCSTR)sSubjectName + nSubjectNameLen - (nTokenLen - 1)) == 0) // "*..." wildchar match
                {
                    AL_TRACE_INFO(_T("Servername %hs match %hs."), (LPCSTR)sSubjectName, pszToken);
                    break;
                }
            } else {
                //
                // End of list reached, not found.
                //
                AL_TRACE_ERROR(_T("Servername %hs does not match any of %hs."), (LPCSTR)sSubjectName, (LPCSTR)pConfigData->m_sServerName);
                dwReturnCode = ERROR_INVALID_DOMAINNAME;
                break;
            }
        }
    } else
        AL_TRACE_ERROR(_T("CertGetNameString failed (%ld)."), dwReturnCode = GetLastError());

    return dwReturnCode;
}
