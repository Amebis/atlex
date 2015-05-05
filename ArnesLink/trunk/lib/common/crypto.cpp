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
#pragma comment(lib, "Crypt32.lib")


DWORD AL::Crypto::AcquireContext(_Out_ HCRYPTPROV *phCSP, _In_z_ LPCTSTR pszContainer, _In_opt_z_ LPCTSTR pszCSPName, _In_opt_ DWORD dwType)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // Connect to help CSP
    //
    if (!CryptAcquireContext(phCSP, pszContainer, pszCSPName, dwType, 0)) {
        DWORD dwErr = GetLastError();

        if (dwErr == NTE_BAD_KEYSET || dwErr == NTE_BAD_KEY_STATE) {
            //
            // Key is invalid, try to make a new one
            //
            if (!CryptAcquireContext(phCSP, pszContainer, pszCSPName, dwType, CRYPT_NEWKEYSET)) {
                dwErr = GetLastError();

                if (dwErr == NTE_EXISTS) {
                    //
                    // Key is corrupt, silly microsoft...
                    // Let's delete it and make a new one ;)
                    //
                    if (CryptAcquireContext(phCSP, pszContainer, pszCSPName, dwType, CRYPT_DELETEKEYSET)) {
                        if (!CryptAcquireContext(phCSP, pszContainer, pszCSPName, dwType, CRYPT_NEWKEYSET)) {
                            AL_TRACE_ERROR(_T("CryptAcquireContext(NEWKEYSET) failed (%ld)."), GetLastError());
                            dwReturnCode = ERROR_ENCRYPTION_FAILED;
                        }
                    } else if (wcscmp(pszContainer, L"ArnesLink") == 0) {
                        AL_TRACE_ERROR(_T("Could not create a new keyset (%ld)."), GetLastError());
                        dwReturnCode = ERROR_ENCRYPTION_FAILED;
                    } else {
                        AL_TRACE_WARNING(_T("CryptAcquireContext(CRYPT_DELETEKEYSET) failed (%ld), trying to create with different container"), GetLastError());

                        //
                        // Let's try one more time with a different container
                        // and then throw an error
                        //
                        if (!pszContainer)
                            dwReturnCode = AL::Crypto::AcquireContext(phCSP, L"ArnesLink", pszCSPName, dwType);
                    }
                } else {
                    AL_TRACE_ERROR(_T("CryptAcquireContext(NEWKEYSET) failed (%ld)."), dwErr);
                    dwReturnCode = ERROR_ENCRYPTION_FAILED;
                }
            }
        } else {
            AL_TRACE_ERROR(_T("CryptAcquireContext(0) failed (%ld)."), dwErr);
            dwReturnCode = ERROR_ENCRYPTION_FAILED;
        }
    }

    return dwReturnCode;
}


DWORD AL::Crypto::GetCertificate(_In_count_c_(20) LPCBYTE pbServerCertSHA1, _Out_ PCCERT_CONTEXT *ppCertContext)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // Connect to help CSP
    //
    ATL::Crypt::CContext ctx;
    if ((dwReturnCode = AL::Crypto::AcquireContext(&ctx, NULL)) == NO_ERROR) {
        ATL::Crypt::CCertStore cs;
        if (cs.Create(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, (HCRYPTPROV)NULL, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"MY")) {
            for (PCCERT_CONTEXT pCertContext = NULL;;) {
                if ((pCertContext = CertEnumCertificatesInStore(cs, pCertContext)) != NULL) {
                    //
                    // Get HASH of certificate
                    //
                    ATL::CAtlArray<BYTE> aSHA1;
                    if ((dwReturnCode = AL::Crypto::GetHash(ctx, CALG_SHA1, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, aSHA1)) == NO_ERROR) {
                        if (aSHA1.GetCount() == 20 && memcmp(pbServerCertSHA1, aSHA1.GetData(), 20) == 0) {
                            *ppCertContext = pCertContext;
                            break;
                        }
                    }
                } else {
                    AL_TRACE_ERROR(_T("no certificates found"));
                    dwReturnCode = ERROR_CANTOPEN;
                    break;
                }
            }
        } else {
            AL_TRACE_ERROR(_T("CertOpenStore failed (%ld)."), GetLastError());
            dwReturnCode = ERROR_CANTOPEN;
        }
    }

    return dwReturnCode;
}


DWORD AL::Crypto::GetHash(_In_ HCRYPTPROV hCSP, _In_ ALG_ID algid, _In_bytecount_(dwMsgSize) LPCVOID pMsg, _In_ DWORD dwMsgSize, _Out_ ATL::CAtlArray<BYTE> &aHash)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    ATL::Crypt::CHash hash;
    if (hash.Create(hCSP, algid, 0, 0)) {
        if (CryptHashData(hash, (const BYTE*)pMsg, dwMsgSize, 0)) {
            if (!CryptGetHashParam(hash, HP_HASHVAL, aHash, 0)) {
                AL_TRACE_ERROR(_T("CryptGetHashParam failed (%ld)."), GetLastError());
                dwReturnCode = ERROR_ENCRYPTION_FAILED;
            }
        } else {
            AL_TRACE_ERROR(_T("CryptHashData failed (%ld)."), GetLastError());
            dwReturnCode = ERROR_ENCRYPTION_FAILED;
        }
    } else {
        AL_TRACE_ERROR(_T("CryptCreateHash failed (%ld)."), GetLastError());
        dwReturnCode = ERROR_ENCRYPTION_FAILED;
    }

    return dwReturnCode;
}


//
// Generate secure random data
//
DWORD AL::Crypto::GenSecureRandom(_Inout_bytecount_(dwRandomSize) LPVOID pRandom, IN DWORD dwRandomSize)
{
    DWORD dwReturnCode = NO_ERROR;

    AL_TRACE_DEBUG(_T("(%ld)"), dwRandomSize);

    ATL::Crypt::CContext ctx;
    if ((dwReturnCode = AL::Crypto::AcquireContext(&ctx, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL)) == NO_ERROR) {
        if (!CryptGenRandom(ctx, dwRandomSize, (BYTE*)pRandom)) {
            AL_TRACE_ERROR(_T("CryptGenRandom failed (%ld)"), GetLastError());
            dwReturnCode = ERROR_ENCRYPTION_FAILED;
        }
    }

    return dwReturnCode;
}


//
// Helper function for importing the SSL session keys
// Tricks MS into importing clear text PKCS blobs
//
DWORD AL::Crypto::CreatePrivateExponentOneKey(_In_ HCRYPTPROV hProv, _In_ DWORD dwKeySpec, _Out_ HCRYPTKEY *phPrivateKey)
{
    DWORD dwReturnCode = NO_ERROR;

    if (dwKeySpec != AT_KEYEXCHANGE && dwKeySpec != AT_SIGNATURE) {
        AL_TRACE_ERROR(_T("dwKeySpec must be one of AT_KEYEXCHANGE or AT_SIGNATURE."));
        return ERROR_INVALID_PARAMETER;
    }

    AL_TRACE_DEBUG(_T("(%ld)"), dwKeySpec);

    *phPrivateKey = NULL;

    // Generate the private key
    ATL::Crypt::CKey key;
    if (key.Generate(hProv, dwKeySpec, CRYPT_EXPORTABLE)) {
        // Export the private key, we'll convert it to a private
        // exponent of one key
        ATL::CAtlArray<BYTE> aKeyBLOB;
        if (CryptExportKey(key, 0, PRIVATEKEYBLOB, 0, aKeyBLOB)) {
            BYTE *pbKeyBLOB = aKeyBLOB.GetData(), *p;
            DWORD dwBitLen;

            // Get the bit length of the key
            memcpy(&dwBitLen, &pbKeyBLOB[12], sizeof(DWORD));

            // Modify the Exponent in Key BLOB format
            // Key BLOB format is documented in SDK
            p = &pbKeyBLOB[16];

            // Convert pubexp in rsapubkey to 1
            for (DWORD n = 0; n < 4; n++, p++)
                *p = n == 0 ? 1 : 0;

            // Skip modulus, prime1, prime2
            p += dwBitLen/8;
            p += dwBitLen/16;
            p += dwBitLen/16;

            // Convert exponent1 to 1
            for (DWORD n = 0; n < dwBitLen/16; n++, p++)
                *p = n == 0 ? 1 : 0;

            // Convert exponent2 to 1
            for (DWORD n = 0; n < dwBitLen/16; n++, p++)
                *p = n == 0 ? 1 : 0;

            // Skip coefficient
            p += (dwBitLen/16);

            // Convert privateExponent to 1
            for (DWORD n = 0; n < dwBitLen/8; n++, p++)
                *p = n == 0 ? 1 : 0;

            if (!CryptImportKey(hProv, pbKeyBLOB, (DWORD)aKeyBLOB.GetCount(), 0, 0, phPrivateKey)) {
                AL_TRACE_ERROR(_T("CryptImportKey failed (%ld)."), dwReturnCode = GetLastError());
                *phPrivateKey = NULL;
            }
        } else
            AL_TRACE_ERROR(_T("CryptExportKey failed (%ld)."), dwReturnCode = GetLastError());
    } else
        AL_TRACE_ERROR(_T("CryptGenKey failed (%ld)."), dwReturnCode = GetLastError());

    return dwReturnCode;
}


//
// Helper function for exporting the SSL session key
//
BOOL AL::Crypto::ExportPlainSessionBlob(_In_ HCRYPTKEY hPublicKey, _In_ HCRYPTKEY hSessionKey, _Out_bytecap_(*dwKeyMaterialSize) LPBYTE *pbKeyMaterial, _Out_ DWORD *pdwKeyMaterial)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    *pbKeyMaterial  = NULL;
    *pdwKeyMaterial = 0;

    ATL::CAtlArray<BYTE> aSessionBLOB;
    if (CryptExportKey(hSessionKey, hPublicKey, SIMPLEBLOB, 0, aSessionBLOB)) {
        // Get session key size in bits
        DWORD dwSize = sizeof(DWORD);
        if (CryptGetKeyParam(hSessionKey, KP_KEYLEN, (LPBYTE)pdwKeyMaterial, &dwSize, 0)) {
            // Get the number of bytes and allocate buffer
            *pdwKeyMaterial /= 8;
            if ((dwReturnCode = AL::Heap::Alloc(*pdwKeyMaterial, (LPVOID*)pbKeyMaterial)) == NO_ERROR) {
                LPBYTE p;

                // Skip the header
                p = aSessionBLOB.GetData();
                p += sizeof(BLOBHEADER);
                p += sizeof(ALG_ID);

                // We are at the beginning of the key
                // but we need to start at the end since
                // it's reversed
                p += (*pdwKeyMaterial - 1);

                // Copy the raw key into our return buffer
                for (DWORD n = 0; n < *pdwKeyMaterial; n++, p--)
                    (*pbKeyMaterial)[n] = *p;
            } else
                *pdwKeyMaterial = 0;
        } else
            AL_TRACE_ERROR(_T("CryptGetKeyParam failed (%ld)."), dwReturnCode = GetLastError());
    } else
        AL_TRACE_ERROR(_T("CryptExportKey failed (%ld)."), dwReturnCode = GetLastError());

    return dwReturnCode;
}

//
// Helper function for importing the SSL session key
//
BOOL AL::Crypto::ImportPlainSessionBlob(_In_ HCRYPTPROV hProv, _In_ HCRYPTKEY hPrivateKey, _In_ ALG_ID dwAlgId, _In_bytecount_(dwKeyMaterialSize) LPBYTE pbKeyMaterial, _In_ DWORD dwKeyMaterialSize, _Out_ ATL::Crypt::CKey &keySession)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Double check to see if this provider supports this algorithm
    // and key size
    PROV_ENUMALGS_EX ProvEnum;
    DWORD dwSize;
    for (DWORD dwFlags = CRYPT_FIRST;;) {
        dwSize = sizeof(ProvEnum);
        if (CryptGetProvParam(hProv, PP_ENUMALGS_EX, (LPBYTE)&ProvEnum, &dwSize, dwFlags)) {
            if (ProvEnum.aiAlgid == dwAlgId) {
                dwReturnCode = NO_ERROR;
                break;
            }

            dwFlags = 0;
        } else {
            dwReturnCode = GetLastError();
            if (dwReturnCode == ERROR_NO_MORE_ITEMS) {
                AL_TRACE_ERROR(_T("Unsupported algorithm (%ld)."), dwAlgId);
                dwReturnCode = ERROR_NOT_SUPPORTED;
            } else
                AL_TRACE_ERROR(_T("CryptGetProvParam(PP_ENUMALGS_EX) failed (%ld)."), dwReturnCode);
            break;
        }
    }
    if (dwReturnCode == NO_ERROR) {
        //
        // We have to get the key size(including padding)
        // from an HCRYPTKEY handle.  PP_ENUMALGS_EX contains
        // the key size without the padding so we can't use it.
        //
        ATL::Crypt::CKey keyTemp;
        if (keyTemp.Generate(hProv, dwAlgId, 0)) {
            DWORD dwProvSessionKeySize;
            dwSize = sizeof(dwProvSessionKeySize);
            if (CryptGetKeyParam(keyTemp, KP_KEYLEN, (LPBYTE)&dwProvSessionKeySize, &dwSize, 0)) {
                //
                // Get private key's algorithm
                //
                ALG_ID idPrivKeyAlg;
                dwSize = sizeof(idPrivKeyAlg);
                if (CryptGetKeyParam(hPrivateKey, KP_ALGID, (LPBYTE)&idPrivKeyAlg, &dwSize, 0)) {
                    //
                    // Get private key's length in bits
                    //
                    DWORD dwPublicKeySize;
                    dwSize = sizeof(dwPublicKeySize);
                    if (CryptGetKeyParam(hPrivateKey, KP_KEYLEN, (LPBYTE)&dwPublicKeySize, &dwSize, 0)) {
                        DWORD dwSessionBLOBSize = (dwPublicKeySize/8) + sizeof(ALG_ID) + sizeof(BLOBHEADER);
                        ATL::CTempBuffer<BYTE> aSessionBlob(dwSessionBLOBSize);
                        LPBYTE p = aSessionBlob;

                        // SIMPLEBLOB Format is documented in SDK
                        // Copy header to buffer
                        ((BLOBHEADER*)p)->bType    = SIMPLEBLOB;
                        ((BLOBHEADER*)p)->bVersion = 2;
                        ((BLOBHEADER*)p)->reserved = 0;
                        ((BLOBHEADER*)p)->aiKeyAlg = dwAlgId;
                        p += sizeof(BLOBHEADER);

                        // Copy private key algorithm to buffer
                        *((ALG_ID*)p) = idPrivKeyAlg;
                        p += sizeof(ALG_ID);

                        // Place the key material in reverse order
                        for (DWORD n = 0; n < dwKeyMaterialSize; n++, p++)
                            *p = pbKeyMaterial[dwKeyMaterialSize - n - 1];

                        // Clear reserved byte
                        *(p++) = 0;

                        // Generate random data for the rest of the buffer
                        // (except that last two bytes)
                        dwSize = dwSessionBLOBSize - (DWORD)(p - aSessionBlob) - 2;
                        if (CryptGenRandom(hProv, dwSize, p)) {
                            // Change zeros to non-zero values
                            for (DWORD n = 0; n < dwSize; n++, p++)
                                if (*p == 0) *p = 1;

                            // Write the last two bytes.
                            *(p++) = 2;
                            *(p++) = 0;

                            if (!keySession.Import(hProv, aSessionBlob, dwSessionBLOBSize, hPrivateKey, CRYPT_EXPORTABLE | CRYPT_NO_SALT))
                                AL_TRACE_ERROR(_T("CryptImportKey failed (%ld)."), dwReturnCode = GetLastError());
                        } else
                            AL_TRACE_ERROR(_T("CryptGenRandom failed (%ld)."), dwReturnCode = GetLastError());
                    } else
                        AL_TRACE_ERROR(_T("CryptGetKeyParam(KP_KEYLEN, public key) failed (%ld)."), dwReturnCode = GetLastError());
                } else
                    AL_TRACE_ERROR(_T("CryptGetKeyParam(KP_ALGID) failed (%ld)."), dwReturnCode = GetLastError());
            } else
                AL_TRACE_ERROR(_T("CryptGetKeyParam(KP_KEYLEN, session key) failed (%ld)."), dwReturnCode = GetLastError());
        } else
            AL_TRACE_ERROR(_T("CryptGenKey failed (%ld)."), dwReturnCode = GetLastError());
    }

    return dwReturnCode;
}
