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
// Local function declarations
//
static DWORD _PHash(_In_ HCRYPTPROV hCSP, _In_ ALG_ID algOrigKey, _In_bytecount_(dwSecretSize) LPCBYTE pbSecret, _In_ DWORD dwSecretSize, _In_bytecount_(dwSeedSize) LPCBYTE pbSeed, _In_ DWORD dwSeedSize, _Out_bytecap_(dwDataSize) LPBYTE pbData, _In_ DWORD dwDataSize);
static inline DWORD _GenSessionID(_Out_ BYTE pbSessionID[AL_TLS_SESSION_ID_SIZE], _Out_ DWORD *pcbSessionID, _In_ DWORD dwMaxSessionID);
static inline DWORD _GenRandom(_Out_ BYTE pbRandom[AL_TLS_RANDOM_SIZE]);
static DWORD _HMAC(_In_ HCRYPTPROV hCSP, _In_ ALG_ID algOrigKey, _In_bytecount_(dwOrigKeySize) LPCBYTE pbOrigKey, _In_ DWORD dwOrigKeySize, _In_bytecount_(dwSeedSize) LPCBYTE pbSeed, _In_ DWORD dwSeedSize, _Out_bytecap_(dwDataSize) LPBYTE pbData, _In_ DWORD dwDataSize);


//
// Encrypts an SSL record using the specified Keys and MACs
//
DWORD AL::TLS::EncBlock(_Inout_ AL::TLS::CTLSSession *pTLSSession, _In_bytecount_(dwDataSize) LPCBYTE pbData, _In_ DWORD dwDataSize, _Out_bytecap_(*pdwEncBlockSize) LPBYTE *ppbEncBlock, _Out_ DWORD *pdwEncBlockSize)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    if (pTLSSession->m_hCSP) {
        BYTE pbSeqNum[] = { 0, 0, 0, 0, 0, 0, 0, 0 };

        //
        // Sequence number starts at -1
        // and is incremented before use
        //
        (pTLSSession->m_dwSeqNum)++;

        //
        // Hash the seq_num
        //
        AL::Convert::H2N32(pTLSSession->m_dwSeqNum, (LPBYTE)&(pbSeqNum[4]));

        //
        // First calculate the HMAC
        //
        LPBYTE pbTemp;
        DWORD dwTempSize = sizeof(pbSeqNum) + dwDataSize;
        if ((dwReturnCode = AL::Heap::Alloc(dwTempSize, (LPVOID*)&pbTemp)) == NO_ERROR) {
            BYTE pbHash[20];

            memcpy(pbTemp, pbSeqNum, sizeof(pbSeqNum));
            memcpy(pbTemp + sizeof(pbSeqNum), pbData, dwDataSize);

            if ((dwReturnCode = _HMAC(pTLSSession->m_hCSP, pTLSSession->m_algMacKey, pTLSSession->m_pbMacWrite, pTLSSession->m_dwMacKeySize, pbTemp, dwTempSize, pbHash, pTLSSession->m_dwMacKeySize)) == NO_ERROR) {
                //
                // Calculate the padding needed
                //
                //
                // Length of block-ciphered struct before padding
                // Length of Content(21-5=16) + MAC + 1(length byte)
                //
                BYTE bPadding = (dwDataSize - 5 + pTLSSession->m_dwMacKeySize + 1) % 8;

                if (bPadding != 0)
                    bPadding = 8 - bPadding;

                //
                // Total length of encrypted block is content(dwDataSize) + MAC + Padding(2) +paddingLength(1)
                //
                LPBYTE pbEncBlock;
                DWORD dwEncBlockSize = dwDataSize - 5 + pTLSSession->m_dwMacKeySize + bPadding + 1;
                if ((dwReturnCode = AL::Heap::Alloc(dwEncBlockSize, (LPVOID*)&pbEncBlock)) == NO_ERROR) {
                    //
                    // Copy the content block
                    //
                    memcpy(pbEncBlock, pbData + 5, dwDataSize - 5);

                    //
                    // Copy the HMAC, swapped because of little endian big endian thing
                    //
                    LPBYTE pbSwapped;
                    if ((dwReturnCode = AL::Heap::Alloc(pTLSSession->m_dwMacKeySize, (LPVOID*)&pbSwapped)) == NO_ERROR) {
                        AL::Buffer::Swap(pbHash, pbSwapped, pTLSSession->m_dwMacKeySize);
                        memcpy(&(pbEncBlock[dwDataSize-5]), pbHash, pTLSSession->m_dwMacKeySize);

                        //
                        // The padding
                        //
                        for (BYTE i = 0; i < bPadding; i++)
                            pbEncBlock[dwDataSize - 5 + pTLSSession->m_dwMacKeySize + i] = bPadding;

                        //
                        // Length of padding
                        //
                        pbEncBlock[dwDataSize-5+pTLSSession->m_dwMacKeySize+(int)bPadding] = bPadding;

                        DWORD dwDataSize = *pdwEncBlockSize = dwEncBlockSize;
                        if ((dwReturnCode = AL::Heap::Alloc(*pdwEncBlockSize, (LPVOID*)ppbEncBlock)) == NO_ERROR) {
                            memcpy(*ppbEncBlock, pbEncBlock, dwEncBlockSize);

                            if (!CryptEncrypt(pTLSSession->m_keyWrite, 0, FALSE, 0, *ppbEncBlock, &dwDataSize, *pdwEncBlockSize)) {
                                AL_TRACE_ERROR(_T("CryptEncrypt failed (%ld)."), GetLastError());
                                dwReturnCode = ERROR_ENCRYPTION_FAILED;
                                AL::Heap::Free((LPVOID*)ppbEncBlock);
                            }
                        }

                        AL::Heap::Free((LPVOID*)&pbSwapped);
                    }

                    AL::Heap::Free((LPVOID*)&pbEncBlock);
                }
            }

            AL::Heap::Free((LPVOID*)&pbTemp);
        }
    } else {
        AL_TRACE_ERROR(_T("No handle to CSP."));
        dwReturnCode = ERROR_ENCRYPTION_FAILED;
    }

    return dwReturnCode;
}


//
// Decrypt a encrypted SSL record
// Padding is not implemented yet
//
DWORD AL::TLS::DecBlock(_In_ const AL::TLS::CTLSSession *pTLSSession, _In_bytecount_(dwEncBlockSize) LPCBYTE pbEncBlock, _In_ DWORD dwEncBlockSize, _Out_bytecap_(*pdwRecordSize) LPBYTE *ppbRecord, _Out_ DWORD *pdwRecordSize)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    if (pTLSSession->m_hCSP) {
        LPBYTE pbDecBlock;
        DWORD dwDecBlockSize = dwEncBlockSize;
        if ((dwReturnCode = AL::Heap::Alloc(dwDecBlockSize, (LPVOID*)&pbDecBlock)) == NO_ERROR) {
            memcpy(pbDecBlock, pbEncBlock, dwDecBlockSize);

            if (CryptDecrypt(pTLSSession->m_keyRead, 0, FALSE, 0, pbDecBlock, &dwDecBlockSize)) {
                //
                // Strip MAC and padding
                //
                BYTE bPadding = pbDecBlock[dwDecBlockSize-1];

                *pdwRecordSize = dwDecBlockSize - pTLSSession->m_dwMacKeySize - bPadding - 1;

                if (*pdwRecordSize > 0) {
                    //
                    // Check padding NOT IMPLEMENTED
                    //
/*
                    AL_TRACE_INFO(_T("looping for %ld", (dwDecBlockSize - (DWORD)bPadding);

                    for (DWORD i = dwDecBlockSize; i > (dwDecBlockSize - (DWORD)bPadding); i--) {
                        AL_TRACE_INFO(_T("i:%ld"), i);
                        AL_TRACE_INFO(_T("0x%x"), pbDecBlock[i]);

                        if (pbDecBlock[i] != bPadding) {
                            AL_TRACE_ERROR(_T("Padding failed."));
                            dwReturnCode = ERROR_ENCRYPTION_FAILED;
                            break;
                        }
                    }
*/
                    if (dwReturnCode == NO_ERROR) {
                        if ((dwReturnCode = AL::Heap::Alloc(*pdwRecordSize, (LPVOID*)ppbRecord)) == NO_ERROR)
                            memcpy(*ppbRecord, pbDecBlock, *pdwRecordSize);
                    }
                } else {
                    //
                    // Padding failed, but continue to parse rest of packets.
                    //
                    AL_TRACE_ERROR(_T("Incorrect padding."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                }
            } else {
                AL_TRACE_ERROR(_T("CryptDecrypt failed (%ld)."), GetLastError());
                dwReturnCode = ERROR_ENCRYPTION_FAILED;
            }

            AL::Heap::Free((LPVOID*)&pbDecBlock);
        }
    } else {
        AL_TRACE_ERROR(_T("No handle to CSP."));
        dwReturnCode = ERROR_ENCRYPTION_FAILED;
    }

    return dwReturnCode;
}


//
// Helper function for implementing TLS according to
// http://www.ietf.org/rfc/rfc2104.txt
// Functions are named to mirror function in RFC
//
DWORD AL::TLS::PRF(_In_ HCRYPTPROV hCSP, _In_bytecount_(dwSecretSize) LPCBYTE pbSecret, _In_ DWORD dwSecretSize, _In_bytecount_(dwLabelSize) LPCBYTE pbLabel, _In_ DWORD dwLabelSize, _In_bytecount_(dwSeedSize) LPCBYTE pbSeed, _In_ DWORD dwSeedSize, _Out_bytecap_(dwDataSize) LPBYTE pbData, _In_ DWORD dwDataSize)
{
    DWORD dwReturnCode = NO_ERROR;

    //
    // Split secret into two halves
    //
    DWORD
        L_S1 = dwSecretSize / 2 + dwSecretSize % 2,
        L_S2 = L_S1;

    LPCBYTE
        S1 = pbSecret,
        S2 = pbSecret + L_S1;

    //
    // Create clear exchange key
    //
    LPBYTE pbTemp;
    DWORD dwTempSize = dwLabelSize + dwSeedSize;
    if ((dwReturnCode = AL::Heap::Alloc(dwTempSize, (LPVOID*)&pbTemp)) == NO_ERROR) {
        memcpy(pbTemp,               pbLabel, dwLabelSize);
        memcpy(pbTemp + dwLabelSize, pbSeed,  dwSeedSize);

        LPBYTE pbMD5;
        if ((dwReturnCode = AL::Heap::Alloc(dwDataSize, (LPVOID*)&pbMD5)) == NO_ERROR) {
            if ((dwReturnCode = _PHash(hCSP, CALG_MD5, S1, L_S1, pbTemp, dwTempSize, pbMD5, dwDataSize)) == NO_ERROR) {
                LPBYTE pbSHA1;
                if ((dwReturnCode = AL::Heap::Alloc(dwDataSize, (LPVOID*)&pbSHA1)) == NO_ERROR) {
                    if ((dwReturnCode = _PHash(hCSP, CALG_SHA1, S2, L_S2, pbTemp, dwTempSize, pbSHA1, dwDataSize)) == NO_ERROR) {
                        //
                        // Xor
                        //
                        for (DWORD i = 0; i < dwDataSize; i++)
                            pbData[i] = pbMD5[i] ^ pbSHA1[i];
                    }

                    AL::Heap::Free((LPVOID*)&pbSHA1);
                }
            }

            AL::Heap::Free((LPVOID*)&pbMD5);
        }

        AL::Heap::Free((LPVOID*)&pbTemp);
    }

    return dwReturnCode;
}


//
// Derives the required session keys and macs
//
DWORD AL::TLS::DeriveKeys(_Inout_ AL::TLS::CTLSSession *pTLSSession)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    if (pTLSSession->m_hCSP) {
        //
        // client_write_MAC_secret[SecurityParameters.hash_size]
        // server_write_MAC_secret[SecurityParameters.hash_size]
        // client_write_key[SecurityParameters.key_material_length]
        // server_write_key[SecurityParameters.key_material_length]
        // client_write_IV[SecurityParameters.IV_size]
        // server_write_IV[SecurityParameters.IV_size]
        //
        LPBYTE pbKeyMaterial;
        DWORD dwKeyMaterialSize = (pTLSSession->m_dwMacKeySize + pTLSSession->m_dwEncKeySize + 8) * 2;
        if ((dwReturnCode = AL::Heap::Alloc(dwKeyMaterialSize, (LPVOID*)&pbKeyMaterial)) == NO_ERROR) {
            //
            // key_block = PRF(SecurityParameters.master_secret,
            //                  "key expansion",
            // SecurityParameters.server_random +
            // SecurityParameters.client_random);

            BYTE pbTemp[AL_TLS_RANDOM_SIZE * 2];
            memcpy(pbTemp,                      pTLSSession->m_pbRandomServer, AL_TLS_RANDOM_SIZE);
            memcpy(pbTemp + AL_TLS_RANDOM_SIZE, pTLSSession->m_pbRandomClient, AL_TLS_RANDOM_SIZE);

            if ((dwReturnCode = AL::TLS::PRF(pTLSSession->m_hCSP, pTLSSession->m_pbMS, AL_TLS_MS_SIZE, (LPCBYTE)AL_TLS_KEY_EXPANSION_LABEL, sizeof(AL_TLS_KEY_EXPANSION_LABEL) - sizeof(CHAR), pbTemp, sizeof(pbTemp), pbKeyMaterial, dwKeyMaterialSize)) == NO_ERROR) {
                //
                // WriteMAC key
                //
                memcpy(pTLSSession->m_pbMacWrite, pbKeyMaterial, pTLSSession->m_dwMacKeySize);

                //
                // Read MAC key
                //
                memcpy(pTLSSession->m_pbMacRead, pbKeyMaterial + pTLSSession->m_dwMacKeySize, pTLSSession->m_dwMacKeySize);

                ATL::Crypt::CKey keyPub;
                if ((dwReturnCode = AL::Crypto::CreatePrivateExponentOneKey(pTLSSession->m_hCSP, AT_KEYEXCHANGE, &keyPub)) == NO_ERROR) {
                    //
                    // Write Enc Key
                    //
                    if ((dwReturnCode = AL::Crypto::ImportPlainSessionBlob(pTLSSession->m_hCSP, keyPub, pTLSSession->m_algEncKey, pbKeyMaterial + (pTLSSession->m_dwMacKeySize * 2), pTLSSession->m_dwEncKeySize, pTLSSession->m_keyWrite)) == NO_ERROR) {
                        //
                        // IV
                        //
                        if (CryptSetKeyParam(pTLSSession->m_keyWrite, KP_IV, pbKeyMaterial + ((pTLSSession->m_dwMacKeySize + pTLSSession->m_dwEncKeySize) * 2), 0)) {
                            //
                            // Read Enc Key
                            //
                            if ((dwReturnCode = AL::Crypto::ImportPlainSessionBlob(pTLSSession->m_hCSP, keyPub, pTLSSession->m_algEncKey, pbKeyMaterial + (pTLSSession->m_dwMacKeySize * 2) + pTLSSession->m_dwEncKeySize, pTLSSession->m_dwEncKeySize, pTLSSession->m_keyRead)) == NO_ERROR) {
                                //
                                // IV
                                //
                                if (!CryptSetKeyParam(pTLSSession->m_keyRead, KP_IV, pbKeyMaterial + ((pTLSSession->m_dwMacKeySize + pTLSSession->m_dwEncKeySize) * 2) + 8, 0)) {
                                    AL_TRACE_ERROR(_T("CryptSetKeyParam(KP_IV) failed (%ld)."), GetLastError());
                                    dwReturnCode = ERROR_ENCRYPTION_FAILED;
                                }
                            } else
                                dwReturnCode = ERROR_ENCRYPTION_FAILED;
                        } else {
                            AL_TRACE_ERROR(_T("CryptSetKeyParam(KP_IV) failed (%ld)."), GetLastError());
                            dwReturnCode = ERROR_ENCRYPTION_FAILED;
                        }
                    }
                } else
                    dwReturnCode = ERROR_ENCRYPTION_FAILED;
            }

            AL::Heap::Free((LPVOID*)&pbKeyMaterial);
        }
    } else {
        AL_TRACE_ERROR(_T("No handle to CSP."));
        dwReturnCode = ERROR_ENCRYPTION_FAILED;
    }

    return dwReturnCode;
}


//
// This function parses a server packet message and acts accordingly
//
DWORD AL::TLS::ParseServerPacket(_Inout_ AL::TLS::CSessionData *pSessionData)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    AL::TLS::CTLSSession *pTLSSession = &(pSessionData->m_TLSSession);
    const BYTE *pbEAPMsg = pTLSSession->m_aReceiveMsg.GetData();
    SIZE_T nEAPMsgSize = pTLSSession->m_aReceiveMsg.GetCount();

    //
    // Check for TTLS
    //
    for (SIZE_T nCursor = 0; nCursor < nEAPMsgSize && dwReturnCode == NO_ERROR; ) {
        //
        // ssl record header
        //
        if (pbEAPMsg[nCursor] == 0x16) { // handshake message
            AL_TRACE_DEBUG(_T("Found handshake message."));
            nCursor++;

            //
            // Check major minor number
            //
            if (pbEAPMsg[nCursor] == 0x03 && pbEAPMsg[nCursor+1] == 0x01) {
                nCursor += 2;
                if (nCursor > nEAPMsgSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of message."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                DWORD dwRecordLength = AL::Convert::N2H16(&(pbEAPMsg[nCursor]));
                nCursor += 2;
                if (nCursor > nEAPMsgSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of message."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                if (pTLSSession->m_fCipherSpec) {
                    LPBYTE pbRecord;
                    DWORD dwRecordSize;
                    if ((dwReturnCode = AL::TLS::DecBlock(pTLSSession, &(pbEAPMsg[nCursor]), dwRecordLength, &pbRecord, &dwRecordSize)) == NO_ERROR) {
                        dwReturnCode = AL::TTLS::ParseHandshakeRecord(pTLSSession, pbRecord, dwRecordSize);
                        AL::Heap::Free((LPVOID*)&pbRecord);
                    }
                } else
                    dwReturnCode = AL::TTLS::ParseHandshakeRecord(pTLSSession, &(pbEAPMsg[nCursor]), dwRecordLength);

                nCursor += dwRecordLength;
            } else {
                AL_TRACE_ERROR(_T("Incorrect SSL version."));
                dwReturnCode = ERROR_PPP_INVALID_PACKET;
            }
        } else if (pbEAPMsg[nCursor] == 0x14) { // change_cipher_spec message
            AL_TRACE_DEBUG(_T("Found changed cipher_spec message."));
            nCursor++;
            if (nCursor > nEAPMsgSize) {
                AL_TRACE_ERROR(_T("Unexpected end of message."));
                dwReturnCode = ERROR_PPP_INVALID_PACKET;
                break;
            }

            //
            // Check major minor number
            //
            if (pbEAPMsg[nCursor] == 0x03 && pbEAPMsg[nCursor+1] == 0x01) {
                nCursor += 2;
                if (nCursor > nEAPMsgSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of message."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                DWORD dwRecordLength = AL::Convert::N2H16(&(pbEAPMsg[nCursor]));
                nCursor += 2;
                if (nCursor > nEAPMsgSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of message."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                if (pbEAPMsg[nCursor] != 0x01) {
                    //
                    // ChangeCypherSpec should be value 1 from now on
                    // indicating we are encrypting the line
                    //
                    pTLSSession->m_fCipherSpec = FALSE;
                    AL_TRACE_ERROR(_T("Unexpected change chiper spec (received: %d, expected: %d)."), pbEAPMsg[nCursor], 0x01);
                    dwReturnCode = ERROR_NO_REMOTE_ENCRYPTION;
                } else {
                    //
                    // If we receive a change_cipher_spec 1 from the server
                    // and we are not in change_cipher_spec 1 mode this could
                    // mean a session resumption
                    // If we also want to resume a session then import the
                    // previous master_key and derive the encryption keys
                    // (to read the server finished message)
                    // and set the change_cipher_spec to 1
                    //
                    if (!pTLSSession->m_fCipherSpec) {
                        if (pSessionData->m_cfg.m_fUseSessionResumption) {
                            if ((dwReturnCode = AL::TLS::DeriveKeys(pTLSSession)) == NO_ERROR)
                                pTLSSession->m_fCipherSpec = TRUE;
                        } else {
                            AL_TRACE_ERROR(_T("Server trying to establish invalid TLS session."));
                            dwReturnCode = ERROR_PPP_INVALID_PACKET;
                        }
                    }
                    // TODO: This was the original code. See the first comment below.
                    //nCursor++;
                }

                // TODO: Verify if the following line is correct. According to my personal observation of this function,
                // everywhere the cursor is incremented by dwRecordLength other than this block. Is this exception intentional or erroneus?
                nCursor = nCursor + dwRecordLength;
            } else {
                AL_TRACE_ERROR(_T("Incorrect SSL version."));
                dwReturnCode = ERROR_PPP_INVALID_PACKET;
                break;
            }
        } else if (pbEAPMsg[nCursor] == 0x17) { // application data
            AL_TRACE_DEBUG(_T("Application data."));
            nCursor++;
            if (nCursor > nEAPMsgSize) {
                AL_TRACE_ERROR(_T("Unexpected end of message."));
                dwReturnCode = ERROR_PPP_INVALID_PACKET;
                break;
            }

            //
            // Check major minor number
            //
            if (pbEAPMsg[nCursor] == 0x03 && pbEAPMsg[nCursor+1] == 0x01) {
                nCursor += 2;
                if (nCursor > nEAPMsgSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of message."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                DWORD dwRecordLength = AL::Convert::N2H16(&(pbEAPMsg[nCursor]));
                nCursor += 2;
                if (nCursor > nEAPMsgSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of message."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                LPBYTE pbRecord;
                DWORD dwRecordSize;
                if ((dwReturnCode = AL::TLS::DecBlock(pTLSSession, &pbEAPMsg[nCursor], dwRecordLength, &pbRecord, &dwRecordSize)) == NO_ERROR) {
                    dwReturnCode = AL::TLS::ParseApplicationDataRecord(pSessionData, pbRecord, dwRecordSize);
                    AL::Heap::Free((LPVOID*)&pbRecord);
                } else if (dwReturnCode == ERROR_PPP_INVALID_PACKET)
                    dwReturnCode = NO_ERROR;
                else
                    break;

                nCursor = nCursor + dwRecordLength;
            } else {
                AL_TRACE_ERROR(_T("Unknown message type (%d-%d)."), pbEAPMsg[nCursor], pbEAPMsg[nCursor+1]);
                dwReturnCode = ERROR_PPP_INVALID_PACKET;
                break;
            }
        } else if (pbEAPMsg[nCursor] == 0x18) { // inner application data
            AL_TRACE_DEBUG(_T("Innner application data."));
            nCursor++;
            if (nCursor > nEAPMsgSize) {
                AL_TRACE_ERROR(_T("Unexpected end of message."));
                dwReturnCode = ERROR_PPP_INVALID_PACKET;
                break;
            }

            //
            // Check major minor number
            //
            if (pbEAPMsg[nCursor] == 0x03 && pbEAPMsg[nCursor+1] == 0x01) {
                nCursor += 2;
                if (nCursor > nEAPMsgSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of message."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                DWORD dwRecordLength = AL::Convert::N2H16(&(pbEAPMsg[nCursor]));
                nCursor += 2;
                if (nCursor > nEAPMsgSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of message."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                LPBYTE pbRecord;
                DWORD dwRecordSize;
                if ((dwReturnCode = AL::TLS::DecBlock(pTLSSession, &pbEAPMsg[nCursor], dwRecordLength, &pbRecord, &dwRecordSize)) == NO_ERROR) {
                    dwReturnCode = AL::TTLS::ParseInnerApplicationDataRecord(pTLSSession, pbRecord, dwRecordSize);
                    AL::Heap::Free((LPVOID*)&pbRecord);
                } else if (dwReturnCode == ERROR_PPP_INVALID_PACKET)
                    dwReturnCode = NO_ERROR;
                else
                    break;

                nCursor = nCursor + dwRecordLength;
            } else {
                AL_TRACE_ERROR(_T("Unknown message type (%d-%d)."), pbEAPMsg[nCursor], pbEAPMsg[nCursor+1]);
                dwReturnCode = ERROR_PPP_INVALID_PACKET;
                break;
            }
        } else if (pbEAPMsg[nCursor] == 0x15) { // alert!
            AL_TRACE_DEBUG(_T("Alert data."));
            nCursor++;
            if (nCursor > nEAPMsgSize) {
                AL_TRACE_ERROR(_T("Unexpected end of message."));
                dwReturnCode = ERROR_PPP_INVALID_PACKET;
                break;
            }

            //
            // Check major minor number
            //
            if (pbEAPMsg[nCursor] == 0x03 && pbEAPMsg[nCursor+1] == 0x01) {
                nCursor += 2;
                if (nCursor > nEAPMsgSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of message."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                DWORD dwRecordLength = AL::Convert::N2H16(&(pbEAPMsg[nCursor]));
                nCursor += 2;
                if (nCursor > nEAPMsgSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of message."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                AL_TRACE_DEBUG(_T("alert data (%ld)"), dwRecordLength);
                AL_DUMP_DEBUG(&pbEAPMsg[nCursor], dwRecordLength);

                pTLSSession->m_fFoundAlert = TRUE;

                AL_TRACE_ERROR(_T("Received alert."));
                dwReturnCode = ERROR_NOT_AUTHENTICATED;

                nCursor = nCursor + dwRecordLength;
            } else {
                AL_TRACE_ERROR(_T("Unknown message type (%d-%d)."), pbEAPMsg[nCursor], pbEAPMsg[nCursor+1]);
                dwReturnCode = ERROR_PPP_INVALID_PACKET;
                break;
            }
        } else {
            AL_TRACE_ERROR(_T("Unknown SSL record (0x%x)."), pbEAPMsg[nCursor]);
            dwReturnCode = ERROR_PPP_INVALID_PACKET;
        }
    }

    return dwReturnCode;
}


//
// Helper funcion to add EAP message
//
DWORD AL::TLS::AddEAPMessage(_Inout_ AL::TLS::CSessionData *pSessionData, _In_bytecount_(dwEAPAttributeSize) LPCBYTE pbEAPAttribute, _In_ DWORD dwEAPAttributeSize, _Inout_ AL::EAP::CPacket &pktSend, _Out_ EapPeerMethodOutput* pEapPeerMethodOutput)
{
    DWORD dwReturnCode = NO_ERROR;

    LPBYTE pbRecord;
    DWORD dwRecordSize;
    if ((dwReturnCode = AL::TLS::Record::MakeApplication(&(pSessionData->m_TLSSession), pbEAPAttribute, dwEAPAttributeSize, &pbRecord, &dwRecordSize, TRUE)) == NO_ERROR) {
        if ((dwReturnCode = pktSend.Append(pbRecord, dwRecordSize, dwRecordSize)) == NO_ERROR) {
            pEapPeerMethodOutput->action = EapPeerMethodResponseActionSend;
            pSessionData->m_Inner.m_EapState = AL::EAP::INNERSTATE_MakeMessage;
        }

        AL::Heap::Free((LPVOID*)&pbRecord);
    }

    return dwReturnCode;
}


//
// Build a application record
//
DWORD AL::TLS::Record::MakeApplication(_Inout_ AL::TLS::CTLSSession *pTLSSession, _In_bytecount_(dwMessageSize) LPCBYTE pbMessage, _In_ DWORD dwMessageSize, _Out_bytecap_(*pdwRecordSize) LPBYTE *ppbRecord, _Out_ DWORD *pdwRecordSize, _In_ BOOL bEncrypt)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    LPBYTE pbTLSMessage;
    DWORD dwTLSMessageSize;

    //
    // Do we need to encrypt the application record?
    //
    if (bEncrypt) {
        LPBYTE pbTempRecord;
        DWORD dwTempRecordSize;

        //
        // First build an unencrypted application record.
        //
        if ((dwReturnCode = AL::TLS::Record::MakeApplication(pTLSSession, pbMessage, dwMessageSize, &pbTempRecord, &dwTempRecordSize, FALSE)) == NO_ERROR) {
            //
            // Encrypt this record which will be add to the final handshake record
            //
            dwReturnCode = AL::TLS::EncBlock(pTLSSession, pbTempRecord, dwTempRecordSize, &pbTLSMessage, &dwTLSMessageSize);
            SecureZeroMemory(pbTempRecord, dwTempRecordSize);
            AL::Heap::Free((LPVOID*)&pbTempRecord);
            AL_TRACE_INFO(_T("Encrypted: %ldB"), dwTLSMessageSize);
        } else {
            pbTLSMessage = NULL;
            dwTLSMessageSize = 0;
        }
    } else {
        pbTLSMessage = (LPBYTE)pbMessage;
        dwTLSMessageSize = dwMessageSize;
    }

    if (dwReturnCode == NO_ERROR) {
        *pdwRecordSize = 0x05 + dwTLSMessageSize;
        if ((dwReturnCode = AL::Heap::Alloc(*pdwRecordSize, (LPVOID*)ppbRecord)) == NO_ERROR) {
            DWORD dwCursor = 0;

            //
            // SSL record header
            //
            (*ppbRecord)[dwCursor++] = 0x17; // SSL record type is application = 23
            (*ppbRecord)[dwCursor++] = 0x03; // SSL major version number
            (*ppbRecord)[dwCursor++] = 0x01; // SSL minor version number

            AL::Convert::H2N16((WORD)dwTLSMessageSize, &((*ppbRecord)[dwCursor]));
            dwCursor += 2;

            memcpy(&((*ppbRecord)[dwCursor]), pbTLSMessage, dwTLSMessageSize);
            dwCursor += dwTLSMessageSize;
        }

        //
        // If we used encryption then we must free the allocated TLSMessage.
        //
        if (bEncrypt)
            AL::Heap::Free((LPVOID*)&pbTLSMessage);
    }

    return dwReturnCode;
}


//
// Build a handshake record
//
DWORD AL::TLS::Record::MakeHandshake(_Inout_ AL::TLS::CTLSSession *pTLSSession, _In_bytecount_(dwMessageSize) LPCBYTE pbMessage, _In_ DWORD dwMessageSize, _Out_bytecap_(*pdwRecordSize) LPBYTE *ppbRecord, _Out_ DWORD *pdwRecordSize, _In_ BOOL bEncrypt)
{
    DWORD dwReturnCode = NO_ERROR;
    LPBYTE pbTLSMessage;
    DWORD dwTLSMessageSize;

    AL_TRACE_DEBUG(_T("Encrypt: %d"), bEncrypt);

    //
    // Do we need to encrypt the handshake record?
    //
    if (bEncrypt) {
        LPBYTE pbTempRecord;
        DWORD cbTempRecord;

        //
        // First build a handshake record (no encryption)
        //
        if ((dwReturnCode = AL::TLS::Record::MakeHandshake(pTLSSession, pbMessage, dwMessageSize, &pbTempRecord, &cbTempRecord, FALSE)) == NO_ERROR) {
            //
            // Encrypt this record which will be add to the final handshake record
            //
            dwReturnCode = AL::TLS::EncBlock(pTLSSession, pbTempRecord, cbTempRecord, &pbTLSMessage, &dwTLSMessageSize);
            AL::Heap::Free((LPVOID*)&pbTempRecord);
        } else {
            pbTLSMessage = NULL;
            dwTLSMessageSize = 0;
        }
    } else {
        pbTLSMessage = (LPBYTE)pbMessage;
        dwTLSMessageSize = dwMessageSize;
    }

    if (dwReturnCode == NO_ERROR) {
        *pdwRecordSize = 0x05 + dwTLSMessageSize;
        if ((dwReturnCode = AL::Heap::Alloc(*pdwRecordSize, (LPVOID*)ppbRecord)) == NO_ERROR) {
            DWORD dwCursor = 0;

            //
            // ssl record header
            //
            (*ppbRecord)[dwCursor++] = 0x16; // ssl record type is handshake = 22
            (*ppbRecord)[dwCursor++] = 0x03; // ssl major version number
            (*ppbRecord)[dwCursor++] = 0x01; // ssl minor version number

            AL::Convert::H2N16((WORD)dwTLSMessageSize, &((*ppbRecord)[dwCursor]));
            dwCursor += 2;

            memcpy(&((*ppbRecord)[dwCursor]), pbTLSMessage, dwTLSMessageSize);
            dwCursor += dwTLSMessageSize;

            //
            // If we used encryption then we must free the allocated TLSMessage
            //
            if (bEncrypt)
                AL::Heap::Free((LPVOID*)&pbTLSMessage);
        }
    }

    return dwReturnCode;
}


//
// Adds a change cipher spec handshake record to the send message
//
DWORD AL::TLS::Record::MakeChangeCipherSpec(_Out_bytecap_(*pdwRecordSize) LPBYTE *ppbRecord, _Out_ DWORD *pdwRecordSize)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    *pdwRecordSize = 0x06;
    if ((dwReturnCode = AL::Heap::Alloc(*pdwRecordSize, (LPVOID*)ppbRecord)) == NO_ERROR) {
        DWORD dwCursor = 0;

        //
        // ssl record header
        //
        (*ppbRecord)[dwCursor++] = 0x14; // ssl record type is change cipher spec = 20
        (*ppbRecord)[dwCursor++] = 0x03; // ssl major version number
        (*ppbRecord)[dwCursor++] = 0x01; // ssl minor version number

        AL::Convert::H2N16(0x01, &((*ppbRecord)[dwCursor])); // length of message
        dwCursor += 2;

        (*ppbRecord)[dwCursor++] = 0x01;
    }

    return dwReturnCode;
}


//
// This function will build the TLS ClientHello record
//
DWORD AL::TLS::Msg::MakeClientHello(_Out_ BYTE pbRandomClient[AL_TLS_RANDOM_SIZE], _In_bytecount_(dwTLSSessionIDSize) LPCBYTE pbTLSSessionID, _In_ DWORD dwTLSSessionIDSize, _Out_bytecap_(*pdwTLSMessageSize) LPBYTE *ppbTLSMessage, _Out_ DWORD *pdwTLSMessageSize, _Out_ ALG_ID *palgEncKey, _Out_ DWORD *pdwEncKeySize, _Out_ ALG_ID *palgMacKey, _Out_ DWORD *pdwMacKeySize)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    *pdwTLSMessageSize = 0x0D + AL_TLS_RANDOM_SIZE + dwTLSSessionIDSize;
    if ((dwReturnCode = AL::Heap::Alloc(*pdwTLSMessageSize, (LPVOID*)ppbTLSMessage)) == NO_ERROR) {
        DWORD dwCursor = 0;

        //
        // ssl handshake header
        //
        (*ppbTLSMessage)[dwCursor++] = 0x01;   // message type is client_hello = 1

        // length of fragment is length of total message (*pdwTLSMessageSize) - header(4)
        AL::Convert::H2N24(*pdwTLSMessageSize - 4, &((*ppbTLSMessage)[dwCursor]));
        dwCursor += 3;

        //
        // Version 3.1 (WORD)
        // 00000011 00000001
        //
        (*ppbTLSMessage)[dwCursor++] = 0x03;
        (*ppbTLSMessage)[dwCursor++] = 0x01;

        if ((dwReturnCode = _GenRandom(pbRandomClient)) == NO_ERROR) {
            //
            // Random
            //
            memcpy(&((*ppbTLSMessage)[dwCursor]), pbRandomClient, AL_TLS_RANDOM_SIZE);
            dwCursor += AL_TLS_RANDOM_SIZE;

            //
            // Session ID size
            //
            (*ppbTLSMessage)[dwCursor++] = (BYTE)dwTLSSessionIDSize;

            //
            // SessionID
            //
            memcpy(&((*ppbTLSMessage)[dwCursor]), pbTLSSessionID, dwTLSSessionIDSize);
            dwCursor += dwTLSSessionIDSize;

            //
            // Length of cypher_suite:
            //
            AL::Convert::H2N16(0x02, &((*ppbTLSMessage)[dwCursor]));
            dwCursor += 2;

            //
            // TLS_RSA_WITH_3DES_EDE_CBC_SHA { 0x00, 0x0A }
            // TLS_RSA_WITH_RC4_128_MD5      { 0x00,0x04 }
            // TLS_RSA_WITH_RC4_128_SHA1     { 0x00,0x05 }
            //
            *palgEncKey = CALG_3DES;
            *pdwEncKeySize = 24;

            *palgMacKey = CALG_SHA1;
            *pdwMacKeySize = 20;

            (*ppbTLSMessage)[dwCursor++] = 0x00;
            (*ppbTLSMessage)[dwCursor++] = 0x0A;

            //
            // Compression
            //
            (*ppbTLSMessage)[dwCursor++] = 0x01;   // length of compression section
            (*ppbTLSMessage)[dwCursor++] = 0x00; // no compression
        } else
            AL::Heap::Free((LPVOID*)ppbTLSMessage);
    }

    return dwReturnCode;
}


//
// This function will build the TLS ServerHello record
//
DWORD AL::TLS::Msg::MakeServerHello(_Out_ BYTE pbRandomServer[AL_TLS_RANDOM_SIZE], _In_bytecount_(dwTLSSessionIDSize) LPCBYTE pbTLSSessionID, _In_ DWORD dwTLSSessionIDSize, _Out_bytecap_(*pdwTLSMessageSize) LPBYTE *ppbTLSMessage, _Out_ DWORD *pdwTLSMessageSize, _Out_ ALG_ID *palgEncKey, _Out_ DWORD *pdwEncKeySize, _Out_ ALG_ID *palgMacKey, _Out_ DWORD *pdwMacKeySize)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    *pdwTLSMessageSize = 0x0A+AL_TLS_RANDOM_SIZE+dwTLSSessionIDSize;
    if ((dwReturnCode = AL::Heap::Alloc(*pdwTLSMessageSize, (LPVOID*)ppbTLSMessage)) == NO_ERROR) {
        DWORD dwCursor = 0;

        //
        // ssl handshake header
        //
        (*ppbTLSMessage)[dwCursor++] = 0x02;   // message type is server_hello = 2

        // length of fragment is length of total message (*pdwTLSMessageSize) - header(4)
        AL::Convert::H2N24(*pdwTLSMessageSize - 4, &((*ppbTLSMessage)[dwCursor]));
        dwCursor += 3;

        //
        // Version 3.1 (WORD)
        // 00000011 00000001
        //
        (*ppbTLSMessage)[dwCursor++] = 0x03;
        (*ppbTLSMessage)[dwCursor++] = 0x01;

        if ((dwReturnCode = _GenRandom(pbRandomServer)) == NO_ERROR) {
            //
            // Random
            //
            memcpy(&((*ppbTLSMessage)[dwCursor]), pbRandomServer, AL_TLS_RANDOM_SIZE);
            dwCursor += AL_TLS_RANDOM_SIZE;

            //
            // Session ID size
            //
            (*ppbTLSMessage)[dwCursor++] = (BYTE)dwTLSSessionIDSize;

            //
            // SessionID
            //
            memcpy(&((*ppbTLSMessage)[dwCursor]), pbTLSSessionID, dwTLSSessionIDSize);
            dwCursor += dwTLSSessionIDSize;

            //
            // TLS_RSA_WITH_3DES_EDE_CBC_SHA { 0x00, 0x0A }
            // TLS_RSA_WITH_RC4_128_MD5      { 0x00,0x04 }
            // TLS_RSA_WITH_RC4_128_SHA1     { 0x00,0x05 }
            //
            *palgEncKey = CALG_3DES;
            *pdwEncKeySize = 24;

            *palgMacKey = CALG_SHA1;
            *pdwMacKeySize = 20;

            (*ppbTLSMessage)[dwCursor++] = 0x00;
            (*ppbTLSMessage)[dwCursor++] = 0x0A;

            //
            // Compression
            //
            (*ppbTLSMessage)[dwCursor++] = 0x00; // no compression
        } else
            AL::Heap::Free((LPVOID*)ppbTLSMessage);
    }

    return dwReturnCode;
}


//
// This function will build Certificate Request
//
DWORD AL::TLS::Msg::MakeCertificateRequest(_Out_bytecap_(*pdwTLSMessageSize) LPBYTE *ppbTLSMessage, _Out_ DWORD *pdwTLSMessageSize)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    *pdwTLSMessageSize = 0x04;
    if ((dwReturnCode = AL::Heap::Alloc(*pdwTLSMessageSize, (LPVOID*)ppbTLSMessage)) == NO_ERROR) {
        DWORD dwCursor = 0;

        //
        // ssl handshake header
        //
        (*ppbTLSMessage)[dwCursor++] = 0x0D;   // message type is server_done = 13

        // length of fragment is length of total message (0)
        AL::Convert::H2N24(0x00 , &((*ppbTLSMessage)[dwCursor]));
    }

    return dwReturnCode;
}


//
// This function will build the Server Hello Done Message
//
DWORD AL::TLS::Msg::MakeServerHelloDone(_Out_bytecap_(*pdwTLSMessageSize) LPBYTE *ppbTLSMessage, _Out_ DWORD *pdwTLSMessageSize)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    *pdwTLSMessageSize = 0x04;
    if ((dwReturnCode = AL::Heap::Alloc(*pdwTLSMessageSize, (LPVOID*)ppbTLSMessage)) == NO_ERROR) {
        DWORD dwCursor = 0;

        //
        // ssl handshake header
        //
        (*ppbTLSMessage)[dwCursor++] = 0x0E;   // message type is server_done = 14

        // length of fragment is length of total message (0)
        AL::Convert::H2N24(0x00 , &((*ppbTLSMessage)[dwCursor]));
    }

    return dwReturnCode;
}


//
// This function will build the Client Certificate Message
//
DWORD AL::TLS::Msg::MakeClientCertificate(_Out_bytecap_(*pdwTLSMessageSize) LPBYTE *ppbTLSMessage, _Out_ DWORD *pdwTLSMessageSize)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    *pdwTLSMessageSize = 0x07;
    if ((dwReturnCode = AL::Heap::Alloc(*pdwTLSMessageSize, (LPVOID*)ppbTLSMessage)) == NO_ERROR) {
        DWORD dwCursor = 0;

        (*ppbTLSMessage)[dwCursor++] = 0x0B;   // message type is certificate

        AL::Convert::H2N24(0x03, &((*ppbTLSMessage)[dwCursor]));
        dwCursor += 3;

        AL::Convert::H2N24(0x00, &((*ppbTLSMessage)[dwCursor]));
        dwCursor += 3;
    }

    return dwReturnCode;
}


//
// This function will build the Server Certificate Message
//
DWORD AL::TLS::Msg::MakeServerCertificate(_In_ LPCBYTE pbServerCertSHA1, _Out_bytecap_(*pdwTLSMessageSize) LPBYTE *ppbTLSMessage, _Out_ DWORD *pdwTLSMessageSize)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // First find certificate in local store ("MY")
    //
    ATL::Crypt::CCertContext cc;
    if ((dwReturnCode = AL::Crypto::GetCertificate(pbServerCertSHA1, &cc)) == NO_ERROR) {
        //
        // Retrieve Certificate Hierarchy
        //
        CERT_CHAIN_PARA ChainParams;
        CERT_ENHKEY_USAGE EnhkeyUsage;
        CERT_USAGE_MATCH CertUsage;

        //
        // Initialize the certificate chain validation
        //
        EnhkeyUsage.cUsageIdentifier = 0;
        EnhkeyUsage.rgpszUsageIdentifier = NULL;

        CertUsage.dwType = USAGE_MATCH_TYPE_AND;
        CertUsage.Usage  = EnhkeyUsage;

        ZeroMemory(&ChainParams, sizeof(ChainParams));
        ChainParams.cbSize = sizeof(ChainParams);
        ChainParams.dwUrlRetrievalTimeout = 1;
        ChainParams.RequestedUsage = CertUsage;

        //
        // Check the certificate chain
        // do not check urls as we do not have any IP connectivity
        //
        ATL::Crypt::CCertChainContext ccc;
        if (ccc.Create(HCCE_LOCAL_MACHINE, cc, NULL, NULL, &ChainParams, 0, NULL)) {
            if (ccc->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR) {
                if (ccc->rgpChain[0]) {
                    DWORD dwCertListLength = 0;

                    //
                    // Have to determine length of message first
                    // First retrieve total length of all certificates
                    //
                    for (DWORD i = 0; i < ccc->rgpChain[0]->cElement; i++) {
                        PCCERT_CONTEXT pChainCertContext = ccc->rgpChain[0]->rgpElement[i]->pCertContext;

                        //
                        // Length is current length + header(length:3) + certificate(pChainCertContext->cbCertEncoded:?)
                        //
                        dwCertListLength = dwCertListLength + 0x03 + pChainCertContext->cbCertEncoded;
                    }

                    //
                    // Now add certificate message header(type:1+msg_length:3+certlistlength:3)
                    //
                    *pdwTLSMessageSize = dwCertListLength + 0x07;

                    //
                    // Built initial certificate message
                    //
                    if ((dwReturnCode = AL::Heap::Alloc(*pdwTLSMessageSize, (LPVOID*)ppbTLSMessage)) == NO_ERROR) {
                        DWORD dwCursor = 0;

                        (*ppbTLSMessage)[dwCursor++] = 0x0B;   // message type is certificate

                        //
                        // length of message
                        //
                        AL::Convert::H2N24(dwCertListLength + 0x03, &((*ppbTLSMessage)[dwCursor])); // length of message
                        dwCursor += 3;

                        //
                        // Certificate list length
                        //
                        AL::Convert::H2N24(dwCertListLength, &((*ppbTLSMessage)[dwCursor])); // list length
                        dwCursor += 3;

                        for (DWORD i = 0; i < ccc->rgpChain[0]->cElement; i++) {
                            PCCERT_CONTEXT pChainCertContext = ccc->rgpChain[0]->rgpElement[i]->pCertContext;

                            //
                            // Length of certificate
                            //
                            AL::Convert::H2N24(pChainCertContext->cbCertEncoded, &((*ppbTLSMessage)[dwCursor])); // length of message
                            dwCursor += 3;

                            //
                            // Certificate
                            //
                            memcpy(&((*ppbTLSMessage)[dwCursor]), pChainCertContext->pbCertEncoded, pChainCertContext->cbCertEncoded);
                            dwCursor += pChainCertContext->cbCertEncoded;
                        }
                    }
                }
            } else {
                AL_TRACE_ERROR(_T("Chain could not be validated (%ld)."), ccc->TrustStatus.dwErrorStatus);
                dwReturnCode = ERROR_CANTOPEN;
            }
        } else {
            AL_TRACE_ERROR(_T("CertGetCertificateChain failed (%ld)."), GetLastError());
            dwReturnCode = ERROR_INTERNAL_ERROR;
        }
    }

    return dwReturnCode;
}


//
// This function will build the Client Key Exchange Message
//
DWORD AL::TLS::Msg::MakeClientKeyExchange(_In_bytecount_(dwEncPMSSize) LPCBYTE pbEncPMS, _In_ DWORD dwEncPMSSize, _Out_bytecap_(*pdwTLSMessageSize) LPBYTE *ppbTLSMessage, _Out_ DWORD *pdwTLSMessageSize)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    *pdwTLSMessageSize = 0x06 + dwEncPMSSize;
    if ((dwReturnCode = AL::Heap::Alloc(*pdwTLSMessageSize, (LPVOID*)ppbTLSMessage)) == NO_ERROR) {
        DWORD dwCursor = 0;

        (*ppbTLSMessage)[dwCursor++] = 0x10; // message type is client_exchange

        AL::Convert::H2N24(dwEncPMSSize + 0x02, &((*ppbTLSMessage)[dwCursor])); // length of message
        dwCursor += 3;

        //
        // cke header
        //
        AL::Convert::H2N16((WORD)dwEncPMSSize, &((*ppbTLSMessage)[dwCursor])); // length of encrypted data
        dwCursor += 2;

        //
        // Copy the encrypted block
        // But first swap it because of big and little endians... ;)
        //
        LPBYTE pbSwapped;
        if ((dwReturnCode = AL::Heap::Alloc(dwEncPMSSize, (LPVOID*)&pbSwapped)) == NO_ERROR) {
            AL::Buffer::Swap(pbEncPMS, pbSwapped, dwEncPMSSize);
            memcpy(&((*ppbTLSMessage)[dwCursor]), pbSwapped, dwEncPMSSize);
            dwCursor += dwEncPMSSize;

            AL::Heap::Free((LPVOID*)&pbSwapped);
        } else
            AL::Heap::Free((LPVOID*)ppbTLSMessage);
    }

    return dwReturnCode;
}


//
// This function will build the Finished Message
//
DWORD AL::TLS::Msg::MakeFinished(_In_ const AL::TLS::CTLSSession *pTLSSession, _In_bytecount_(dwLabelSize) LPCBYTE pbLabel, _In_ DWORD dwLabelSize, _In_bytecount_(dwMSSize) LPCBYTE pbMS, _In_ DWORD dwMSSize, _Out_bytecap_(*pdwTLSMessageSize) LPBYTE *ppbTLSMessage, _Out_ DWORD *pdwTLSMessageSize)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    *pdwTLSMessageSize = 0x04 + AL_TLS_FINISH_SIZE;
    if ((dwReturnCode = AL::Heap::Alloc(*pdwTLSMessageSize, (LPVOID*)ppbTLSMessage)) == NO_ERROR) {
        DWORD dwCursor = 0;

        (*ppbTLSMessage)[dwCursor++] = 0x14; // finish message

        AL::Convert::H2N24((WORD)AL_TLS_FINISH_SIZE, &((*ppbTLSMessage)[dwCursor]));
        dwCursor += 3;

        if (pTLSSession->m_hCSP) {
            //
            // First calculate length of total handshake msg.
            //
            SIZE_T nDataSize = 0;
            for (POSITION pos = pTLSSession->m_lHandshakeMsgs.GetHeadPosition(); pos; pTLSSession->m_lHandshakeMsgs.GetNext(pos))
                nDataSize += pTLSSession->m_lHandshakeMsgs.GetAt(pos).GetCount();

            LPBYTE pbData;
            if ((dwReturnCode = AL::Heap::Alloc(nDataSize, (LPVOID*)&pbData)) == NO_ERROR) {
                SIZE_T nOffset = 0;

                for (POSITION pos = pTLSSession->m_lHandshakeMsgs.GetHeadPosition(); pos; pTLSSession->m_lHandshakeMsgs.GetNext(pos)) {
                    const ATL::CAtlArray<BYTE> &aMsg = pTLSSession->m_lHandshakeMsgs.GetAt(pos);
                    SIZE_T nMsgSize = aMsg.GetCount();
                    memcpy(pbData + nOffset, aMsg.GetData(), nMsgSize);
                    nOffset += nMsgSize;
                }

                ATL::CAtlArray<BYTE> aMD5;
                if ((AL::Crypto::GetHash(pTLSSession->m_hCSP, CALG_MD5, pbData, (DWORD)nDataSize, aMD5)) == NO_ERROR) {
                    ATL::CAtlArray<BYTE> aSHA1;
                    if ((AL::Crypto::GetHash(pTLSSession->m_hCSP, CALG_SHA1, pbData, (DWORD)nDataSize, aSHA1)) == NO_ERROR) {
                        LPBYTE pHash;
                        if ((dwReturnCode = AL::Heap::Alloc(36, (LPVOID*)&pHash)) == NO_ERROR) {
                            memcpy(pHash     ,  aMD5.GetData(), 16);
                            memcpy(pHash + 16, aSHA1.GetData(), 20);

                            if ((dwReturnCode = AL::TLS::PRF(pTLSSession->m_hCSP, pbMS, dwMSSize, pbLabel, dwLabelSize, pHash, 36, &((*ppbTLSMessage)[dwCursor]), AL_TLS_FINISH_SIZE)) == NO_ERROR)
                                dwCursor += AL_TLS_FINISH_SIZE;

                            AL::Heap::Free((LPVOID*)&pHash);
                        }
                    }
                }

                AL::Heap::Free((LPVOID*)&pbData);
            }
        } else {
            AL_TRACE_ERROR(_T("No handle to CSP."));
            dwReturnCode = ERROR_ENCRYPTION_FAILED;
        }

        if (dwReturnCode != NO_ERROR) {
            AL::Heap::Free((LPVOID*)ppbTLSMessage);
            *pdwTLSMessageSize = 0;
        }
    }

    return dwReturnCode;
}


//
// This function verifies the server finished message
//
DWORD AL::TLS::Msg::VerifyFinished(_In_ const AL::TLS::CTLSSession *pTLSSession, _In_bytecount_(dwLabelSize) LPCBYTE pbLabel, _In_ DWORD dwLabelSize, _In_bytecount_(dwMSSize) LPCBYTE pbMS, _In_ DWORD dwMSSize, _In_bytecount_(dwVerifyFinishedSize) LPCBYTE pbVerifyFinished, _In_ DWORD dwVerifyFinishedSize)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    if (dwVerifyFinishedSize != AL_TLS_FINISH_SIZE)
        return ERROR_ENCRYPTION_FAILED;

    LPBYTE pbFinished;
    if ((dwReturnCode = AL::Heap::Alloc(AL_TLS_FINISH_SIZE, (LPVOID*)&pbFinished)) == NO_ERROR) {
        if (pTLSSession->m_hCSP) {
            //
            // first calculate length of total handshake msg
            //
            SIZE_T nDataSize = 0;

            for (POSITION pos = pTLSSession->m_lHandshakeMsgs.GetHeadPosition(); pos; pTLSSession->m_lHandshakeMsgs.GetNext(pos))
                nDataSize += pTLSSession->m_lHandshakeMsgs.GetAt(pos).GetCount();

            LPBYTE pbData;
            if ((dwReturnCode = AL::Heap::Alloc(nDataSize, (LPVOID*)&pbData)) == NO_ERROR) {
                SIZE_T nOffset = 0;

                for (POSITION pos = pTLSSession->m_lHandshakeMsgs.GetHeadPosition(); pos; pTLSSession->m_lHandshakeMsgs.GetNext(pos)) {
                    const ATL::CAtlArray<BYTE> &aMsg = pTLSSession->m_lHandshakeMsgs.GetAt(pos);
                    SIZE_T nMsgSize = aMsg.GetCount();
                    memcpy(pbData + nOffset, aMsg.GetData(), nMsgSize);
                    nOffset += nMsgSize;
                }

                ATL::CAtlArray<BYTE> aMD5;
                if ((AL::Crypto::GetHash(pTLSSession->m_hCSP, CALG_MD5, pbData, (DWORD)nDataSize, aMD5)) == NO_ERROR) {
                    ATL::CAtlArray<BYTE> aSHA1;
                    if ((AL::Crypto::GetHash(pTLSSession->m_hCSP, CALG_SHA1, pbData, (DWORD)nDataSize, aSHA1)) == NO_ERROR) {
                        LPBYTE pHash;
                        if ((dwReturnCode = AL::Heap::Alloc(36, (LPVOID*)&pHash)) == NO_ERROR) {
                            memcpy(pHash     ,  aMD5.GetData(), 16);
                            memcpy(pHash + 16, aSHA1.GetData(), 20);

                            if ((dwReturnCode = AL::TLS::PRF(pTLSSession->m_hCSP, pbMS, dwMSSize, pbLabel, dwLabelSize, (LPCBYTE)pHash, 36, pbFinished, AL_TLS_FINISH_SIZE)) == NO_ERROR) {
                                if (memcmp(pbFinished, pbVerifyFinished, AL_TLS_FINISH_SIZE) != 0) {
                                    AL_TRACE_ERROR(_T("Messages differ."));
                                    dwReturnCode = ERROR_ENCRYPTION_FAILED;
                                }
                            }

                            AL::Heap::Free((LPVOID*)&pHash);
                        }
                    }
                }

                AL::Heap::Free((LPVOID*)&pbData);
            }
        } else {
            AL_TRACE_ERROR(_T("No handle to CSP."));
            dwReturnCode = ERROR_ENCRYPTION_FAILED;
        }

        AL::Heap::Free((LPVOID*)&pbFinished);
    }

    return dwReturnCode;
}


//
// Helper function for implementing TLS according to
// http://www.ietf.org/rfc/rfc2104.txt
// Functions are named to mirror function in RFC
//
static DWORD _PHash(_In_ HCRYPTPROV hCSP, _In_ ALG_ID algOrigKey, _In_bytecount_(dwSecretSize) LPCBYTE pbSecret, _In_ DWORD dwSecretSize, _In_bytecount_(dwSeedSize) LPCBYTE pbSeed, _In_ DWORD dwSeedSize, _Out_bytecap_(dwDataSize) LPBYTE pbData, _In_ DWORD dwDataSize)
{
    DWORD dwReturnCode = NO_ERROR;
    DWORD dwHashSize;

    if (algOrigKey == CALG_MD5)
        dwHashSize = 16;
    else if (algOrigKey == CALG_SHA1)
        dwHashSize = 20;
    else
        return ERROR_NOT_SUPPORTED;

    //
    // Create temporary buffer, must be at least big enough for dwHashSize + dwSeedSize
    //
    DWORD dwTempSize = dwHashSize + dwSeedSize;
    LPBYTE pbTemp;
    if ((dwReturnCode = AL::Heap::Alloc(dwTempSize, (LPVOID*)&pbTemp)) == NO_ERROR) {
        //
        // Create buffer large enough for required material
        //
        DWORD dwIterations = dwDataSize / dwHashSize + (dwDataSize % dwHashSize == 0 ? 0 : 1);
        LPBYTE pbBuf;
        if ((dwReturnCode = AL::Heap::Alloc(dwIterations * dwHashSize, (LPVOID*)&pbBuf)) == NO_ERROR) {
            //
            // P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
            //   HMAC_hash(secret, A(2) + seed) +
            //   HMAC_hash(secret, A(3) + seed) + ...
            //
            // Where + indicates concatenation.
            //
            // A() is defined as:
            // A(0) = seed
            // A(i) = HMAC_hash(secret, A(i-1))
            //

            //
            // A(1) = P_MD5(secret, seed)
            //
            BYTE pbA[20];
            if ((dwReturnCode = _HMAC(hCSP, algOrigKey, pbSecret, dwSecretSize, pbSeed, dwSeedSize, pbA, dwHashSize)) == NO_ERROR) {
                for (DWORD i = 0; i < dwIterations; i++) {
                    //
                    // P_MD5(secret, A(i) + seed)
                    //
                    memcpy_s(pbTemp,              dwTempSize,              pbA,    dwHashSize);
                    memcpy_s(pbTemp + dwHashSize, dwTempSize - dwHashSize, pbSeed, dwSeedSize);

                    if ((dwReturnCode = _HMAC(hCSP, algOrigKey, pbSecret, dwSecretSize, pbTemp, dwHashSize + dwSeedSize, pbBuf + (i * dwHashSize), dwHashSize)) == NO_ERROR) {
                        //
                        // A(i) = P_MD5(secret, a(i-1))
                        //
                        dwReturnCode = _HMAC(hCSP, algOrigKey, pbSecret, dwSecretSize, pbA, dwHashSize, pbA, dwHashSize);
                    }

                    if (dwReturnCode != NO_ERROR)
                        break;
                }

                //
                // Copy required data
                //
                if (dwReturnCode == NO_ERROR)
                    memcpy(pbData, pbBuf, dwDataSize);
            }

            AL::Heap::Free((LPVOID*)&pbBuf);
        }

        AL::Heap::Free((LPVOID*)&pbTemp);
    }

    return dwReturnCode;
}


//
// Generate a new SSL Session ID
//
static inline DWORD _GenSessionID(_Out_ BYTE pbSessionID[AL_TLS_SESSION_ID_SIZE], _Out_ DWORD *pcbSessionID, _In_ DWORD dwMaxSessionID)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    *pcbSessionID = dwMaxSessionID;

    if ((dwReturnCode = AL::Crypto::GenSecureRandom(pbSessionID, AL_TLS_RANDOM_SIZE)) == NO_ERROR) {
        AL_TRACE_DEBUG(_T("random bytes(%ld)"), AL_TLS_SESSION_ID_SIZE);
        AL_DUMP_DEBUG(pbSessionID, AL_TLS_SESSION_ID_SIZE);
    }

    return dwReturnCode;
}


//
// Generate the 32 random bytes for the client
//
static inline DWORD _GenRandom(_Out_ BYTE pbRandom[AL_TLS_RANDOM_SIZE])
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    dwReturnCode = AL::Crypto::GenSecureRandom(pbRandom, AL_TLS_RANDOM_SIZE);

    return dwReturnCode;
}


//
// Helper function for implementing TLS according to
// http://www.ietf.org/rfc/rfc2104.txt
// Functions are named to mirror function in RFC
//
static DWORD _HMAC(_In_ HCRYPTPROV hCSP, _In_ ALG_ID algOrigKey, _In_bytecount_(dwOrigKeySize) LPCBYTE pbOrigKey, _In_ DWORD dwOrigKeySize, _In_bytecount_(dwSeedSize) LPCBYTE pbSeed, _In_ DWORD dwSeedSize, _Out_bytecap_(dwDataSize) LPBYTE pbData, _In_ DWORD dwDataSize)
{
    DWORD dwReturnCode = NO_ERROR;
    DWORD dwHashSize;
    LPCBYTE pbKey = NULL;
    DWORD dwKeySize = 0;

    if (algOrigKey == CALG_MD5)
        dwHashSize = 16;
    else if (algOrigKey == CALG_SHA1)
        dwHashSize = 20;
    else
        return ERROR_NOT_SUPPORTED;

    //
    // if key is longer than 64 bytes reset it to key=MD5(key)
    //
    if (dwOrigKeySize > 64) {
        ATL::Crypt::CHash hash;
        if (hash.Create(hCSP, algOrigKey, 0, 0)) {
            if (CryptHashData(hash, pbOrigKey, dwOrigKeySize, 0)) {
                BYTE pbTempKey[20];
                if (CryptGetHashParam(hash, HP_HASHVAL, pbTempKey, &dwHashSize, 0)) {
                    pbKey     = pbTempKey;
                    dwKeySize = dwHashSize;
                } else {
                    AL_TRACE_ERROR(_T("CryptGetHashParam(HP_HASHVAL) failed (%ld)."), GetLastError());
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
    } else {
        pbKey     = pbOrigKey;
        dwKeySize = dwOrigKeySize;
    }

    if (dwReturnCode == NO_ERROR) {
        BYTE pbK_ipad[64];    // inner padding - key XORd with ipad
        BYTE pbK_opad[64];    // outer padding - key XORd with opad

        //
        // the HMAC_MD5 transform looks like:
        //
        // MD5(K XOR opad, MD5(K XOR ipad, text))
        //
        // where K is an n byte key
        // ipad is the byte 0x36 repeated 64 times
        // opad is the byte 0x5c repeated 64 times
        // and text is the data being protected
        //

        //
        // start out by storing key in pads
        //
        memcpy_s  (pbK_ipad,             sizeof(pbK_ipad),             pbKey, dwKeySize);
        ZeroMemory(pbK_ipad + dwKeySize, sizeof(pbK_ipad) - dwKeySize);
        memcpy_s  (pbK_opad,             sizeof(pbK_opad),             pbKey, dwKeySize);
        ZeroMemory(pbK_opad + dwKeySize, sizeof(pbK_opad) - dwKeySize);

        //
        // XOR key with ipad and opad values
        //
        for (int i = 0; i < 64; i++) {
            pbK_ipad[i] ^= 0x36;
            pbK_opad[i] ^= 0x5c;
        }

        //
        // perform inner MD5
        //
        ATL::Crypt::CHash hash;
        if (hash.Create(hCSP, algOrigKey, 0, 0)) {
            if (CryptHashData(hash, pbK_ipad, sizeof(pbK_ipad), 0)) {
                if (CryptHashData(hash, pbSeed, dwSeedSize, 0)) {
                    if (CryptGetHashParam(hash, HP_HASHVAL, pbData, &dwDataSize, 0)) {
                        //
                        // perform outer MD5
                        //
                        ATL::Crypt::CHash hash;
                        if (hash.Create(hCSP, algOrigKey, 0, 0)) {
                            if (CryptHashData(hash, pbK_opad, sizeof(pbK_opad), 0)) {
                                if (CryptHashData(hash, pbData, dwDataSize, 0)) {
                                    if (!CryptGetHashParam(hash, HP_HASHVAL, pbData, &dwDataSize, 0)) {
                                        AL_TRACE_ERROR(_T("CryptGetHashParam(HP_HASHVAL) failed (%ld)."), GetLastError());
                                        dwReturnCode = ERROR_ENCRYPTION_FAILED;
                                    }
                                } else {
                                    AL_TRACE_ERROR(_T("CryptHashData failed (%ld)."), GetLastError());
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
                    } else {
                        AL_TRACE_ERROR(_T("CryptGetHashParam(HP_HASHVAL) failed (%ld)."), GetLastError());
                        dwReturnCode = ERROR_ENCRYPTION_FAILED;
                    }
                } else {
                    AL_TRACE_ERROR(_T("CryptHashData failed (%ld)."), GetLastError());
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
    }

    return dwReturnCode;
}
