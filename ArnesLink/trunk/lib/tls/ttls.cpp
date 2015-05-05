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
// Local function declaration
//
static DWORD _GenRSAEncPMS(_Inout_ AL::TLS::CTLSSession *pTLSSession, _Out_ LPBYTE *ppbEncPMS, _Out_ DWORD *pdwEncPMSSize);
static DWORD _ComputeMS(_In_ HCRYPTPROV hCSP, _In_ LPCBYTE pbRandomClient, _In_ LPCBYTE pbRandomServer, _Inout_ LPBYTE pbPMS, _Out_ LPBYTE pbMS);
static DWORD _GenPMS(_Inout_ BYTE pbPMS[AL_TLS_PMS_SIZE]);


//
// This function reads in fragmented message and puts the result in the pbFragmentedMessage
//
DWORD AL::TTLS::ReadMessage(_Inout_ AL::TLS::CTLSSession *pTLSSession, _In_ BYTE bPacketId, _In_ const EapPacket *pReceivePacket, _Out_ AL::EAP::CPacket &pktSend, _Inout_ EapPeerMethodOutput *pEapPeerMethodOutput, _Out_ BYTE *pbMethodVersion, _In_ DWORD dwEAPPacketLength, _In_ BYTE bEapProtocolId, _In_ BYTE bVersion)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // First read TLS version
    //
    *pbMethodVersion = pReceivePacket->Data[1] & AL_EAP_METHOD_VERSION;

    if (dwEAPPacketLength < 7) {
        pTLSSession->ResetReceiveMsg();
    } else if (pReceivePacket->Data[1] & AL_TLS_REQUEST_MORE_FRAG) {
        //
        // First look how big the complete message is
        // Then request other fragments
        //
        if (pTLSSession->m_aReceiveMsg.IsEmpty()) {
            //
            // First fragmented message
            //
            if (pReceivePacket->Data[1] & AL_TLS_REQUEST_LENGTH_INC) {
                //
                // Length of total fragmented EAP-TLS packet
                //
                SIZE_T nMsgSize = AL::Convert::N2H32(&(pReceivePacket->Data[2]));
                if (pTLSSession->m_aReceiveMsg.SetCount(nMsgSize)) {
                    LPBYTE pMsg = pTLSSession->m_aReceiveMsg.GetData();
                    if (pReceivePacket->Data[1] & AL_TLS_REQUEST_LENGTH_INC) {
                        //
                        // Copy Fragmented data (length of message - EAP header(10))
                        //
                        pTLSSession->m_nReceiveCursor = dwEAPPacketLength - 10;
                        memcpy(pMsg, &(pReceivePacket->Data[6]), pTLSSession->m_nReceiveCursor);
                    } else {
                        pTLSSession->m_nReceiveCursor = dwEAPPacketLength - 6;
                        memcpy(pMsg, &(pReceivePacket->Data[2]), pTLSSession->m_nReceiveCursor);
                    }
                } else {
                    AL_TRACE_ERROR(_T("Error allocating memory for message."));
                    dwReturnCode = ERROR_OUTOFMEMORY;
                    pEapPeerMethodOutput->action = EapPeerMethodResponseActionNone;
                }
            } else {
                //
                // NOT IMPLEMENTED YET
                //
                //
                // Length is not include
                // don't now how to react yet
                // NOTE: should we continue?
                //
                AL_TRACE_ERROR(_T("Not an AL_TLS_REQUEST_MORE_FRAG. Not implemented."));
                dwReturnCode = ERROR_PPP_INVALID_PACKET;
                pEapPeerMethodOutput->action = EapPeerMethodResponseActionDiscard;
            }
        } else {
            //
            // Nth fragmented message
            //

            //
            // Just copy memory from previous frag cursor till length of message
            //
            LPBYTE pMsg = pTLSSession->m_aReceiveMsg.GetData() + pTLSSession->m_nReceiveCursor;
            if (pReceivePacket->Data[1] & AL_TLS_REQUEST_LENGTH_INC) {
                //
                // If length is included then copy from 6th byte and onwards
                //
                memcpy(pMsg, &(pReceivePacket->Data[6]), dwEAPPacketLength - 10);
                pTLSSession->m_nReceiveCursor += dwEAPPacketLength - 10;
            } else {
                //
                // If length is not included then copy from 2nd byte and onwards
                //
                memcpy(pMsg, &(pReceivePacket->Data[2]), dwEAPPacketLength - 6);
                pTLSSession->m_nReceiveCursor += dwEAPPacketLength - 6;
            }
        }

        if (dwReturnCode == NO_ERROR) {
            //
            //
            // When an EAP-TLS peer receives an EAP-Request packet with the M bit
            // set (MORE_FRAGMENTS), it MUST respond with an EAP-Response with EAP-Type=AL::EAP::g_bType and
            // no data
            //
            if ((dwReturnCode = pktSend.CreateResponse(bPacketId, bEapProtocolId, bVersion)) == NO_ERROR)
                pEapPeerMethodOutput->action = EapPeerMethodResponseActionSend;
            else
                pEapPeerMethodOutput->action = EapPeerMethodResponseActionNone;
        }
    } else {
        if (!pTLSSession->m_aReceiveMsg.IsEmpty()) {
            LPBYTE pMsg = pTLSSession->m_aReceiveMsg.GetData() + pTLSSession->m_nReceiveCursor;
            if (pReceivePacket->Data[1] & AL_TLS_REQUEST_LENGTH_INC) {
                //
                // If length is included then copy from 6th byte and onwards
                //
                memcpy(pMsg, &(pReceivePacket->Data[6]), dwEAPPacketLength - 10);
                pTLSSession->m_nReceiveCursor += dwEAPPacketLength - 10;
            } else {
                //
                // If length is not included then copy from 2nd byte and onwards
                //
                memcpy(pMsg, &(pReceivePacket->Data[2]), dwEAPPacketLength - 6);
                pTLSSession->m_nReceiveCursor += dwEAPPacketLength - 6;
            }
        } else {
            //
            // Normal unfragmented message
            //
            //
            // Length of total fragmented EAP-TLS packet
            //
            SIZE_T nMsgSize = pReceivePacket->Data[1] & AL_TLS_REQUEST_LENGTH_INC ? AL::Convert::N2H32(&(pReceivePacket->Data[2])) : dwEAPPacketLength - 6;
            if (pTLSSession->m_aReceiveMsg.SetCount(nMsgSize)) {
                LPBYTE pMsg = pTLSSession->m_aReceiveMsg.GetData();
                if (pReceivePacket->Data[1] & AL_TLS_REQUEST_LENGTH_INC) {
                    //
                    // If length is included then copy from 6th byte and onwards
                    //
                    pTLSSession->m_nReceiveCursor = dwEAPPacketLength - 10;
                    memcpy(pMsg, &(pReceivePacket->Data[6]), pTLSSession->m_nReceiveCursor);
                } else {
                    //
                    // If length is not included then copy from 2nd byte and onwards
                    //
                    pTLSSession->m_nReceiveCursor = dwEAPPacketLength - 6;
                    memcpy(pMsg, &(pReceivePacket->Data[2]), pTLSSession->m_nReceiveCursor);
                }
            } else {
                AL_TRACE_ERROR(_T("Error allocating memory for message."));
                dwReturnCode = ERROR_OUTOFMEMORY;
                pEapPeerMethodOutput->action = EapPeerMethodResponseActionNone;
            }
        }
    }

    return dwReturnCode;
}


//
// Create the SendPacket
// This function will fragment the actual EAP packet into segments
// if the packet is to large
//
DWORD AL::TTLS::SendMessage(_In_bytecount_(dwSendMsgSize) LPCBYTE pbSendMsg, _In_ DWORD dwSendMsgSize, _Inout_ DWORD *pdwSendCursor, _In_ BYTE bPacketId, _Inout_ AL::EAP::CPacket &pktSend, _Inout_ EapPeerMethodOutput *pEapPeerMethodOutput)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // First let see if we need to fragment the message.
    //
    if (dwSendMsgSize > AL_TLS_MAX_FRAG_SIZE) {
        if (*pdwSendCursor == 0) {
            pktSend->Data[1] |= AL_TLS_REQUEST_LENGTH_INC | AL_TLS_REQUEST_MORE_FRAG;

            //
            // Add message
            //
            if ((dwReturnCode = pktSend.Append(&(pbSendMsg[0]), AL_TLS_MAX_FRAG_SIZE, dwSendMsgSize)) == NO_ERROR) {
                *pdwSendCursor = AL_TLS_MAX_FRAG_SIZE;
                pEapPeerMethodOutput->action = EapPeerMethodResponseActionSend;
            }
        } else {
            if ((*pdwSendCursor + AL_TLS_MAX_FRAG_SIZE) > dwSendMsgSize) {
                //
                // Add message
                //
                if ((dwReturnCode = pktSend.Append(&(pbSendMsg[*pdwSendCursor]), dwSendMsgSize - *pdwSendCursor, dwSendMsgSize)) == NO_ERROR) {
                    *pdwSendCursor += AL_TLS_MAX_FRAG_SIZE;
                    pEapPeerMethodOutput->action = EapPeerMethodResponseActionSend;
                }
            } else {
                //
                // Nth message
                //
                pktSend->Data[1] |= AL_TLS_REQUEST_MORE_FRAG;

                //
                // Add message
                //
                if ((dwReturnCode = pktSend.Append(&(pbSendMsg[*pdwSendCursor]), AL_TLS_MAX_FRAG_SIZE, dwSendMsgSize)) == NO_ERROR) {
                    *pdwSendCursor += AL_TLS_MAX_FRAG_SIZE;
                    pEapPeerMethodOutput->action = EapPeerMethodResponseActionSend;
                }
            }
        }
    } else if (dwSendMsgSize == 0) {
        if ((dwReturnCode = pktSend.Append(pbSendMsg, dwSendMsgSize, dwSendMsgSize)) == NO_ERROR)
            pEapPeerMethodOutput->action = EapPeerMethodResponseActionSend;
    } else {
        pktSend->Data[1] |= AL_TLS_REQUEST_LENGTH_INC;

        if ((dwReturnCode = pktSend.Append(pbSendMsg, dwSendMsgSize, dwSendMsgSize)) == NO_ERROR)
            pEapPeerMethodOutput->action = EapPeerMethodResponseActionSend;
    }

    return dwReturnCode;
}


//
// This function builds the next response message
//
DWORD AL::TTLS::BuildResponsePacket(_Inout_ AL::TLS::CTLSSession *pTLSSession, _In_ BYTE bPacketId, _Out_ AL::EAP::CPacket &pktSend, _Inout_ EapPeerMethodOutput *pEapPeerMethodOutput, _In_ BYTE bEapProtocolId, _In_ BYTE bFlags)
{
    DWORD dwReturnCode = NO_ERROR;

    AL_TRACE_DEBUG(_T("TLS state: %d"), pTLSSession->m_TLSState);

    switch (pTLSSession->m_TLSState) {
        case AL::TLS::STATE_START:
            if ((dwReturnCode = pktSend.CreateResponse(bPacketId, bEapProtocolId, bFlags)) == NO_ERROR) {
                LPBYTE pbTLSMessage;
                DWORD dwTLSMessageSize;
                if ((dwReturnCode = AL::TLS::Msg::MakeClientHello(pTLSSession->m_pbRandomClient, pTLSSession->m_aTLSSessionID.GetData(), (DWORD)pTLSSession->m_aTLSSessionID.GetCount(), &pbTLSMessage, &dwTLSMessageSize, &pTLSSession->m_algEncKey, &pTLSSession->m_dwEncKeySize, &pTLSSession->m_algMacKey, &pTLSSession->m_dwMacKeySize)) == NO_ERROR) {
                    LPBYTE pbRecord;
                    DWORD dwRecordSize;
                    if ((dwReturnCode = AL::TLS::Record::MakeHandshake(pTLSSession, pbTLSMessage, dwTLSMessageSize, &pbRecord, &dwRecordSize, pTLSSession->m_fCipherSpec)) == NO_ERROR) {
                        if ((dwReturnCode = pktSend.Append(pbRecord, dwRecordSize, dwRecordSize)) == NO_ERROR) {
                            //
                            // Save for later use with finished message
                            //
                            dwReturnCode = pTLSSession->AddHandshakeMessage(pbTLSMessage, dwTLSMessageSize);
                            pEapPeerMethodOutput->action = EapPeerMethodResponseActionSend;
                            pTLSSession->m_TLSState = AL::TLS::STATE_SERVER_HELLO;
                        }

                        AL::Heap::Free((LPVOID*)&pbRecord);
                    }

                    AL::Heap::Free((LPVOID*)&pbTLSMessage);
                }
            }
            break;

        case AL::TLS::STATE_VERIFY_CERT_UI:
        case AL::TLS::STATE_SERVER_HELLO:
            if ((dwReturnCode = pktSend.CreateResponse(bPacketId, bEapProtocolId, bFlags)) == NO_ERROR) {
                //
                // If a certificate was requested then respond with an empty certificate list
                //
                if (pTLSSession->m_fCertRequest) {
                    //
                    // Add certificate handshake record
                    //
                    LPBYTE pbTLSMessage;
                    DWORD dwTLSMessageSize;
                    if ((dwReturnCode = AL::TLS::Msg::MakeClientCertificate(&pbTLSMessage, &dwTLSMessageSize)) == NO_ERROR) {
                        LPBYTE pbRecord;
                        DWORD dwRecordSize;
                        if ((dwReturnCode = AL::TLS::Record::MakeHandshake(pTLSSession, pbTLSMessage, dwTLSMessageSize, &pbRecord, &dwRecordSize, pTLSSession->m_fCipherSpec)) == NO_ERROR) {
                            if ((dwReturnCode = pktSend.Append(pbRecord, dwRecordSize, dwRecordSize)) == NO_ERROR)
                                dwReturnCode = pTLSSession->AddHandshakeMessage(pbTLSMessage, dwTLSMessageSize);

                            AL::Heap::Free((LPVOID*)&pbRecord);
                        }

                        AL::Heap::Free((LPVOID*)&pbTLSMessage);
                    }
                }

                //
                // Add client key exchange handshake record
                //
                if (dwReturnCode == NO_ERROR) {
                    //
                    // Generate and encrypt the pre_master_secret or
                    // ClientDiffieHellmanPublic
                    //
                    if (pTLSSession->m_pbCipher[0] == 0x00 && pTLSSession->m_pbCipher[1] == 0x0A) {
                        LPBYTE pbEncPMS;
                        DWORD dwEncPMSSize;
                        if ((dwReturnCode = _GenRSAEncPMS(pTLSSession, &pbEncPMS, &dwEncPMSSize)) == NO_ERROR) {
                            if ((dwReturnCode = _ComputeMS(pTLSSession->m_hCSP, pTLSSession->m_pbRandomClient, pTLSSession->m_pbRandomServer, pTLSSession->m_pbPMS, pTLSSession->m_pbMS)) == NO_ERROR) {
                                LPBYTE pbTLSMessage;
                                DWORD dwTLSMessageSize;
                                if ((dwReturnCode = AL::TLS::Msg::MakeClientKeyExchange(pbEncPMS, dwEncPMSSize, &pbTLSMessage, &dwTLSMessageSize)) == NO_ERROR) {
                                    LPBYTE pbRecord;
                                    DWORD dwRecordSize;
                                    if ((dwReturnCode = AL::TLS::Record::MakeHandshake(pTLSSession, pbTLSMessage, dwTLSMessageSize, &pbRecord, &dwRecordSize, pTLSSession->m_fCipherSpec)) == NO_ERROR) {
                                        if ((dwReturnCode = pktSend.Append(pbRecord, dwRecordSize, dwRecordSize)) == NO_ERROR)
                                            dwReturnCode = pTLSSession->AddHandshakeMessage(pbTLSMessage, dwTLSMessageSize);

                                        AL::Heap::Free((LPVOID*)&pbRecord);
                                    }

                                    AL::Heap::Free((LPVOID*)&pbTLSMessage);
                                }
                            }

                            AL::Heap::Free((LPVOID*)&pbEncPMS);
                        }
                    } else if (pTLSSession->m_pbCipher[0] == 0x00 && pTLSSession->m_pbCipher[1] == 0x13) {
                        AL_TRACE_ERROR(_T("Diffie Helman requested but not supported."));
                        dwReturnCode = ERROR_NOT_SUPPORTED;
                    } else {
                        //
                        // Will never reach this point but...
                        //
                        AL_TRACE_ERROR(_T("Unsupported cipher requested (%d-%d)."), pTLSSession->m_pbCipher[0], pTLSSession->m_pbCipher[1]);
                        dwReturnCode = ERROR_ENCRYPTION_FAILED;
                    }
                }

                //
                // Add change cipher spec record
                //
                if (dwReturnCode == NO_ERROR) {
                    LPBYTE pbRecord;
                    DWORD dwRecordSize;
                    if ((dwReturnCode = AL::TLS::Record::MakeChangeCipherSpec(&pbRecord, &dwRecordSize)) == NO_ERROR) {
                        dwReturnCode = pktSend.Append(pbRecord, dwRecordSize, dwRecordSize);
                        AL::Heap::Free((LPVOID*)&pbRecord);
                    }
                }

                //
                // Change the cipher_spec
                //
                pTLSSession->m_fCipherSpec = TRUE;

                //
                // Add finished handshake record
                //
                if (dwReturnCode == NO_ERROR) {
                    if ((dwReturnCode = AL::TLS::DeriveKeys(pTLSSession)) == NO_ERROR) {
                        LPBYTE pbTLSMessage;
                        DWORD dwTLSMessageSize;
                        if ((dwReturnCode = AL::TLS::Msg::MakeFinished(pTLSSession, (LPCBYTE)AL_TLS_CLIENT_FINISHED_LABEL, sizeof(AL_TLS_CLIENT_FINISHED_LABEL) - sizeof(CHAR), pTLSSession->m_pbMS, AL_TLS_MS_SIZE, &pbTLSMessage, &dwTLSMessageSize)) == NO_ERROR) {
                            LPBYTE pbRecord;
                            DWORD dwRecordSize;
                            if ((dwReturnCode = AL::TLS::Record::MakeHandshake(pTLSSession, pbTLSMessage, dwTLSMessageSize, &pbRecord, &dwRecordSize, pTLSSession->m_fCipherSpec)) == NO_ERROR) {
                                if ((dwReturnCode = pktSend.Append(pbRecord, dwRecordSize, dwRecordSize)) == NO_ERROR) {
                                    //
                                    // It is now safe add the client finished message needed to verify the
                                    // server finished message
                                    //
                                    if ((dwReturnCode = pTLSSession->AddHandshakeMessage(pbTLSMessage, dwTLSMessageSize)) == NO_ERROR) {
                                        //
                                        // We have sent our finished message!
                                        //
                                        pTLSSession->m_fSentFinished = TRUE;
                                        pEapPeerMethodOutput->action = EapPeerMethodResponseActionSend;
                                        pTLSSession->m_TLSState = AL::TLS::STATE_CHANGE_CIPHER_SPEC;
                                    }
                                }

                                AL::Heap::Free((LPVOID*)&pbRecord);
                            }

                            AL::Heap::Free((LPVOID*)&pbTLSMessage);
                        }
                    }
                }
            }
            break;

        case AL::TLS::STATE_RESUME_SESSION:
            if ((dwReturnCode = pktSend.CreateResponse(bPacketId, bEapProtocolId, bFlags)) == NO_ERROR) {
                //
                // Add change cipher spec record
                //
                if (dwReturnCode == NO_ERROR) {
                    LPBYTE pbRecord;
                    DWORD dwRecordSize;
                    if ((dwReturnCode = AL::TLS::Record::MakeChangeCipherSpec(&pbRecord, &dwRecordSize)) == NO_ERROR) {
                        dwReturnCode = pktSend.Append(pbRecord, dwRecordSize, dwRecordSize);
                        AL::Heap::Free((LPVOID*)&pbRecord);
                    }
                }

                //
                // Add finished handhshake record
                //
                if (dwReturnCode == NO_ERROR) {
                    LPBYTE pbTLSMessage;
                    DWORD dwTLSMessageSize;
                    if ((dwReturnCode = AL::TLS::Msg::MakeFinished(pTLSSession, (LPCBYTE)AL_TLS_CLIENT_FINISHED_LABEL, sizeof(AL_TLS_CLIENT_FINISHED_LABEL) - sizeof(CHAR), pTLSSession->m_pbMS, AL_TLS_MS_SIZE, &pbTLSMessage, &dwTLSMessageSize)) == NO_ERROR) {
                        LPBYTE pbRecord;
                        DWORD dwRecordSize;
                        if ((dwReturnCode = AL::TLS::Record::MakeHandshake(pTLSSession, pbTLSMessage, dwTLSMessageSize, &pbRecord, &dwRecordSize, pTLSSession->m_fCipherSpec)) == NO_ERROR) {
                            if ((dwReturnCode = pktSend.Append(pbRecord, dwRecordSize, dwRecordSize)) == NO_ERROR) {
                                //
                                // It is now safe add the client finished message needed to verify the
                                // server finished message
                                //
                                if ((dwReturnCode = pTLSSession->AddHandshakeMessage(pbTLSMessage, dwTLSMessageSize)) == NO_ERROR) {
                                    //
                                    // We have sent our finished message!
                                    //
                                    pTLSSession->m_fSentFinished = TRUE;
                                    pEapPeerMethodOutput->action = EapPeerMethodResponseActionSend;
                                    pTLSSession->m_TLSState = AL::TLS::STATE_RESUME_SESSION_ACK;
                                }
                            }

                            AL::Heap::Free((LPVOID*)&pbRecord);
                        }

                        AL::Heap::Free((LPVOID*)&pbTLSMessage);
                    }
                }
            }
            break;

        case AL::TLS::STATE_RESUME_SESSION_ACK:
            if ((dwReturnCode = pktSend.CreateResponse(bPacketId, bEapProtocolId, bFlags)) == NO_ERROR) {
                pEapPeerMethodOutput->action = EapPeerMethodResponseActionSend;
                pTLSSession->m_TLSState = AL::TLS::STATE_INNER_AUTHENTICATION;
            }
            break;

        case AL::TLS::STATE_CHANGE_CIPHER_SPEC:
        case AL::TLS::STATE_INNER_AUTHENTICATION:
            break;

        default:
            AL_TRACE_ERROR(_T("Invalid state."));
            dwReturnCode = ERROR_PPP_INVALID_PACKET;
    }

    return dwReturnCode;
}


//
// This function parses a handshake message and acts accordingly
//
DWORD AL::TTLS::ParseHandshakeRecord(_Inout_ AL::TLS::CTLSSession *pTLSSession, _In_bytecount_(dwRecordSize) LPCBYTE pbRecord, _In_ DWORD dwRecordSize)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // Loop through message
    //
    for (SIZE_T nCursor = 0; nCursor < dwRecordSize && dwReturnCode == NO_ERROR; ) {
        switch (pbRecord[nCursor++]) {
            case 0x02: //server_hello
                if (nCursor > dwRecordSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of record."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                //
                // Length of record is 3 bytes!!
                // skip first byte and read in integer
                //
                nCursor += 3;
                if (nCursor > dwRecordSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of record."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                //
                // Check TLS version
                //
                if ((pbRecord[nCursor] == 0x03) && (pbRecord[nCursor+1] == 0x01)) {
                    nCursor += 2;
                    if (nCursor > dwRecordSize) {
                        AL_TRACE_ERROR(_T("Unexpected end of record."));
                        dwReturnCode = ERROR_PPP_INVALID_PACKET;
                        break;
                    }

                    //
                    // Copy Random data
                    //
                    memcpy(pTLSSession->m_pbRandomServer, &(pbRecord[nCursor]), AL_TLS_RANDOM_SIZE);
                    nCursor += AL_TLS_RANDOM_SIZE;
                    if (nCursor > dwRecordSize) {
                        AL_TRACE_ERROR(_T("Unexpected end of record."));
                        dwReturnCode = ERROR_PPP_INVALID_PACKET;
                        break;
                    }

                    //
                    // Session length
                    //
                    SIZE_T nTLSSessionIDSize = pbRecord[nCursor];
                    if (nTLSSessionIDSize > 0) {
                        nCursor++;
                        if (nCursor > dwRecordSize) {
                            AL_TRACE_ERROR(_T("Unexpected end of record."));
                            dwReturnCode = ERROR_PPP_INVALID_PACKET;
                            break;
                        }

                        //
                        // Save session ID
                        //
                        if (pTLSSession->m_aTLSSessionID.SetCount(nTLSSessionIDSize))
                            memcpy(pTLSSession->m_aTLSSessionID.GetData(), &(pbRecord[nCursor]), nTLSSessionIDSize);
                        nCursor += nTLSSessionIDSize;

                        //
                        // set the time this session ID was set
                        //
                        time(&(pTLSSession->m_tTLSSessionID));
                    } else {
                        //
                        // previous version required a session id, according to RFC this
                        // is not correct as an empty one simply means do not cache this session
                        //
                        nCursor++;
                    }
                    if (nCursor > dwRecordSize) {
                        AL_TRACE_ERROR(_T("Unexpected end of record."));
                        dwReturnCode = ERROR_PPP_INVALID_PACKET;
                        break;
                    }

                    pTLSSession->m_pbCipher[0] = pbRecord[nCursor];
                    nCursor++;
                    if (nCursor > dwRecordSize) {
                        AL_TRACE_ERROR(_T("Unexpected end of record."));
                        dwReturnCode = ERROR_PPP_INVALID_PACKET;
                        break;
                    }

                    pTLSSession->m_pbCipher[1] = pbRecord[nCursor];

                    HCRYPTPROV hCSP;
                    //
                    // Found the cipher message, should be either 0x13 or 0x0A
                    //
                    if (pTLSSession->m_pbCipher[0] == 0x00 && pTLSSession->m_pbCipher[1] == 0x0A) {
                        //
                        // TLS_RSA_WITH_3DES_EDE_CBC_SHA { 0x00, 0x0A }
                        //
                        //
                        //
                        // Connect to help CSP
                        //
                        dwReturnCode = AL::Crypto::AcquireContext(&hCSP, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL);
                    } else if (pTLSSession->m_pbCipher[0] == 0x00 && pTLSSession->m_pbCipher[1] == 0x13) {
                        //
                        // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA { 0x00, 0x13 }
                        //
                        dwReturnCode = AL::Crypto::AcquireContext(&hCSP, NULL, MS_ENH_DSS_DH_PROV, PROV_DH_SCHANNEL);
                    } else {
                        //
                        // this is not possible, except if the RADIUS TLS implementation is screwy
                        //
                        AL_TRACE_ERROR(_T("Cipher not supported."));
                        hCSP = NULL;
                        dwReturnCode = ERROR_ENCRYPTION_FAILED;
                    }

                    if (dwReturnCode != NO_ERROR)
                        break;

                    pTLSSession->m_hCSP.Attach(hCSP);

                    nCursor++;
                    if (nCursor > dwRecordSize) {
                        AL_TRACE_ERROR(_T("Unexpected end of record."));
                        dwReturnCode = ERROR_PPP_INVALID_PACKET;
                        break;
                    }

                    pTLSSession->m_bCompression = pbRecord[nCursor];
                    nCursor++;
                } else {
                    AL_TRACE_ERROR(_T("Incorrect TLS version."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                }
                break;

            case 0x0B: { // certificate
                if (nCursor > dwRecordSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of record."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                nCursor += 3;
                if (nCursor > dwRecordSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of record."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                DWORD dwCertificateListSize = AL::Convert::N2H24(&(pbRecord[nCursor]));
                nCursor += 3;
                if (nCursor > dwRecordSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of record."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                //
                // Loop through cert list until done.
                //
                pTLSSession->m_lCertificateChain.RemoveAll();
                while (nCursor <= dwCertificateListSize) {
                    DWORD dwCertSize = AL::Convert::N2H24(&(pbRecord[nCursor]));
                    nCursor += 3;
                    if (nCursor > dwRecordSize) {
                        AL_TRACE_ERROR(_T("Unexpected end of record."));
                        dwReturnCode = ERROR_PPP_INVALID_PACKET;
                        break;
                    }

                    ATL::Crypt::CCertContext &cc = pTLSSession->m_lCertificateChain.GetAt(pTLSSession->m_lCertificateChain.AddTail());
                    if (!cc.Create(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &(pbRecord[nCursor]), dwCertSize)) {
                        AL_TRACE_ERROR(_T("Error creating certificate context (%ld)."), dwReturnCode = GetLastError());
                        break;
                    }
                    nCursor += dwCertSize;
                }
                break;
            }

            case 0x0C: { // server_key_exchange
                if (nCursor > dwRecordSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of record."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                DWORD dwServerKeyExchangeSize = AL::Convert::N2H24(&(pbRecord[nCursor]));
                nCursor += 3;
                if (nCursor > dwRecordSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of record."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                nCursor += dwServerKeyExchangeSize;
                break;
            }

            case 0x0D: { // certificate request
                if (nCursor > dwRecordSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of record."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                DWORD dwCertRequestSize = AL::Convert::N2H24(&(pbRecord[nCursor]));
                nCursor += 3;
                if (nCursor > dwRecordSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of record."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                nCursor += dwCertRequestSize;
                pTLSSession->m_fCertRequest = TRUE;
                break;
            }

            case 0x0E: // ServerDone
                if (nCursor > dwRecordSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of record."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }
                nCursor += 3;
                break;

            case 0x14: { // Finished message
                if (nCursor > dwRecordSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of record."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                DWORD dwRecordSize = AL::Convert::N2H24(&(pbRecord[nCursor]));
                nCursor += 3;
                if (nCursor > dwRecordSize) {
                    AL_TRACE_ERROR(_T("Unexpected end of record."));
                    dwReturnCode = ERROR_PPP_INVALID_PACKET;
                    break;
                }

                //
                // Verify the finished message
                //
                if ((dwReturnCode = AL::TLS::Msg::VerifyFinished(pTLSSession, (LPCBYTE)AL_TLS_SERVER_FINISHED_LABEL, sizeof(AL_TLS_SERVER_FINISHED_LABEL) - sizeof(CHAR), pTLSSession->m_pbMS, AL_TLS_MS_SIZE, &(pbRecord[nCursor]), dwRecordSize)) == NO_ERROR)
                    pTLSSession->m_fServerFinished = TRUE;
                nCursor += dwRecordSize;
                break;
            }

            default:
                AL_TRACE_WARNING(_T("Unknown TLS record (0x%x)."), pbRecord[nCursor - 1]);
                break;
        }
    }

    //
    // Add the message for finished message hash
    //
    pTLSSession->AddHandshakeMessage(pbRecord, dwRecordSize);

    return dwReturnCode;
}


//
// This function parses an inner application data message and acts accordingly
//
DWORD AL::TTLS::ParseInnerApplicationDataRecord(_Inout_ AL::TLS::CTLSSession *pTLSSession, _In_bytecount_(dwRecordSize) LPCBYTE pbRecord, _In_ DWORD dwRecordSize)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    if (dwRecordSize == 0)
        return NO_ERROR;

    AL_TRACE_ERROR(_T("Not supported."));
    dwReturnCode = ERROR_NOT_SUPPORTED;

    return dwReturnCode;
}


//
// This Encrypt the PMS (Pre Master Secret) using RSA
//
static DWORD _GenRSAEncPMS(_Inout_ AL::TLS::CTLSSession *pTLSSession, _Out_ LPBYTE *ppbEncPMS, _Out_ DWORD *pdwEncPMSSize)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    if (pTLSSession->m_hCSP) {
        //
        // Import the public key
        //
        const ATL::Crypt::CCertContext &cc = pTLSSession->m_lCertificateChain.GetHead();
        ATL::Crypt::CKey keyPubServer;
        if (keyPubServer.ImportPublic(pTLSSession->m_hCSP, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &(cc->pCertInfo->SubjectPublicKeyInfo))) {
            //
            // First generate 48 bytes encrypted PMS
            //
            if ((dwReturnCode = _GenPMS(pTLSSession->m_pbPMS)) == NO_ERROR) {
                *pdwEncPMSSize = AL_TLS_PMS_SIZE;

                if (!CryptEncrypt(keyPubServer, 0, TRUE, 0, NULL, pdwEncPMSSize, 0))
                    dwReturnCode = GetLastError();

                if (dwReturnCode == NO_ERROR || dwReturnCode == ERROR_MORE_DATA) {
                    DWORD dwBufLen = *pdwEncPMSSize;
                    if ((dwReturnCode = AL::Heap::Alloc(*pdwEncPMSSize, (LPVOID*)ppbEncPMS)) == NO_ERROR) {
                        memcpy(*ppbEncPMS, pTLSSession->m_pbPMS, AL_TLS_PMS_SIZE);

                        *pdwEncPMSSize = AL_TLS_PMS_SIZE;

                        if (!CryptEncrypt(keyPubServer, 0, TRUE, 0, *ppbEncPMS, pdwEncPMSSize, dwBufLen)) {
                            AL_TRACE_ERROR(_T("CryptEncrypt failed (%ld)."), GetLastError());
                            dwReturnCode = ERROR_ENCRYPTION_FAILED;
                        }

                        if (dwReturnCode != NO_ERROR)
                            AL::Heap::Free((LPVOID*)&ppbEncPMS);
                    }
                } else {
                    AL_TRACE_ERROR(_T("CryptEncrypt failed (%ld)."), dwReturnCode);
                    dwReturnCode = ERROR_ENCRYPTION_FAILED;
                }
            }
        } else {
            AL_TRACE_ERROR(_T("CryptImportPublicKeyInfo failed (%ld)."), GetLastError());
            dwReturnCode = ERROR_ENCRYPTION_FAILED;
        }
    } else {
        AL_TRACE_ERROR(_T("ERROR::no handle to help CSP"));
        dwReturnCode = ERROR_ENCRYPTION_FAILED;
    }

    return dwReturnCode;
}


//
// Compute the SSL Master Secret
// Calling this function also removes the PMS from memory
//
static DWORD _ComputeMS(_In_ HCRYPTPROV hCSP, _In_ LPCBYTE pbRandomClient, _In_ LPCBYTE pbRandomServer, _Inout_ LPBYTE pbPMS, _Out_ LPBYTE pbMS)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    BYTE pbTemp[AL_TLS_RANDOM_SIZE*2];
    memcpy(pbTemp,                      pbRandomClient, AL_TLS_RANDOM_SIZE);
    memcpy(pbTemp + AL_TLS_RANDOM_SIZE, pbRandomServer, AL_TLS_RANDOM_SIZE);

    static const BYTE pcLabel[] = "master secret";
    DWORD dwLabelSize = sizeof(pcLabel) - sizeof(CHAR);
    dwReturnCode = AL::TLS::PRF(hCSP, pbPMS, AL_TLS_PMS_SIZE, pcLabel, dwLabelSize, pbTemp, sizeof(pbTemp), pbMS, AL_TLS_MS_SIZE);

    //
    // Sanitize pre master secret.
    //
    SecureZeroMemory(pbPMS, AL_TLS_PMS_SIZE);

    return dwReturnCode;
}


//
// Generate the 48 random bytes for the PMS (Pre Master Secret)
//
static DWORD _GenPMS(_Inout_ BYTE pbPMS[AL_TLS_PMS_SIZE])
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    pbPMS[0] = 0x03;
    pbPMS[1] = 0x01;

    dwReturnCode = AL::Crypto::GenSecureRandom(&pbPMS[2], AL_TLS_PMS_SIZE - 2);

    return dwReturnCode;
}
