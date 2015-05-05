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
// Name: AuthHandleInnerEAPAuthentication
// Description: This function is called when the TLS tunnel has been
// setup and the inner authentication must be done using EAPHost
//
#ifdef AL_EAPHOST
DWORD AuthHandleInnerEAPHOSTAuthentication(_Inout_ AL::TLS::CSessionData *pSessionData, _Out_ AL::EAP::CPacket &pktSend, _Out_ EapPeerMethodOutput* pEapPeerMethodOutput)
{
    dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    EapPacket *pInnerEapHostReceivePacket;
    DWORD dwSizeOfInnerEapHostReceivePacket;
    EapPacket *pInnerEapHostSendPacket;
    DWORD dwSizeOfInnerEapHostSendPacket;
    EapHostPeerResponseAction eapHostPeerResponseAction;
    EAP_ERROR *pEapError = NULL;
    LPBYTE pbUIContextData;
    DWORD cbUIContextData;
    BYTE pbMA[] = { 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00 };
    LPBYTE pbAVP;
    DWORD cbAVP;
    LPBYTE pbMAAVP;
    DWORD cbMAAVP;
    LPBYTE pbEAPAVP;
    DWORD cbEAPAVP;
    LPBYTE pbStateAVP;
    DWORD cbStateAVP;
    LPBYTE pbEAPAttribute;
    DWORD cbEAPAttribute;
    PCHAR pcInnerEapIdentity;
    DWORD ccInnerEapIdentity;
    LPBYTE pbRecord;
    DWORD cbRecord;
    DWORD dwReturnCode;

    switch (pSessionData->m_Inner.m_EapState) {
        case AL::EAP::INNERSTATE_Start:

            AL_TRACE_INFO(_T("INNERSTATE_Start"));

            //
            // Build the AVPS for EAP
            //
            ccInnerEapIdentity = (DWORD)wcslen(pSessionData->m_user.m_InnerEap.pwcIdentity);

            !!if ((pcInnerEapIdentity = (PCHAR)malloc(ccInnerEapIdentity + 1)))
            {
                WideCharToMultiByte(CP_UTF8, 0, pSessionData->m_user.m_InnerEap.pwcIdentity, -1, pcInnerEapIdentity, ccInnerEapIdentity + 1, NULL, NULL);
            } else {
                AL_TRACE_ERROR(_T("not enough memory"));

                dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
            }

            if (dwReturnCode == NO_ERROR) {
                if ((dwReturnCode = AL::TLS::AuthMakeEAPResponseAttribute(0x01, 0x00, (LPBYTE)pcInnerEapIdentity, ccInnerEapIdentity, &pbEAPAttribute, &cbEAPAttribute)) == NO_ERROR) {
                    if ((dwReturnCode = AL::TLS::AuthMakeDiameterAttribute(0x4F, pbEAPAttribute, cbEAPAttribute, &pbEAPAVP, &cbEAPAVP)) == NO_ERROR) {
                        //
                        // Add empty message authenticator
                        //
                        if ((dwReturnCode = AL::TLS::AuthMakeDiameterAttribute(0x50,
                                                                pbMA,
                                                                sizeof(pbMA),
                                                                &pbMAAVP,
                                                                &cbMAAVP)) == NO_ERROR)
                        {
                            cbAVP = cbEAPAVP + cbMAAVP;

                            !!if ((pbAVP = (LPBYTE)malloc(cbAVP)))
                            {
                                memcpy(pbAVP, pbEAPAVP, cbEAPAVP);
                                memcpy(pbAVP + cbEAPAVP, pbMAAVP, cbMAAVP);

                                if ((dwReturnCode = AL::TLS::Record::MakeApplication(pSessionData->m_hCSP,
                                                                        pSessionData->m_hWriteKey,
                                                                        pSessionData->m_dwMacKey,
                                                                        pSessionData->m_dwMacKeySize,
                                                                        pSessionData->m_pbMacWrite,
                                                                        &(pSessionData->m_dwSeqNum),
                                                                        pbAVP,
                                                                        cbAVP,
                                                                        &pbRecord,
                                                                        &cbRecord,
                                                                        pSessionData->m_bCipherSpec)) == NO_ERROR)
                                {
                                    // TODO: AL::TLS::AddMessage() => AL::EAP::CPacket::Append()
                                    dwReturnCode = AL::TLS::AddMessage(pbRecord,
                                                            cbRecord,
                                                            cbRecord,
                                                            pSendPacket,
                                                            dwSendPacketSize);

                                    pEapOutput->Action = EAPACTION_Send;

                                    pSessionData->m_Inner.m_EapState = AL::EAP::INNERSTATE_MakeMessage;

                                    AL::Heap::Free((LPVOID*)&pbRecord);
                                    cbRecord = 0;
                                }

                                AL::Heap::Free((LPVOID*)&pbAVP);
                                cbAVP = 0;
                            } else
                                dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

                            AL::Heap::Free((LPVOID*)&pbMAAVP);
                            cbMAAVP = 0;
                        }


                        AL::Heap::Free((LPVOID*)&pbEAPAVP);
                        cbEAPAVP = 0;
                    }

                    AL_TRACE_INFO(_T("freeing pbEAPAttribute"));

                    AL::Heap::Free((LPVOID*)&pbEAPAttribute);
                    cbEAPAttribute = 0;
                }

                AL_TRACE_INFO(_T("freeing pcInnerEapIdentity"));

                AL::Heap::Free((LPVOID*)&pcInnerEapIdentity);
                ccInnerEapIdentity= 0;
            }

        break;

        case AL::EAP::INNERSTATE_MakeMessage:

            AL_TRACE_INFO(_T("INNERSTATE_MakeMessage"));

            if (pSessionData->m_TLSSession.m_pbInnerEapMessage) {
                pInnerEapHostReceivePacket = (EapPacket *) pSessionData->m_TLSSession.m_pbInnerEapMessage;

                dwSizeOfInnerEapHostReceivePacket = AL::Convert::N2H16(pInnerEapHostReceivePacket->Length);

                AL_TRACE_INFO(_T("INNERSTATE_MakeMessage:pInnerEapHostReceivePacket(%ld)"),
                    dwSizeOfInnerEapHostReceivePacket);
                AL::Trace::Dump(Debug,  (LPBYTE)pInnerEapHostReceivePacket, dwSizeOfInnerEapHostReceivePacket);

                //
                // Let's see what is in the packet
                //
                switch (pInnerEapHostReceivePacket->Code) {
                    case EAPCODE_Request:

                        AL_TRACE_INFO(_T("INNERSTATE_MakeMessage::EAPCODE_Request"));

                    case EAPCODE_Success:

                        AL_TRACE_INFO(_T("INNERSTATE_MakeMessage::EAPCODE_Success"));

                    case EAPCODE_Failure:

                        AL_TRACE_INFO(_T("INNERSTATE_MakeMessage::EAPCODE_Failure"));

                        if (pInnerEapHostReceivePacket->Data[0] !=
                            pSessionData->m_Inner.eapcfg.eapMethodType.eapType.type)
                        {
                            //
                            // Not for our Inner EAP DLL so send NAK request for our auth type
                            //
                            AL_TRACE_INFO(_T("Request for 0x%x."), pInnerEapHostReceivePacket->Data[0]);

                            if ((dwReturnCode = AL::TLS::AuthMakeEAPResponseAttribute(0x03,
                                        pInnerEapHostReceivePacket->Id,
                                        (LPBYTE) &(pSessionData->m_Inner.eapcfg.eapMethodType.eapType.type),
                                        1,
                                        &pbEAPAttribute,
                                        &cbEAPAttribute)) == NO_ERROR)
                            {
                                //
                                // Add EAP Message
                                //
                                if ((dwReturnCode = AL::TLS::AuthMakeDiameterAttribute(0x4F, pbEAPAttribute, cbEAPAttribute, &pbEAPAVP, &cbEAPAVP)) == NO_ERROR) {
                                    //
                                    // Add empty message authenticator
                                    //
                                    if ((dwReturnCode = AL::TLS::AuthMakeDiameterAttribute(0x50,
                                                                            pbMA,
                                                                            sizeof(pbMA),
                                                                            &pbMAAVP,
                                                                            &cbMAAVP)) == NO_ERROR)
                                    {
                                        if (pSessionData->m_TLSSession.m_cbState > 0) {
                                            //
                                            // Copy state attribute into response
                                            //
                                            if ((dwReturnCode = AL::TLS::AuthMakeDiameterAttribute(0x18,
                                                                            pSessionData->m_TLSSession.m_pbState,
                                                                            pSessionData->m_TLSSession.m_cbState,
                                                                            &pbStateAVP,
                                                                            &cbStateAVP)) == NO_ERROR)
                                            {
                                                cbAVP = cbEAPAVP + cbMAAVP + cbStateAVP;

                                                !!if ((pbAVP = (LPBYTE)malloc(cbAVP)))
                                                {
                                                    memcpy(pbAVP, pbEAPAVP, cbEAPAVP);
                                                    memcpy(pbAVP + cbEAPAVP, pbMAAVP, cbMAAVP);
                                                    memcpy(pbAVP + cbEAPAVP + cbMAAVP, pbStateAVP, cbStateAVP);
                                                } else
                                                    dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
                                            }
                                        } else {
                                            //
                                            // copy only EAP-MESSAGE and Message Authenticator
                                            //
                                            cbAVP = cbEAPAVP + cbMAAVP;

                                            !!if ((pbAVP = (LPBYTE)malloc(cbAVP)))
                                            {
                                                memcpy(pbAVP, pbEAPAVP, cbEAPAVP);
                                                memcpy(pbAVP + cbEAPAVP, pbMAAVP, cbMAAVP);
                                            } else
                                                dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
                                        }

                                        if (dwReturnCode == NO_ERROR) {
                                            if ((dwReturnCode = AL::TLS::Record::MakeApplication(pSessionData->m_hCSP,
                                                                                    pSessionData->m_hWriteKey,
                                                                                    pSessionData->m_dwMacKey,
                                                                                    pSessionData->m_dwMacKeySize,
                                                                                    pSessionData->m_pbMacWrite,
                                                                                    &(pSessionData->m_dwSeqNum),
                                                                                    pbAVP,
                                                                                    cbAVP,
                                                                                    &pbRecord,
                                                                                    &cbRecord,
                                                                                    pSessionData->m_bCipherSpec)) == NO_ERROR)
                                            {
                                                // TODO: AL::TLS::AddMessage() => AL::EAP::CPacket::Append()
                                                dwReturnCode = AL::TLS::AddMessage(pbRecord,
                                                                        cbRecord,
                                                                        cbRecord,
                                                                        pSendPacket,
                                                                        dwSendPacketSize);

                                                pEapOutput->Action = EAPACTION_Send;

                                                pSessionData->m_Inner.m_EapState = AL::EAP::INNERSTATE_MakeMessage;

                                                AL::Heap::Free((LPVOID*)&pbRecord);
                                                cbRecord = 0;
                                            }

                                            AL::Heap::Free((LPVOID*)&pbAVP);
                                            cbAVP = 0;
                                        }

                                        AL::Heap::Free((LPVOID*)&pbMAAVP);
                                        cbMAAVP = 0;
                                    }

                                    AL::Heap::Free((LPVOID*)&pbEAPAVP);
                                    cbEAPAVP = 0;
                                }

                                AL_TRACE_INFO(_T("freeing pbEAPAttribute"));

                                AL::Heap::Free((LPVOID*)&pbEAPAttribute);
                                cbEAPAttribute = 0;
                            }
                        }

                    break;

                    case EAPCODE_Response:

                    default:

                        dwReturnCode  = ERROR_PPP_INVALID_PACKET;

                    break;
                }
            } else {
                pInnerEapHostReceivePacket = NULL;
                dwSizeOfInnerEapHostReceivePacket = 0;
            }

            //
            // If we haven't sent anything yet and no error has occured then continue
            //
            if (pEapOutput->Action != EAPACTION_Send && dwReturnCode == NO_ERROR) {
                AL_TRACE_INFO(_T("building sendpacket"));

                if ((dwReturnCode = EapHostPeerProcessReceivedPacket(
                        pSessionData->m_Inner.m_eapSessionId,//Session Id
                        dwSizeOfInnerEapHostReceivePacket, //Length of the Packet
                        (LPBYTE)pInnerEapHostReceivePacket, //Packet
                        &eapHostPeerResponseAction, //EapHostPeerResponseAction
                        &pEapError
)) == NO_ERROR)
                {
                    AL_TRACE_INFO(_T("EapHostPeerResponseAction: %ld"), eapHostPeerResponseAction);

                    switch (eapHostPeerResponseAction) {
                        case EapHostPeerResponseInvokeUi:

                            AL_TRACE_INFO(_T("EapHostPeerResponseInvokeUi"));

                            cbUIContextData = 0;

                            if ((dwReturnCode = EapHostPeerGetUIContext(
                                            pSessionData->m_Inner.m_eapSessionId,
                                            &cbUIContextData,
                                            &pbUIContextData,
                                            &pEapError)) == NO_ERROR)
                            {
                                pEapOutput->fInvokeInteractiveUI = TRUE;

                                pSessionData->m_InteractiveUIType = AL::TLS::UITYPE_INNER_EAPHOST;
                                pSessionData->m_Inner.m_EapState = AL::EAP::INNERSTATE_InteractiveUI;

                                //
                                // Copy Inner UI Context Data
                                //
                                if (cbUIContextData <= sizeof(pSessionData->m_pbInnerUIContextData)) {
                                    memcpy(pSessionData->m_pbInnerUIContextData, pbUIContextData, cbUIContextData);
                                    pSessionData->m_cbInnerUIContextData = cbUIContextData;

                                    pEapOutput->pUIContextData = (LPBYTE)pSessionData;
                                    pEapOutput->dwSizeOfUIContextData = sizeof(AL::TLS::CSessionData);

                                    pEapOutput->Action = EAPACTION_NoAction;
                                } else
                                    dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
                            } else {
                                if (pEapError)
                                    EapHostPeerFreeEapError(pEapError);
                            }

                        break;

                        case EapHostPeerResponseSend:

                            AL_TRACE_INFO(_T("EapHostPeerResponseSend"));

                            dwSizeOfInnerEapHostSendPacket = 0;

                            if ((dwReturnCode = EapHostPeerGetSendPacket(
                                            pSessionData->m_Inner.m_eapSessionId,
                                            &dwSizeOfInnerEapHostSendPacket,
                                            (LPBYTE *) &pInnerEapHostSendPacket,
                                            &pEapError)) == NO_ERROR)
                            {
                                AL_TRACE_INFO(_T("EapHostPeerGetSendPacket succeeded, sending packet(%ld):"), dwSizeOfInnerEapHostSendPacket);
                                AL::Trace::Dump(Debug,  (LPBYTE)pInnerEapHostSendPacket, dwSizeOfInnerEapHostSendPacket);

                                //
                                // Build response attribute
                                //
                                if ((dwReturnCode = AL::TLS::AuthMakeDiameterAttribute(0x4F, (LPBYTE)pInnerEapHostSendPacket, AL::Convert::N2H16(pInnerEapHostSendPacket->Length), &pbEAPAVP, &cbEAPAVP)) == NO_ERROR) {
                                    //
                                    // Add empty message authenticator
                                    //
                                    if ((dwReturnCode = AL::TLS::AuthMakeDiameterAttribute(0x50,
                                                                            pbMA,
                                                                            sizeof(pbMA),
                                                                            &pbMAAVP,
                                                                            &cbMAAVP)) == NO_ERROR)
                                    {
                                        if (pSessionData->m_TLSSession.m_cbState > 0) {
                                            //
                                            // Copy state attribute into response
                                            //
                                            if ((dwReturnCode = AL::TLS::AuthMakeDiameterAttribute(0x18,
                                                                            pSessionData->m_TLSSession.m_pbState,
                                                                            pSessionData->m_TLSSession.m_cbState,
                                                                            &pbStateAVP,
                                                                            &cbStateAVP)) == NO_ERROR)
                                            {
                                                cbAVP = cbEAPAVP + cbMAAVP + cbStateAVP;

                                                !!if ((pbAVP = (LPBYTE)malloc(cbAVP)))
                                                {
                                                    memcpy(pbAVP, pbEAPAVP, cbEAPAVP);
                                                    memcpy(pbAVP + cbEAPAVP, pbMAAVP, cbMAAVP);
                                                    memcpy(pbAVP + cbEAPAVP + cbMAAVP, pbStateAVP, cbStateAVP);
                                                } else
                                                    dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
                                            }
                                        } else {
                                            //
                                            // copy only EAP-MESSAGE and Message Authenticator
                                            //
                                            cbAVP = cbEAPAVP + cbMAAVP;

                                            !!if ((pbAVP = (LPBYTE)malloc(cbAVP)))
                                            {
                                                memcpy(pbAVP, pbEAPAVP, cbEAPAVP);
                                                memcpy(pbAVP + cbEAPAVP, pbMAAVP, cbMAAVP);
                                            } else
                                                dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
                                        }

                                        if (dwReturnCode == NO_ERROR) {
                                            if ((dwReturnCode = AL::TLS::Record::MakeApplication(pSessionData->m_hCSP,
                                                                                    pSessionData->m_hWriteKey,
                                                                                    pSessionData->m_dwMacKey,
                                                                                    pSessionData->m_dwMacKeySize,
                                                                                    pSessionData->m_pbMacWrite,
                                                                                    &(pSessionData->m_dwSeqNum),
                                                                                    pbAVP,
                                                                                    cbAVP,
                                                                                    &pbRecord,
                                                                                    &cbRecord,
                                                                                    pSessionData->m_bCipherSpec)) == NO_ERROR)
                                            {
                                                // TODO: AL::TLS::AddMessage() => AL::EAP::CPacket::Append()
                                                dwReturnCode = AL::TLS::AddMessage(pbRecord,
                                                                        cbRecord,
                                                                        cbRecord,
                                                                        pSendPacket,
                                                                        dwSendPacketSize);

                                                pEapOutput->Action = EAPACTION_Send;

                                                pSessionData->m_Inner.m_EapState = AL::EAP::INNERSTATE_MakeMessage;

                                                AL::Heap::Free((LPVOID*)&pbRecord);
                                                cbRecord = 0;
                                            }

                                            AL::Heap::Free((LPVOID*)&pbAVP);
                                            cbAVP = 0;
                                        }

                                        AL::Heap::Free((LPVOID*)&pbMAAVP);
                                        cbMAAVP = 0;
                                    }

                                    AL::Heap::Free((LPVOID*)&pbEAPAVP);
                                    cbEAPAVP = 0;
                                }
                            } else {
                                if (pEapError)
                                    EapHostPeerFreeEapError(pEapError);
                            }

                        break;

                        default:

                            dwReturnCode = ERROR_NOT_SUPPORTED;

                        break;
                    }
                } else {
                    AL_TRACE_INFO(_T("pInnerEapHostReceivePacket failed (%ld)."), dwReturnCode);

                    if (pEapError)
                        EapHostPeerFreeEapError(pEapError);
                }
            }

        break;

        case AL::EAP::INNERSTATE_Finished:

            AL_TRACE_INFO(_T("INNERSTATE_Finished"));

            //
            // should never get here
            //
            dwReturnCode = ERROR_PPP_INVALID_PACKET;

        break;

        default:

            AL_TRACE_ERROR(_T("unknown inner authentication state"));

            dwReturnCode = ERROR_PPP_INVALID_PACKET;

        break;
    }

    AL_TRACE_DEBUG(_T("Returning (%ld), action (0x%x), authcode (0x%x)."), dwReturnCode, pEapOutput->Action, pEapOutput->dwAuthResultCode);

    return dwReturnCode;
}
#endif // AL_EAPHOST


//
// This function is called when the TLS tunnel has been
// setup and the inner authentication must be done using EAP
//
DWORD AuthHandleInnerEAPAuthentication(_Inout_ AL::TLS::CSessionData *pSessionData, _Out_ AL::EAP::CPacket &pktSend, _Out_ EapPeerMethodOutput* pEapPeerMethodOutput)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // Reset InteractiveUI every time we get a InnerMakeMessage
    //
    pSessionData->m_Inner.m_EapInput.fDataReceivedFromInteractiveUI = FALSE;
    pSessionData->m_Inner.m_EapInput.dwSizeOfDataFromInteractiveUI  = 0;

    switch (pSessionData->m_Inner.m_EapState) {
        case AL::EAP::INNERSTATE_Start:
            AL_TRACE_INFO(_T("INNERSTATE_Start"));

            //
            // Build initial packet for the EAP method, which is an EMPTY packet
            //
            pEapPeerMethodOutput->action = EapPeerMethodResponseActionSend;
            pSessionData->m_Inner.m_EapState = AL::EAP::INNERSTATE_Identity;
            break;

        case AL::EAP::INNERSTATE_Identity:
            AL_TRACE_INFO(_T("INNERSTATE_Identity"));

            if (pSessionData->m_TLSSession.m_pktInnerEAPMsg != NULL) {
                //
                // Let's see what is in the packet
                //
                switch (pSessionData->m_TLSSession.m_pktInnerEAPMsg->Code) {
                    case EAPCODE_Request:
                        // should be an Identity packet
                        if (pSessionData->m_TLSSession.m_pktInnerEAPMsg->Data[0] == 1) {
                            if (pEapPeerMethodOutput->action != EapPeerMethodResponseActionSend && dwReturnCode == NO_ERROR) {
                                //
                                // Build the identity AVP for EAP
                                //
                                ATL::CW2A sIdentity(pSessionData->m_user.m_sIdentity, CP_UTF8);
                                LPBYTE pbEAPAttribute;
                                DWORD dwEAPAttributeSize;
                                if ((dwReturnCode = AL::TLS::AuthMakeEAPResponseAttribute(0x01, pSessionData->m_TLSSession.m_pktInnerEAPMsg->Id, pSessionData->m_bCurrentMethodVersion, (LPCBYTE)(LPCSTR)sIdentity, (DWORD)strlen(sIdentity), &pbEAPAttribute, &dwEAPAttributeSize)) == NO_ERROR) {
                                    dwReturnCode = AL::TLS::AddEAPMessage(pSessionData, pbEAPAttribute, dwEAPAttributeSize, pktSend, pEapPeerMethodOutput);
                                    AL::Heap::Free((LPVOID*)&pbEAPAttribute);
                                }
                            }
                        } else {
                            AL_TRACE_ERROR(_T("Expected identity packet (1), received (0x%x)."), pSessionData->m_TLSSession.m_pktInnerEAPMsg->Data[0]);
                            dwReturnCode  = ERROR_PPP_INVALID_PACKET;
                        }
                        break;

                    default:
                        AL_TRACE_ERROR(_T("Received an invalid packet code (0x%x)."), pSessionData->m_TLSSession.m_pktInnerEAPMsg->Code);
                        dwReturnCode  = ERROR_PPP_INVALID_PACKET;
                }
            } else
                AL_TRACE_WARNING(_T("AL_AL_TLS_STATE_Start::pReceivePacket is NULL."));
            break;

        case AL::EAP::INNERSTATE_InteractiveUI:
            AL_TRACE_INFO(_T("INNERSTATE_InteractiveUI"));

            if (!pSessionData->m_aDataFromInteractiveUI.IsEmpty()) {
                LPCBYTE pReturnData = pSessionData->m_aDataFromInteractiveUI.GetData();
                MemUnpack(&pReturnData, dwReturnCode);
                if (dwReturnCode == NO_ERROR) {
                    //
                    // Everything is OK.
                    //
                    AL_TRACE_INFO(_T("Interactive UI finished. Resuming..."));
                    pSessionData->m_Inner.m_EapInput.fDataReceivedFromInteractiveUI = TRUE;
                    MemUnpack(&pReturnData, pSessionData->m_Inner.m_EapInput.dwSizeOfDataFromInteractiveUI);
                    pSessionData->m_Inner.m_EapInput.pDataFromInteractiveUI = (LPBYTE)pReturnData;
                } else {
                    AL_TRACE_ERROR(_T("Interactive UI failed (%ld)."), dwReturnCode);
                    pSessionData->m_Inner.m_EapInput.fDataReceivedFromInteractiveUI = FALSE;
                    pSessionData->m_Inner.m_EapInput.dwSizeOfDataFromInteractiveUI  = 0;
                    pSessionData->m_Inner.m_EapInput.pDataFromInteractiveUI         = NULL;
                    pEapPeerMethodOutput->action = EapPeerMethodResponseActionNone;
                }
            } else {
                AL_TRACE_INFO(_T("User has not exited from dialog yet."));
                pEapPeerMethodOutput->action = EapPeerMethodResponseActionNone;
            }
            break; // This break was missing in SecureW2. For a reason or by mistake?

        case AL::EAP::INNERSTATE_MakeMessage: {
            AL_TRACE_INFO(_T("INNERSTATE_MakeMessage"));

            if (pSessionData->m_TLSSession.m_pktInnerEAPMsg != NULL) {
                //
                // Let's see what is in the packet
                //
                switch (pSessionData->m_TLSSession.m_pktInnerEAPMsg->Code) {
                    case EAPCODE_Success:
                        AL_TRACE_INFO(_T("EAPCODE_Success"));

                        //
                        // Some servers also use the EAP extension in PEAPv1
                        // but because we can never check to see if the extension should have
                        // been sent we only check this if PEAPv0 is used...
                        //
                        if (pSessionData->m_bCurrentMethodVersion == AL_EAP_PEAP_V0 && !pSessionData->m_fSentEapExtensionSuccess) {
                            AL_TRACE_ERROR(_T("Received a success message but we did not send or receive the EapExtension."));
                            dwReturnCode  = ERROR_PPP_INVALID_PACKET;
                        }
                        break;

                    case EAPCODE_Failure:
                        AL_TRACE_INFO(_T("EAPCODE_Failure"));

                        //
                        // We received a failure, respond with an ack.
                        //
                        pEapPeerMethodOutput->action = EapPeerMethodResponseActionSend;
                        pSessionData->m_Inner.m_EapState = AL::EAP::INNERSTATE_Identity;
                        break;

                    case EAPCODE_Request:
                        AL_TRACE_INFO(_T("EAPCODE_Request"));

                        if (pSessionData->m_TLSSession.m_pktInnerEAPMsg->Data[0] == 0x21) {
                            //
                            // we received an EAP extended request (PEAPv0)
                            // but as some server misuse this extension in PEAPV1 we will accept it...
                            //
                            if (pSessionData->m_bCurrentMethodVersion > 0)
                                AL_TRACE_WARNING(_T("Incorrect extension response packet received, but handling anyway as it will brake authentication..."));

                            //
                            // Did we receive a success EAP extension?
                            //
                            if (pSessionData->m_TLSSession.m_pktInnerEAPMsg->Data[6] == 1)
                                AL_TRACE_INFO(_T("Received an EAP extension SUCCESS."));
                            else
                                AL_TRACE_INFO(_T("Received an EAP extension FAILURE."));

                            //
                            // Copy over the EAP extension success/failure message.
                            //
                            BYTE pbExtensionPacket[] = {
                                0x03,                                                       // EAP extension type
                                0x00, 0x02,                                                 // EAP extension length value
                                0x00, pSessionData->m_TLSSession.m_pktInnerEAPMsg->Data[6], // value (success/failure)
                            };

                            //
                            // Respond
                            //
                            LPBYTE pbEAPAttribute;
                            DWORD dwEAPAttributeSize;
                            if ((dwReturnCode = AL::TLS::AuthMakeEAPResponseAttribute(0x21, pSessionData->m_TLSSession.m_pktInnerEAPMsg->Id, 0x80, pbExtensionPacket, sizeof(pbExtensionPacket), &pbEAPAttribute, &dwEAPAttributeSize)) == NO_ERROR) {
                                dwReturnCode = AL::TLS::AddEAPMessage(pSessionData, pbEAPAttribute, dwEAPAttributeSize, pktSend, pEapPeerMethodOutput);

                                //
                                // Save the fact that we sent an EAP extension success packet
                                //
                                if (dwReturnCode == NO_ERROR && pSessionData->m_TLSSession.m_pktInnerEAPMsg->Data[6] == 1)
                                    pSessionData->m_fSentEapExtensionSuccess = TRUE;

                                AL::Heap::Free((LPVOID*)&pbEAPAttribute);
                            }
                        } else if (pSessionData->m_TLSSession.m_pktInnerEAPMsg->Data[0] != pSessionData->m_Inner.m_eapcfg.m_dwType) {
                            //
                            // Not for our Inner EAP DLL so send NACK request for our auth type
                            //
                            AL_TRACE_WARNING(_T("Request for invalid method (0x%x), sending NACK."), pSessionData->m_TLSSession.m_pktInnerEAPMsg->Data[0]);

                            LPBYTE pbEAPAttribute;
                            DWORD dwEAPAttributeSize;
                            if ((dwReturnCode = AL::TLS::AuthMakeEAPResponseAttribute(0x03, pSessionData->m_TLSSession.m_pktInnerEAPMsg->Id, pSessionData->m_bCurrentMethodVersion, (LPBYTE) &(pSessionData->m_Inner.m_eapcfg.m_dwType), 1, &pbEAPAttribute, &dwEAPAttributeSize)) == NO_ERROR) {
                                dwReturnCode = AL::TLS::AddEAPMessage(pSessionData, pbEAPAttribute, dwEAPAttributeSize, pktSend, pEapPeerMethodOutput);
                                AL::Heap::Free((LPVOID*)&pbEAPAttribute);
                            }
                        }
                        break;

                    default:
                        AL_TRACE_ERROR(_T("Invalid packet."));
                        dwReturnCode  = ERROR_PPP_INVALID_PACKET;
                }
            }

            //
            // If we haven't sent anything yet and no error has occured then continue
            //
            if (pEapPeerMethodOutput->action != EapPeerMethodResponseActionSend && dwReturnCode == NO_ERROR) {
                //
                // InnerEapSendPacket must be our dwSendPacketSize
                // (1490) - 90 (header information needed to transport through ttls)
                //
                DWORD dwInnerEapSendPacketSize = 1490 - 90;
                PPP_EAP_PACKET *pInnerEapSendPacket;
                if ((dwReturnCode = AL::Heap::Alloc(dwInnerEapSendPacketSize, (LPVOID*)&pInnerEapSendPacket)) == NO_ERROR) {
                    PPP_EAP_OUTPUT InnerEapOutput;
                    ZeroMemory(&InnerEapOutput, sizeof(InnerEapOutput));

                    if ((dwReturnCode = pSessionData->m_Inner.m_eap.m_info.RasEapMakeMessage(pSessionData->m_Inner.m_pbSessionData, (PPP_EAP_PACKET*)(EapPacket*)pSessionData->m_TLSSession.m_pktInnerEAPMsg, pInnerEapSendPacket, dwInnerEapSendPacketSize, &InnerEapOutput, &(pSessionData->m_Inner.m_EapInput))) == NO_ERROR) {
                        //
                        // Let's see what the module wants us to do.
                        //
                        if (InnerEapOutput.fSaveUserData) {
                            AL_TRACE_INFO(_T("Saving inner user data."));

                            //
                            // Save the EapOutPut.pUserData
                            //
                            if (pSessionData->m_user.m_aEAPUserData.SetCount(InnerEapOutput.dwSizeOfUserData))
                                memcpy(pSessionData->m_user.m_aEAPUserData.GetData(), InnerEapOutput.pUserData, InnerEapOutput.dwSizeOfUserData);
                        }

                        if (InnerEapOutput.fSaveConnectionData) {
                            AL_TRACE_INFO(_T("Saving inner connection data."));

                            //
                            // Save the EapOutPut.pConnectionData
                            //
                            if (pSessionData->m_cfg.m_aEAPConnectionData.SetCount(InnerEapOutput.dwSizeOfConnectionData)) {
                                memcpy(pSessionData->m_cfg.m_aEAPConnectionData.GetData(), InnerEapOutput.pConnectionData, InnerEapOutput.dwSizeOfConnectionData);
                                pSessionData->m_fSaveConfigData = TRUE;
                            }
                        }

                        pEapPeerMethodOutput->action = EapPeerMethodResponseActionNone;

                        if (InnerEapOutput.fInvokeInteractiveUI) {
                            AL_TRACE_INFO(_T("Inner EAP method requested interactive UI."));

#ifdef AL_WIN10_DISABLE_INTERACTIONS
                            if (AL::System::g_uliVerEap3Host.HighPart < 0x000a0000)
#endif
                            {
                                //
                                // Show RASEAP interactive UI.
                                //
                                pEapPeerMethodOutput->action     = EapPeerMethodResponseActionInvokeUI;
                                pSessionData->m_Inner.m_EapState = AL::EAP::INNERSTATE_InteractiveUI;
                                if ((dwReturnCode = pSessionData->m_blobDataForInteractiveUI.Create(
                                        sizeof(BYTE) +
                                        sizeof(size_t) +
                                        InnerEapOutput.dwSizeOfUIContextData)) == NO_ERROR)
                                {
                                    LPBYTE pbCursor = (LPBYTE)pSessionData->m_blobDataForInteractiveUI.GetData();
                                    MemPack(&pbCursor, (BYTE)AL::TLS::UITYPE_INNER_EAP);
                                    MemPack(&pbCursor, (size_t)InnerEapOutput.dwSizeOfUIContextData);
                                    memcpy(pbCursor, InnerEapOutput.pUIContextData, InnerEapOutput.dwSizeOfUIContextData);
                                } else
                                    AL_TRACE_ERROR(_T("Error allocating memory for interactive UI data BLOB."), dwReturnCode = ERROR_OUTOFMEMORY);
                            }
#ifdef AL_WIN10_DISABLE_INTERACTIONS
                            else
                                AL_TRACE_ERROR(_T("Interactive UI is not supported on this version of Windows."), dwReturnCode = ERROR_NOT_SUPPORTED);
#endif
                        } else {
                            switch (InnerEapOutput.Action) {
                                case EAPACTION_Authenticate:
                                    //
                                    // Not sure what to do now...
                                    //
                                    AL_TRACE_WARNING(_T("EAPACTION_Authenticate"));
                                    break;

                                case EAPACTION_NoAction:
                                    AL_TRACE_INFO(_T("EAPACTION_NoAction"));
                                case EAPACTION_Done:
                                    AL_TRACE_INFO(_T("EAPACTION_Done"));

                                    //
                                    // Inner EAP method is happy so we send an ACK to complete inner SUCCESS/FAILURE
                                    //
                                    switch (pSessionData->m_TLSSession.m_pktInnerEAPMsg->Code) {
                                        case EAPCODE_Success:
                                        case EAPCODE_Failure:
                                            pEapPeerMethodOutput->action = EapPeerMethodResponseActionSend;

                                            pSessionData->m_Inner.m_EapState = AL::EAP::INNERSTATE_Identity;
                                            pSessionData->m_Inner.m_fHandledAccessReject = TRUE;
                                            break;

                                        default:
                                            pEapPeerMethodOutput->action = EapPeerMethodResponseActionNone;
                                    }
                                    break;

                                case EAPACTION_SendAndDone:
                                case EAPACTION_Send:
                                case EAPACTION_SendWithTimeout:
                                case EAPACTION_SendWithTimeoutInteractive:
                                    AL_TRACE_INFO(_T("EAPACTION_Send*"));
                                    if (pSessionData->m_bCurrentMethodVersion == 0)
                                        dwReturnCode = AL::TLS::AddEAPMessage(pSessionData, (LPCBYTE)pInnerEapSendPacket->Data, AL::Convert::N2H16(pInnerEapSendPacket->Length) - 4, pktSend, pEapPeerMethodOutput);
                                    else
                                        dwReturnCode = AL::TLS::AddEAPMessage(pSessionData, (LPCBYTE)pInnerEapSendPacket, AL::Convert::N2H16(pInnerEapSendPacket->Length), pktSend, pEapPeerMethodOutput);
                            }
                        }
                    } else
                        AL_TRACE_ERROR(_T("pInnerEapMakeMessage failed (%ld)."), dwReturnCode);

                    AL::Heap::Free((LPVOID*)&pInnerEapSendPacket);
                }
            }
            break;
        }

        case AL::EAP::INNERSTATE_Finished:
            //
            // Should never get here.
            //
            AL_TRACE_ERROR(_T("INNERSTATE_Finished"));
            dwReturnCode = ERROR_PPP_INVALID_PACKET;
            break;

        default:
            AL_TRACE_ERROR(_T("Unknown inner authentication state."));
            dwReturnCode = ERROR_PPP_INVALID_PACKET;
    }

    return dwReturnCode;
}

//
// This function builds a EAP response attribute
//
DWORD AL::TLS::AuthMakeEAPResponseAttribute(IN BYTE bType, IN BYTE bPacketId, IN BYTE bFlags, IN LPCBYTE pbData, IN DWORD cbData, OUT LPBYTE *ppbEAPAttribute, OUT DWORD *pcbEAPAttribute)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    if ((bFlags & AL_EAP_PEAP_V1) ||
        bType == 0x21) // extension packet does require headers..... weird MS
    {
        if (bType == 1 || bType == 3)  // Identity or NACK
            *pcbEAPAttribute = 0x05 + cbData;
        else
            *pcbEAPAttribute = 0x06 + cbData;
    } else {
        if (bType == 1 || bType == 3) // Identity or NACK
            *pcbEAPAttribute = 0x01 + cbData;
        else
            *pcbEAPAttribute = 0x02 + cbData;
    }

    if ((dwReturnCode = AL::Heap::Alloc(*pcbEAPAttribute, (LPVOID*) ppbEAPAttribute)) == NO_ERROR) {
        DWORD dwCursor = 0;

        //
        // Response
        //
        if ((bFlags & AL_EAP_PEAP_V1) ||
            bType == 0x21) // extension packet does require headers..... weird MS
        {
            (*ppbEAPAttribute)[dwCursor++] = 0x02; // code
            (*ppbEAPAttribute)[dwCursor++] = bPacketId; // id

            AL::Convert::H2N16((WORD)*pcbEAPAttribute, &((*ppbEAPAttribute)[dwCursor])); // total length of packet
            dwCursor+=2;
        }

        (*ppbEAPAttribute)[dwCursor++] = bType; // type

        if (bType != 1 && bType != 3) // Neither identity, neither NACK
            (*ppbEAPAttribute)[dwCursor++] = bFlags; // flags

        memcpy(&((*ppbEAPAttribute)[dwCursor]), pbData, cbData);
    }

    return dwReturnCode;
}
