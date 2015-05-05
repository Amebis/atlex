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
// Local data types
//
struct WORKBUFFER {
    LPVOID pCommonWorkBuffer;
    AL::EAP::CPacket pktSend;
    AL::CMonitor Monitor;
};


//
// Free memory allocated by this module
//
VOID WINAPI EapPeerFreeMemory(IN LPVOID pbMemory)
{
    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_VOID_DEBUG;

        // Sanity check
        if (!pbMemory)
            return;

        AL::Heap::Free(&pbMemory);
    }
    AL::Trace::Done();
}


//
// Free EAP_ERROR memory allocated by this module
//
VOID WINAPI EapPeerFreeErrorMemory(IN EAP_ERROR* pEapError)
{
    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_VOID_DEBUG;

        // Sanity check
        if (!pEapError) {
            // Nothing to do; exit cleanly.
            AL_TRACE_WARNING(_T("pEapError is NULL."));
        } else
            AL::EAP::FreeError(&pEapError);
    }
    AL::Trace::Done();
}


//
// Return structure containing pointer to EapHost functions
//
DWORD WINAPI EapPeerGetInfo(IN EAP_TYPE* pEapType, OUT EAP_PEER_METHOD_ROUTINES* pEapPeerMethodRoutines, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
#ifdef _DEBUG
        //Sleep(10000);
#endif

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (!pEapType) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pEapType is NULL."), NULL);
        } else if (pEapType->type != AL::EAP::g_bType) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" Input EAP type (%d) does not match the supported EAP type (%d)."), (int)pEapType->type, (int)AL::EAP::g_bType);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (!pEapPeerMethodRoutines) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pEapPeerMethodRoutines is NULL."), NULL);
        } else {
            ZeroMemory(pEapPeerMethodRoutines, sizeof(*pEapPeerMethodRoutines));

            pEapPeerMethodRoutines->dwVersion                    = AL_VERSION;
            pEapPeerMethodRoutines->EapPeerInitialize            = EapPeerInitialize;
            pEapPeerMethodRoutines->EapPeerShutdown              = EapPeerShutdown;
            pEapPeerMethodRoutines->EapPeerBeginSession          = EapPeerBeginSession;
            pEapPeerMethodRoutines->EapPeerEndSession            = EapPeerEndSession;
#ifdef AL_GENERIC_CREDENTIAL_UI
            pEapPeerMethodRoutines->EapPeerSetCredentials        = EapPeerSetCredentials;
#else
            pEapPeerMethodRoutines->EapPeerGetIdentity           = EapPeerGetIdentity;
#endif
            pEapPeerMethodRoutines->EapPeerProcessRequestPacket  = EapPeerProcessRequestPacket;
            pEapPeerMethodRoutines->EapPeerGetResponsePacket     = EapPeerGetResponsePacket;
            pEapPeerMethodRoutines->EapPeerGetResult             = EapPeerGetResult;
            pEapPeerMethodRoutines->EapPeerGetUIContext          = EapPeerGetUIContext;
            pEapPeerMethodRoutines->EapPeerSetUIContext          = EapPeerSetUIContext;
            pEapPeerMethodRoutines->EapPeerGetResponseAttributes = EapPeerGetResponseAttributes;
            pEapPeerMethodRoutines->EapPeerSetResponseAttributes = EapPeerSetResponseAttributes;
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// Initialize the module
//
DWORD WINAPI EapPeerInitialize(OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
        AL_TRACE_INFO(_T("ArnesLink v%s"), _T(AL_VERSION_STR));

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else
            dwReturnCode = AL::EAP::Init(ppEapError);
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// De-Initialize the module
//
DWORD WINAPI EapPeerShutdown(OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else
            dwReturnCode = AL::EAP::Done(ppEapError);
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// Convert an XML structure to a configuration blob
//
DWORD WINAPI EapPeerConfigXml2Blob(IN DWORD dwFlags, IN EAP_METHOD_TYPE eapMethodType, IN IXMLDOMDocument2* pXMLConfigDoc, OUT __out_ecount(*pdwSizeOfConnectionOut) BYTE **ppbConnectionOut, OUT DWORD* pdwSizeOfConnectionOut, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
        AL_TRACE_DEBUG(_T("dwFlags (0x%x)"), dwFlags);
#ifdef _DEBUG
        //Sleep(10000);
#endif

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (eapMethodType.eapType.type != AL::EAP::g_bType) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" Input EAP type (%d) does not match the supported EAP type (%d)."), (int)eapMethodType.eapType.type, (int)AL::EAP::g_bType);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (eapMethodType.dwAuthorId != AL_EAP_AUTHOR_ID) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" EAP author (%d) does not match the supported author (%d)."), (int)eapMethodType.dwAuthorId, (int)AL_EAP_AUTHOR_ID);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (!ppbConnectionOut) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" ppbConnectionOut is NULL."), NULL);
        } else if (!pdwSizeOfConnectionOut) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pdwSizeOfConnectionOut is NULL."), NULL);
        } else if (!pXMLConfigDoc) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pXMLConfigDoc is NULL."), NULL);
        } else {
            AL::EAP::CBlob blobConnectionOut;
            if ((dwReturnCode = AL::EAP::ConfigXml2Blob(dwFlags, pXMLConfigDoc, blobConnectionOut, ppEapError)) == NO_ERROR) {
                *pdwSizeOfConnectionOut = (DWORD)blobConnectionOut.GetCookieSize();
                AL_TRACE_INFO(_T("Configuration BLOB: %ldB (payload: %ldB)."), *pdwSizeOfConnectionOut, blobConnectionOut.GetSize());
                *ppbConnectionOut = (LPBYTE)blobConnectionOut.Detach();
            }
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// Convert a configuration blob to an XML structure
//
DWORD WINAPI EapPeerConfigBlob2Xml(IN DWORD dwFlags, IN EAP_METHOD_TYPE eapMethodType, IN __in_ecount(dwSizeOfConnectionIn) const BYTE *pbConnectionIn, IN DWORD dwSizeOfConnectionIn, OUT IXMLDOMDocument2 **ppXMLConfigDoc, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
        AL_TRACE_DEBUG(_T("dwFlags (0x%x)"), dwFlags);
#ifdef _DEBUG
        //Sleep(10000);
#endif

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (eapMethodType.eapType.type != AL::EAP::g_bType) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" Input EAP type (%d) does not match the supported EAP type (%d)."), (int)eapMethodType.eapType.type, (int)AL::EAP::g_bType);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (eapMethodType.dwAuthorId != AL_EAP_AUTHOR_ID) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" EAP author (%d) does not match the supported author (%d)."), (int)eapMethodType.dwAuthorId, (int)AL_EAP_AUTHOR_ID);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (!ppXMLConfigDoc) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" ppXMLConfigDoc is NULL."), NULL);
        } else {
            AL::EAP::CBlobReader blobConnection;
            if ((dwReturnCode = blobConnection.Mount(pbConnectionIn, dwSizeOfConnectionIn)) == NO_ERROR) {
                dwReturnCode = AL::EAP::ConfigBlob2Xml(dwFlags, blobConnection.GetSize(), blobConnection.GetData(), ppXMLConfigDoc, ppEapError);
            } else {
                ATL::CAtlStringW sTemp;
                sTemp.Format(_T(__FUNCTION__) _T(" Error parsing configuration BLOB (%ld)."), dwReturnCode);
                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, sTemp, NULL);
            }
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// Return EAP method properties dynamically
//
DWORD WINAPI EapPeerGetMethodProperties(IN DWORD dwVersion, IN DWORD dwFlags, IN EAP_METHOD_TYPE eapMethodType, IN HANDLE hUserImpersonationToken, IN DWORD dwSizeOfConnectionDataIn, IN BYTE* pConnectionDataIn, IN DWORD dwSizeOfUserDataIn, IN BYTE* pUserDataIn, OUT EAP_METHOD_PROPERTY_ARRAY* pMethodPropertyArray, OUT EAP_ERROR** ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
#ifdef _DEBUG
        //Sleep(10000);
#endif

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (eapMethodType.eapType.type != AL::EAP::g_bType) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" Input EAP type (%d) does not match the supported EAP type (%d)."), (int)eapMethodType.eapType.type, (int)AL::EAP::g_bType);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (eapMethodType.dwAuthorId != AL_EAP_AUTHOR_ID) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" EAP author (%d) does not match the supported author (%d)."), (int)eapMethodType.dwAuthorId, (int)AL_EAP_AUTHOR_ID);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (!pMethodPropertyArray) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pMethodPropertyArray is NULL."), NULL);
        } else {
            dwReturnCode = AL::EAP::GetMethodProperties(dwVersion, dwFlags, eapMethodType, hUserImpersonationToken, dwSizeOfConnectionDataIn, pConnectionDataIn, dwSizeOfUserDataIn, pUserDataIn, pMethodPropertyArray, ppEapError);
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// Show Configuration interface
//
DWORD WINAPI EapPeerInvokeConfigUI(IN EAP_METHOD_TYPE* pEapMethodType, IN HWND hWndParent, IN DWORD dwFlags, IN DWORD dwSizeOfConnectionDataIn, IN LPCBYTE pbConnectionDataIn, OUT DWORD *pdwSizeOfConnectionDataOut, OUT LPBYTE *ppbConnectionDataOut, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
        AL_TRACE_DEBUG(_T("dwFlags (0x%x)"), dwFlags);
#ifdef _DEBUG
        //MessageBox(NULL, _T("Attach debugger!"), _T(__FUNCTION__), MB_OK);
#endif

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (!pEapMethodType) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pEapMethodType is NULL."), NULL);
        } else if (pEapMethodType->eapType.type != AL::EAP::g_bType) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" Input EAP type (%d) does not match the supported EAP type (%d)."), (int)pEapMethodType->eapType.type, (int)AL::EAP::g_bType);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (pEapMethodType->dwAuthorId != AL_EAP_AUTHOR_ID) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" EAP author (%d) does not match the supported author (%d)."), (int)pEapMethodType->dwAuthorId, (int)AL_EAP_AUTHOR_ID);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (!pdwSizeOfConnectionDataOut) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pdwSizeOfConnectionDataOut is NULL."), NULL);
        } else if (!ppbConnectionDataOut) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" ppbConnectionDataOut is NULL."), NULL);
        } else {
#ifdef USE_WINXP_THEMES
            InitCommonControls();
#endif
            AL::EAP::CBlobReader blobConnectionIn;
            if ((dwReturnCode = blobConnectionIn.Mount(pbConnectionDataIn, dwSizeOfConnectionDataIn)) == NO_ERROR) {
                AL::EAP::CBlob blobConnectionOut;
                if ((dwReturnCode = AL::EAP::InvokeConfigUI(hWndParent, dwFlags, blobConnectionIn.GetSize(), blobConnectionIn.GetData(), blobConnectionOut, ppEapError)) == NO_ERROR) {
                    *pdwSizeOfConnectionDataOut = (DWORD)blobConnectionOut.GetCookieSize();
                    AL_TRACE_INFO(_T("Configuration BLOB: %ldB (payload: %ldB)."), *pdwSizeOfConnectionDataOut, blobConnectionOut.GetSize());
                    *ppbConnectionDataOut = (LPBYTE)blobConnectionOut.Detach();
                }
            } else {
                ATL::CAtlStringW sTemp;
                sTemp.Format(_T(__FUNCTION__) _T(" Error parsing configuration BLOB (%ld)."), dwReturnCode);
                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, sTemp, NULL);
            }
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// Function to convert XML containing credentials to credentials blob
//
DWORD WINAPI EapPeerCredentialsXml2Blob(IN DWORD dwFlags, IN EAP_METHOD_TYPE eapMethodType, IN IXMLDOMDocument2* pXMLCredentialsDoc, IN __in_ecount(dwSizeOfConnectionIn) const BYTE *pbConnectionIn, IN DWORD dwSizeOfConnectionIn, OUT __out_ecount(*pdwSizeOfCredentialsOut) BYTE **ppbCredentialsOut, OUT DWORD* pdwSizeOfCredentialsOut, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
        AL_TRACE_DEBUG(_T("dwFlags (0x%x)"), dwFlags);

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (eapMethodType.eapType.type != AL::EAP::g_bType) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" Input EAP type (%d) does not match the supported EAP type (%d)."), (int)eapMethodType.eapType.type, (int)AL::EAP::g_bType);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (eapMethodType.dwAuthorId != AL_EAP_AUTHOR_ID) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" EAP author (%d) does not match the supported author (%d)."), (int)eapMethodType.dwAuthorId, (int)AL_EAP_AUTHOR_ID);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (!ppbCredentialsOut) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" ppbCredentialsOut is NULL."), NULL);
        } else if (!pdwSizeOfCredentialsOut) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pdwSizeOfCredentialsOut is NULL."), NULL);
        } else if (!pXMLCredentialsDoc) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pXMLCredentialsDoc is NULL."), NULL);
        } else {
            AL::EAP::CBlobReader blobConnectionIn;
            if ((dwReturnCode = blobConnectionIn.Mount(pbConnectionIn, dwSizeOfConnectionIn)) == NO_ERROR) {
                AL::EAP::CBlob blobCredentialsOut;
                if ((dwReturnCode = AL::EAP::CredentialsXml2Blob(dwFlags, pXMLCredentialsDoc, blobConnectionIn.GetSize(), blobConnectionIn.GetData(), blobCredentialsOut, ppEapError)) == NO_ERROR) {
                    *pdwSizeOfCredentialsOut = (DWORD)blobCredentialsOut.GetCookieSize();
                    AL_TRACE_INFO(_T("User BLOB: %ldB (payload: %ldB)."), *pdwSizeOfCredentialsOut, blobCredentialsOut.GetSize());
                    *ppbCredentialsOut = (LPBYTE)blobCredentialsOut.Detach();
                }
            } else {
                ATL::CAtlStringW sTemp;
                sTemp.Format(_T(__FUNCTION__) _T(" Error parsing configuration BLOB (%ld)."), dwReturnCode);
                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, sTemp, NULL);
            }
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// Function to return Inputfields
//
DWORD WINAPI EapPeerQueryCredentialInputFields(IN HANDLE hUserToken, IN EAP_METHOD_TYPE eapMethodType, IN DWORD dwFlags, IN DWORD dwEapConnDataSize, IN LPCBYTE pbEapConnData, OUT EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldArray, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
        AL_TRACE_DEBUG(_T("dwFlags (0x%x)"), dwFlags);

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (eapMethodType.eapType.type != AL::EAP::g_bType) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" Input EAP type (%d) does not match the supported EAP type (%d)."), (int)eapMethodType.eapType.type, (int)AL::EAP::g_bType);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (eapMethodType.dwAuthorId != AL_EAP_AUTHOR_ID) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" EAP author (%d) does not match the supported author (%d)."), (int)eapMethodType.dwAuthorId, (int)AL_EAP_AUTHOR_ID);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (!pEapConfigInputFieldArray) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pEapConfigInputFieldArray is NULL."), NULL);
        } else {
            AL::EAP::CBlobReader blobConnectionIn;
            if ((dwReturnCode = blobConnectionIn.Mount(pbEapConnData, dwEapConnDataSize)) == NO_ERROR) {
                dwReturnCode = AL::EAP::QueryCredentialInputFields(hUserToken, dwFlags, blobConnectionIn.GetSize(), blobConnectionIn.GetData(), pEapConfigInputFieldArray, ppEapError);
            } else {
                ATL::CAtlStringW sTemp;
                sTemp.Format(_T(__FUNCTION__) _T(" Error parsing configuration BLOB (%ld)."), dwReturnCode);
                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, sTemp, NULL);
            }
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// Function to return user blob according to Inputfields provided by EapHost
//
DWORD WINAPI EapPeerQueryUserBlobFromCredentialInputFields(IN HANDLE hUserToken, IN EAP_METHOD_TYPE eapMethodType, IN DWORD dwFlags, IN DWORD dwEapConnDataSize, IN LPCBYTE pbEapConnData, IN CONST EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldArray, OUT DWORD *pdwUserBlobSize, OUT LPBYTE *ppbUserBlob, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
        AL_TRACE_DEBUG(_T("dwFlags (0x%x)"), dwFlags);

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (eapMethodType.eapType.type != AL::EAP::g_bType) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" Input EAP type (%d) does not match the supported EAP type (%d)."), (int)eapMethodType.eapType.type, (int)AL::EAP::g_bType);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (eapMethodType.dwAuthorId != AL_EAP_AUTHOR_ID) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" EAP author (%d) does not match the supported author (%d)."), (int)eapMethodType.dwAuthorId, (int)AL_EAP_AUTHOR_ID);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (!pEapConfigInputFieldArray) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pEapConfigInputFieldArray is NULL."), NULL);
        } else if (!pdwUserBlobSize) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pdwUserBlobSize is NULL."), NULL);
        } else if (!ppbUserBlob) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" ppbUserBlob is NULL."), NULL);
        } else {
            AL::EAP::CBlobReader blobConnectionIn;
            if ((dwReturnCode = blobConnectionIn.Mount(pbEapConnData, dwEapConnDataSize)) == NO_ERROR) {
                AL::EAP::CBlob blobUserOut;
                if ((dwReturnCode = AL::EAP::QueryUserBlobFromCredentialInputFields(hUserToken, dwFlags, blobConnectionIn.GetSize(), blobConnectionIn.GetData(), pEapConfigInputFieldArray, blobUserOut, ppEapError)) == NO_ERROR) {
                    *pdwUserBlobSize = (DWORD)blobUserOut.GetCookieSize();
                    AL_TRACE_INFO(_T("User BLOB: %ldB (payload: %ldB)."), *pdwUserBlobSize, blobUserOut.GetSize());
                    *ppbUserBlob = (LPBYTE)blobUserOut.Detach();
                }
            } else {
                ATL::CAtlStringW sTemp;
                sTemp.Format(_T(__FUNCTION__) _T(" Error parsing configuration BLOB (%ld)."), dwReturnCode);
                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, sTemp, NULL);
            }
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


#ifndef AL_GENERIC_CREDENTIAL_UI

//
// Retrieve the user identity (non-interactive)
//
DWORD WINAPI EapPeerGetIdentity(IN DWORD dwFlags, IN DWORD dwSizeOfConnectionData, IN const BYTE *pbConnectionData, IN DWORD dwSizeOfUserDataIn, IN const BYTE *pbUserDataIn, IN HANDLE hTokenImpersonateUser, OUT BOOL *pfInvokeUI, OUT DWORD *pdwSizeOfUserDataOut, OUT LPBYTE *ppbUserDataOut, OUT LPWSTR *ppwcIdentity, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
        AL_TRACE_DEBUG(_T("dwFlags (0x%x)"), dwFlags);
#ifdef _DEBUG
        //Sleep(10000);
#endif

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (!pfInvokeUI) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pfInvokeUI is NULL."), NULL);
        } else if (!ppwcIdentity) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" ppwcIdentity is NULL."), NULL);
        } else {
            AL::EAP::CBlobReader blobConnectionIn;
            if ((dwReturnCode = blobConnectionIn.Mount(pbConnectionData, dwSizeOfConnectionData)) == NO_ERROR) {
                AL::EAP::CBlobReader blobUserIn;
                if ((dwReturnCode = blobUserIn.Mount(pbUserDataIn, dwSizeOfUserDataIn)) == NO_ERROR) {
                    AL::EAP::CBlob blobUserOut;
                    AL::EAP::CBlobFlat blobIdentity;
                    if ((dwReturnCode = AL::EAP::GetIdentity(dwFlags, blobConnectionIn.GetSize(), blobConnectionIn.GetData(), blobUserIn.GetSize(), blobUserIn.GetData(), hTokenImpersonateUser, pfInvokeUI, blobUserOut, blobIdentity, ppEapError)) == NO_ERROR) {
                        *pdwSizeOfUserDataOut = (DWORD)blobUserOut.GetCookieSize();
                        AL_TRACE_INFO(_T("User BLOB: %ldB (payload: %ldB)."), *pdwSizeOfUserDataOut, blobUserOut.GetSize());
                        *ppbUserDataOut = (LPBYTE)blobUserOut.Detach();
                        *ppwcIdentity   = (LPWSTR)blobIdentity.Detach();
                    }

#ifdef AL_WIN10_DISABLE_INTERACTIONS
                    if (*pfInvokeUI && AL::System::g_uliVerEap3Host.HighPart >= 0x000a0000) {
                        //
                        // Peer requested UI. This won't fly on Windows 10.
                        // Return an error to EAP to stop the process instead of hanging it.
                        //
                        if (*ppbUserDataOut) {
                            EapPeerFreeMemory(*ppbUserDataOut);
                            *ppbUserDataOut = NULL;
                        }
                        *pdwSizeOfUserDataOut = 0;

                        if (*ppwcIdentity) {
                            EapPeerFreeMemory(*ppwcIdentity);
                            *ppwcIdentity = NULL;
                        }

                        //
                        // Report the error.
                        //
                        AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_FOUND, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_CRED_MISSING), ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_CRED_MISSING_DESC));
                        AL::CMonitor monitor;
                        monitor.Init(hTokenImpersonateUser, NULL);
                        monitor.SendError(*ppEapError);
                    }
#endif
                } else {
                    ATL::CAtlStringW sTemp;
                    sTemp.Format(_T(__FUNCTION__) _T(" Error parsing user BLOB (%ld)."), dwReturnCode);
                    AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, sTemp, NULL);
                }
            } else {
                ATL::CAtlStringW sTemp;
                sTemp.Format(_T(__FUNCTION__) _T(" Error parsing configuration BLOB (%ld)."), dwReturnCode);
                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, sTemp, NULL);
            }
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}

#endif


//
// Show Identity User interface (Baloon)
//
DWORD WINAPI EapPeerInvokeIdentityUI(IN EAP_METHOD_TYPE *pEapMethodType, IN DWORD dwFlags, IN HWND hWndParent, IN DWORD dwSizeOfConnectionData, IN const BYTE *pbConnectionData, IN DWORD dwSizeOfUserDataIn, IN const BYTE *pbUserDataIn, OUT DWORD *pdwSizeOfUserDataOut, OUT LPBYTE *ppbUserDataOut, OUT LPWSTR *ppwszIdentity, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
        AL_TRACE_DEBUG(_T("dwFlags (0x%x)"), dwFlags);
#ifdef _DEBUG
        //MessageBox(NULL, _T("Attach debugger!"), _T(__FUNCTION__), MB_OK);
#endif

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (!pEapMethodType) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pEapMethodType is NULL."), NULL);
        } else if (pEapMethodType->eapType.type != AL::EAP::g_bType) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" Input EAP type (%d) does not match the supported EAP type (%d)."), (int)pEapMethodType->eapType.type, (int)AL::EAP::g_bType);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (pEapMethodType->dwAuthorId != AL_EAP_AUTHOR_ID) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" EAP author (%d) does not match the supported author (%d)."), (int)pEapMethodType->dwAuthorId, (int)AL_EAP_AUTHOR_ID);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (!pdwSizeOfUserDataOut) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pdwSizeOfUserDataOut is NULL."), NULL);
        } else if (!ppbUserDataOut) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" ppbUserDataOut is NULL."), NULL);
        } else if (!ppwszIdentity) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" ppwszIdentity is NULL."), NULL);
        } else {
#ifdef USE_WINXP_THEMES
            InitCommonControls();
#endif
            AL::EAP::CBlobReader blobConnectionIn;
            if ((dwReturnCode = blobConnectionIn.Mount(pbConnectionData, dwSizeOfConnectionData)) == NO_ERROR) {
                AL::EAP::CBlobReader blobUserIn;
                if ((dwReturnCode = blobUserIn.Mount(pbUserDataIn, dwSizeOfUserDataIn)) == NO_ERROR) {
                    AL::EAP::CBlob blobUserOut;
                    AL::EAP::CBlobFlat blobIdentity;
                    if ((dwReturnCode = AL::EAP::InvokeIdentityUI(hWndParent, dwFlags, blobConnectionIn.GetSize(), blobConnectionIn.GetData(), blobUserIn.GetSize(), blobUserIn.GetData(), blobUserOut, blobIdentity, ppEapError)) == NO_ERROR) {
                        *pdwSizeOfUserDataOut = (DWORD)blobUserOut.GetCookieSize();
                        AL_TRACE_INFO(_T("User BLOB: %ldB (payload: %ldB)."), *pdwSizeOfUserDataOut, blobUserOut.GetSize());
                        *ppbUserDataOut = (LPBYTE)blobUserOut.Detach();
                        *ppwszIdentity  = (LPWSTR)blobIdentity.Detach();
                    }
                } else {
                    ATL::CAtlStringW sTemp;
                    sTemp.Format(_T(__FUNCTION__) _T(" Error parsing user BLOB (%ld)."), dwReturnCode);
                    AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, sTemp, NULL);
                }
            } else {
                ATL::CAtlStringW sTemp;
                sTemp.Format(_T(__FUNCTION__) _T(" Error parsing configuration BLOB (%ld)."), dwReturnCode);
                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, sTemp, NULL);
            }
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// Identity has been determined, begin an authentication session
//
DWORD WINAPI EapPeerBeginSession(IN DWORD dwFlags, IN const EapAttributes* pAttributeArray, IN HANDLE hTokenImpersonateUser, IN DWORD dwSizeOfConnectionData, IN BYTE *pbConnectionData, IN DWORD dwSizeOfUserData, IN BYTE *pbUserData, IN DWORD dwMaxSendPacketSize, OUT EAP_SESSION_HANDLE* pEapSessionHandle, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
        AL_TRACE_DEBUG(_T("dwFlags (0x%x)"), dwFlags);

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (!pEapSessionHandle) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pEapSessionHandle is NULL."), NULL);
        } else {
            AL::EAP::CBlobReader blobConnectionIn;
            if ((dwReturnCode = blobConnectionIn.Mount(pbConnectionData, dwSizeOfConnectionData)) == NO_ERROR) {
                AL::EAP::CBlobReader blobUserIn;
                if ((dwReturnCode = blobUserIn.Mount(pbUserData, dwSizeOfUserData)) == NO_ERROR) {
                    //
                    // Allocate work buffer for EAPHost.
                    //
                    WORKBUFFER *pwb = new WORKBUFFER;
                    if (pwb) {
                        pwb->Monitor.Init(hTokenImpersonateUser, pwb);

                        //
                        // Call EAP method specific function, this will allocate common work buffer
                        //
                        if ((dwReturnCode = AL::EAP::BeginSession(dwFlags, hTokenImpersonateUser, blobConnectionIn.GetSize(), blobConnectionIn.GetData(), blobUserIn.GetSize(), blobUserIn.GetData(), &(pwb->Monitor), &(pwb->pCommonWorkBuffer), ppEapError)) == NO_ERROR)
                            *pEapSessionHandle = pwb;

                        if (dwReturnCode != NO_ERROR) {
                            pwb->Monitor.SendError(*ppEapError);

                            //
                            // Cleanup the session.
                            //
                            delete pwb;
                        }
                    } else
                        AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_OUTOFMEMORY, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for WORKBUFFER."), NULL);
                }
            } else {
                ATL::CAtlStringW sTemp;
                sTemp.Format(_T(__FUNCTION__) _T(" Error parsing configuration BLOB (%ld)."), dwReturnCode);
                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, sTemp, NULL);
            }
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// Authentication has finished (either successful or not), End authentication session (Cleanup)
//
DWORD WINAPI EapPeerEndSession(IN EAP_SESSION_HANDLE eapSessionHandle, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
#ifdef _DEBUG
        //Sleep(10000);
#endif

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (!eapSessionHandle) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" eapSessionHandle is NULL."), NULL);
        } else {
            WORKBUFFER *pwb = (WORKBUFFER*)eapSessionHandle;

            dwReturnCode = AL::EAP::EndSession(pwb->pCommonWorkBuffer, ppEapError);

            if (dwReturnCode != NO_ERROR)
                pwb->Monitor.SendError(*ppEapError);

            //
            // Cleanup the session.
            //
            delete pwb;
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


#ifdef AL_GENERIC_CREDENTIAL_UI

//
// Set the user identity
//
DWORD WINAPI EapPeerSetCredentials(IN EAP_SESSION_HANDLE eapSessionHandle, IN WCHAR *pwszIdentity, IN WCHAR *pwszPassword, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
#ifdef _DEBUG
        //Sleep(10000);
#endif

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (!eapSessionHandle) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" eapSessionHandle is NULL."), NULL);
        } else {
            WORKBUFFER *pwb = (WORKBUFFER*)eapSessionHandle;

            if ((dwReturnCode = AL::EAP::SetCredentials(pwb->pCommonWorkBuffer, pwszIdentity, pwszPassword, ppEapError)) != NO_ERROR)
                pwb->Monitor.SendError(*ppEapError);
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}

#endif


//
// Process a recieved request packet
//
DWORD WINAPI EapPeerProcessRequestPacket(IN EAP_SESSION_HANDLE eapSessionHandle, IN DWORD cbReceivePacket, IN EapPacket* pReceivePacket, OUT EapPeerMethodOutput* pEapPeerMethodOutput, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
#ifdef _DEBUG
        //Sleep(10000);
#endif

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (!eapSessionHandle) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" eapSessionHandle is NULL."), NULL);
        } else if (!pReceivePacket) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pReceivePacket is NULL."), NULL);
        } else if (!pEapPeerMethodOutput) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pEapPeerMethodOutput is NULL."), NULL);
        } else {
            WORKBUFFER *pwb = (WORKBUFFER*)eapSessionHandle;

            {
                DWORD dwSizeOfReceivedPacket = AL::Convert::N2H16(pReceivePacket->Length);
                AL_TRACE_INFO(_T("Received: %x-%x (%ldB)."), (int)(pReceivePacket->Code), (int)(pReceivePacket->Id), dwSizeOfReceivedPacket);
            }

            if ((dwReturnCode = AL::EAP::Process(pwb->pCommonWorkBuffer, pReceivePacket, pwb->pktSend, pEapPeerMethodOutput, ppEapError)) != NO_ERROR)
                pwb->Monitor.SendError(*ppEapError);
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// Retrieve a response packet to send
//
DWORD WINAPI EapPeerGetResponsePacket(IN EAP_SESSION_HANDLE eapSessionHandle, IN OUT DWORD* pcbSendPacket, OUT EapPacket* pSendPacket, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (!eapSessionHandle) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" eapSessionHandle is NULL."), NULL);
        } else if (!pcbSendPacket) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pcbSendPacket is NULL."), NULL);
        } else if (!pSendPacket) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pSendPacket is NULL."), NULL);
        } else {
            WORKBUFFER *pwb = (WORKBUFFER*)eapSessionHandle;
            DWORD dwSizeOfSendPacket = pwb->pktSend.GetSize();

            AL_TRACE_INFO(_T("Responding: %x-%x (%ldB)..."), (int)(pwb->pktSend->Code), (int)(pwb->pktSend->Id), dwSizeOfSendPacket);

            if (*pcbSendPacket >= dwSizeOfSendPacket) {
                memcpy(pSendPacket, (const EapPacket*)pwb->pktSend, dwSizeOfSendPacket);
                *pcbSendPacket = dwSizeOfSendPacket;
            } else
                AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INSUFFICIENT_BUFFER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Buffer too small."), NULL);

            if (dwReturnCode != NO_ERROR)
                pwb->Monitor.SendError(*ppEapError);
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// Return the authentication result. In this function the user data and/or
// configuration data is also returned to the upper layer to be stored
//
DWORD WINAPI EapPeerGetResult(IN EAP_SESSION_HANDLE eapSessionHandle, IN EapPeerMethodResultReason eapPeerMethodResultReason, OUT EapPeerMethodResult *pEapPeerMethodResult, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
#ifdef _DEBUG
        //Sleep(10000);
#endif

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (!eapSessionHandle) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" eapSessionHandle is NULL."), NULL);
        } else if (!pEapPeerMethodResult) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pEapPeerMethodResult is NULL."), NULL);
        } else {
            WORKBUFFER *pwb = (WORKBUFFER*)eapSessionHandle;

            if ((dwReturnCode = AL::Heap::Alloc(sizeof(EAP_ATTRIBUTES), (LPVOID*)&(pEapPeerMethodResult->pAttribArray))) == NO_ERROR)
                dwReturnCode = AL::EAP::GetResult(pwb->pCommonWorkBuffer, eapPeerMethodResultReason, pEapPeerMethodResult, ppEapError);
            else
                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for EAP_ATTRIBUTES."), NULL);

            //
            // Report all errata encountered.
            //
            if (pEapPeerMethodResult->dwFailureReasonCode != NO_ERROR && pEapPeerMethodResult->pEapError)
                pwb->Monitor.SendError(pEapPeerMethodResult->pEapError);
            if (dwReturnCode != NO_ERROR)
                pwb->Monitor.SendError(*ppEapError);
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// Before the Interactive UI is called, this function is called in which the
// context data for the Interactive UI is returned
//
DWORD WINAPI EapPeerGetUIContext(IN EAP_SESSION_HANDLE eapSessionHandle, OUT DWORD *pdwSizeOfUIContextData, OUT BYTE **ppbUIContextData, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
#ifdef _DEBUG
        //Sleep(10000);
#endif

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (!eapSessionHandle) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" eapSessionHandle is NULL."), NULL);
        } else if (!pdwSizeOfUIContextData) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pdwSizeOfUIContextData is NULL."), NULL);
        } else if (!ppbUIContextData) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" ppbUIContextData is NULL."), NULL);
        } else {
            WORKBUFFER *pwb = (WORKBUFFER*)eapSessionHandle;

            if ((dwReturnCode = AL::EAP::GetUIContext(pwb->pCommonWorkBuffer, pdwSizeOfUIContextData, ppbUIContextData, ppEapError)) != NO_ERROR)
                pwb->Monitor.SendError(*ppEapError);
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// Show Interactive User interface (Baloon)
//
DWORD WINAPI EapPeerInvokeInteractiveUI(IN EAP_METHOD_TYPE* pEapMethodType, IN HWND hWndParent, IN DWORD dwSizeofUIContextData, IN BYTE *pbUIContextData, OUT DWORD* pdwSizeOfDataFromInteractiveUI, OUT BYTE **ppbDataFromInteractiveUI, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
#ifdef _DEBUG
        //MessageBox(NULL, _T("Attach debugger!"), _T(__FUNCTION__), MB_OK);
#endif

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (!pEapMethodType) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pEapMethodType is NULL."), NULL);
        } else if (pEapMethodType->eapType.type != AL::EAP::g_bType) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" Input EAP type (%d) does not match the supported EAP type (%d)."), (int)pEapMethodType->eapType.type, (int)AL::EAP::g_bType);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (pEapMethodType->dwAuthorId != AL_EAP_AUTHOR_ID) {
            ATL::CAtlStringW sTemp;
            sTemp.Format(_T(__FUNCTION__) _T(" EAP author (%d) does not match the supported author (%d)."), (int)pEapMethodType->dwAuthorId, (int)AL_EAP_AUTHOR_ID);
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, sTemp, NULL);
        } else if (!pbUIContextData) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pbUIContextData is NULL."), NULL);
        } else if (!ppbDataFromInteractiveUI) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" ppbDataFromInteractiveUI is NULL."), NULL);
        } else if (!pdwSizeOfDataFromInteractiveUI) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pdwSizeOfDataFromInteractiveUI is NULL."), NULL);
        } else {
#ifdef USE_WINXP_THEMES
            InitCommonControls();
#endif
            AL::EAP::CBlobReader blobUIContextDataIn;
            if ((dwReturnCode = blobUIContextDataIn.Mount(pbUIContextData, dwSizeofUIContextData)) == NO_ERROR) {
                AL::EAP::CBlob blobDataFromInteractiveUI;
                if ((dwReturnCode = AL::EAP::InvokeInteractiveUI(hWndParent, blobUIContextDataIn.GetSize(), blobUIContextDataIn.GetData(), blobDataFromInteractiveUI, ppEapError)) == NO_ERROR) {
                    *pdwSizeOfDataFromInteractiveUI = (DWORD)blobDataFromInteractiveUI.GetCookieSize();
                    AL_TRACE_INFO(_T("Data from interactive UI: %ldB (payload: %ldB)."), *pdwSizeOfDataFromInteractiveUI, blobDataFromInteractiveUI.GetSize());
                    *ppbDataFromInteractiveUI = (LPBYTE)blobDataFromInteractiveUI.Detach();
                }
            } else {
                ATL::CAtlStringW sTemp;
                sTemp.Format(_T(__FUNCTION__) _T(" Error parsing UI context data BLOB (%ld)."), dwReturnCode);
                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, sTemp, NULL);
            }
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// After the Interactive UI is called, this function is called in which the
// context data for the Interactive UI is provided
//
DWORD WINAPI EapPeerSetUIContext(IN EAP_SESSION_HANDLE eapSessionHandle, IN DWORD dwSizeOfUIContextData, IN const BYTE *pbUIContextData, OUT EapPeerMethodOutput* pEapPeerMethodOutput, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_INFO(dwReturnCode);
#ifdef _DEBUG
        //Sleep(10000);
#endif

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (!eapSessionHandle) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" eapSessionHandle is NULL."), NULL);
        } else if (!pEapPeerMethodOutput) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pEapPeerMethodOutput is NULL."), NULL);
        } else {
            WORKBUFFER *pwb = (WORKBUFFER*)eapSessionHandle;
            AL::EAP::CBlobReader blobUIContextDataIn;
            if ((dwReturnCode = blobUIContextDataIn.Mount(pbUIContextData, dwSizeOfUIContextData, TRUE)) == NO_ERROR) {
                if ((dwReturnCode = AL::EAP::SetUIContext(pwb->pCommonWorkBuffer, blobUIContextDataIn.GetSize(), blobUIContextDataIn.GetData(), ppEapError)) == NO_ERROR) {
                    //
                    // Make call to AL::EAP::ProccessRequestPacket one more time to retrieve action
                    // based on current status.
                    //
                    dwReturnCode = AL::EAP::Process(pwb->pCommonWorkBuffer, NULL, pwb->pktSend, pEapPeerMethodOutput, ppEapError);
                }
            } else {
                ATL::CAtlStringW sTemp;
                sTemp.Format(_T(__FUNCTION__) _T(" Error parsing UI context BLOB (%ld)."), dwReturnCode);
                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, sTemp, NULL);
            }

            if (dwReturnCode != NO_ERROR)
                pwb->Monitor.SendError(*ppEapError);
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// The EapPeerQueryInteractiveUIInputFields function obtains
// the input fields for interactive UI components to be raised on the supplicant.
//
DWORD WINAPI EapPeerQueryInteractiveUIInputFields(IN DWORD dwVersion, IN DWORD dwFlags, IN DWORD dwSizeofUIContextData, IN __in_ecount(dwSizeofUIContextData) const BYTE *pUIContextData, OUT EAP_INTERACTIVE_UI_DATA* pEapInteractiveUIData, OUT EAP_ERROR **ppEapError, IN OUT LPVOID *pvReserved)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_WARNING(dwReturnCode);
        AL_TRACE_DEBUG(_T("dwFlags (0x%x)"), dwFlags);

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (!pUIContextData) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pUIContextData is NULL."), NULL);
        } else if (!pEapInteractiveUIData) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pEapInteractiveUIData is NULL."), NULL);
        } else
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Unsupported"), NULL);
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// The EapPeerQueryUIBlobFromInteractiveUIInputFields function converts user
// information into a user BLOB that can be consumed by EAPHost run-time functions.
//
DWORD WINAPI EapPeerQueryUIBlobFromInteractiveUIInputFields(IN DWORD dwVersion, IN DWORD dwFlags, IN DWORD dwSizeofUIContextData, IN __in_ecount(dwSizeofUIContextData) const BYTE *pUIContextData, IN const EAP_INTERACTIVE_UI_DATA *pEapInteractiveUIData, OUT DWORD * pdwSizeOfDataFromInteractiveUI, OUT __deref_out_ecount(*pdwSizeOfDataFromInteractiveUI) BYTE **ppDataFromInteractiveUI, OUT EAP_ERROR **ppEapError, IN OUT LPVOID *pvReserved)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_WARNING(dwReturnCode);
        AL_TRACE_DEBUG(_T("dwFlags (0x%x)"), dwFlags);

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (!pUIContextData) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pUIContextData is NULL."), NULL);
        } else if (!pEapInteractiveUIData) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pEapInteractiveUIData is NULL."), NULL);
        } else if (!ppDataFromInteractiveUI) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" ppDataFromInteractiveUI is NULL."), NULL);
        } else
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Unsupported"), NULL);
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// Set any attributes from response
// NOT IMPLEMENTED
//
DWORD WINAPI EapPeerSetResponseAttributes(IN EAP_SESSION_HANDLE eapSessionHandle, IN EapAttributes *pAttribs, OUT EapPeerMethodOutput *pEapOutput, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_WARNING(dwReturnCode);

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (!eapSessionHandle) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" eapSessionHandle is NULL."), NULL);
        } else if (!pAttribs) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pAttribs is NULL."), NULL);
        } else {
            pEapOutput->action             = EapPeerMethodResponseActionNone;
            pAttribs->dwNumberOfAttributes = 0;
            pAttribs->pAttribs             = NULL;
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// Return any attributes from response
// NOT IMPLEMENTED
//
DWORD WINAPI EapPeerGetResponseAttributes(IN EAP_SESSION_HANDLE eapSessionHandle, OUT EapAttributes* pAttribs, OUT EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::Trace::Init(AL::Trace::g_pszID);
    {
        AL_TRACEFN_WARNING(dwReturnCode);

        // Sanity check
        if (!ppEapError) {
            AL_TRACE_ERROR(_T("ppEapError is NULL."));
            dwReturnCode = ERROR_INVALID_PARAMETER;
        } else if (!eapSessionHandle) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" eapSessionHandle is NULL."), NULL);
        } else if (!pAttribs) {
            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pAttribs is NULL."), NULL);
        } else {
            pAttribs->dwNumberOfAttributes = 0;
            pAttribs->pAttribs             = NULL;
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}
