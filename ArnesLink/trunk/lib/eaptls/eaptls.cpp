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
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "msxml6.lib")


//
// Local function declaration
//
static DWORD _GetEAP(_In_ DWORD dwFlags, _In_ const AL::TLS::CConfigData *pConfigData, _Inout_ AL::TLS::CUserData *pUserData, _Out_ BOOL *pfInvokeUI);
#ifdef AL_EAPHOST
static DWORD _GetEAPHOST(_In_ DWORD dwFlags, _In_ const AL::TLS::CConfigData *pConfigData, _Out_ AL::TLS::CUserData *pUserData, _Out_ BOOL *pfInvokeUI);
#endif
static DWORD _GetPAP(_In_ DWORD dwFlags, _In_ const AL::TLS::CConfigData *pConfigData, _Inout_ AL::TLS::CUserData *pUserData, _Out_ BOOL *pfInvokeUI);
static DWORD _InvokeUserUIEAP(_In_ HWND hWndParent, _In_ DWORD dwFlags, _In_ const AL::TLS::CConfigData *pConfigData, _Inout_ AL::TLS::CUserData *pUserData);
static DWORD _InvokeUserUIPAP(_In_ HWND hWndParent, _In_ DWORD dwFlags, _In_ const AL::TLS::CConfigData *pConfigData, _Inout_ AL::TLS::CUserData *pUserData);
static DWORD _HandleOuterIdentity(_In_ const AL::TLS::CConfigData *pConfigData, _In_ const AL::TLS::CUserData *pUserData, _Out_ AL::EAP::CBlobFlat &blobIdentity);
static DWORD _GenerateKeyMaterial(_In_ HCRYPTPROV hCSP, _In_ BYTE bEapType, _In_ DWORD bCurrentMethodVersion, _In_ LPCBYTE pbRandomClient, _In_ LPCBYTE pbRandomServer, _In_ LPCBYTE pbMS, _Out_ LPBYTE pbKeyMaterial, _In_ DWORD cbKeyMaterial);
static DWORD _MakeMPPEKey(_In_ LPCBYTE pbKeyMaterial, _In_ DWORD cbKeyMaterial, _Out_cap_c_(3) EAP_ATTRIBUTE **ppUserAttributes);


//
// Initialize the module
//
DWORD AL::EAP::Init(_Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    return dwReturnCode;
}


//
// De-Initialize the module
//
DWORD AL::EAP::Done(_Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    return dwReturnCode;
}


//
// Convert an XML structure to a byte blob, this blob is used in
// the API function calls during authentication
//
DWORD AL::EAP::ConfigXml2Blob(_In_ DWORD dwFlags, _In_ IXMLDOMDocument2 *pXMLConfigDoc, _Out_ CBlob &blobConnectionOut, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // Load configuration from XML.
    //
    AL::TLS::CConfigData cfg;
    if ((dwReturnCode = cfg.Load(pXMLConfigDoc)) != NO_ERROR) {
        //
        // No matter if something went wrong. Just keep the default settings and/or the settings we managed to read.
        //
        AL_TRACE_WARNING(_T("::Error loading XML configuration. Configuration remains default or incomplete (%ld)."), dwReturnCode);
        dwReturnCode = NO_ERROR;
    }

    //
    // Allocate configuration BLOB.
    //
    if ((dwReturnCode = blobConnectionOut.Create(MemGetPackedSize(cfg))) == NO_ERROR) {
        //
        // Save configuration to BLOB.
        //
        LPBYTE pbCursor = (LPBYTE)blobConnectionOut.GetData();
        MemPack(&pbCursor, cfg);
    } else
        AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for configuration BLOB."), NULL);

    return dwReturnCode;
}


//
// Convert a configuration blob to an XML structure
//
DWORD AL::EAP::ConfigBlob2Xml(_In_ DWORD dwFlags, _In_ SIZE_T nConnectionSize, _In_bytecount_(nConnectionSize) LPCVOID pConnection, _Out_ IXMLDOMDocument2 **ppXMLConfigDoc, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    *ppXMLConfigDoc = NULL;

    //
    // Load configuration from BLOB.
    //
    AL::TLS::CConfigData cfg;
    if (pConnection)
        MemUnpack((const BYTE**)&pConnection, cfg);

    HRESULT hr;
    CComPtr<IXMLDOMDocument2> pXmlDoc;
    if (SUCCEEDED(hr = pXmlDoc.CoCreateInstance(CLSID_DOMDocument60, NULL, CLSCTX_INPROC_SERVER))) {
        if ((dwReturnCode = cfg.Save(pXmlDoc)) == NO_ERROR)
            *ppXMLConfigDoc = pXmlDoc.Detach();
        else
            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatW(_T(__FUNCTION__) _T(" Error saving configuration to XMLDOMDocument2 (%ld)."), dwReturnCode), NULL);
    } else
        AL::EAP::RecordError(ppEapError, dwReturnCode = HRESULT_CODE(hr), 0, NULL, NULL, NULL, ATL::CStrFormatW(_T(__FUNCTION__) _T(" Error creating XMLDOMDocument2 (0x%lx)."), hr), NULL);

    return dwReturnCode;
}


DWORD AL::EAP::GetMethodProperties(_In_ DWORD dwVersion, _In_ DWORD dwFlags, _In_ EAP_METHOD_TYPE eapMethodType, _In_ HANDLE hTokenImpersonateUser, _In_ SIZE_T nConnectionDataSize, _In_bytecount_(nConnectionDataSize) LPCVOID pConnectionData, _In_ SIZE_T nUserDataSize, _In_bytecount_(nUserDataSize) LPCVOID pUserData, _Out_ EAP_METHOD_PROPERTY_ARRAY *pMethodPropertyArray, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // Load configuration from BLOB.
    //
    AL::TLS::CConfigData cfg;
    if (pConnectionData)
        MemUnpack((const BYTE**)&pConnectionData, cfg);

    //
    // Allocate and fill property array.
    //
    pMethodPropertyArray->dwNumberOfProperties = 20;
    if ((dwReturnCode = AL::Heap::Alloc(sizeof(EAP_METHOD_PROPERTY)*pMethodPropertyArray->dwNumberOfProperties, (LPVOID*)&(pMethodPropertyArray->pMethodProperty))) == NO_ERROR) {
        pMethodPropertyArray->pMethodProperty[ 0].eapMethodPropertyType                  = emptPropCipherSuiteNegotiation;
        pMethodPropertyArray->pMethodProperty[ 0].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[ 0].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[ 0].eapMethodPropertyValue.empvBool.value  = TRUE;

        pMethodPropertyArray->pMethodProperty[ 1].eapMethodPropertyType                  = emptPropMutualAuth;
        pMethodPropertyArray->pMethodProperty[ 1].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[ 1].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[ 1].eapMethodPropertyValue.empvBool.value  = TRUE;

        pMethodPropertyArray->pMethodProperty[ 2].eapMethodPropertyType                  = emptPropIntegrity;
        pMethodPropertyArray->pMethodProperty[ 2].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[ 2].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[ 2].eapMethodPropertyValue.empvBool.value  = TRUE;

        pMethodPropertyArray->pMethodProperty[ 3].eapMethodPropertyType                  = emptPropReplayProtection;
        pMethodPropertyArray->pMethodProperty[ 3].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[ 3].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[ 3].eapMethodPropertyValue.empvBool.value  = TRUE;

        pMethodPropertyArray->pMethodProperty[ 4].eapMethodPropertyType                  = emptPropConfidentiality;
        pMethodPropertyArray->pMethodProperty[ 4].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[ 4].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[ 4].eapMethodPropertyValue.empvBool.value  = TRUE;

        pMethodPropertyArray->pMethodProperty[ 5].eapMethodPropertyType                  = emptPropKeyDerivation;
        pMethodPropertyArray->pMethodProperty[ 5].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[ 5].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[ 5].eapMethodPropertyValue.empvBool.value  = TRUE;

        pMethodPropertyArray->pMethodProperty[ 6].eapMethodPropertyType                  = emptPropKeyStrength128;
        pMethodPropertyArray->pMethodProperty[ 6].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[ 6].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[ 6].eapMethodPropertyValue.empvBool.value  = TRUE;

        pMethodPropertyArray->pMethodProperty[ 7].eapMethodPropertyType                  = emptPropDictionaryAttackResistance;
        pMethodPropertyArray->pMethodProperty[ 7].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[ 7].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[ 7].eapMethodPropertyValue.empvBool.value  = TRUE;

        pMethodPropertyArray->pMethodProperty[ 8].eapMethodPropertyType                  = emptPropFastReconnect;
        pMethodPropertyArray->pMethodProperty[ 8].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[ 8].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[ 8].eapMethodPropertyValue.empvBool.value  = TRUE;

        pMethodPropertyArray->pMethodProperty[ 9].eapMethodPropertyType                  = emptPropCryptoBinding;
        pMethodPropertyArray->pMethodProperty[ 9].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[ 9].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[ 9].eapMethodPropertyValue.empvBool.value  = TRUE;

        pMethodPropertyArray->pMethodProperty[10].eapMethodPropertyType                  = emptPropSessionIndependence;
        pMethodPropertyArray->pMethodProperty[10].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[10].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[10].eapMethodPropertyValue.empvBool.value  = TRUE;

        pMethodPropertyArray->pMethodProperty[11].eapMethodPropertyType                  = emptPropFragmentation;
        pMethodPropertyArray->pMethodProperty[11].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[11].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[11].eapMethodPropertyValue.empvBool.value  = TRUE;

        pMethodPropertyArray->pMethodProperty[12].eapMethodPropertyType                  = emptPropStandalone;
        pMethodPropertyArray->pMethodProperty[12].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[12].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[12].eapMethodPropertyValue.empvBool.value  = TRUE;

        pMethodPropertyArray->pMethodProperty[13].eapMethodPropertyType                  = emptPropMppeEncryption;
        pMethodPropertyArray->pMethodProperty[13].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[13].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[13].eapMethodPropertyValue.empvBool.value  = TRUE;

        pMethodPropertyArray->pMethodProperty[14].eapMethodPropertyType                  = emptPropTunnelMethod;
        pMethodPropertyArray->pMethodProperty[14].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[14].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[14].eapMethodPropertyValue.empvBool.value  = TRUE;

        pMethodPropertyArray->pMethodProperty[15].eapMethodPropertyType                  = emptPropSupportsConfig;
        pMethodPropertyArray->pMethodProperty[15].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[15].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[15].eapMethodPropertyValue.empvBool.value  = TRUE;

        pMethodPropertyArray->pMethodProperty[16].eapMethodPropertyType                  = emptPropMachineAuth;
        pMethodPropertyArray->pMethodProperty[16].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[16].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[16].eapMethodPropertyValue.empvBool.value  = !cfg.m_sIdentity.IsEmpty() && !cfg.m_sPassword.IsEmpty() ? TRUE : FALSE;

        pMethodPropertyArray->pMethodProperty[17].eapMethodPropertyType                  = emptPropUserAuth;
        pMethodPropertyArray->pMethodProperty[17].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[17].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[17].eapMethodPropertyValue.empvBool.value  = TRUE;

        pMethodPropertyArray->pMethodProperty[18].eapMethodPropertyType                  = emptPropIdentityPrivacy;
        pMethodPropertyArray->pMethodProperty[18].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[18].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[18].eapMethodPropertyValue.empvBool.value  = TRUE;

        pMethodPropertyArray->pMethodProperty[19].eapMethodPropertyType                  = emptPropSharedStateEquivalence;
        pMethodPropertyArray->pMethodProperty[19].eapMethodPropertyValueType             = empvtBool;
        pMethodPropertyArray->pMethodProperty[19].eapMethodPropertyValue.empvBool.length = sizeof(BOOL);
        pMethodPropertyArray->pMethodProperty[19].eapMethodPropertyValue.empvBool.value  = TRUE;
    } else
        AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for EAP_METHOD_PROPERTY array."), NULL);

    return dwReturnCode;
}


//
// Show Configuration User interface
//
DWORD AL::EAP::InvokeConfigUI(_In_ HWND hWndParent, _In_ DWORD dwFlags, _In_ SIZE_T nConnectionDataInSize, _In_bytecount_(nConnectionDataInSize) LPCVOID pConnectionDataIn, _Out_ CBlob &blobConnectionDataOut, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    AL::TLS::CConfigData cfg;
    if (pConnectionDataIn)
        MemUnpack((const BYTE**)&pConnectionDataIn, cfg);

    if (DialogBoxParam(AL::System::g_hResource, MAKEINTRESOURCE(IDD_AL_CONFIG), hWndParent, &AL::TLS::DlgProc::Config, (LPARAM)&cfg)) {
        //
        // Allocate configuration BLOB.
        //
        if ((dwReturnCode = blobConnectionDataOut.Create(MemGetPackedSize(cfg))) == NO_ERROR) {
            //
            // Save configuration to BLOB.
            //
            LPBYTE pbCursor = (LPBYTE)blobConnectionDataOut.GetData();
            MemPack(&pbCursor, cfg);
        } else
            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for configuration BLOB."), NULL);
    } else {
        AL_TRACE_ERROR(_T("User cancelled"));
        dwReturnCode = ERROR_CANCELLED;
    }

    return dwReturnCode;
}


DWORD AL::EAP::CredentialsXml2Blob(_In_ DWORD dwFlags, _In_ IXMLDOMDocument2 *pXMLCredentialsDoc, _In_ SIZE_T nConfigInSize, _In_bytecount_(nConfigInSize) LPCVOID pConfigIn, _Out_ CBlob &blobCredentialsOut, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    CComPtr<IXMLDOMNode> pXmlElCredentials;
    if ((dwReturnCode = AL::XML::SelectNode(pXMLCredentialsDoc, CComBSTR(L"//EapHostUserCredentials/Credentials"), &pXmlElCredentials)) == NO_ERROR) {
        AL::TLS::CUserData user;

        {
            CComBSTR bstr;
            if ((AL::XML::GetElementValue(pXmlElCredentials, CComBSTR(L"UserID"), &bstr)) == NO_ERROR)
                user.m_sIdentity = bstr;
        }

        {
            CComBSTR bstr;
            if ((AL::XML::GetElementValue(pXmlElCredentials, CComBSTR(L"UserPassword"), &bstr)) == NO_ERROR)
                user.m_sPassword = bstr;
            SecureZeroMemory((BSTR)bstr, sizeof(OLECHAR)*bstr.Length());
        }

        //
        // Allocate user data BLOB.
        //
        if ((dwReturnCode = blobCredentialsOut.Create(MemGetPackedSize(user))) == NO_ERROR) {
            //
            // Save user data to BLOB.
            //
            LPBYTE pbCursor = (LPBYTE)blobCredentialsOut.GetData();
            MemPack(&pbCursor, user);
        } else
            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for user data BLOB."), NULL);
    } else
        AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Credentials not found."), NULL);

    return dwReturnCode;
}


DWORD AL::EAP::QueryCredentialInputFields(_In_ HANDLE hUserToken, _In_ DWORD dwFlags, _In_ SIZE_T nConnectionDataSize, _In_bytecount_(nConnectionDataSize) LPCVOID pConnectionData, _Out_ EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldArray, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    AL::TLS::CConfigData cfg;
    if (pConnectionData)
        MemUnpack((const BYTE**)&pConnectionData, cfg);

    pEapConfigInputFieldArray->dwVersion        = AL_EAP_CREDENTIAL_VERSION;
    pEapConfigInputFieldArray->dwNumberOfFields = 2;

    if ((dwReturnCode = AL::Heap::Alloc(sizeof(EAP_CONFIG_INPUT_FIELD_DATA)*pEapConfigInputFieldArray->dwNumberOfFields, (LPVOID*)&pEapConfigInputFieldArray->pFields)) == NO_ERROR) {
        pEapConfigInputFieldArray->pFields[0].dwSize      = sizeof(EAP_CONFIG_INPUT_FIELD_DATA);
        pEapConfigInputFieldArray->pFields[0].Type        = EapConfigInputUsername;
        pEapConfigInputFieldArray->pFields[0].dwFlagProps = EAP_CONFIG_INPUT_FIELD_PROPS_DEFAULT;
        if ((dwReturnCode = AL::Heap::Alloc(sizeof(WCHAR)*MAX_EAP_CONFIG_INPUT_FIELD_LENGTH, (LPVOID*)&pEapConfigInputFieldArray->pFields[0].pwszLabel)) == NO_ERROR) {
            if (!cfg.m_sAltIdentityLbl.IsEmpty())
                wmemcpy_s(pEapConfigInputFieldArray->pFields[0].pwszLabel, MAX_EAP_CONFIG_INPUT_FIELD_LENGTH, (LPCTSTR)cfg.m_sAltIdentityLbl, cfg.m_sAltIdentityLbl.GetLength() + 1);
            else
                LoadString(AL::System::g_hResource, IDS_AL_IDENTITY_LBL, pEapConfigInputFieldArray->pFields[0].pwszLabel, MAX_EAP_CONFIG_INPUT_FIELD_LENGTH);
            if ((dwReturnCode = AL::Heap::Alloc(sizeof(WCHAR)*MAX_EAP_CONFIG_INPUT_FIELD_VALUE_LENGTH, (LPVOID*)&pEapConfigInputFieldArray->pFields[0].pwszData)) == NO_ERROR) {
                wmemcpy_s(pEapConfigInputFieldArray->pFields[0].pwszData, MAX_EAP_CONFIG_INPUT_FIELD_VALUE_LENGTH, (LPCWSTR)cfg.m_sIdentity, cfg.m_sIdentity.GetLength());
                pEapConfigInputFieldArray->pFields[0].dwMinDataLength = sizeof(WCHAR);
                pEapConfigInputFieldArray->pFields[0].dwMaxDataLength = sizeof(WCHAR)*(MAX_EAP_CONFIG_INPUT_FIELD_VALUE_LENGTH - 1);

                pEapConfigInputFieldArray->pFields[1].dwSize      = sizeof(EAP_CONFIG_INPUT_FIELD_DATA);
                pEapConfigInputFieldArray->pFields[1].Type        = EapConfigInputPassword;
                pEapConfigInputFieldArray->pFields[1].dwFlagProps = EAP_CONFIG_INPUT_FIELD_PROPS_DEFAULT;
                if ((dwReturnCode = AL::Heap::Alloc(sizeof(WCHAR)*MAX_EAP_CONFIG_INPUT_FIELD_LENGTH, (LPVOID*)&pEapConfigInputFieldArray->pFields[1].pwszLabel)) == NO_ERROR) {
                    if (!cfg.m_sAltPasswordLbl.IsEmpty())
                        wmemcpy_s(pEapConfigInputFieldArray->pFields[1].pwszLabel, MAX_EAP_CONFIG_INPUT_FIELD_LENGTH, (LPCTSTR)cfg.m_sAltPasswordLbl, cfg.m_sAltPasswordLbl.GetLength() + 1);
                    else
                        LoadString(AL::System::g_hResource, IDS_AL_PASSWORD_LBL, pEapConfigInputFieldArray->pFields[1].pwszLabel, MAX_EAP_CONFIG_INPUT_FIELD_LENGTH);
                    if ((dwReturnCode = AL::Heap::Alloc(sizeof(WCHAR)*MAX_EAP_CONFIG_INPUT_FIELD_VALUE_LENGTH, (LPVOID*)&pEapConfigInputFieldArray->pFields[1].pwszData)) == NO_ERROR) {
                        wmemcpy_s(pEapConfigInputFieldArray->pFields[1].pwszData, MAX_EAP_CONFIG_INPUT_FIELD_VALUE_LENGTH, L"", _countof(L""));
                        pEapConfigInputFieldArray->pFields[1].dwMinDataLength = sizeof(WCHAR);
                        pEapConfigInputFieldArray->pFields[1].dwMaxDataLength = sizeof(WCHAR)*(MAX_EAP_CONFIG_INPUT_FIELD_VALUE_LENGTH - 1);
                    } else
                        AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for password value."), NULL);
                    if (dwReturnCode != NO_ERROR)
                        AL::Heap::Free((LPVOID*)&pEapConfigInputFieldArray->pFields[1].pwszLabel);
                } else
                    AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for password label."), NULL);
                if (dwReturnCode != NO_ERROR)
                    AL::Heap::Free((LPVOID*)&pEapConfigInputFieldArray->pFields[0].pwszData);
            } else
                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for user name value."), NULL);
            if (dwReturnCode != NO_ERROR)
                AL::Heap::Free((LPVOID*)&pEapConfigInputFieldArray->pFields[0].pwszLabel);
        } else
            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for user name label."), NULL);
        if (dwReturnCode != NO_ERROR)
            AL::Heap::Free((LPVOID*)&pEapConfigInputFieldArray->pFields);
    } else
        AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for EAP_CONFIG_INPUT_FIELD_DATA."), NULL);

    return dwReturnCode;
}


DWORD AL::EAP::QueryUserBlobFromCredentialInputFields(_In_ HANDLE hUserToken, _In_ DWORD dwFlags, _In_ SIZE_T nEapConnDataSize, _In_bytecount_(nEapConnDataSize) LPCVOID pEapConnData, _In_ const EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldArray, _Out_ CBlob &blobUserOut, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    if (pEapConfigInputFieldArray->dwVersion >= AL_EAP_CREDENTIAL_VERSION) {
        AL::TLS::CUserData user;

        for (DWORD i = 0; i < pEapConfigInputFieldArray->dwNumberOfFields; i++) {
            switch (pEapConfigInputFieldArray->pFields[i].Type) {
                case EapConfigInputUsername:
                    user.m_sIdentity.SetString(pEapConfigInputFieldArray->pFields[i].pwszData, (int)wcsnlen(pEapConfigInputFieldArray->pFields[i].pwszData, MAX_EAP_CONFIG_INPUT_FIELD_VALUE_LENGTH));
                    break;

                case EapConfigInputPassword:
                    user.m_sPassword.SetString(pEapConfigInputFieldArray->pFields[i].pwszData, (int)wcsnlen(pEapConfigInputFieldArray->pFields[i].pwszData, MAX_EAP_CONFIG_INPUT_FIELD_VALUE_LENGTH));
                    break;
            }
        }

        //
        // Allocate user data BLOB.
        //
        if ((dwReturnCode = blobUserOut.Create(MemGetPackedSize(user))) == NO_ERROR) {
            //
            // Save user data to BLOB.
            //
            LPBYTE pbCursor = (LPBYTE)blobUserOut.GetData();
            MemPack(&pbCursor, user);
        } else
            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for user data BLOB."), NULL);
    } else
        AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatW(_T(__FUNCTION__) _T(" Wrong config input field array version (%ld)."), pEapConfigInputFieldArray->dwVersion), NULL);

    return dwReturnCode;
}


#ifndef AL_GENERIC_CREDENTIAL_UI

//
// Retrieve Identity without user interaction, return *pfInvokeUI = TRUE if
// User Interface is required
//
DWORD AL::EAP::GetIdentity(_In_ DWORD dwFlags, _In_ SIZE_T nConnectionDataSize, _In_bytecount_(nConnectionDataSize) LPCVOID pConnectionData, _In_ SIZE_T nUserDataInSize, _In_bytecount_(nUserDataInSize) LPCVOID pUserDataIn, _In_ HANDLE hTokenImpersonateUser, _Out_ BOOL *pfInvokeUI, _Out_ CBlob &blobUserOut, _Out_ CBlobFlat &blobIdentity, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    *pfInvokeUI = FALSE; // Assume UI won't be necessary.

    AL::TLS::CConfigData cfg;
    if (pConnectionData)
        MemUnpack((const BYTE**)&pConnectionData, cfg);

    AL::TLS::CUserData user;
    if (pUserDataIn) {
        //
        // Previous user data available, copy it and overwrite it with information
        // retrieved from the UI.
        //
        MemUnpack((const BYTE**)&pUserDataIn, user);
    }

    if (AL::EAP::g_bType == AL_EAP_TYPE_PEAP || cfg.m_InnerAuth == AL::TLS::INNERMETHOD_EAP) {
        AL_TRACE_INFO(_T("Using inner RASEAP..."));

        if ((dwReturnCode = _GetEAP(dwFlags, &cfg, &user, pfInvokeUI)) != NO_ERROR)
            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormat(_T(__FUNCTION__) _T(" Error preparing credentials from configuration profile (%ld)."), dwReturnCode), NULL);
#ifdef AL_EAPHOST
    } else if (wcscmp(cfg.pwcInnerAuth, L"EAPHOST") == 0) {
        AL_TRACE_INFO(_T("Using inner EAPHOST..."));
        if ((dwReturnCode = _GetEAPHOST(dwFlags, &ConfigData, &user, pfInvokeUI)) != NO_ERROR)
            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatW(_T(__FUNCTION__) _T(" Error preparing credentials from EAPHOST (%ld)."), dwReturnCode), NULL);
#endif
    } else {
        AL_TRACE_INFO(_T("Using PAP..."));

        if ((dwReturnCode = _GetPAP(dwFlags, &cfg, &user, pfInvokeUI)) != NO_ERROR)
            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormat(_T(__FUNCTION__) _T(" Error preparing credentials from configuration profile (%ld)."), dwReturnCode), NULL);
    }

    if (dwReturnCode == NO_ERROR && *pfInvokeUI == FALSE) {
        if ((dwReturnCode = _HandleOuterIdentity(&cfg, &user, blobIdentity)) == NO_ERROR) {
            AL_TRACE_INFO(_T("Outer identity: %s"), blobIdentity.GetData());

            //
            // Allocate user data BLOB.
            //
            if ((dwReturnCode = blobUserOut.Create(MemGetPackedSize(user))) == NO_ERROR) {
                //
                // Save user data to BLOB.
                //
                LPBYTE pbCursor = (LPBYTE)blobUserOut.GetData();
                MemPack(&pbCursor, user);
            } else
                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for user data BLOB."), NULL);
        } else
            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormat(_T(__FUNCTION__) _T(" Error preparing outer identity (%ld)."), dwReturnCode), NULL);
    }

    return dwReturnCode;
}

#endif


DWORD AL::EAP::InvokeIdentityUI(_In_ HWND hWndParent, _In_ DWORD dwFlags, _In_ SIZE_T nConnectionDataSize, _In_bytecount_(nConnectionDataSize) LPCVOID pConnectionData, _In_ SIZE_T nUserDataInSize, _In_bytecount_(nUserDataInSize) LPCVOID pUserDataIn, _Out_ CBlob &blobUserOut, _Out_ CBlobFlat &blobIdentity, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    AL::TLS::CConfigData cfg;
    if (pConnectionData)
        MemUnpack((const BYTE**)&pConnectionData, cfg);

    AL::TLS::CUserData user;
    if (pUserDataIn) {
        //
        // Previous user data available, copy it and overwrite it with information
        // retrieved from the UI.
        //
        MemUnpack((const BYTE**)&pUserDataIn, user);
    }

    if (AL::EAP::g_bType == AL_EAP_TYPE_PEAP || cfg.m_InnerAuth == AL::TLS::INNERMETHOD_EAP) {
        AL_TRACE_INFO(_T("Using inner RASEAP..."));
        if ((dwReturnCode = _InvokeUserUIEAP(hWndParent, dwFlags, &cfg, &user)) != NO_ERROR)
            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormat(_T(__FUNCTION__) _T(" Error launching credentials UI (%ld)."), dwReturnCode), NULL);
#ifdef AL_EAPHOST
    } else if (wcscmp(cfg.pwcInnerAuth, L"EAPHOST") == 0) {
        AL_TRACE_INFO(_T("Using inner EAPHOST..."));
        !!!
#endif
    } else {
        AL_TRACE_INFO(_T("Using PAP..."));
        if ((dwReturnCode = _InvokeUserUIPAP(hWndParent, dwFlags, &cfg, &user)) != NO_ERROR)
            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormat(_T(__FUNCTION__) _T(" Error launching credentials UI (%ld)."), dwReturnCode), NULL);
    }

    if (dwReturnCode == NO_ERROR) {
        if ((dwReturnCode = _HandleOuterIdentity(&cfg, &user, blobIdentity)) == NO_ERROR) {
            AL_TRACE_INFO(_T("Outer identity: %s"), blobIdentity.GetData());

            //
            // Allocate user data BLOB.
            //
            if ((dwReturnCode = blobUserOut.Create(MemGetPackedSize(user))) == NO_ERROR) {
                //
                // Save user data to BLOB.
                //
                LPBYTE pbCursor = (LPBYTE)blobUserOut.GetData();
                MemPack(&pbCursor, user);
            } else
                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for user data BLOB."), NULL);
        } else
            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormat(_T(__FUNCTION__) _T(" Error preparing outer identity (%ld)."), dwReturnCode), NULL);
    }

    return dwReturnCode;
}


//
// Identity has been determined, begin an authentication session.
//
DWORD AL::EAP::BeginSession(_In_ DWORD dwFlags, _In_ HANDLE hTokenImpersonateUser, _In_ SIZE_T nConnectionDataSize, _In_bytecount_(nConnectionDataSize) LPCVOID pConnectionData, _In_ SIZE_T nUserDataSize, _In_bytecount_(nUserDataSize) LPCVOID pUserData, _In_ const AL::CMonitor *pMonitor, _Out_ LPVOID *ppWorkBuffer, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    *ppWorkBuffer = NULL;

    AL::TLS::CSessionData *pSessionData = new AL::TLS::CSessionData(hTokenImpersonateUser, (LPCBYTE)pConnectionData, (LPCBYTE)pUserData, pMonitor);
    if (pSessionData) {
        //
        // Enable session resumption? (Only if previous authentication was successful).
        //
        if (pSessionData->m_cfg.m_fUseSessionResumption && pSessionData->m_user.m_EapReasonLast == EapPeerMethodResultSuccess) {
            AL_TRACE_INFO(_T("Resuming previous session..."));
            pSessionData->m_TLSSession.m_aTLSSessionID.Copy(pSessionData->m_user.m_aTLSSessionID);
            pSessionData->m_TLSSession.m_tTLSSessionID = pSessionData->m_user.m_tTLSSessionID;
            memcpy_s(pSessionData->m_TLSSession.m_pbMS, sizeof(pSessionData->m_TLSSession.m_pbMS), pSessionData->m_user.m_pbMS, sizeof(pSessionData->m_user.m_pbMS));
        } else {
            AL_TRACE_INFO(_T("Starting a new session..."));
            pSessionData->m_user.m_aTLSSessionID.RemoveAll();
            ZeroMemory(pSessionData->m_user.m_pbMS, sizeof(pSessionData->m_user.m_pbMS));
        }

        if (AL::EAP::g_bType == AL_EAP_TYPE_PEAP || pSessionData->m_cfg.m_InnerAuth == AL::TLS::INNERMETHOD_EAP) {
            //
            // If we are using EAP then load in the current EAP config.
            //
            AL_TRACE_INFO(_T("Initializing inner RASEAP..."));

            //
            // Read in config data for current EAP method.
            //
            if ((dwReturnCode = pSessionData->m_Inner.m_eapcfg.Load(AL_EAP_TYPE_MSCHAPV2)) == NO_ERROR) {
                AL_TRACE_INFO(_T("Connecting to method %s..."), (LPCTSTR)pSessionData->m_Inner.m_eapcfg.m_sFriendlyName);

                //
                // Instantialize to EAP DLL.
                //
                if ((dwReturnCode = pSessionData->m_Inner.m_eap.Load(&pSessionData->m_Inner.m_eapcfg)) == NO_ERROR) {
                    if ((dwReturnCode = pSessionData->m_Inner.m_eap.m_info.RasEapInitialize(TRUE)) == NO_ERROR) {
                        ZeroMemory(&(pSessionData->m_Inner.m_EapInput), sizeof(pSessionData->m_Inner.m_EapInput));

                        pSessionData->m_Inner.m_EapInput.dwSizeInBytes                  = sizeof(pSessionData->m_Inner.m_EapInput);
                        pSessionData->m_Inner.m_EapInput.bInitialId                     = 0;
                        pSessionData->m_Inner.m_EapInput.dwAuthResultCode               = 0;
                        pSessionData->m_Inner.m_EapInput.dwSizeOfConnectionData         = (DWORD)pSessionData->m_cfg.m_aEAPConnectionData.GetCount();
                        pSessionData->m_Inner.m_EapInput.pConnectionData                = pSessionData->m_cfg.m_aEAPConnectionData.GetData();
                        pSessionData->m_Inner.m_EapInput.dwSizeOfDataFromInteractiveUI  = 0;
                        pSessionData->m_Inner.m_EapInput.pDataFromInteractiveUI         = NULL;
                        pSessionData->m_Inner.m_EapInput.dwSizeOfUserData               = (DWORD)pSessionData->m_user.m_aEAPUserData.GetCount();
                        pSessionData->m_Inner.m_EapInput.pUserData                      = pSessionData->m_user.m_aEAPUserData.GetData();
                        pSessionData->m_Inner.m_EapInput.fAuthenticationComplete        = FALSE;
                        pSessionData->m_Inner.m_EapInput.fAuthenticator                 = FALSE;
                        pSessionData->m_Inner.m_EapInput.fDataReceivedFromInteractiveUI = FALSE;
                        pSessionData->m_Inner.m_EapInput.fSuccessPacketReceived         = FALSE;
                        pSessionData->m_Inner.m_EapInput.hReserved                      = 0;
                        pSessionData->m_Inner.m_EapInput.hTokenImpersonateUser          = hTokenImpersonateUser;
                        // FIXME:
                        //pSessionData->m_Inner.m_EapInput.pUserAttributes = pInput->pUserAttributes;
                        pSessionData->m_Inner.m_EapInput.pwszIdentity                   = (WCHAR*)(LPCWSTR)pSessionData->m_user.m_sIdentity;
                        pSessionData->m_Inner.m_EapInput.pwszPassword                   = (WCHAR*)(LPCWSTR)pSessionData->m_user.m_sPassword;
                        pSessionData->m_Inner.m_EapInput.fFlags                         = RAS_EAP_FLAG_LOGON;

                        if ((dwReturnCode = pSessionData->m_Inner.m_eap.m_info.RasEapBegin((LPVOID*)&(pSessionData->m_Inner.m_pbSessionData), &(pSessionData->m_Inner.m_EapInput))) == NO_ERROR)
                            pSessionData->m_Inner.m_EapState = AL::EAP::INNERSTATE_Start;
                        else
                            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormat(_T(__FUNCTION__) _T(" Inner RasEapBegin failed (%ld)."), dwReturnCode), NULL);
                    } else
                        AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormat(_T(__FUNCTION__) _T(" Inner method RasEapInitialize failed (%ld)."), dwReturnCode), NULL);
                } else
                    AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormat(_T(__FUNCTION__) _T(" Error instantializing inner method (%ld)."), dwReturnCode), NULL);
            } else
                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormat(_T(__FUNCTION__) _T(" Error reading inner method (%ld)."), dwReturnCode), NULL);
#ifdef AL_EAPHOST
        } else if (wcscmp(pSessionData->m_cfg.m_pwcInnerAuth, L"EAPHOST") == 0) {
            AL_TRACE_INFO(_T("initializing Inner EAPHOST Method"));

            !!if ((pSessionData->m_Inner.pEapPeerData = (AL::RASEAP::CPeerData*)malloc(sizeof(AL::RASEAP::CPeerData)))) {
                //
                // FIXME: Read EAPHost configuration
                //
                pSessionData->m_Inner.m_eapcfg.eapMethodType.eapType.type = 6;
                pSessionData->m_Inner.m_eapcfg.eapMethodType.eapType.dwVendorId = 0;
                pSessionData->m_Inner.m_eapcfg.eapMethodType.eapType.dwVendorType = 0;
                pSessionData->m_Inner.m_eapcfg.eapMethodType.dwAuthorId = 311;

                if ((dwReturnCode = EapHostPeerInitialize()) == NO_ERROR) {
                    DWORD dwFlags = 0;
                    HANDLE hTokenImpersonateUser = NULL;
                    EAP_ERROR *pEapError = NULL;

                    pSessionData->m_Inner.m_eapSessionId = 0;

                    if ((dwReturnCode = EapHostPeerBeginSession(
                        dwFlags, //Flags
                        pSessionData->m_Inner.m_eapcfg.eapMethodType,//EAP_METHOD_TYPE
                        NULL, //EapAttributes
                        hTokenImpersonateUser, //HANDLE
                        0, //Connection Data Size
                        NULL, //Connection Data
                        0, //User Data Size
                        NULL,   //User Data
                        1400, //Max Packet
                        NULL, //ConnectionId
                        NULL,   //Notification Call Back Handler
                        NULL, //Context Data (Thread Identifier)
                        &pSessionData->m_Inner.m_eapSessionId,// Session Id
                        &pEapError)) != NO_ERROR)
                    {
                        if (pEapError)
                            EapHostPeerFreeEapError(pEapError);
                    }

                    if (dwReturnCode != NO_ERROR) {
                        //
                        // Something went wrong, de-initialize EapHost
                        //
                        EapHostPeerUninitialize();
                    }
                }

                if (dwReturnCode != NO_ERROR)
                    AL::Heap::Free((LPVOID*)&(pSessionData->m_Inner.pEapPeerData));
            } else
                dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
#endif // AL_EAPHOST
        }

        if (dwReturnCode == NO_ERROR)
            *ppWorkBuffer = pSessionData;
        else
            delete pSessionData;
    } else
        AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_OUTOFMEMORY, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for session data."), NULL);

    return dwReturnCode;
}


//
// Authentication has finished (either successful or not), End authentication session (Cleanup)
//
DWORD AL::EAP::EndSession(_In_ LPVOID pWorkBuffer, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    // Sanity check
    if (pWorkBuffer == NULL) {
        AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pWorkBuffer is NULL."), NULL);
    } else {
        AL::TLS::CSessionData *pSessionData = (AL::TLS::CSessionData*)pWorkBuffer;

        AL_TRACE_INFO(_T("Cleaning session data..."));
        delete pSessionData;
    }

    return dwReturnCode;
}


#ifdef AL_GENERIC_CREDENTIAL_UI

DWORD AL::EAP::SetCredentials(_Inout_ LPVOID pWorkBuffer, _In_z_ LPCWSTR pszIdentity, _In_z_ LPCWSTR pszPassword, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    // Sanity check
    if (!pWorkBuffer) {
        AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pWorkBuffer is NULL."), NULL);
    } else {
        AL::TLS::CSessionData *pSessionData = (AL::TLS::CSessionData*)pWorkBuffer;

        pSessionData->m_user.m_sIdentity = pszIdentity;
        pSessionData->m_user.m_sPassword = pszPassword;
    }

    return dwReturnCode;
}

#endif


//
// Process an EAP packet
//
DWORD AL::EAP::Process(_Inout_ LPVOID pWorkBuffer, _In_ EapPacket *pReceivePacket, _Out_ CPacket &pktSend, _Out_ EapPeerMethodOutput* pEapPeerMethodOutput, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    // Sanity check
    if (pWorkBuffer == NULL) {
        AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pWorkBuffer is NULL."), NULL);
    } else {
        AL::TLS::CSessionData *pSessionData = (AL::TLS::CSessionData*)pWorkBuffer;
        AL_TRACE_INFO(_T("Method version: %d"), (int)pSessionData->m_bCurrentMethodVersion);

        //
        // Always allow notifications.
        //
        pEapPeerMethodOutput->fAllowNotifications = TRUE;

        //
        // Copy the packet ID for later use
        //
        if (pReceivePacket) {
            AL_TRACE_DEBUG(_T("Received packet (ID: %d, length: %d)."), (int)pReceivePacket->Id, (int)AL::Convert::N2H16(pReceivePacket->Length));
            AL_DUMP_DEBUG((LPBYTE)pReceivePacket, AL::Convert::N2H16(pReceivePacket->Length));

            pSessionData->m_bPacketId = pReceivePacket->Id;

            //
            // Check for unexpected start packet during communication.
            //
            if (pSessionData->m_TLSSession.m_TLSState != AL::TLS::STATE_START && AL::Convert::N2H16(pReceivePacket->Length) == 5 && pReceivePacket->Data[1] & AL_TLS_REQUEST_START) {
                AL_TRACE_WARNING(_T("Received unexpected EAPTTLS_REQUEST_START packet."));

                //
                // Reset TLS session data.
                //
                pSessionData->m_TLSSession.Reset();
            }
        }

        AL_TRACE_INFO(_T("TLS state: %d"), pSessionData->m_TLSSession.m_TLSState);
        switch (pSessionData->m_TLSSession.m_TLSState) {
            case AL::TLS::STATE_START:
                if (pReceivePacket) {
                    switch (pReceivePacket->Code) {
                        case EAPCODE_Request:
                            AL_TRACE_INFO(_T("STATE_START::Request Packet->"));
                            if (pReceivePacket->Data[1] & AL_TLS_REQUEST_START) {
                                pSessionData->m_pMonitor->SendMsg(L"info", ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSG_OUTER_AUTH), NULL);
                                pSessionData->m_bCurrentMethodVersion = pReceivePacket->Data[1] & AL_EAP_METHOD_VERSION;
                                AL_TRACE_INFO(_T("Using method version %d."), (int)pSessionData->m_bCurrentMethodVersion);
                                if ((dwReturnCode = AL::TTLS::BuildResponsePacket(&(pSessionData->m_TLSSession), pSessionData->m_bPacketId, pktSend, pEapPeerMethodOutput, AL::EAP::g_bType, pSessionData->m_bCurrentMethodVersion)) != NO_ERROR)
                                    AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_PACKET_RESPONSE_BUILD, pSessionData->m_TLSSession.m_TLSState, dwReturnCode), NULL);
                            } else
                                AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_PPP_INVALID_PACKET, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_PACKET_REQUEST_UNEXPECTED, (int)pReceivePacket->Data[1]), NULL);
                            break;

                        default:
                            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_PPP_INVALID_PACKET, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_PACKET_UNEXPECTED, pSessionData->m_TLSSession.m_TLSState, (int)pReceivePacket->Code), NULL);
                    }
                } else
                    AL_TRACE_WARNING(_T("STATE_START::pReceivePacket is NULL."));
                break;

            case AL::TLS::STATE_SERVER_HELLO:
                if (pReceivePacket) {
                    switch (pReceivePacket->Code) {
                        case EAPCODE_Request:
                            AL_TRACE_INFO(_T("STATE_SERVER_HELLO::Request Packet->"));

                            //
                            // This function will read all the information in the fragged messages
                            //
                            if ((dwReturnCode = AL::TTLS::ReadMessage(&(pSessionData->m_TLSSession), pSessionData->m_bPacketId, pReceivePacket, pktSend, pEapPeerMethodOutput, &pSessionData->m_bNewMethodVersion, AL::Convert::N2H16(&(pReceivePacket->Length[0])), AL::EAP::g_bType, pSessionData->m_bCurrentMethodVersion)) != NO_ERROR) {
                                pSessionData->m_TLSSession.ResetReceiveMsg();
                                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_MESSAGE_READ, (int)pReceivePacket->Code, dwReturnCode), NULL);
                            } else if (pSessionData->m_bNewMethodVersion != pSessionData->m_bCurrentMethodVersion) {
                                AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_PPP_INVALID_PACKET, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_SRV_UNEXCPECTED_VERSION, (int)pReceivePacket->Code, (int)pSessionData->m_bNewMethodVersion, (int)pSessionData->m_bCurrentMethodVersion), NULL);
                            } else if (pEapPeerMethodOutput->action != EapPeerMethodResponseActionSend) {
                                if ((dwReturnCode = AL::TLS::ParseServerPacket(pSessionData)) == NO_ERROR) {
                                    if (pSessionData->m_TLSSession.m_fServerFinished && pSessionData->m_TLSSession.m_fCipherSpec && pSessionData->m_cfg.m_fUseSessionResumption) {
                                        //
                                        // Found a change cipher spec and a finished message which means we are allowed to resume a session
                                        // if we want to resume as well then everything is ok else fail...
                                        //
                                        //
                                        // Set appropiate state
                                        //
                                        AL_TRACE_INFO(_T("Resuming session..."));
                                        pSessionData->m_TLSSession.m_TLSState = AL::TLS::STATE_RESUME_SESSION;
                                        if ((dwReturnCode = AL::TTLS::BuildResponsePacket(&(pSessionData->m_TLSSession), pSessionData->m_bPacketId, pktSend, pEapPeerMethodOutput, AL::EAP::g_bType, pSessionData->m_bCurrentMethodVersion)) != NO_ERROR)
                                            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_PACKET_RESPONSE_BUILD, pSessionData->m_TLSSession.m_TLSState, dwReturnCode), NULL);
                                    } else {
                                        //
                                        // Continue with TLS handshake.
                                        //
                                        //
                                        // Check if we have a certificate.
                                        //
                                        AL_TRACE_INFO(_T("TLS handshake..."));
                                        if (!pSessionData->m_TLSSession.m_lCertificateChain.IsEmpty()) {
                                            const ATL::Crypt::CCertContext &cc = pSessionData->m_TLSSession.m_lCertificateChain.GetHead();

                                            //
                                            // If required check server namespace.
                                            //
                                            if (dwReturnCode == NO_ERROR && !pSessionData->m_cfg.m_sServerName.IsEmpty()) {
                                                if ((dwReturnCode = AL::TLS::Cert::VerifyServerName(&(pSessionData->m_cfg), cc)) == NO_ERROR) {
                                                    ATL::CAtlStringW sSubjectName;
                                                    CertGetNameString(cc, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, sSubjectName);
                                                    pSessionData->m_pMonitor->SendMsg(L"success", ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSG_SERVER_NAME, (LPCWSTR)sSubjectName), NULL);
                                                } else if (dwReturnCode == ERROR_INVALID_DOMAINNAME) {
                                                    ATL::CAtlStringA sSubjectName;
                                                    CertGetNameStringA(cc, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, sSubjectName);
                                                    AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_SERVER_NAME_INACCEPTABLE), ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_SERVER_NAME_INACCEPTABLE_DESC, (LPCSTR)sSubjectName, (LPCTSTR)pSessionData->m_cfg.m_sProviderID));
                                                } else if (dwReturnCode != NO_ERROR)
                                                    AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_SERVER_NAME, dwReturnCode), NULL);
                                            }

                                            //
                                            // If required verify chain.
                                            //
                                            if (dwReturnCode == NO_ERROR) {
                                                BOOL bUntrustedCert = FALSE;
#ifdef _DEBUG
                                                //Sleep(10000);
#endif

                                                if ((dwReturnCode = AL::TLS::Cert::VerifyChain(&(pSessionData->m_cfg.m_lTrustedRootCAs), &(pSessionData->m_TLSSession.m_lCertificateChain), pSessionData->m_TLSSession.m_lCertificateChain.GetHeadPosition())) == NO_ERROR) {
                                                    pSessionData->m_pMonitor->SendMsg(L"success", ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSG_CA_TRUSTED), NULL);
                                                } else if (dwReturnCode == (DWORD)CERT_E_UNTRUSTEDROOT) {
                                                    ATL::CAtlStringA sSubjectName;
                                                    CertGetNameStringA(cc, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, sSubjectName);
                                                    AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_SERVER_CERT_UNTRUSTED), ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_SERVER_CERT_UNTRUSTED_DESC, (LPCSTR)sSubjectName));
                                                    bUntrustedCert = TRUE;
                                                } else if (dwReturnCode == ERROR_FILE_NOT_FOUND) {
                                                    ATL::CAtlStringA sSubjectName;
                                                    CertGetNameStringA(cc, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, sSubjectName);
                                                    AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_SERVER_CERT_INACCEPTABLE), ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_SERVER_CERT_INACCEPTABLE_DESC, (LPCSTR)sSubjectName, (LPCTSTR)pSessionData->m_cfg.m_sProviderID));
                                                    bUntrustedCert = TRUE;
                                                } else
                                                    AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_SERVER_CERT_CHAIN, dwReturnCode), NULL);

                                                //
                                                // Only show dialog if EAP supports custom UI.
                                                //
                                                if (dwReturnCode != NO_ERROR && bUntrustedCert
#ifdef AL_WIN10_DISABLE_INTERACTIONS
                                                    && AL::System::g_uliVerEap3Host.HighPart < 0x000a0000
#endif
                                                    )
                                                {
                                                    //
                                                    // Report error to monitor anyway, before cleaning it.
                                                    //
                                                    pSessionData->m_pMonitor->SendMsg(L"error", (*ppEapError)->pRootCauseString, (*ppEapError)->pRepairString);
                                                    AL::EAP::FreeError(ppEapError);
                                                    dwReturnCode = NO_ERROR;

                                                    //
                                                    // Could not validate chain => show dialog to allow user to install missing certificates.
                                                    //
                                                    pEapPeerMethodOutput->action          = EapPeerMethodResponseActionInvokeUI;
                                                    pSessionData->m_TLSSession.m_TLSState = AL::TLS::STATE_VERIFY_CERT_UI;
                                                    if ((dwReturnCode = pSessionData->m_blobDataForInteractiveUI.Create(
                                                            sizeof(BYTE) +
                                                            MemGetPackedSize(pSessionData->m_TLSSession.m_lCertificateChain) +
                                                            MemGetPackedSize(pSessionData->m_cfg.m_lTrustedRootCAs))) == NO_ERROR)
                                                    {
                                                        LPBYTE pbCursor = (LPBYTE)pSessionData->m_blobDataForInteractiveUI.GetData();
                                                        MemPack(&pbCursor, (BYTE)AL::TLS::UITYPE_VERIFY_CERT);
                                                        MemPack(&pbCursor, pSessionData->m_TLSSession.m_lCertificateChain);
                                                        MemPack(&pbCursor, pSessionData->m_cfg.m_lTrustedRootCAs);
                                                    } else
                                                        AL_TRACE_ERROR(_T("Error allocating memory for interactive UI data BLOB."), dwReturnCode = ERROR_OUTOFMEMORY);
                                                }
                                            }

                                            //
                                            // If did not encounter an error and we do not need to show the InteractiveUI
                                            // then continue with next response
                                            //
                                            if (dwReturnCode == NO_ERROR && pEapPeerMethodOutput->action != EapPeerMethodResponseActionInvokeUI) {
                                                if ((dwReturnCode = AL::TTLS::BuildResponsePacket(&(pSessionData->m_TLSSession), pSessionData->m_bPacketId, pktSend, pEapPeerMethodOutput, AL::EAP::g_bType, pSessionData->m_bCurrentMethodVersion)) != NO_ERROR)
                                                    AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_PACKET_RESPONSE_BUILD, pSessionData->m_TLSSession.m_TLSState, dwReturnCode), NULL);
                                            }
                                        } else {
                                            //
                                            // Could not find a certificate, fail
                                            //
                                            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_AUTH_INTERNAL, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_SERVER_CERT_MISSING), NULL);
                                        }
                                    }
                                } else
                                    AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_PACKET_INVALID, dwReturnCode), NULL);

                                pSessionData->m_TLSSession.ResetReceiveMsg();
                            }
                            break;

                        default:
                            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_PPP_INVALID_PACKET, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_PACKET_UNEXPECTED, pSessionData->m_TLSSession.m_TLSState, (int)pReceivePacket->Code), NULL);
                    }
                } else
                    AL_TRACE_WARNING(_T("STATE_SERVER_HELLO pReceivePacket is NULL."));
                break;

            case AL::TLS::STATE_VERIFY_CERT_UI:
#ifdef _DEBUG
                //Sleep(10000);
#endif
                if (!pSessionData->m_aDataFromInteractiveUI.IsEmpty()) {
                    LPCBYTE pReturnData = pSessionData->m_aDataFromInteractiveUI.GetData();
                    MemUnpack(&pReturnData, dwReturnCode);
                    if (dwReturnCode == NO_ERROR) {
                        //
                        // Everything is OK, re-read profile configuration
                        //
                        AL_TRACE_INFO(_T("User confirmed server certificate as trusted. Resuming..."));
                        MemUnpack(&pReturnData, pSessionData->m_cfg.m_lTrustedRootCAs);
                        pSessionData->m_fSaveConfigData = TRUE;

                        pSessionData->m_pMonitor->SendMsg(L"success", ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSG_CERTIFICATE_CONFIRMED), NULL);
                        if ((dwReturnCode = AL::TTLS::BuildResponsePacket(&(pSessionData->m_TLSSession), pSessionData->m_bPacketId, pktSend, pEapPeerMethodOutput, AL::EAP::g_bType, pSessionData->m_bCurrentMethodVersion)) != NO_ERROR)
                            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_PACKET_RESPONSE_BUILD, pSessionData->m_TLSSession.m_TLSState, dwReturnCode), NULL);
                    } else {
                        AL_TRACE_ERROR(_T("User declined server certificate."));
                        dwReturnCode = ERROR_CANCELLED;
                    }
                } else {
                    AL_TRACE_INFO(_T("User has not exited from dialog yet."));
                    dwReturnCode = PENDING;
                }
                break;

            case AL::TLS::STATE_CHANGE_CIPHER_SPEC:
                if (pReceivePacket) {
                    switch (pReceivePacket->Code) {
                        case EAPCODE_Request:
                            AL_TRACE_INFO(_T("STATE_CHANGE_CIPHER_SPEC::Request Packet->"));

                            //
                            // This function will read all the information in the fragged messages
                            //
                            if ((dwReturnCode = AL::TTLS::ReadMessage(&(pSessionData->m_TLSSession), pSessionData->m_bPacketId, pReceivePacket, pktSend, pEapPeerMethodOutput, &pSessionData->m_bNewMethodVersion, AL::Convert::N2H16(&(pReceivePacket->Length[0])), AL::EAP::g_bType, pSessionData->m_bCurrentMethodVersion)) != NO_ERROR) {
                                pSessionData->m_TLSSession.ResetReceiveMsg();
                                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_MESSAGE_READ, (int)pReceivePacket->Code, dwReturnCode), NULL);
                            } else if (pSessionData->m_bNewMethodVersion != pSessionData->m_bCurrentMethodVersion) {
                                AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_PPP_INVALID_PACKET, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_SRV_UNEXCPECTED_VERSION, (int)pReceivePacket->Code, (int)pSessionData->m_bNewMethodVersion, (int)pSessionData->m_bCurrentMethodVersion), NULL);
                            } else if (pEapPeerMethodOutput->action != EapPeerMethodResponseActionSend) {
                                if ((dwReturnCode = AL::TLS::ParseServerPacket(pSessionData)) == NO_ERROR) {
                                    if (pSessionData->m_TLSSession.m_fCipherSpec && pSessionData->m_TLSSession.m_fServerFinished) {
                                        //
                                        // This means the tunnel was setup successfuly
                                        // start inner authentication
                                        //
                                        if ((dwReturnCode = pktSend.CreateResponse(pSessionData->m_bPacketId, AL::EAP::g_bType, pSessionData->m_bCurrentMethodVersion)) == NO_ERROR) {
                                            AL_TRACE_INFO(_T("Performing inner authentication..."));
                                            if ((dwReturnCode = AL::TLS::AuthHandleInnerAuthentication(pSessionData, pktSend, pEapPeerMethodOutput)) != NO_ERROR)
                                                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_HANDLE_INNER_AUTH, dwReturnCode), NULL);
                                        } else
                                            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_PACKET_RESPONSE_INIT, dwReturnCode), NULL);
                                    } else
                                        AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_PPP_INVALID_PACKET, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_PACKET_NO_CHIPHER, pSessionData->m_TLSSession.m_TLSState, (int)pReceivePacket->Code), NULL);
                                } else
                                    AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_PACKET_INVALID, dwReturnCode), NULL);

                                pSessionData->m_TLSSession.ResetReceiveMsg();
                            }
                            break;

                        default:
                            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_PPP_INVALID_PACKET, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_PACKET_UNEXPECTED, pSessionData->m_TLSSession.m_TLSState, (int)pReceivePacket->Code), NULL);
                    }
                } else
                    AL_TRACE_WARNING(_T("STATE_CHANGE_CIPHER_SPEC pReceivePacket is NULL."));
                break;

            case AL::TLS::STATE_RESUME_SESSION_ACK:
                //
                // If we are ready for session resumption then allow inner EAP to handle the data else
                // continue as normal
                //
                if (pReceivePacket) {
                    switch (pReceivePacket->Code) {
                        case EAPCODE_Request:
                            AL_TRACE_INFO(_T("STATE_RESUME_SESSION_ACK::Request Packet->"));
                            if (pSessionData->m_cfg.m_fUseSessionResumption && pSessionData->m_TLSSession.m_fCipherSpec && pSessionData->m_TLSSession.m_fServerFinished && pSessionData->m_TLSSession.m_fSentFinished) {
                                //
                                // This will allow PEAP to handle EAP extensions
                                //
                                pSessionData->m_Inner.m_EapState = AL::EAP::INNERSTATE_MakeMessage;
                            } else
                                AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_PPP_INVALID_PACKET, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_PACKET_NO_CHIPHER, pSessionData->m_TLSSession.m_TLSState, (int)pReceivePacket->Code), NULL);
                    }
                }

                // REVISE: No break here? Is that on purpose? Checked SecureW2 code and there's no break there either.

            case AL::TLS::STATE_INNER_AUTHENTICATION:
                if (pReceivePacket) {
                    switch (pReceivePacket->Code) {
                        case EAPCODE_Request: AL_TRACE_INFO   (_T("STATE_INNER_AUTHENTICATION::Request Packet->")); break;
                        case EAPCODE_Success: AL_TRACE_INFO   (_T("STATE_INNER_AUTHENTICATION::Success Packet->")); break;
                        case EAPCODE_Failure: AL_TRACE_WARNING(_T("STATE_INNER_AUTHENTICATION::Failure Packet->")); break;
                    }
                    switch (pReceivePacket->Code) {
                        case EAPCODE_Request:
                        case EAPCODE_Success:
                        case EAPCODE_Failure:
                            //
                            // This function will read all the information in the fragged messages
                            //
                            if ((dwReturnCode = AL::TTLS::ReadMessage(&(pSessionData->m_TLSSession), pSessionData->m_bPacketId, pReceivePacket, pktSend, pEapPeerMethodOutput, &pSessionData->m_bNewMethodVersion, AL::Convert::N2H16(&(pReceivePacket->Length[0])), AL::EAP::g_bType, pSessionData->m_bCurrentMethodVersion)) != NO_ERROR) {
                                pSessionData->m_TLSSession.ResetReceiveMsg();
                                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_MESSAGE_READ, (int)pReceivePacket->Code, dwReturnCode), NULL);
                            } else if (pSessionData->m_bNewMethodVersion != pSessionData->m_bCurrentMethodVersion) {
                                AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_PPP_INVALID_PACKET, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_SRV_UNEXCPECTED_VERSION, (int)pReceivePacket->Code, (int)pSessionData->m_bNewMethodVersion, (int)pSessionData->m_bCurrentMethodVersion), NULL);
                            } else if (pEapPeerMethodOutput->action != EapPeerMethodResponseActionSend) {
                                if ((dwReturnCode = AL::TLS::ParseServerPacket(pSessionData)) == NO_ERROR) {
                                    if ((dwReturnCode = pktSend.CreateResponse(pSessionData->m_bPacketId, AL::EAP::g_bType, pSessionData->m_bCurrentMethodVersion)) == NO_ERROR) {
                                        AL_TRACE_INFO(_T("Performing inner authentication..."));
                                        if ((dwReturnCode = AL::TLS::AuthHandleInnerAuthentication(pSessionData, pktSend, pEapPeerMethodOutput)) != NO_ERROR)
                                            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_HANDLE_INNER_AUTH, dwReturnCode), NULL);
                                    } else
                                        AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_PACKET_RESPONSE_INIT, dwReturnCode), NULL);
                                } else
                                    AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_PACKET_INVALID, dwReturnCode), NULL);

                                pSessionData->m_TLSSession.ResetReceiveMsg();
                            }
                            break;

                        default:
                            AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_PPP_INVALID_PACKET, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_PACKET_UNEXPECTED, pSessionData->m_TLSSession.m_TLSState, (int)pReceivePacket->Code), NULL);
                    }
                } else {
                    //
                    // Could be that the user interface was invoked.
                    //
                    if ((dwReturnCode = pktSend.CreateResponse(pSessionData->m_bPacketId, AL::EAP::g_bType, pSessionData->m_bCurrentMethodVersion)) == NO_ERROR) {
                        AL_TRACE_INFO(_T("Performing inner authentication..."));
                        if ((dwReturnCode = AL::TLS::AuthHandleInnerAuthentication(pSessionData, pktSend, pEapPeerMethodOutput)) != NO_ERROR)
                            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_HANDLE_INNER_AUTH, dwReturnCode), NULL);

                        pSessionData->m_TLSSession.ResetReceiveMsg();
                    } else
                        AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_PACKET_RESPONSE_INIT, dwReturnCode), NULL);
                }
                break;

            case AL::TLS::STATE_FINISHED:
                AL_TRACE_INFO(_T("STATE_FINISHED."));
                pEapPeerMethodOutput->action = EapPeerMethodResponseActionNone;
                dwReturnCode = NO_ERROR;
                break;

            default:
                AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_UNKNOWN, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_TLS_UNKNOWN_STATE, pSessionData->m_TLSSession.m_TLSState), NULL);
        }

        AL_TRACE_DEBUG(_T("Sending packet (ID: %d, length: %dB)..."), (int)pktSend->Id, (int)pktSend.GetSize());
        AL_DUMP_DEBUG((LPCBYTE)(const EapPacket*)pktSend, pktSend.GetSize());
    }

    return dwReturnCode;
}


//
// Return the authentication result. In this function the user data and/or
// configuration data is also returned to the upper layer to be stored
//
DWORD AL::EAP::GetResult(_Inout_ LPVOID pWorkBuffer, _In_ EapPeerMethodResultReason eapReason, _Inout_ EapPeerMethodResult *pEapPeerMethodResult, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL::TLS::CSessionData *pSessionData = (AL::TLS::CSessionData*)pWorkBuffer;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // Initialize members of EapPeerMethodResult structure.
    // Do not use ZeroMemory() or memset, as this would loose pAttribArray pointer.
    //
    pEapPeerMethodResult->fIsSuccess                         = FALSE;
    pEapPeerMethodResult->dwFailureReasonCode                = NO_ERROR;
    pEapPeerMethodResult->fSaveUserData                      = FALSE;
    pEapPeerMethodResult->pUserData                          = NULL;
    pEapPeerMethodResult->dwSizeofUserData                   = 0;
    pEapPeerMethodResult->fSaveConnectionData                = FALSE;
    pEapPeerMethodResult->pConnectionData                    = NULL;
    pEapPeerMethodResult->dwSizeofConnectionData             = 0;
    pEapPeerMethodResult->pAttribArray->pAttribs             = NULL;
    pEapPeerMethodResult->pAttribArray->dwNumberOfAttributes = 0;
    pEapPeerMethodResult->pEapError                          = NULL;

    //
    // Update the authentication state
    //
    pSessionData->m_user.m_EapReasonLast = eapReason;

    //
    // When using inner EAP inform the inner method of the result (except if this is a session resume or the access/reject was already handled)
    //
    if ((AL::EAP::g_bType == AL_EAP_TYPE_PEAP || pSessionData->m_cfg.m_InnerAuth == AL::TLS::INNERMETHOD_EAP) &&
        pSessionData->m_TLSSession.m_TLSState != AL::TLS::STATE_RESUME_SESSION_ACK &&
        !pSessionData->m_Inner.m_fHandledAccessReject)
    {
        //
        // For RASEAP construct a EAP Success or Failure packet
        //
        AL_TRACE_INFO(_T("Inner RASEAP..."));

        if ((dwReturnCode = pSessionData->m_TLSSession.m_pktInnerEAPMsg.Create(eapReason == EapPeerMethodResultSuccess ? EapCodeSuccess : EapCodeFailure, pSessionData->m_bPacketId + 1, 4)) == NO_ERROR) {
            AL::EAP::CPacket pktSend;
            EapPeerMethodOutput EapOutput;
            ZeroMemory(&EapOutput, sizeof(EapOutput));
            if ((dwReturnCode = AL::TLS::AuthHandleInnerAuthentication(pSessionData, pktSend, &EapOutput)) != NO_ERROR)
                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatW(_T(__FUNCTION__) _T(" Error handling inner authentication (%ld)."), dwReturnCode), NULL);
        } else
            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatW(_T(__FUNCTION__) _T(" Error initializing packet (%ld)."), dwReturnCode), NULL);
    } else {
        // TODO: For EapHost call GetResult on inner EAP method
    }

    if (dwReturnCode == NO_ERROR) {
        if (eapReason == EapPeerMethodResultSuccess) {
            AL_TRACE_INFO(_T("Authentication succeeded."));

            if (pSessionData->m_TLSSession.m_TLSState == AL::TLS::STATE_RESUME_SESSION_ACK || pSessionData->m_TLSSession.m_TLSState == AL::TLS::STATE_INNER_AUTHENTICATION) {
                pSessionData->m_pMonitor->SendMsg(L"success", ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSG_AUTH_SUCCEEDED), NULL);

                {
                    BYTE pbKeyMaterial[AL_TLS_RANDOM_SIZE*2];
                    if ((dwReturnCode = _GenerateKeyMaterial(pSessionData->m_TLSSession.m_hCSP, AL::EAP::g_bType, pSessionData->m_bCurrentMethodVersion, pSessionData->m_TLSSession.m_pbRandomClient, pSessionData->m_TLSSession.m_pbRandomServer, pSessionData->m_TLSSession.m_pbMS, pbKeyMaterial, sizeof(pbKeyMaterial))) == NO_ERROR) {
                        if ((dwReturnCode = _MakeMPPEKey(pbKeyMaterial, sizeof(pbKeyMaterial), &(pEapPeerMethodResult->pAttribArray->pAttribs))) == NO_ERROR) {
                            pEapPeerMethodResult->pAttribArray->dwNumberOfAttributes = 3;
                            pEapPeerMethodResult->fIsSuccess = TRUE;
                        } else
                            AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatW(_T(__FUNCTION__) _T(" Error making MPPE key (%ld)."), dwReturnCode), NULL);
                    } else
                        AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatW(_T(__FUNCTION__) _T(" Error generating key material (%ld)."), dwReturnCode), NULL);
                }

                if (pSessionData->m_cfg.m_fUseSessionResumption) {
                    //
                    // Save TLS session data for TLS session resumption.
                    //
                    AL_TRACE_INFO(_T("Saving TLS session..."));

                    pSessionData->m_user.m_aTLSSessionID.Copy(pSessionData->m_TLSSession.m_aTLSSessionID);
                    pSessionData->m_user.m_tTLSSessionID = pSessionData->m_TLSSession.m_tTLSSessionID;
                    memcpy_s(pSessionData->m_user.m_pbMS, sizeof(pSessionData->m_user.m_pbMS), pSessionData->m_TLSSession.m_pbMS, sizeof(pSessionData->m_TLSSession.m_pbMS));
                }

                if (pSessionData->m_user.m_fSaveCredentials) {
                    //
                    // User opted to remember credentials. Save credentials to configuration.
                    //
                    pSessionData->m_cfg.m_sIdentity = pSessionData->m_user.m_sIdentity;
                    pSessionData->m_cfg.m_sPassword = pSessionData->m_user.m_sPassword;
                    pSessionData->m_fSaveConfigData = TRUE;
                } else if (pSessionData->m_user.m_fPromptForCredentials) {
                    //
                    // User was prompted for credentials, and supplied valid credentials, but explicitly opted not to remember credentials. Blank the credentials in configuration.
                    //
                    pSessionData->m_cfg.m_sIdentity.Empty();
                    pSessionData->m_cfg.m_sPassword.Empty();
                    pSessionData->m_fSaveConfigData = TRUE;
                }

                //
                // Authentication was successful. No need to re-prompt for credentials.
                //
                pSessionData->m_user.m_fPromptForCredentials = FALSE;

                //
                // Allocate user data BLOB.
                //
                AL::EAP::CBlob blob;
                if ((dwReturnCode = blob.Create(MemGetPackedSize(pSessionData->m_user))) == NO_ERROR) {
                    //
                    // Save user data to BLOB.
                    //
                    LPBYTE pbCursor = (LPBYTE)blob.GetData();
                    MemPack(&pbCursor, pSessionData->m_user);
                    pEapPeerMethodResult->fSaveUserData    = TRUE;
                    pEapPeerMethodResult->dwSizeofUserData = (DWORD)blob.GetCookieSize();
                    AL_TRACE_INFO(_T("User data BLOB: %ldB (payload: %ldB)."), pEapPeerMethodResult->dwSizeofUserData, blob.GetSize());
                    pEapPeerMethodResult->pUserData        = (LPBYTE)blob.Detach();

                    if (pSessionData->m_fSaveConfigData) {
                        //
                        // Allocate configuration BLOB.
                        //
                        if ((dwReturnCode = blob.Create(MemGetPackedSize(pSessionData->m_cfg))) == NO_ERROR) {
                            //
                            // Save configuration to BLOB.
                            //
                            LPBYTE pbCursor = (LPBYTE)blob.GetData();
                            MemPack(&pbCursor, pSessionData->m_cfg);
                            pEapPeerMethodResult->fSaveConnectionData    = TRUE;
                            pEapPeerMethodResult->dwSizeofConnectionData = (DWORD)blob.GetCookieSize();
                            AL_TRACE_INFO(_T("Configuration BLOB: %ldB (payload: %ldB)."), pEapPeerMethodResult->dwSizeofConnectionData, blob.GetSize());
                            pEapPeerMethodResult->pConnectionData        = (LPBYTE)blob.Detach();
                        } else
                            AL_TRACE_ERROR(_T("Error allocating memory for configuration BLOB."), dwReturnCode);
                    }
                } else
                    AL_TRACE_ERROR(_T("Error allocating memory for user data BLOB."), dwReturnCode);

                pSessionData->m_TLSSession.m_TLSState = AL::TLS::STATE_FINISHED;
            } else
                AL_TRACE_WARNING(_T("Invalid authentication state (%ld)."), pSessionData->m_TLSSession.m_TLSState);
        } else {
            AL_TRACE_WARNING(_T("Authentication failed."));
            AL_TRACE_DEBUG(_T("pSessionData->m_TLSSession.m_TLSState: %ld"), pSessionData->m_TLSSession.m_TLSState);

            //
            // If we failed after the TLS was setup (in the inner authentication).
            //
            if (pSessionData->m_TLSSession.m_TLSState == AL::TLS::STATE_INNER_AUTHENTICATION) {
                AL_TRACE_ERROR(_T("Inner authentication failed."));

                if (AL::EAP::g_bType == AL_EAP_TYPE_PEAP || pSessionData->m_cfg.m_InnerAuth == AL::TLS::INNERMETHOD_EAP) {
                    //
                    // Sanitize RASEAP data. It will be set again on EapPeerGetIdentity().
                    //
                    pSessionData->m_user.m_sIdentity.Empty();
                    pSessionData->m_user.m_aEAPUserData.RemoveAll();
                } else {
                    //
                    // Sanitize credentials. They will be set again on EapPeerGetIdentity() from user prompt.
                    //
                    pSessionData->m_user.m_sIdentity.Empty();
                    pSessionData->m_user.m_sPassword.Empty();
                }
                pSessionData->m_user.m_fPromptForCredentials = TRUE;

                //
                // Allocate user data BLOB.
                //
                AL::EAP::CBlob blob;
                if ((dwReturnCode = blob.Create(MemGetPackedSize(pSessionData->m_user))) == NO_ERROR) {
                    //
                    // Save user data to BLOB.
                    //
                    LPBYTE pbCursor = (LPBYTE)blob.GetData();
                    MemPack(&pbCursor, pSessionData->m_user);
                    pEapPeerMethodResult->fSaveUserData    = TRUE;
                    pEapPeerMethodResult->dwSizeofUserData = (DWORD)blob.GetCookieSize();
                    AL_TRACE_INFO(_T("User data BLOB: %ldB (payload: %ldB)."), pEapPeerMethodResult->dwSizeofUserData, blob.GetSize());
                    pEapPeerMethodResult->pUserData        = (LPBYTE)blob.Detach();
                } else
                    AL_TRACE_ERROR(_T("Error allocating memory for user data BLOB."), dwReturnCode);

                AL::EAP::RecordError(&(pEapPeerMethodResult->pEapError), pEapPeerMethodResult->dwFailureReasonCode = ERROR_AUTHENTICATION_FAILURE, 0, NULL, NULL, NULL, ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_AUTH_FAILED), ATL::CStrFormatMsgW(AL::System::g_hResource, IDS_AL_MSGERR_AUTH_FAILED_DESC, (LPCWSTR)pSessionData->m_user.m_sIdentity, (LPCTSTR)pSessionData->m_cfg.m_sProviderID));
            }
        }
    }

    return dwReturnCode;
}


//
// Before the Interactive UI is called, this function is called in which the
// context data for the Interactive UI is returned
//
DWORD AL::EAP::GetUIContext(_Inout_ LPVOID pWorkBuffer, _Out_ DWORD *pdwUIContextDataSize, _Out_bytecap_(*pdwUIContextDataSize) LPBYTE *ppbUIContextData, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    // Sanity check
    if (pWorkBuffer == NULL) {
        AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pWorkBuffer is NULL."), NULL);
    } else {
        AL::TLS::CSessionData *pSessionData = (AL::TLS::CSessionData*)pWorkBuffer;

        *pdwUIContextDataSize = (DWORD)pSessionData->m_blobDataForInteractiveUI.GetCookieSize();
        *ppbUIContextData     = (LPBYTE)pSessionData->m_blobDataForInteractiveUI.GetCookieData();
        AL_TRACE_INFO(_T("Interactive UI data BLOB: %ldB (payload: %ldB)."), *pdwUIContextDataSize, pSessionData->m_blobDataForInteractiveUI.GetSize());
    }

    return dwReturnCode;
}


//
// Show Interactive User interface (Baloon)
//
DWORD AL::EAP::InvokeInteractiveUI(_In_ HWND hWndParent, _In_ SIZE_T nUIContextDataSize, _In_bytecount_(nUIContextDataSize) LPCVOID pUIContextData, _Out_ AL::EAP::CBlob &blobDataFromInteractiveUI, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    // Sanity check
    if (pUIContextData == NULL) {
        AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pUIContextData is NULL."), NULL);
    } else {
        BYTE bInteractiveUIType;
        MemUnpack((const BYTE**)&pUIContextData, bInteractiveUIType);

        AL_TRACE_INFO(_T("UI type: %d"), bInteractiveUIType);
        switch (bInteractiveUIType) {
            case AL::TLS::UITYPE_VERIFY_CERT: {
                //
                // Read data from interactive UI BLOB.
                //
                ATL::CAtlList<ATL::Crypt::CCertContext> lCertificateChain;
                MemUnpack((const BYTE**)&pUIContextData, lCertificateChain);
                AL::TLS::CCertList lTrustedRootCAs;
                MemUnpack((const BYTE**)&pUIContextData, lTrustedRootCAs);

                //
                // Show server trust dialog.
                //
                LPVOID ppParameters[2] = { &lCertificateChain, &lTrustedRootCAs };
                if (DialogBoxParam(AL::System::g_hResource, MAKEINTRESOURCE(IDD_AL_UNTRUSTEDCERT), hWndParent, AL::TLS::DlgProc::ServerUntrusted, (LPARAM)ppParameters)) {
                    //
                    // User managed to install certificates.
                    //
                    if ((dwReturnCode = blobDataFromInteractiveUI.Create(sizeof(DWORD) + MemGetPackedSize(lTrustedRootCAs))) == NO_ERROR) {
                        LPBYTE pbCursor = (LPBYTE)blobDataFromInteractiveUI.GetData();
                        MemPack(&pbCursor, (DWORD)NO_ERROR);
                        MemPack(&pbCursor, lTrustedRootCAs);
                    } else
                        AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for UI data."), NULL);
                } else {
                    //
                    // User cancelled.
                    //
                    if ((dwReturnCode = blobDataFromInteractiveUI.Create(sizeof(DWORD))) == NO_ERROR) {
                        LPBYTE pbCursor = (LPBYTE)blobDataFromInteractiveUI.GetData();
                        MemPack(&pbCursor, (DWORD)ERROR_CANCELLED);
                    } else
                        AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for UI data."), NULL);
                }
                break;
            }

            case AL::TLS::UITYPE_INNER_EAP: {
                //
                // Read data from interactive UI BLOB.
                //
                ATL::CAtlArray<BYTE> aInteractiveUIData;
                MemUnpack((const BYTE**)&pUIContextData, aInteractiveUIData);

                AL::RASEAP::CPeerData eapcfg;
                if ((dwReturnCode = eapcfg.Load(AL_EAP_TYPE_MSCHAPV2)) == NO_ERROR) {
                    //
                    // Connect to EAP DLL.
                    //
                    AL::RASEAP::CPeerInteractiveUI eap;
                    if ((dwReturnCode = eap.Load(&eapcfg)) == NO_ERROR) {
                        LPBYTE pbInnerEapDataFromInteractiveUI = NULL;
                        DWORD dwInnerEapDataFromInteractiveUISize = 0;
                        if ((dwReturnCode = eap.RasEapInvokeInteractiveUI(eapcfg.m_dwType, hWndParent, aInteractiveUIData.GetData(), (DWORD)aInteractiveUIData.GetCount(), &pbInnerEapDataFromInteractiveUI, &dwInnerEapDataFromInteractiveUISize)) == NO_ERROR) {
                            //
                            // Interactive UI succeeded.
                            //
                            if ((dwReturnCode = blobDataFromInteractiveUI.Create(sizeof(DWORD) + sizeof(DWORD) + dwInnerEapDataFromInteractiveUISize)) == NO_ERROR) {
                                LPBYTE pbCursor = (LPBYTE)blobDataFromInteractiveUI.GetData();
                                MemPack(&pbCursor, (DWORD)NO_ERROR);
                                MemPack(&pbCursor, dwInnerEapDataFromInteractiveUISize);
                                memcpy(pbCursor, pbInnerEapDataFromInteractiveUI, dwInnerEapDataFromInteractiveUISize);
                            } else
                                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for UI data."), NULL);
                        } else {
                            //
                            // Interactive UI failed.
                            //
                            if ((dwReturnCode = blobDataFromInteractiveUI.Create(sizeof(DWORD))) == NO_ERROR) {
                                LPBYTE pbCursor = (LPBYTE)blobDataFromInteractiveUI.GetData();
                                MemPack(&pbCursor, dwReturnCode);
                            } else
                                AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error allocating memory for UI data."), NULL);
                        }
                        if (pbInnerEapDataFromInteractiveUI)
                            eap.RasEapFreeMemory(pbInnerEapDataFromInteractiveUI);
                    } else
                        AL::EAP::RecordError(ppEapError, dwReturnCode, 0, NULL, NULL, NULL, ATL::CStrFormatW(_T(__FUNCTION__) _T(" Creating inner peer failed (%ld)."), dwReturnCode), NULL);
                }
                break;
            }

#ifdef AL_EAPHOST
            case AL::TLS::UITYPE_INNER_EAPHOST: {
                EAP_ERROR *pEapError = NULL;
                /*
                if ((dwReturnCode = EapHostPeerInvokeInteractiveUI(hWndParent,
                    pSessionData->m_cbInnerUIContextData,
                    pSessionData->m_pbInnerUIContextData,
                    &dwInnerEapDataFromInteractiveUISize,
                    &pbInnerEapDataFromInteractiveUI,
                    &pEapError)) == NO_ERROR)
                {
                    !!if ((*ppDataFromInteractiveUI = (LPBYTE)malloc(dwInnerEapDataFromInteractiveUISize))) {
                        memcpy(*ppDataFromInteractiveUI,
                                pbInnerEapDataFromInteractiveUI,
                                dwInnerEapDataFromInteractiveUISize);

                        *lpdwSizeOfDataFromInteractiveUI = dwInnerEapDataFromInteractiveUISize;
                    } else {
                        dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
                    }
                } else {
                    if (pEapError)
                        EapHostPeerFreeEapError(pEapError);
                }
                */
                break;
            }
#endif

            default:
                AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_CANCELLED, 0, NULL, NULL, NULL, ATL::CStrFormatW(_T(__FUNCTION__) _T(" Unknown interactive UI type (0x%lx)."), bInteractiveUIType), NULL);
        }
    }

    return dwReturnCode;
}


//
// After the Interactive UI is called, this function is called in which the
// context data for the Interactive UI is provided
//
DWORD AL::EAP::SetUIContext(_Inout_ LPVOID pWorkBuffer, _In_ SIZE_T nUIContextDataSize, _In_bytecount_(nUIContextDataSize) LPCVOID pUIContextData, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    // Sanity check
    if (pWorkBuffer == NULL) {
        AL::EAP::RecordError(ppEapError, dwReturnCode = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pWorkBuffer is NULL."), NULL);
    } else {
        AL::TLS::CSessionData *pSessionData = (AL::TLS::CSessionData*)pWorkBuffer;

        if (pUIContextData && nUIContextDataSize) {
            if (pSessionData->m_aDataFromInteractiveUI.SetCount(nUIContextDataSize)) {
                memcpy(pSessionData->m_aDataFromInteractiveUI.GetData(), pUIContextData, nUIContextDataSize);
            } else
                AL_TRACE_ERROR(_T("Error allocating memory for UI context data BLOB."), dwReturnCode = ERROR_OUTOFMEMORY);
        } else {
            // NULL response
            pSessionData->m_aDataFromInteractiveUI.RemoveAll();
        }
    }

    return dwReturnCode;
}


static DWORD _GetEAP(_In_ DWORD dwFlags, _In_ const AL::TLS::CConfigData *pConfigData, _Inout_ AL::TLS::CUserData *pUserData, _Out_ BOOL *pfInvokeUI)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // First let's check in the registry if the inner EAP
    // handles the user credentials itself.
    //
    AL::RASEAP::CPeerData eapcfg;
    if ((dwReturnCode = eapcfg.Load(AL_EAP_TYPE_MSCHAPV2)) == NO_ERROR) {
        if (eapcfg.m_dwInvokeUsernameDlg == 1 && eapcfg.m_dwInvokePasswordDlg == 1) {
            //
            // EAP method does not support interaction. Use our own.
            //
            dwReturnCode = _GetPAP(dwFlags, pConfigData, pUserData, pfInvokeUI);
        } else {
            if (!pConfigData->m_sIdentity.IsEmpty() && !pConfigData->m_aEAPUserData.IsEmpty()) {
                pUserData->m_sIdentity = pConfigData->m_sIdentity;
                pUserData->m_aEAPUserData.Copy(pConfigData->m_aEAPUserData);
            }

            if (dwFlags & RAS_EAP_FLAG_MACHINE_AUTH) {
                //
                // This is per-machine authentication. Do not prompt for credentials. Ever!
                //
                *pfInvokeUI = FALSE;
                if (!pConfigData->m_sIdentity.IsEmpty() && !pConfigData->m_aEAPUserData.IsEmpty()) {
                    AL_TRACE_INFO(_T("Using configured credentials for computer authentication."));
                } else {
                    AL_TRACE_ERROR(_T("No credentials configured. Computer authentication not possible."));
                    dwReturnCode = ERROR_NO_SUCH_USER;
                }
            } else {
                //
                // This is per-user authentication.
                //
                if (pUserData->m_fPromptForCredentials) {
                    AL_TRACE_INFO(_T("User prompt for credentials requested explicitly..."));
                    *pfInvokeUI = TRUE;
                } else if (!pConfigData->m_sIdentity.IsEmpty() && !pConfigData->m_aEAPUserData.IsEmpty()) {
                    AL_TRACE_INFO(_T("Using configured credentials."));
                    *pfInvokeUI = FALSE;
                } else {
                    AL_TRACE_INFO(_T("No credentials configured. Requesting user interface..."));
                    *pfInvokeUI = TRUE;
                }
            }
        }
    }

    return dwReturnCode;
}


#ifdef AL_EAPHOST

static DWORD _GetEAPHOST(_In_ DWORD dwFlags, _In_ const AL::TLS::CConfigData *pConfigData, _Out_ AL::TLS::CUserData *pUserData, _Out_ BOOL *pfInvokeUI)
{
    dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    LPBYTE pbInnerEapUserDataOut = NULL;
    DWORD dwInnerEapUserDataOut = 0;
    WCHAR *pwcIdentity;
    DWORD dwReturnCode;

    pUserData->PrevAuthResult = PREV_AUTH_RESULT_pending;

    if ((dwReturnCode = EapHostPeerInitialize()) == NO_ERROR) {
        DWORD dwFlags = 0;
        EAP_METHOD_TYPE eapMethodType;
        HANDLE hTokenImpersonateUser = NULL;
        size_t threadId = 0;
        EAP_SESSIONID m_eapSessionId = 0;
        EAP_ERROR *pEapError = NULL;
        EapPacket *pEapSendPacket;
        DWORD dwSizeOfEapSendPacket;
        EapPacket eapReceivePacket;
        EapHostPeerResponseAction eapHostPeerResponseAction;
        PCHAR pcIdentity;

        eapMethodType.eapType.type = 6;
        eapMethodType.eapType.dwVendorId = 0;
        eapMethodType.eapType.dwVendorType = 0;
        eapMethodType.dwAuthorId = 311;

        if ((dwReturnCode = EapHostPeerBeginSession(
                        dwFlags, //Flags
                        eapMethodType, //EAP_METHOD_TYPE
                        NULL, //EapAttributes
                        hTokenImpersonateUser, //HANDLE
                        0, //Connection Data Size
                        NULL, //Connection Data
                        0, //User Data Size
                        NULL,   //User Data
                        1400, //Max Packet
                        NULL, //ConnectionId
                        NULL,   //Notification Call Back Handler
                        NULL, //Context Data (Thread Identifier)
                        &m_eapSessionId,    // Session Id
                        &pEapError)) == NO_ERROR)
        {
            AL_TRACE_INFO(_T("pInnerEapHostPeerBeginSession succeeded, m_eapSessionId: %ld"),
                m_eapSessionId);

            //
            // Fill the elments of the Identity Request Packet.
            //
            eapReceivePacket.Code = EapCodeRequest;
            eapReceivePacket.Id = 0;
            AL::Convert::H2N16(5, (LPBYTE) &(eapReceivePacket.Length));
            eapReceivePacket.Data[0] = 0x01; //Identity Request Type

            if ((dwReturnCode = EapHostPeerProcessReceivedPacket(
                m_eapSessionId, //Session Id
                5, //Length of the Packet
                (LPBYTE) &eapReceivePacket, //Packet
                &eapHostPeerResponseAction, //EapHostPeerResponseAction
                &pEapError
)) == NO_ERROR)
            {
                AL_TRACE_INFO(_T("EapHostPeerProcessReceivedPacket succeeded: %ld"),
                    eapHostPeerResponseAction);

                switch (eapHostPeerResponseAction) {
                    case EapHostPeerResponseSend:

                        dwSizeOfEapSendPacket = 0;

                        //
                        // Send identity packet to retrieve inner EAP identity
                        //
                        if ((dwReturnCode = EapHostPeerGetSendPacket(
                                        m_eapSessionId,
                                        &dwSizeOfEapSendPacket,
                                        (LPBYTE *) &pEapSendPacket,
                                        &pEapError)) == NO_ERROR)
                        {
                            AL_TRACE_INFO(_T("EapHostPeerGetSendPacket succeeded, sending packet(%ld):"), dwSizeOfEapSendPacket);
                            AL::Trace::Dump(Info,  (LPBYTE)pEapSendPacket, dwSizeOfEapSendPacket);

                            //
                            // Extract identity
                            //
                            !!if ((pcIdentity = (CHAR*) malloc(dwSizeOfEapSendPacket - 5 + 1))) {
                                //
                                // Copy to string
                                //
                                ZeroMemory(pcIdentity, dwSizeOfEapSendPacket - 5 + 1);

                                memcpy_s(pcIdentity, dwSizeOfEapSendPacket - 5 + 1, &pEapSendPacket->Data[1], dwSizeOfEapSendPacket - 5);

                                //
                                // Convert to wide char string
                                //
                                if ((pwcIdentity = (WCHAR*)malloc((dwSizeOfEapSendPacket - 5 + 1) * sizeof(WCHAR)))) {
                                    ZeroMemory(pwcIdentity, dwSizeOfEapSendPacket - 5 + 1);

                                    if (MultiByteToWideChar(CP_UTF8, 0, pcIdentity, -1, pwcIdentity, dwSizeOfEapSendPacket - 5 + 1) > 0) {
                                        AL_TRACE_INFO(_T("EapHostPeerGetSendPacket:: pwcIdentity: %s"), pwcIdentity);
                                    } else
                                        dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

                                    if (dwReturnCode != NO_ERROR)
                                        AL::Heap::Free((LPVOID*)&pwcIdentity);
                                } else
                                    dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

                                AL::Heap::Free((LPVOID*)&pcIdentity);
                            } else
                                dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
                        } else {
                            AL_TRACE_INFO(_T("EapHostPeerGetSendPacket failed: %ld"), dwReturnCode);

                            if (pEapError)
                                EapHostPeerFreeEapError(pEapError);
                        }

                        if (dwReturnCode == NO_ERROR) {
                            if (pwcIdentity) {
                                if (wcslen(pwcIdentity)) {
                                    //
                                    // Copy the inner Identity
                                    //
                                    if (wcslen(pwcIdentity) < _countof(pUserData->m_InnerEap.pwcIdentity)) {
                                        wcscpy_s(pUserData->m_InnerEap.pwcIdentity, _countof(pUserData->m_InnerEap.pwcIdentity), pwcIdentity);
                                        wcscpy_s(pUserData->pwcIdentity,            _countof(pUserData->pwcIdentity),            pwcIdentity);
                                    } else {
                                        AL_TRACE_INFO(_T("pwcInnerEapIdentityOut is too large"));
                                        dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
                                    }
                                }
                            } else {
                                dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
                            }
                        }

                    break;

                    default:

                        dwReturnCode = ERROR_NOT_SUPPORTED;

                    break;
                }
            } else {
                AL_TRACE_INFO(_T("EapHostPeerProcessReceivedPacket failed: %ld"), dwReturnCode);

                if (pEapError)
                    EapHostPeerFreeEapError(pEapError);
            }

            EapHostPeerEndSession(m_eapSessionId, &pEapError);
        } else {
            if (pEapError)
                EapHostPeerFreeEapError(pEapError);
        }

        EapHostPeerUninitialize();
    } else
        AL_TRACE_INFO(_T("pInnerEapHostPeerInitialize failed: %ld"), dwReturnCode);

    return dwReturnCode;
}

#endif // AL_EAPHOST


static DWORD _GetPAP(_In_ DWORD dwFlags, _In_ const AL::TLS::CConfigData *pConfigData, _Inout_ AL::TLS::CUserData *pUserData, _Out_ BOOL *pfInvokeUI)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    if (!pConfigData->m_sIdentity.IsEmpty() && !pConfigData->m_sPassword.IsEmpty()) {
        pUserData->m_sIdentity = pConfigData->m_sIdentity;
        pUserData->m_sPassword = pConfigData->m_sPassword;
    }

    if (dwFlags & RAS_EAP_FLAG_MACHINE_AUTH) {
        //
        // This is per-machine authentication. Do not prompt for credentials. Ever!
        //
        *pfInvokeUI = FALSE;
        if (!pConfigData->m_sIdentity.IsEmpty() && !pConfigData->m_sPassword.IsEmpty()) {
            AL_TRACE_INFO(_T("Using configured credentials for computer authentication."));
        } else {
            AL_TRACE_ERROR(_T("No credentials configured. Computer authentication not possible."));
            dwReturnCode = ERROR_NO_SUCH_USER;
        }
    } else {
        //
        // This is per-user authentication.
        //
        if (pUserData->m_fPromptForCredentials) {
            AL_TRACE_INFO(_T("User prompt for credentials requested explicitly..."));
            *pfInvokeUI = TRUE;
        } else if (!pConfigData->m_sIdentity.IsEmpty() && !pConfigData->m_sPassword.IsEmpty()) {
            AL_TRACE_INFO(_T("Using configured credentials."));
            *pfInvokeUI = FALSE;
        } else {
            AL_TRACE_INFO(_T("No credentials configured. Requesting user interface..."));
            *pfInvokeUI = TRUE;
        }
    }

    return dwReturnCode;
}


//
// Show Identity User interface (Baloon)
//
static DWORD _InvokeUserUIEAP(_In_ HWND hWndParent, _In_ DWORD dwFlags, _In_ const AL::TLS::CConfigData *pConfigData, _Inout_ AL::TLS::CUserData *pUserData)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // First let's check in the registry if the inner EAP
    // handles the user credentials itself.
    //
    AL::RASEAP::CPeerData eapcfg;
    if ((dwReturnCode = eapcfg.Load(AL_EAP_TYPE_MSCHAPV2)) == NO_ERROR) {
        if (eapcfg.m_dwInvokeUsernameDlg == 1 && eapcfg.m_dwInvokePasswordDlg == 1) {
            //
            // EAP method does not support interaction. Use our own.
            //
            dwReturnCode = _InvokeUserUIPAP(hWndParent, dwFlags, pConfigData, pUserData);
        } else {
            //
            // Copy any information we already have.
            //
            pUserData->m_aEAPUserData.Copy(pConfigData->m_aEAPUserData);

            //
            // Load EAP DLL.
            //
            AL::RASEAP::CPeerIdentity eap;
            if ((dwReturnCode = eap.Load(&eapcfg)) == NO_ERROR) {
                //
                // Show user credentials dialog.
                //
                LPBYTE pbInnerEapUserDataOut = NULL;
                DWORD dwInnerEapUserDataOutSize = 0;
                WCHAR *pwcInnerEapIdentityOut = NULL;
                if ((dwReturnCode = eap.RasEapGetIdentity(eapcfg.m_dwType, hWndParent, dwFlags, NULL, NULL, pConfigData->m_aEAPConnectionData.GetData(), (DWORD)pConfigData->m_aEAPConnectionData.GetCount(), pUserData->m_aEAPUserData.GetData(), (DWORD)pUserData->m_aEAPUserData.GetCount(), &pbInnerEapUserDataOut, &dwInnerEapUserDataOutSize, &pwcInnerEapIdentityOut)) == NO_ERROR) {
                    //
                    // Copy the inner user data if any and then free it.
                    //
                    if (pbInnerEapUserDataOut) {
                        if (pUserData->m_aEAPUserData.SetCount(dwInnerEapUserDataOutSize))
                            memcpy(pUserData->m_aEAPUserData.GetData(), pbInnerEapUserDataOut, dwInnerEapUserDataOutSize);
                    } else
                        pUserData->m_aEAPUserData.RemoveAll();

                    if (pwcInnerEapIdentityOut) {
                        pUserData->m_sIdentity = pwcInnerEapIdentityOut;
                        AL_TRACE_DEBUG(_T("pwcInnerIdentityOut: %ls"), pwcInnerEapIdentityOut);
                    }
                } else
                    AL_TRACE_ERROR(_T("RasEapGetIdentity failed (%ld)."), dwReturnCode);

                if (pbInnerEapUserDataOut)
                    eap.RasEapFreeMemory(pbInnerEapUserDataOut);
                if (pwcInnerEapIdentityOut)
                    eap.RasEapFreeMemory((LPBYTE)pwcInnerEapIdentityOut);
            } else
                dwReturnCode = GetLastError();
        }
    }

    return dwReturnCode;
}


//
// Show Identity User interface (Baloon)
//
static DWORD _InvokeUserUIPAP(_In_ HWND hWndParent, _In_ DWORD dwFlags, _In_ const AL::TLS::CConfigData *pConfigData, _Inout_ AL::TLS::CUserData *pUserData)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    //
    // Copy any information we already have.
    //
    pUserData->m_sIdentity = pConfigData->m_sIdentity;
    pUserData->m_sPassword = pConfigData->m_sPassword;

    //
    // Show user credentials dialog.
    //
    AL_TRACE_INFO(_T("Invoking credentials UI..."));
    LPVOID ppParameters[2] = { pUserData, (LPVOID)pConfigData };
    if (!DialogBoxParam(AL::System::g_hResource, MAKEINTRESOURCE(IDD_AL_CREDENTIALS), hWndParent, AL::TLS::DlgProc::Credentials, (LPARAM)ppParameters)) {
        AL_TRACE_WARNING(_T("User cancelled."));
        dwReturnCode = ERROR_CANCELLED;
    }

    return dwReturnCode;
}


//
// Handle outer identity according to configuration
//
static DWORD _HandleOuterIdentity(_In_ const AL::TLS::CConfigData *pConfigData, _In_ const AL::TLS::CUserData *pUserData, _Out_ AL::EAP::CBlobFlat &blobIdentity)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    SIZE_T nIdentityLen;
    LPCWSTR pwcIdentity;
    if (pConfigData->m_sOuterIdentity.IsEmpty()) {
        //
        // Outer identity will be the same as inner.
        //
        AL_TRACE_INFO(_T("Using same outer identity..."));
        nIdentityLen = pUserData->m_sIdentity.GetLength();
        pwcIdentity = pUserData->m_sIdentity;
    } else if (pConfigData->m_sOuterIdentity[0] == L'@' && pConfigData->m_sOuterIdentity[1] == 0) {
        //
        // Outer identity will be "@domain" or ""
        // conforms with RFC 4282 in which the username part of the identity is stripped completely.
        //
        AL_TRACE_INFO(_T("Using empty outer identity..."));

        //
        // Determine domain name from user ID.
        //
        if ((pwcIdentity = wcschr(pUserData->m_sIdentity, L'@')) != NULL) {
            nIdentityLen = (LPCWSTR)pUserData->m_sIdentity + pUserData->m_sIdentity.GetLength() - pwcIdentity;
        } else {
            pwcIdentity = NULL;
            nIdentityLen = 0;
        }
    } else {
        //
        // Outer identity will use alternate user ID.
        //
        AL_TRACE_INFO(_T("Using custom alternate outer identity..."));
        nIdentityLen = pConfigData->m_sOuterIdentity.GetLength();
        pwcIdentity = pConfigData->m_sOuterIdentity;
    }

    //
    // Allocate identity BLOB.
    //
    if ((dwReturnCode = blobIdentity.Create((nIdentityLen + 1)*sizeof(WCHAR))) == NO_ERROR) {
        //
        // Save identity to BLOB.
        //
        wmemcpy((wchar_t*)blobIdentity.GetData(), pwcIdentity, nIdentityLen); // No need to zero terminate, as AL::Heap::Alloc() in AL::EAP::CBlobFlat::Create() zeroed everything.
    }

    return dwReturnCode;
}


static DWORD _GenerateKeyMaterial(_In_ HCRYPTPROV hCSP, _In_ BYTE bEapType, _In_ DWORD bCurrentMethodVersion, _In_ LPCBYTE pbRandomClient, _In_ LPCBYTE pbRandomServer, _In_ LPCBYTE pbMS, _Out_ LPBYTE pbKeyMaterial, _In_ DWORD cbKeyMaterial)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    if (hCSP) {
        LPCBYTE pbLabel = NULL;
        DWORD dwLabelSize = 0;

        //
        // Define label according to TTLS version
        //
        if (bEapType == AL_EAP_TYPE_PEAP) {
            if (bCurrentMethodVersion == AL_EAP_PEAP_V0) {
                pbLabel     = (LPCBYTE)AL_EAP_KEYING_MATERIAL_LABEL_PEAP_V0;
                dwLabelSize = sizeof(AL_EAP_KEYING_MATERIAL_LABEL_PEAP_V0) - sizeof(CHAR);
            } else if (bCurrentMethodVersion == AL_EAP_PEAP_V1) {
                pbLabel     = (LPCBYTE)AL_EAP_KEYING_MATERIAL_LABEL_PEAP_V1;
                dwLabelSize = sizeof(AL_EAP_KEYING_MATERIAL_LABEL_PEAP_V1) - sizeof(CHAR);
            } else {
                AL_TRACE_ERROR(_T("Invalid method version."));
                dwReturnCode = ERROR_AUTH_INTERNAL;
            }
        } else if (bEapType == AL_EAP_TYPE_TTLS) {
            if (bCurrentMethodVersion == AL_EAP_TTLS_V0) {
                pbLabel     = (LPCBYTE)AL_EAP_KEYING_MATERIAL_LABEL_TTLS_V0;
                dwLabelSize = sizeof(AL_EAP_KEYING_MATERIAL_LABEL_TTLS_V0) - sizeof(CHAR);
            } else if (bCurrentMethodVersion == AL_EAP_TTLS_V1) {
                pbLabel     = (LPCBYTE)AL_EAP_KEYING_MATERIAL_LABEL_TTLS_V1;
                dwLabelSize = sizeof(AL_EAP_KEYING_MATERIAL_LABEL_TTLS_V1) - sizeof(CHAR);
            } else {
                AL_TRACE_ERROR(_T("Invalid method version."));
                dwReturnCode = ERROR_AUTH_INTERNAL;
            }
        } else {
            AL_TRACE_ERROR(_T("Invalid bEapType."));
            dwReturnCode = ERROR_AUTH_INTERNAL;
        }

        if (dwReturnCode == NO_ERROR) {
            BYTE pbClientServerRandom[AL_TLS_RANDOM_SIZE*2];

            ZeroMemory(pbClientServerRandom, sizeof(pbClientServerRandom));
            memcpy(pbClientServerRandom,                      pbRandomClient, AL_TLS_RANDOM_SIZE);
            memcpy(pbClientServerRandom + AL_TLS_RANDOM_SIZE, pbRandomServer, AL_TLS_RANDOM_SIZE);

            dwReturnCode = AL::TLS::PRF(hCSP, pbMS, AL_TLS_MS_SIZE, pbLabel, dwLabelSize, pbClientServerRandom, sizeof(pbClientServerRandom), pbKeyMaterial, cbKeyMaterial);
        }
    }

    return dwReturnCode;
}


//
// Creates the MPPE Keys needed for line encryption
//
static DWORD _MakeMPPEKey(_In_ LPCBYTE pbKeyMaterial, _In_ DWORD cbKeyMaterial, _Out_cap_c_(3) EAP_ATTRIBUTE **ppUserAttributes)
{
    DWORD dwReturnCode = NO_ERROR;
    AL_TRACEFN_DEBUG(dwReturnCode);

    LPBYTE pb;

    //
    // Copy the Read and Write keys into the radus attributes
    //
    //
    // Create the MPPE Struct:
    if ((dwReturnCode = AL::Heap::Alloc(sizeof(EAP_ATTRIBUTE) * 3, (LPVOID*)ppUserAttributes)) == NO_ERROR) {
        AL_TRACE_DEBUG(_T("Allocated %ldB for attributes."), sizeof(EAP_ATTRIBUTE) * 3);

        //
        //
        // Bytes needed:
        //      4: Vendor-Id
        //      1: Vendor-Type
        //      1: Vendor-Length
        //      2: Salt
        //      1: Key-Length
        //     32: Key
        //     15: Padding
        //     -----------------
        //     56: Total
        //


        //
        // Copy MS-MPPE-Send-Key
        //
        if ((dwReturnCode = AL::Heap::Alloc(56, (LPVOID*)&((*ppUserAttributes)[0].pValue))) == NO_ERROR) {
            pb = (LPBYTE)(*ppUserAttributes)[0].pValue;

            AL::Convert::H2N32(311, pb); // Vendor-Id
            pb[4] = 16; // Vendor-Type (MS-MPPE-Send-Key)
            pb[5] = 56 - 4; // Vendor-Length (all except Vendor-Id)
            // pByte[6-7] is the zero-filled salt field
            pb[8] = 32; // Key-Length

            memcpy(pb + 9, pbKeyMaterial, 32);

            // pByte[41-55] is the Padding (zero octets)

            (*ppUserAttributes)[0].eaType   = eatVendorSpecific;
            (*ppUserAttributes)[0].dwLength = 56;

            //
            // Copy MS-MPPE-Recv-Key
            //
            if ((dwReturnCode = AL::Heap::Alloc(56, (LPVOID*)&((*ppUserAttributes)[1].pValue))) == NO_ERROR) {
                pb = (LPBYTE)(*ppUserAttributes)[1].pValue;

                AL::Convert::H2N32(311, pb); // Vendor-Id
                pb[4] = 17;                  // Vendor-Type (MS-MPPE-Recv-Key)
                pb[5] = 56 - 4;              // Vendor-Length (all except Vendor-Id)
                // pByte[6-7] is the zero-filled salt field
                pb[8] = 32;                  // Key-Length

                memcpy(pb + 9, pbKeyMaterial+32, 32);

                // pByte[41-55] is the Padding (zero octets)

                (*ppUserAttributes)[1].dwLength = 56;
                (*ppUserAttributes)[1].eaType  = eatVendorSpecific;

                //
                // For Termination
                //
                (*ppUserAttributes)[2].eaType    = eatMinimum;
                (*ppUserAttributes)[2].dwLength = 0;
                (*ppUserAttributes)[2].pValue    = NULL;
            }

            if (dwReturnCode != NO_ERROR)
                AL::Heap::Free((LPVOID*)&(*ppUserAttributes)[0].pValue);
        }

        if (dwReturnCode != NO_ERROR)
            AL::Heap::Free((LPVOID*)ppUserAttributes);
    }

    return dwReturnCode;
}
