/*
    Copyright 1991-2015 Amebis

    This file is part of ArnesLink.

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


AL::TLS::CConfigData::CConfigData() :
    m_sProviderID(L"DEFAULT"),
    m_InnerAuth(AL::EAP::g_bType == AL_EAP_TYPE_PEAP ? INNERMETHOD_EAP : INNERMETHOD_PAP),
    m_sPassword(&AL::Heap::g_stringMgrParanoid),
    m_fUseSessionResumption(FALSE)
{
}


DWORD AL::TLS::CConfigData::Save(_Inout_ IXMLDOMDocument2 *pXMLConfigDoc) const
{
    DWORD dwReturnCode = NO_ERROR;
    HRESULT hr;

    pXMLConfigDoc->put_async(VARIANT_FALSE);
    pXMLConfigDoc->setProperty(CComBSTR(L"SelectionNamespaces"), CComVariant(L"xmlns:eap-metadata=\"urn:ietf:params:xml:ns:yang:ietf-eap-metadata\""));

    //
    // Load empty configuration.
    //
    VARIANT_BOOL isSuccess = VARIANT_FALSE;
    CComPtr<IXMLDOMNode> pXmlElIdentityProvider;
    if (SUCCEEDED((hr = pXMLConfigDoc->loadXML(L"<Config xmlns=\"http://www.microsoft.com/provisioning/EapHostConfig\"><EAPIdentityProviderList xmlns=\"urn:ietf:params:xml:ns:yang:ietf-eap-metadata\"><EAPIdentityProvider></EAPIdentityProvider></EAPIdentityProviderList></Config>", &isSuccess)))) {
        if (isSuccess) {
            //
            // Select <Config><EAPIdentityProviderList><EAPIdentityProvider> node.
            //
            if ((dwReturnCode = AL::XML::SelectNode(pXMLConfigDoc, CComBSTR(L"//eap-metadata:EAPIdentityProviderList/eap-metadata:EAPIdentityProvider"), &pXmlElIdentityProvider)) != NO_ERROR)
                AL_TRACE_ERROR(_T("Error calling AL::XML::SelectNode (%ld)."), dwReturnCode);
        } else {
            AL_TRACE_ERROR(_T("XMLDOMDocument2::loadXML returned success, however isSuccess is false. Too confused to continue."));
            dwReturnCode = ERROR_UNKNOWN;
        }
    } else {
        AL_TRACE_ERROR(_T("Identity provider not found."));
        dwReturnCode = HRESULT_CODE(hr);
    }

    //
    // Fill XML according to data provided in blob.
    //
    if (pXmlElIdentityProvider) {
        CComVariant varNodeTypeEl(NODE_ELEMENT);
        CComBSTR bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");

        AL_TRACE_INFO(_T("Using connection data provided (provider: %s)..."), (LPCTSTR)m_sProviderID);

        if (!m_sProviderID.IsEmpty()) {
            //
            // Write <ID>.
            //
            dwReturnCode = AL::XML::PutElementValue(pXMLConfigDoc, pXmlElIdentityProvider, CComBSTR(L"ID"), bstrNamespace, CComBSTR(m_sProviderID));
        }

        {
            //
            // Write <ProviderInfo>.
            //
            CComPtr<IXMLDOMNode> pXmlElProviderInfo;
            hr = pXMLConfigDoc->createNode(varNodeTypeEl, CComBSTR(L"ProviderInfo"), bstrNamespace, &pXmlElProviderInfo);

            if (!m_sAltCredentialLbl.IsEmpty()) {
                //
                // Write <CredentialPrompt>.
                //
                dwReturnCode = AL::XML::PutElementValue(pXMLConfigDoc, pXmlElProviderInfo, CComBSTR(L"CredentialPrompt"), bstrNamespace, CComBSTR(m_sAltCredentialLbl));
            }

            if (!m_sAltIdentityLbl.IsEmpty()) {
                //
                // Write <UserNameLabel>.
                //
                dwReturnCode = AL::XML::PutElementValue(pXMLConfigDoc, pXmlElProviderInfo, CComBSTR(L"UserNameLabel"), bstrNamespace, CComBSTR(m_sAltIdentityLbl));
            }

            if (!m_sAltPasswordLbl.IsEmpty()) {
                //
                // Write <PasswordLabel>.
                //
                dwReturnCode = AL::XML::PutElementValue(pXMLConfigDoc, pXmlElProviderInfo, CComBSTR(L"PasswordLabel"), bstrNamespace, CComBSTR(m_sAltPasswordLbl));
            }

            hr = pXmlElIdentityProvider->appendChild(pXmlElProviderInfo, NULL);
        }

        CComPtr<IXMLDOMNode> pXmlElAuthenticationMethod;
        {
            //
            // Write <AuthenticationMethods><AuthenticationMethod>
            //
            CComPtr<IXMLDOMNode> pXmlElAuthenticationMethods;
            hr = pXMLConfigDoc->createNode(varNodeTypeEl, CComBSTR(L"AuthenticationMethods"), bstrNamespace, &pXmlElAuthenticationMethods);
            hr = pXmlElIdentityProvider->appendChild(pXmlElAuthenticationMethods, NULL);
            hr = pXMLConfigDoc->createNode(varNodeTypeEl, CComBSTR(L"AuthenticationMethod"), bstrNamespace, &pXmlElAuthenticationMethod);
            hr = pXmlElAuthenticationMethods->appendChild(pXmlElAuthenticationMethod, NULL);
        }

        //
        // Write <EAPMethod>.
        //
        dwReturnCode = AL::XML::PutElementValue(pXMLConfigDoc, pXmlElAuthenticationMethod, CComBSTR(L"EAPMethod"), bstrNamespace, (DWORD)AL::EAP::g_bType);

        if (!m_sOuterIdentity.IsEmpty()) {
            //
            // Write <ClientSideCredential><AnonymousIdentity>.
            //
            CComPtr<IXMLDOMNode> pXmlElClientSideCredential;
            hr = pXMLConfigDoc->createNode(varNodeTypeEl, CComBSTR(L"ClientSideCredential"), bstrNamespace, &pXmlElClientSideCredential);
            dwReturnCode = AL::XML::PutElementValue(pXMLConfigDoc, pXmlElClientSideCredential, CComBSTR(L"AnonymousIdentity"), bstrNamespace, CComBSTR(m_sOuterIdentity));
            hr = pXmlElAuthenticationMethod->appendChild(pXmlElClientSideCredential, NULL);
        }

        {
            //
            // Write <ServerSideCredential>.
            //
            CComPtr<IXMLDOMNode> pXmlElServerSideCredential;
            hr = pXMLConfigDoc->createNode(varNodeTypeEl, CComBSTR(L"ServerSideCredential"), bstrNamespace, &pXmlElServerSideCredential);
            for (POSITION pos = m_lTrustedRootCAs.GetHeadPosition(); pos; m_lTrustedRootCAs.GetNext(pos)) {
                //
                // Write <CA>.
                //
                CComPtr<IXMLDOMNode> pXmlElCA;
                hr = pXMLConfigDoc->createNode(varNodeTypeEl, CComBSTR(L"CA"), bstrNamespace, &pXmlElCA);

                //
                // Write <format>.
                //
                dwReturnCode = AL::XML::PutElementValue(pXMLConfigDoc, pXmlElCA, CComBSTR(L"format"), bstrNamespace, L"PEM");

                //
                // Write <cert-data>.
                //
                const ATL::Crypt::CCertContext &cc = m_lTrustedRootCAs.GetAt(pos);
                dwReturnCode = AL::XML::PutElementBase64(pXMLConfigDoc, pXmlElCA, CComBSTR(L"cert-data"), bstrNamespace, cc->pbCertEncoded, cc->cbCertEncoded);

                hr = pXmlElServerSideCredential->appendChild(pXmlElCA, NULL);
            }

            {
                //
                // Write <ServerName>s.
                //
                static const CHAR pszSeperators[]= ";";
                int iLenZ = m_sServerName.GetLength() + 1;
                CHAR *pszServerName = new CHAR[iLenZ];
                memcpy(pszServerName, m_sServerName, iLenZ);
                for (LPSTR pszTokenNext = NULL, pszToken = strtok_s(pszServerName, pszSeperators, &pszTokenNext); pszToken; pszToken = strtok_s(NULL, pszSeperators, &pszTokenNext))
                    dwReturnCode = AL::XML::PutElementValue(pXMLConfigDoc, pXmlElServerSideCredential, CComBSTR(L"ServerName"), bstrNamespace, CComBSTR(pszToken));
                delete pszServerName;
            }

            hr = pXmlElAuthenticationMethod->appendChild(pXmlElServerSideCredential, NULL);
        }

        {
            //
            // Write <InnerAuthenticationMethod>.
            //
            CComPtr<IXMLDOMNode> pXmlElInnerAuthenticationMethod;
            hr = pXMLConfigDoc->createNode(varNodeTypeEl, CComBSTR(L"InnerAuthenticationMethod"), bstrNamespace, &pXmlElInnerAuthenticationMethod);

            if (m_InnerAuth == AL::TLS::INNERMETHOD_EAP) {
                //
                // Write <EAPMethod>.
                //
                dwReturnCode = AL::XML::PutElementValue(pXMLConfigDoc, pXmlElInnerAuthenticationMethod, CComBSTR(L"EAPMethod"), bstrNamespace, (DWORD)AL_EAP_TYPE_MSCHAPV2);
            } else {
                //
                // Write <NonEAPAuthMethod>.
                //
                dwReturnCode = AL::XML::PutElementValue(pXMLConfigDoc, pXmlElInnerAuthenticationMethod, CComBSTR(L"NonEAPAuthMethod"), bstrNamespace, L"PAP");
            }

            {
                //
                // Write <ClientSideCredential>.
                //
                CComPtr<IXMLDOMNode> pXmlElClientSideCredential;
                hr = pXMLConfigDoc->createNode(varNodeTypeEl, CComBSTR(L"ClientSideCredential"), bstrNamespace, &pXmlElClientSideCredential);

                if (!m_sIdentity.IsEmpty()) {
                    //
                    // Write <UserName>.
                    //
                    dwReturnCode = AL::XML::PutElementValue(pXMLConfigDoc, pXmlElClientSideCredential, CComBSTR(L"UserName"), bstrNamespace, CComBSTR(m_sIdentity));
                }

                if (AL::EAP::g_bType == AL_EAP_TYPE_PEAP || m_InnerAuth == AL::TLS::INNERMETHOD_EAP) {
                    if (!m_aEAPUserData.IsEmpty()) {
                        //
                        // Write <Password>.
                        //
                        dwReturnCode = AL::XML::PutElementBase64(pXMLConfigDoc, pXmlElClientSideCredential, CComBSTR(L"Password"), bstrNamespace, m_aEAPUserData.GetData(), m_aEAPUserData.GetCount());
                    }
                } else {
                    if (!m_sPassword.IsEmpty()) {
                        //
                        // Write <Password>.
                        //
                        dwReturnCode = AL::XML::PutElementEncrypted(pXMLConfigDoc, pXmlElClientSideCredential, CComBSTR(L"Password"), bstrNamespace, (LPCWSTR)m_sPassword, sizeof(WCHAR)*m_sPassword.GetLength());
                    }
                }
                hr = pXmlElInnerAuthenticationMethod->appendChild(pXmlElClientSideCredential, NULL);
            }

            {
                //
                // Write <VendorSpecific>.
                //
                CComPtr<IXMLDOMNode> pXmlElVendorSpecific;
                hr = pXMLConfigDoc->createNode(varNodeTypeEl, CComBSTR(L"VendorSpecific"), bstrNamespace, &pXmlElVendorSpecific);

                if (m_aEAPConnectionData.GetCount()) {
                    //
                    // Write <EAPConnectionData>.
                    //
                    dwReturnCode = AL::XML::PutElementBase64(pXMLConfigDoc, pXmlElVendorSpecific, CComBSTR(L"EAPConnectionData"), bstrNamespace, m_aEAPConnectionData.GetData(), m_aEAPConnectionData.GetCount());
                }
                hr = pXmlElInnerAuthenticationMethod->appendChild(pXmlElVendorSpecific, NULL);
            }
            hr = pXmlElAuthenticationMethod->appendChild(pXmlElInnerAuthenticationMethod, NULL);
        }

        {
            //
            // Write <VendorSpecific>.
            //
            CComPtr<IXMLDOMNode> pXmlElVendorSpecific;
            hr = pXMLConfigDoc->createNode(varNodeTypeEl, CComBSTR(L"VendorSpecific"), bstrNamespace, &pXmlElVendorSpecific);

            //
            // Write <SessionResumption>.
            //
            dwReturnCode = AL::XML::PutElementValue(pXMLConfigDoc, pXmlElVendorSpecific, CComBSTR(L"SessionResumption"), bstrNamespace, m_fUseSessionResumption);

            hr = pXmlElAuthenticationMethod->appendChild(pXmlElVendorSpecific, NULL);
        }
    }

    return dwReturnCode;
}


DWORD AL::TLS::CConfigData::Load(_In_ IXMLDOMDocument2 *pXMLConfigDoc)
{
    DWORD dwReturnCode = NO_ERROR;
    HRESULT hr;

    ATL::CAtlString sLang;
    sLang.LoadString(AL::System::g_hResource, IDS_AL_LANGUAGE_IANA_SUBTAG);

    pXMLConfigDoc->setProperty(CComBSTR(L"SelectionNamespaces"), CComVariant(L"xmlns:eap-metadata=\"urn:ietf:params:xml:ns:yang:ietf-eap-metadata\""));

    CComPtr<IXMLDOMNode> pXmlElProvider;
    if ((dwReturnCode = AL::XML::SelectNode(pXMLConfigDoc, CComBSTR(L"//eap-metadata:EAPIdentityProvider"), &pXmlElProvider)) == NO_ERROR) {
        //
        // <ID>
        //
        if (AL::XML::GetElementValue(pXmlElProvider, CComBSTR(L"eap-metadata:ID"), m_sProviderID) == NO_ERROR)
            AL_TRACE_INFO(_T("ProviderID: %s"), (LPCTSTR)m_sProviderID);
        else
            m_sProviderID.SetString(L"DEFAULT");

        {
            m_sAltCredentialLbl.Empty();
            m_sAltIdentityLbl.Empty();
            m_sAltPasswordLbl.Empty();

            //
            // <ProviderInfo>
            //
            CComPtr<IXMLDOMElement> pXmlElProviderInfo;
            if (AL::XML::SelectElement(pXmlElProvider, CComBSTR(L"eap-metadata:ProviderInfo"), &pXmlElProviderInfo) == NO_ERROR) {
                //
                // <CredentialPrompt>
                //
                if (AL::XML::GetElementLocalized(pXmlElProviderInfo, CComBSTR(L"eap-metadata:CredentialPrompt"), sLang, m_sAltCredentialLbl) == NO_ERROR)
                    AL_TRACE_INFO(_T("AltCredentialLbl: %s"), (LPCTSTR)m_sAltCredentialLbl);

                //
                // <UserNameLabel>
                //
                if (AL::XML::GetElementLocalized(pXmlElProviderInfo, CComBSTR(L"eap-metadata:UserNameLabel"), sLang, m_sAltIdentityLbl) == NO_ERROR)
                    AL_TRACE_INFO(_T("AltIdentityLbl: %s"), (LPCTSTR)m_sAltIdentityLbl);

                //
                // <PasswordLabel>
                //
                if (AL::XML::GetElementLocalized(pXmlElProviderInfo, CComBSTR(L"eap-metadata:PasswordLabel"), sLang, m_sAltPasswordLbl) == NO_ERROR)
                    AL_TRACE_INFO(_T("AltPasswordLbl: %s"), (LPCTSTR)m_sAltPasswordLbl);
            }
        }

        //
        // Iterate <AuthenticationMethods>s.
        //
        CComPtr<IXMLDOMNodeList> pXmlListMethods;
        if (AL::XML::SelectNodes(pXmlElProvider, CComBSTR(L"eap-metadata:AuthenticationMethods/eap-metadata:AuthenticationMethod"), &pXmlListMethods) == NO_ERROR) {
            long lCount;
            hr = pXmlListMethods->get_length(&lCount);
            for (long i = 0; ; i++) {
                if (i >= lCount) {
                    AL_TRACE_ERROR(_T("No supported authentication method found."));
                    dwReturnCode = ERROR_NOT_FOUND;
                    break;
                }

                CComPtr<IXMLDOMNode> pXmlElMethod;
                pXmlListMethods->get_item(i, &pXmlElMethod);

                {
                    //
                    // Verify <EAPMethod>.
                    //
                    DWORD dwMethodID;
                    if (AL::XML::GetElementValue(pXmlElMethod, CComBSTR(L"eap-metadata:EAPMethod"), &dwMethodID) == NO_ERROR) {
                        if (dwMethodID != AL::EAP::g_bType) {
                            // Configuration data mismatch.
                            AL_TRACE_WARNING(_T("The %ld/%ld method of %s provider doesn't match EAPHost's."), i + 1, lCount, (LPCTSTR)m_sProviderID);
                            continue;
                        }
                    } else {
                        // <EAPMethod> is missing. Assuming OK.
                        AL_TRACE_WARNING(_T("The %ld/%ld method of %s provider is missing <EAPMethod>."), i + 1, lCount, (LPCTSTR)m_sProviderID);
                    }
                }

                {
                    m_lTrustedRootCAs.RemoveAll();
                    m_sServerName.Empty();

                    //
                    // <ServerSideCredential>
                    //
                    CComPtr<IXMLDOMElement> pXmlElServerSideCredential;
                    if (AL::XML::SelectElement(pXmlElMethod, CComBSTR(L"eap-metadata:ServerSideCredential"), &pXmlElServerSideCredential) == NO_ERROR) {
                        {
                            //
                            // Iterate <CA>s.
                            //
                            CComPtr<IXMLDOMNodeList> pXmlListCAs;
                            if (AL::XML::SelectNodes(pXmlElServerSideCredential, CComBSTR(L"eap-metadata:CA"), &pXmlListCAs) == NO_ERROR) {
                                long lCACount;
                                pXmlListCAs->get_length(&lCACount);
                                for (long j = 0; j < lCACount; j++) {
                                    //
                                    // <CA>
                                    //
                                    CComPtr<IXMLDOMNode> pXmlElCA;
                                    pXmlListCAs->get_item(j, &pXmlElCA);
                                    CComBSTR bstrFormat;
                                    if (AL::XML::GetElementValue(pXmlElCA, CComBSTR(L"eap-metadata:format"), &bstrFormat) == NO_ERROR) {
                                        if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrFormat, bstrFormat.Length(), L"PEM", -1, NULL, NULL, 0) == CSTR_EQUAL) {
                                            ATL::CAtlArray<BYTE> aData;
                                            if (AL::XML::GetElementBase64(pXmlElCA, CComBSTR(L"eap-metadata:cert-data"), aData) == NO_ERROR)
                                                m_lTrustedRootCAs.AddCertificate(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, aData.GetData(), (DWORD)aData.GetCount());
                                            else
                                                AL_TRACE_WARNING(_T("The %ld/%ld CA of %ld/%ld method of %s provider has missing or incorrect <cert-data>."), j + 1, lCACount, i + 1, lCount, (LPCTSTR)m_sProviderID);
                                        } else
                                            AL_TRACE_WARNING(_T("The %ld/%ld CA of %ld/%ld method of %s provider is not in PEM format."), j + 1, lCACount, i + 1, lCount, (LPCTSTR)m_sProviderID);
                                    } else
                                        AL_TRACE_WARNING(_T("The %ld/%ld CA of %ld/%ld method of %s provider is missing <format>."), j + 1, lCACount, i + 1, lCount, (LPCTSTR)m_sProviderID);
                                }
                            }
                            AL_TRACE_INFO(_T("%ld CA certificate(s) found."), m_lTrustedRootCAs.GetCount());
                        }

                        {
                            //
                            // Iterate <ServerName>s.
                            //
                            CComPtr<IXMLDOMNodeList> pXmlListServerIDs;
                            if (AL::XML::SelectNodes(pXmlElServerSideCredential, CComBSTR(L"eap-metadata:ServerName"), &pXmlListServerIDs) == NO_ERROR) {
                                long lServerIDCount;
                                pXmlListServerIDs->get_length(&lServerIDCount);
                                for (long j = 0; j < lServerIDCount; j++) {
                                    //
                                    // <ServerName>
                                    //
                                    CComPtr<IXMLDOMNode> pXmlElServerID;
                                    pXmlListServerIDs->get_item(j, &pXmlElServerID);
                                    CComBSTR bstrServerID;
                                    pXmlElServerID->get_text(&bstrServerID);

                                    if (!m_sServerName.IsEmpty()) m_sServerName += ';';
                                    m_sServerName += bstrServerID;
                                }
                                // No need to zero terminate: AL::TLS::Profile::InitDefault() zeroed everything.
                                //if (iOffset < _countof(pConfigData->pwcServerName))
                                //    pConfigData->pwcServerName[iOffset] = 0;
                            }
                            AL_TRACE_INFO(_T("ServerName: %hs"), (LPCSTR)m_sServerName);
                        }
                    }
                }

                //
                // <ClientSideCredential><AnonymousIdentity>
                //
                if (AL::XML::GetElementValue(pXmlElMethod, CComBSTR(L"eap-metadata:ClientSideCredential/eap-metadata:AnonymousIdentity"), m_sOuterIdentity) == NO_ERROR)
                    AL_TRACE_INFO(_T("AlternateOuterIdentity: %ls"), (LPCWSTR)m_sOuterIdentity);
                else
                    m_sOuterIdentity.Empty();

                {
                    m_InnerAuth = AL::EAP::g_bType == AL_EAP_TYPE_PEAP ? INNERMETHOD_EAP : INNERMETHOD_PAP;

                    //
                    // <InnerAuthenticationMethod>
                    //
                    CComPtr<IXMLDOMElement> pXmlElInnerAuthenticationMethod;
                    if (AL::XML::SelectElement(pXmlElMethod, CComBSTR(L"eap-metadata:InnerAuthenticationMethod"), &pXmlElInnerAuthenticationMethod) == NO_ERROR) {
                        if (AL::EAP::g_bType == AL_EAP_TYPE_PEAP) {
                            //
                            // PEAP: Inner authentication is always MSCHAPv2.
                            //
                            m_InnerAuth = AL::TLS::INNERMETHOD_EAP;
                        } else {
                            //
                            // TTLS
                            //
                            BOOL bMethodFound = FALSE;

                            if (!bMethodFound) {
                                //
                                // <EAPMethod>
                                //
                                DWORD dwMethodID;
                                if (AL::XML::GetElementValue(pXmlElInnerAuthenticationMethod, CComBSTR(L"eap-metadata:EAPMethod"), &dwMethodID) == NO_ERROR) {
                                    if (dwMethodID == AL_EAP_TYPE_MSCHAPV2) {
                                        m_InnerAuth = AL::TLS::INNERMETHOD_EAP;
                                        bMethodFound = TRUE;
                                    }
                                }
                            }

                            if (!bMethodFound) {
                                //
                                // <NonEAPAuthMethod>
                                //
                                CComBSTR bstrMethod;
                                if (AL::XML::GetElementValue(pXmlElInnerAuthenticationMethod, CComBSTR(L"eap-metadata:NonEAPAuthMethod"), &bstrMethod) == NO_ERROR) {
                                    if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrMethod, bstrMethod.Length(), L"PAP", -1, NULL, NULL, 0) == CSTR_EQUAL) {
                                        m_InnerAuth = AL::TLS::INNERMETHOD_PAP;
                                        bMethodFound = TRUE;
                                    }
                                }
                            }

                            if (!bMethodFound) {
                                // This is not a TTLS-PAP, neither TTLS-MSCHAPv2.
                                AL_TRACE_WARNING(_T("The %ld/%ld method of %s provider is not TTLS-PAP, neither TTLS-MSCHAPv2."), i + 1, lCount, (LPCTSTR)m_sProviderID);
                                continue;
                            }
                        }
                        AL_TRACE_INFO(_T("InnerAuth: %d"), m_InnerAuth);

                        {
                            m_sIdentity.Empty();
                            m_sPassword.Empty();
                            m_aEAPUserData.SetCount(0);

                            //
                            // <ClientSideCredential>
                            //
                            CComPtr<IXMLDOMElement> pXmlElClientSideCredential;
                            if (AL::XML::SelectElement(pXmlElInnerAuthenticationMethod, CComBSTR(L"eap-metadata:ClientSideCredential"), &pXmlElClientSideCredential) == NO_ERROR) {
                                //
                                // <UserName>
                                //
                                if (AL::XML::GetElementValue(pXmlElClientSideCredential, CComBSTR(L"eap-metadata:UserName"), m_sIdentity) == NO_ERROR)
                                    AL_TRACE_INFO(_T("UserID: %ls"), (LPCWSTR)m_sIdentity);

                                //
                                // <Password>
                                //
                                if (AL::EAP::g_bType == AL_EAP_TYPE_PEAP || m_InnerAuth == AL::TLS::INNERMETHOD_EAP) {
                                    if (AL::XML::GetElementBase64(pXmlElClientSideCredential, CComBSTR(L"eap-metadata:Password"), m_aEAPUserData) == NO_ERROR)
                                        AL_TRACE_INFO(_T("UserData: %ldB"), m_aEAPUserData.GetCount());
                                } else {
                                    if (AL::XML::GetElementEncrypted(pXmlElClientSideCredential, CComBSTR(L"eap-metadata:Password"), m_sPassword) == NO_ERROR) {
#ifdef _DEBUG
                                        AL_TRACE_INFO(_T("UserPassword: %ls"), (LPCWSTR)m_sPassword);
#endif
                                    }
                                }
                            }
                        }

                        {
                            m_aEAPConnectionData.SetCount(0);

                            //
                            // <VendorSpecific>
                            //
                            CComPtr<IXMLDOMElement> pXmlElVendorSpecific;
                            if (AL::XML::SelectElement(pXmlElInnerAuthenticationMethod, CComBSTR(L"eap-metadata:VendorSpecific"), &pXmlElVendorSpecific) == NO_ERROR) {
                                //
                                // <EAPConnectionData>
                                //
                                if (AL::XML::GetElementBase64(pXmlElVendorSpecific, CComBSTR(L"eap-metadata:EAPConnectionData"), m_aEAPConnectionData) == NO_ERROR)
                                    AL_TRACE_INFO(_T("EAPConnectionData: %ldB"), m_aEAPConnectionData.GetCount());
                            }
                        }
                    }

                    {
                        m_fUseSessionResumption = FALSE;

                        //
                        // <VendorSpecific><SessionResumption>
                        //
                        if (AL::XML::GetElementValue(pXmlElMethod, CComBSTR(L"eap-metadata:VendorSpecific/eap-metadata:SessionResumption"), &m_fUseSessionResumption) == NO_ERROR)
                            AL_TRACE_INFO(_T("SessionResumption: %d"), m_fUseSessionResumption);
                    }
                }

                break;
            }
        }
    } else
        AL_TRACE_ERROR(_T("Identity provider not found."));

    return dwReturnCode;
}


VOID MemPack(_Inout_ BYTE **ppbCursor, _In_ const AL::TLS::CConfigData &cfg)
{
    ::MemPack(ppbCursor, cfg.m_sProviderID                );
    ::MemPack(ppbCursor, cfg.m_sOuterIdentity             );
    ::MemPack(ppbCursor, cfg.m_lTrustedRootCAs            );
    ::MemPack(ppbCursor, cfg.m_sServerName                );
    ::MemPack(ppbCursor, (BYTE)cfg.m_InnerAuth            );
    ::MemPack(ppbCursor, cfg.m_sAltCredentialLbl          );
    ::MemPack(ppbCursor, cfg.m_sAltIdentityLbl            );
    ::MemPack(ppbCursor, cfg.m_sAltPasswordLbl            );
    ::MemPack(ppbCursor, cfg.m_sIdentity                  );
    {
        int iCount = cfg.m_sPassword.GetLength();
        ATL::CAtlStringW sEncrypted;
        LPWSTR szBuffer = sEncrypted.GetBuffer(iCount);
        AL::Buffer::XORData((LPCWSTR)cfg.m_sPassword, szBuffer, sizeof(WCHAR)*iCount, AL_SECUREW2_XORPATTERN, sizeof(AL_SECUREW2_XORPATTERN) - sizeof(CHAR));
        sEncrypted.ReleaseBuffer(iCount);
        ::MemPack(ppbCursor, sEncrypted);
    }
    ::MemPack(ppbCursor, cfg.m_aEAPConnectionData         );
    ::MemPack(ppbCursor, cfg.m_aEAPUserData               );
    ::MemPack(ppbCursor, (BYTE)cfg.m_fUseSessionResumption);
}


SIZE_T MemGetPackedSize(_In_ const AL::TLS::CConfigData &cfg)
{
    return 
        ::MemGetPackedSize(cfg.m_sProviderID                ) +
        ::MemGetPackedSize(cfg.m_sOuterIdentity             ) +
        ::MemGetPackedSize(cfg.m_lTrustedRootCAs            ) +
        ::MemGetPackedSize(cfg.m_sServerName                ) +
        ::MemGetPackedSize((BYTE)cfg.m_InnerAuth            ) +
        ::MemGetPackedSize(cfg.m_sAltCredentialLbl          ) +
        ::MemGetPackedSize(cfg.m_sAltIdentityLbl            ) +
        ::MemGetPackedSize(cfg.m_sAltPasswordLbl            ) +
        ::MemGetPackedSize(cfg.m_sIdentity                  ) +
        ::MemGetPackedSize(cfg.m_sPassword                  ) +
        ::MemGetPackedSize(cfg.m_aEAPConnectionData         ) +
        ::MemGetPackedSize(cfg.m_aEAPUserData               ) +
        ::MemGetPackedSize((BYTE)cfg.m_fUseSessionResumption);
}


VOID MemUnpack(_Inout_ const BYTE **ppbCursor, _Out_ AL::TLS::CConfigData &cfg)
{
    BYTE bTemp;

    ::MemUnpack(ppbCursor, cfg.m_sProviderID       );
    ::MemUnpack(ppbCursor, cfg.m_sOuterIdentity    );
    ::MemUnpack(ppbCursor, cfg.m_lTrustedRootCAs   );
    ::MemUnpack(ppbCursor, cfg.m_sServerName       );
    ::MemUnpack(ppbCursor, bTemp                   ); cfg.m_InnerAuth = (AL::TLS::INNERMETHOD_T)bTemp;
    ::MemUnpack(ppbCursor, cfg.m_sAltCredentialLbl );
    ::MemUnpack(ppbCursor, cfg.m_sAltIdentityLbl   );
    ::MemUnpack(ppbCursor, cfg.m_sAltPasswordLbl   );
    ::MemUnpack(ppbCursor, cfg.m_sIdentity         );
    {
        ATL::CAtlStringW sEncrypted;
        ::MemUnpack(ppbCursor, sEncrypted);
        int iCount = sEncrypted.GetLength();
        LPWSTR szBuffer = cfg.m_sPassword.GetBuffer(iCount);
        AL::Buffer::XORData((LPCWSTR)sEncrypted, szBuffer, sizeof(WCHAR)*iCount, AL_SECUREW2_XORPATTERN, sizeof(AL_SECUREW2_XORPATTERN) - sizeof(CHAR));
        cfg.m_sPassword.ReleaseBuffer(iCount);
    }
    ::MemUnpack(ppbCursor, cfg.m_aEAPConnectionData);
    ::MemUnpack(ppbCursor, cfg.m_aEAPUserData      );
    ::MemUnpack(ppbCursor, bTemp                   ); cfg.m_fUseSessionResumption = bTemp ? TRUE : FALSE;
}
