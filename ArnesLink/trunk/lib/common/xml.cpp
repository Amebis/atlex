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


DWORD AL::XML::SelectNode(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrNodeName, _Out_ IXMLDOMNode **ppXmlNode)
{
    DWORD dwReturnCode = NO_ERROR;
    HRESULT hr;

    if (SUCCEEDED(hr = pXmlParent->selectSingleNode(bstrNodeName, ppXmlNode))) {
        if (*ppXmlNode == NULL)
            dwReturnCode = ERROR_NO_DATA;
    } else {
        dwReturnCode = HRESULT_CODE(hr);
        AL_TRACE_ERROR(_T("IXMLDOMNode::selectSingleNode failed for element <%.*ls> (%ld)."), SysStringLen(bstrNodeName), bstrNodeName, dwReturnCode);
    }

    return dwReturnCode;
}


DWORD AL::XML::SelectNodes(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrNodeName, _Out_ IXMLDOMNodeList **ppXmlNodes)
{
    DWORD dwReturnCode = NO_ERROR;
    HRESULT hr;

    if (SUCCEEDED(hr = pXmlParent->selectNodes(bstrNodeName, ppXmlNodes))) {
        if (*ppXmlNodes == NULL)
            dwReturnCode = ERROR_NO_DATA;
    } else {
        dwReturnCode = HRESULT_CODE(hr);
        AL_TRACE_ERROR(_T("IXMLDOMNode::selectNodes failed for elements <%*.ls> (%ld)."), SysStringLen(bstrNodeName), bstrNodeName, dwReturnCode);
    }

    return dwReturnCode;
}


DWORD AL::XML::SelectElement(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ IXMLDOMElement **ppXmlElement)
{
    DWORD dwReturnCode = NO_ERROR;
    HRESULT hr;

    CComPtr<IXMLDOMNode> pXmlNode;
    if ((dwReturnCode = SelectNode(pXmlParent, bstrElementName, &pXmlNode)) == NO_ERROR) {
        if (SUCCEEDED(hr = pXmlNode.QueryInterface(ppXmlElement))) {
            if (*ppXmlElement == NULL)
                dwReturnCode = ERROR_NO_DATA;
        } else
            AL_TRACE_ERROR(_T("QueryInterface failed for element <%.*ls> (%ld)."), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));
    }

    return dwReturnCode;
}


DWORD AL::XML::GetElementValue(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ BSTR *pbstrValue)
{
    DWORD dwReturnCode = NO_ERROR;
    HRESULT hr;

    CComPtr<IXMLDOMElement> pXmlElement;
    if ((dwReturnCode = SelectElement(pXmlParent, bstrElementName, &pXmlElement)) == NO_ERROR) {
        if (SUCCEEDED(hr = pXmlElement->get_text(pbstrValue))) {
            if (*pbstrValue == NULL)
                dwReturnCode = ERROR_NO_DATA;
        } else
            AL_TRACE_ERROR(_T("IXMLDOMElement::get_text failed for element <%.*ls> (%ld)"), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));
    }

    return dwReturnCode;
}


DWORD AL::XML::GetElementValue(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ ATL::CAtlString &sValue)
{
    DWORD dwReturnCode = NO_ERROR;

    CComBSTR bstr;
    if ((dwReturnCode = GetElementValue(pXmlParent, bstrElementName, &bstr)) == NO_ERROR)
        sValue.SetString(bstr, bstr.Length());

    return dwReturnCode;
}



DWORD AL::XML::GetElementValue(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ DWORD *pdwValue)
{
    DWORD dwReturnCode = NO_ERROR;

    CComBSTR bstr;
    if ((dwReturnCode = GetElementValue(pXmlParent, bstrElementName, &bstr)) == NO_ERROR)
        *pdwValue = wcstoul(bstr, NULL, 10);

    return dwReturnCode;
}


DWORD AL::XML::GetElementValue(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ BOOL *pbValue)
{
    DWORD dwReturnCode = NO_ERROR;

    CComBSTR bstr;
    if ((dwReturnCode = GetElementValue(pXmlParent, bstrElementName, &bstr)) == NO_ERROR) {
        if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.Length(), L"true" , -1, NULL, NULL, 0) == CSTR_EQUAL ||
            CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.Length(), L"1"    , -1, NULL, NULL, 0) == CSTR_EQUAL)
            *pbValue = TRUE;
        else if (
            CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.Length(), L"false", -1, NULL, NULL, 0) == CSTR_EQUAL ||
            CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstr, bstr.Length(), L"0"    , -1, NULL, NULL, 0) == CSTR_EQUAL)
            *pbValue = FALSE;
        else {
            AL_TRACE_ERROR(_T("The element <%.*ls> content is not boolean."), SysStringLen(bstrElementName), bstrElementName);
            dwReturnCode = ERROR_INVALID_DATA;
        }
    }

    return dwReturnCode;
}


DWORD AL::XML::GetElementBase64(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ ATL::CAtlArray<BYTE> &aValue)
{
    DWORD dwReturnCode = NO_ERROR;

    CComBSTR bstr;
    if ((dwReturnCode = GetElementValue(pXmlParent, bstrElementName, &bstr)) == NO_ERROR) {
        //
        // Decode Base64 to get binary data.
        //
        AL::Buffer::Base64::CDecoder dec;
        dec.Decode(bstr, aValue);
    }

    return dwReturnCode;
}


DWORD AL::XML::GetElementEncrypted(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ ATL::CAtlString &sValue)
{
    DWORD dwReturnCode = NO_ERROR;
    HRESULT hr;

    CComPtr<IXMLDOMElement> pXmlEl;
    if ((dwReturnCode = SelectElement(pXmlParent, bstrElementName, &pXmlEl)) == NO_ERROR) {
        CComBSTR bstrValue;
        if (SUCCEEDED(hr = pXmlEl->get_text(&bstrValue))) {
            CComVariant varEncryption;
            if (SUCCEEDED(hr = pXmlEl->getAttribute(CComBSTR(L"encryption"), &varEncryption))) {
                if (V_VT(&varEncryption) == VT_BSTR && CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, V_BSTR(&varEncryption), SysStringLen(V_BSTR(&varEncryption)), L"SecureW2", -1, NULL, NULL, 0) == CSTR_EQUAL) {
                    //
                    // Decode Base64 to get encrypted password data.
                    //
                    ATL::CAtlArray<BYTE> aData;
                    {
                        AL::Buffer::Base64::CDecoder dec;
                        dec.Decode(bstrValue, aData);
                    }

                    //
                    // Decode encrypted password data to get clear text password.
                    //
                    LPVOID pData = aData.GetData();
                    SIZE_T nDataSize = aData.GetCount();
                    AL::Buffer::XORData(pData, nDataSize, AL_SECUREW2_XORPATTERN, sizeof(AL_SECUREW2_XORPATTERN) - sizeof(CHAR));

                    //
                    // Copy clear text password and wipe.
                    //
                    sValue.SetString((LPCWSTR)pData, (int)wcsnlen((LPCWSTR)pData, nDataSize/sizeof(WCHAR)));
                    SecureZeroMemory(pData, nDataSize);
                } else if (V_VT(&varEncryption) == VT_NULL) {
                    //
                    // Copy clear text password and wipe.
                    //
                    SIZE_T nDataSize = bstrValue.Length();
                    sValue.SetString(bstrValue, (int)nDataSize);
                    SecureZeroMemory(bstrValue, sizeof(OLECHAR)*nDataSize);
                } else {
                    AL_TRACE_ERROR(_T("Unsupported encryption for element <%.*ls> (%ld)"), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));
                    dwReturnCode = ERROR_NOT_SUPPORTED;
                }
            } else
                AL_TRACE_ERROR(_T("IXMLDOMElement::getAttribute() failed for element <%.*ls> (%ld)"), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));
        } else
            AL_TRACE_ERROR(_T("IXMLDOMElement::get_text failed for element <%.*ls> (%ld)"), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));
    }

    return dwReturnCode;
}


DWORD AL::XML::GetElementLocalized(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _In_z_ LPCTSTR pszLang, _Out_ BSTR *pbstrValue)
{
    DWORD dwReturnCode = NO_ERROR;
    HRESULT hr;

    CComPtr<IXMLDOMElement> pXmlElement;
    if ((dwReturnCode = SelectElement(pXmlParent, bstrElementName, &pXmlElement)) == NO_ERROR) {
        CComPtr<IXMLDOMNodeList> pXmlListLocalizedText;
        long lCount = 0;
        if (AL::XML::SelectNodes(pXmlElement, CComBSTR(L"eap-metadata:localized-text"), &pXmlListLocalizedText) == NO_ERROR &&
            SUCCEEDED(pXmlListLocalizedText->get_length(&lCount)) &&
            lCount > 0)
        {
            CComBSTR bstrDefault, bstrEn;
            for (long i = 0; ; i++) {
                if (i >= lCount) {
                    if (bstrDefault != NULL) {
                        // Return "C" localization.
                        *pbstrValue = bstrDefault.Detach();
                        dwReturnCode = NO_ERROR;
                    } else if (bstrEn != NULL) {
                        // Return "en" localization.
                        *pbstrValue = bstrEn.Detach();
                        dwReturnCode = NO_ERROR;
                    } else {
                        AL_TRACE_ERROR(_T("No supported language found."));
                        dwReturnCode = ERROR_NOT_FOUND;
                    }
                    break;
                }

                CComPtr<IXMLDOMNode> pXmlElLocalizedText;
                pXmlListLocalizedText->get_item(i, &pXmlElLocalizedText);

                {
                    //
                    // Read <lang>.
                    //
                    CComBSTR bstrLang;
                    if (AL::XML::GetElementValue(pXmlElLocalizedText, CComBSTR(L"eap-metadata:lang"), &bstrLang) != NO_ERROR ||
                        CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrLang, bstrLang.Length(), L"C" , -1, NULL, NULL, 0) == CSTR_EQUAL)
                    {
                        // <lang> is missing or "C" language found.
                        CComBSTR bstr;
                        if ((dwReturnCode = AL::XML::GetElementValue(pXmlElLocalizedText, CComBSTR(L"eap-metadata:text"), &bstr)) == NO_ERROR)
                            bstrDefault.Attach(bstr.Detach());
                    } else if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrLang, bstrLang.Length(), pszLang, -1, NULL, NULL, 0) == CSTR_EQUAL) {
                        // Found an exact match.
                        dwReturnCode = AL::XML::GetElementValue(pXmlElLocalizedText, CComBSTR(L"eap-metadata:text"), pbstrValue);
                        break;
                    } else if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrLang, bstrLang.Length(), L"en", -1, NULL, NULL, 0) == CSTR_EQUAL) {
                        // "en" language found.
                        CComBSTR bstr;
                        if ((dwReturnCode = AL::XML::GetElementValue(pXmlElLocalizedText, CComBSTR(L"eap-metadata:text"), &bstr)) == NO_ERROR)
                            bstrEn.Attach(bstr.Detach());
                    }
                }
            }
        } else {
            if (SUCCEEDED(hr = pXmlElement->get_text(pbstrValue))) {
                if (*pbstrValue == NULL)
                    dwReturnCode = ERROR_NO_DATA;
            } else
                AL_TRACE_ERROR(_T("IXMLDOMElement::get_text failed for element <%.*ls> (%ld)"), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));
        }
    }

    return dwReturnCode;
}


DWORD AL::XML::GetElementLocalized(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _In_z_ LPCTSTR pszLang, _Out_ ATL::CAtlString &sValue)
{
    DWORD dwReturnCode = NO_ERROR;

    CComBSTR bstr;
    if ((dwReturnCode = GetElementLocalized(pXmlParent, bstrElementName, pszLang, &bstr)) == NO_ERROR)
        sValue.SetString(bstr, bstr.Length());

    return dwReturnCode;
}


DWORD AL::XML::PutElement(_In_ IXMLDOMDocument2 *pXmlDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _Out_ IXMLDOMElement **ppXmlElement)
{
    DWORD dwReturnCode = NO_ERROR;
    HRESULT hr;
    static const VARIANT varNodeTypeEl = { VT_I4, 0, 0, 0, { NODE_ELEMENT } };

    CComPtr<IXMLDOMNode> pXmlEl;
    if (SUCCEEDED(hr = pXmlDoc->createNode(varNodeTypeEl, bstrElementName, bstrNamespace, &pXmlEl))) {
        if (SUCCEEDED(hr = pCurrentDOMNode->appendChild(pXmlEl, NULL))) {
            if (FAILED(hr = pXmlEl.QueryInterface(ppXmlElement)))
                AL_TRACE_ERROR(_T("IXMLDOMNode::QueryInterface failed for element <%.*ls> (%ld)."), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));
        } else
            AL_TRACE_ERROR(_T("IXMLDOMNode::appendChild failed for element <%.*ls> (%ld)."), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));
    } else
        AL_TRACE_ERROR(_T("IXMLDOMDocument2::createNode failed for element <%.*ls> (%ld)."), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));

    return dwReturnCode;
}


DWORD AL::XML::PutElementValue(_In_ IXMLDOMDocument2 *pXmlDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_z_ const BSTR bstrValue)
{
    DWORD dwReturnCode = NO_ERROR;
    HRESULT hr;
    static const VARIANT varNodeTypeEl = { VT_I4, 0, 0, 0, { NODE_ELEMENT } };

    CComPtr<IXMLDOMNode> pXmlEl;
    if (SUCCEEDED(hr = pXmlDoc->createNode(varNodeTypeEl, bstrElementName, bstrNamespace, &pXmlEl))) {
        CComPtr<IXMLDOMText> pXmlElText;
        if (SUCCEEDED(hr = pXmlDoc->createTextNode(bstrValue, &pXmlElText))) {
            if (SUCCEEDED(hr = pXmlEl->appendChild(pXmlElText, NULL))) {
                if (FAILED(hr = pCurrentDOMNode->appendChild(pXmlEl, NULL)))
                    AL_TRACE_ERROR(_T("IXMLDOMNode::appendChild failed for element <%.*ls> (%ld)."), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));
            } else
                AL_TRACE_ERROR(_T("IXMLDOMNode::appendChild failed for element <%.*ls> (%ld)."), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));
        } else
            AL_TRACE_ERROR(_T("IXMLDOMDocument2::createTextNode failed for element <%.*ls> (%ld)."), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));
    } else
        AL_TRACE_ERROR(_T("IXMLDOMDocument2::createNode failed for element <%.*ls> (%ld)."), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));

    return dwReturnCode;
}


DWORD AL::XML::PutElementValue(_In_ IXMLDOMDocument2 *pXmlDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_ DWORD dwValue)
{
    ATL::CAtlStringW sTemp;
    sTemp.Format(L"%d", dwValue);
    return PutElementValue(pXmlDoc, pCurrentDOMNode, bstrElementName, bstrNamespace, CComBSTR(sTemp));
}


DWORD AL::XML::PutElementValue(_In_ IXMLDOMDocument2 *pXmlDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_ BOOL bValue)
{
    return PutElementValue(pXmlDoc, pCurrentDOMNode, bstrElementName, bstrNamespace, CComBSTR(bValue ? L"true": L"false"));
}


DWORD AL::XML::PutElementBase64(_In_ IXMLDOMDocument2 *pXmlDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_count_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen)
{
    DWORD dwReturnCode = NO_ERROR;

    ATL::CAtlString sBase64;
    {
        AL::Buffer::Base64::CEncoder enc;
        enc.Encode(pValue, nValueLen, sBase64);
    }
    dwReturnCode = PutElementValue(pXmlDoc, pCurrentDOMNode, bstrElementName, bstrNamespace, CComBSTR(sBase64));

    return dwReturnCode;
}


DWORD AL::XML::PutElementEncrypted(_In_ IXMLDOMDocument2 *pXmlDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_count_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen)
{
    DWORD dwReturnCode = NO_ERROR;
    HRESULT hr;
    static const VARIANT varNodeTypeEl = { VT_I4, 0, 0, 0, { NODE_ELEMENT } };

    CComPtr<IXMLDOMNode> pXmlEl;
    if (SUCCEEDED(hr = pXmlDoc->createNode(varNodeTypeEl, bstrElementName, bstrNamespace, &pXmlEl))) {
        //
        // Encrypt data.
        //
        ATL::CAtlArray<BYTE> aEncryptedData;
        if (!aEncryptedData.SetCount(nValueLen)) AtlThrow(E_OUTOFMEMORY);
        AL::Buffer::XORData(pValue, aEncryptedData.GetData(), nValueLen, AL_SECUREW2_XORPATTERN, sizeof(AL_SECUREW2_XORPATTERN) - sizeof(CHAR));

        //
        // Encode to Base64.
        //
        ATL::CAtlString sBase64;
        {
            AL::Buffer::Base64::CEncoder enc;
            enc.Encode(aEncryptedData.GetData(), nValueLen, sBase64);
        }

        //
        // Append to XML.
        //
        CComPtr<IXMLDOMText> pXmlElText;
        if (SUCCEEDED(hr = pXmlDoc->createTextNode(CComBSTR(sBase64), &pXmlElText))) {
            if (SUCCEEDED(hr = pXmlEl->appendChild(pXmlElText, NULL))) {
                CComPtr<IXMLDOMElement> pXmlEl2;
                if (SUCCEEDED(hr = pXmlEl.QueryInterface(&pXmlEl2))) {
                    if (SUCCEEDED(hr = pXmlEl2->setAttribute(CComBSTR(L"encryption"), CComVariant(L"SecureW2")))) {
                        if (FAILED(hr = pCurrentDOMNode->appendChild(pXmlEl, NULL)))
                            AL_TRACE_ERROR(_T("IXMLDOMNode::appendChild failed for element <%.*ls> (%ld)."), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));
                    } else
                        AL_TRACE_ERROR(_T("IXMLDOMElement::setAttribute failed for element <%.*ls> (%ld)."), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));
                } else
                    AL_TRACE_ERROR(_T("QueryInterface failed for element <%.*ls> (%ld)."), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));
            } else
                AL_TRACE_ERROR(_T("IXMLDOMNode::appendChild failed for element <%.*ls> (%ld)."), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));
        } else
            AL_TRACE_ERROR(_T("IXMLDOMDocument2::createTextNode failed for element <%.*ls> (%ld)."), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));
    } else
        AL_TRACE_ERROR(_T("IXMLDOMDocument2::createNode failed for element <%.*ls> (%ld)."), SysStringLen(bstrElementName), bstrElementName, dwReturnCode = HRESULT_CODE(hr));

    return dwReturnCode;
}
