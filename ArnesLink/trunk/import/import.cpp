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
#pragma comment(lib, "msxml6.lib")
#ifdef USE_WINXP_THEMES
#pragma comment(lib, "UxTheme.lib")
#endif
#pragma comment(lib, "Wlanapi.lib")

//
// Global data
//
HINSTANCE AL::System::g_hInstance = NULL;
HINSTANCE AL::System::g_hResource = NULL;


//
// Local Types
//
class CImportSession {
public:
    CImportSession() :
        m_fIsEAPMetadataDraft(FALSE),
        m_lSecurityProviderIndex(0),
        m_sPassword(&AL::Heap::g_stringMgrParanoid),
        m_dwReturnCode(NO_ERROR)
    {
    }

public:
    //
    // Profile XML file.
    //
    ATL::CAtlString m_sFileName;
    CComPtr<IXMLDOMDocument2> m_pXmlDoc;
    BOOL m_fIsEAPMetadataDraft;

    //
    // Security provider index
    //
    long m_lSecurityProviderIndex;

    //
    // Inner Credentials
    //
    CAtlStringW m_sIdentity;
    CAtlStringW m_sPassword;
    CAtlArray<BYTE> m_aEAPUserData;

    //
    // Result code and error description
    //
    DWORD m_dwReturnCode;
    ATL::CAtlString m_sErrorDescription;
};


class CImportCommitThreadSession
{
public:
    CImportCommitThreadSession() :
        m_pImportSession(NULL),
        m_hWndWizard(NULL),
        m_hWndProgress(NULL),
        m_hEventCancel(INVALID_HANDLE_VALUE)
    {
    }

public:
    CImportSession *m_pImportSession;

    //
    // Wizard window.
    //
    HWND m_hWndWizard;

    //
    // Progress indicator window
    //
    HWND m_hWndProgress;

    //
    // Event to terminate the execution prematurely.
    //
    HANDLE m_hEventCancel;
};


//
// Wizard button's text labels
//
static ATL::CAtlString g_sTextBack;
static ATL::CAtlString g_sTextNext;
static ATL::CAtlString g_sTextFinish;
static ATL::CAtlString g_sTextCancel;

static ATL::CAtlString g_sLang;


//
// Local function declarations
//
static int CALLBACK _ImportPSProc(HWND hWnd, UINT uMsg, LPARAM lParam);
static INT_PTR CALLBACK _ImportFileDlgProc(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam);
static DWORD _ImportFileLoad(IN HWND hWnd, IN CImportSession *pImportSession);
static INT_PTR CALLBACK _ImportProfileDlgProc(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam);
static INT_PTR CALLBACK _ImportCredentialsDlgProcEAP(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam);
static INT_PTR CALLBACK _ImportCredentialsDlgProcPAP(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam);
static INT_PTR CALLBACK _ImportCommitDlgProc(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam);
static DWORD WINAPI _ImportCommitThread(IN LPVOID lpThreadParameter);
static INT_PTR CALLBACK _ImportFinishSuccessDlgProc(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam);
static INT_PTR CALLBACK _ImportFinishFailureDlgProc(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam);


//
// Main function
//
int CALLBACK WinMain(_In_ HINSTANCE hInstance, _In_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::System::g_hInstance = hInstance;
    AL::Trace::Init(_T("AL-IMPORT"));
    {
        AL_TRACEFN_INFO(dwReturnCode);

        HRESULT hr;
        hr = CoInitialize(NULL);
        if (SUCCEEDED(hr)) {
#ifdef USE_WINXP_THEMES
            {
                //
                // Initialize Windows XP visual styles
                //
                INITCOMMONCONTROLSEX icc;
                icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
                icc.dwICC = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES | ICC_TREEVIEW_CLASSES;
                InitCommonControlsEx(&icc);
            }
#endif

            if ((dwReturnCode = AL::Heap::Init()) == NO_ERROR) {
                int nArgs;
                LPWSTR *pwcArglist;
                if ((pwcArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs)) != NULL) {
                    AL_TRACE_INFO(_T("arguments (%ld)."), nArgs);

                    if ((AL::System::g_hResource = AL::System::LoadLibrary(AL::System::g_hInstance, _T("al_res.dll"), LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE)) != NULL) {
                        AL_TRACE_INFO(_T("Loaded resource."));

                        //
                        // Load wizard buttons text labels.
                        //
                          g_sTextBack.LoadString(AL::System::g_hResource, IDS_AL_PS_BACK);
                          g_sTextNext.LoadString(AL::System::g_hResource, IDS_AL_PS_NEXT);
                        g_sTextFinish.LoadString(AL::System::g_hResource, IDS_AL_PS_FINISH);
                        g_sTextCancel.LoadString(AL::System::g_hResource, IDS_AL_PS_CANCEL);

                        g_sLang.LoadString(AL::System::g_hResource, IDS_AL_LANGUAGE_IANA_SUBTAG);

                        //
                        // Initialize session.
                        //
                        CImportSession session;
                        if (SUCCEEDED((hr = CoCreateInstance(CLSID_DOMDocument30, NULL, CLSCTX_INPROC_SERVER, IID_IXMLDOMDocument2, reinterpret_cast<void**>(&session.m_pXmlDoc))))) {
                            // Configure XML parser as asynchronous, no validation, without external resolving to make import as robust as possible.
                            hr = session.m_pXmlDoc->put_async(VARIANT_FALSE);
                            hr = session.m_pXmlDoc->put_validateOnParse(VARIANT_FALSE);
                            hr = session.m_pXmlDoc->put_resolveExternals(VARIANT_FALSE);
                            if (nArgs > 1) {
                                session.m_sFileName = pwcArglist[1];
                                dwReturnCode = _ImportFileLoad(NULL, &session);
                            } else
                                dwReturnCode = NO_ERROR;
                            if (dwReturnCode == NO_ERROR) {
                                CAtlArray<HPROPSHEETPAGE> hpsp;

                                if (session.m_sFileName.IsEmpty()) {
                                    PROPSHEETPAGE psp = {};
                                    psp.dwSize = sizeof(psp);
                                    psp.dwFlags = PSP_USEHEADERTITLE;
                                    psp.hInstance = AL::System::g_hResource;
                                    psp.pszHeaderTitle = MAKEINTRESOURCE(IDS_AL_IMPORT_FILE_TITLE);
                                    psp.pszTemplate = MAKEINTRESOURCE(IDD_AL_IMPORT_FILE);
                                    psp.pfnDlgProc = _ImportFileDlgProc;
                                    psp.lParam = (LPARAM)&session;
                                    hpsp.Add(CreatePropertySheetPage(&psp));
                                }

                                {
                                    PROPSHEETPAGE psp = {};
                                    psp.dwSize = sizeof(psp);
                                    psp.dwFlags = PSP_USEHEADERTITLE;
                                    psp.hInstance = AL::System::g_hResource;
                                    psp.pszHeaderTitle = MAKEINTRESOURCE(IDS_AL_IMPORT_PROVIDER_TITLE);
                                    psp.pszTemplate = MAKEINTRESOURCE(IDD_AL_IMPORT_PROVIDER);
                                    psp.pfnDlgProc = _ImportProfileDlgProc;
                                    psp.lParam = (LPARAM)&session;
                                    hpsp.Add(CreatePropertySheetPage(&psp));
                                }

                                {
                                    PROPSHEETPAGE psp = {};
                                    psp.dwSize = sizeof(psp);
                                    psp.dwFlags = PSP_USEHEADERTITLE;
                                    psp.hInstance = AL::System::g_hResource;
                                    psp.pszHeaderTitle = MAKEINTRESOURCE(IDS_AL_IMPORT_CREDENTIALS_TITLE_EAP);
                                    psp.pszTemplate = MAKEINTRESOURCE(IDD_AL_IMPORT_CREDENTIALS_EAP);
                                    psp.pfnDlgProc = _ImportCredentialsDlgProcEAP;
                                    psp.lParam = (LPARAM)&session;
                                    hpsp.Add(CreatePropertySheetPage(&psp));
                                }

                                {
                                    PROPSHEETPAGE psp = {};
                                    psp.dwSize = sizeof(psp);
                                    psp.dwFlags = PSP_USEHEADERTITLE;
                                    psp.hInstance = AL::System::g_hResource;
                                    psp.pszHeaderTitle = MAKEINTRESOURCE(IDS_AL_IMPORT_CREDENTIALS_TITLE_PAP);
                                    psp.pszTemplate = MAKEINTRESOURCE(IDD_AL_IMPORT_CREDENTIALS_PAP);
                                    psp.pfnDlgProc = _ImportCredentialsDlgProcPAP;
                                    psp.lParam = (LPARAM)&session;
                                    hpsp.Add(CreatePropertySheetPage(&psp));
                                }

                                {
                                    PROPSHEETPAGE psp = {};
                                    psp.dwSize = sizeof(psp);
                                    psp.dwFlags = PSP_USEHEADERTITLE;
                                    psp.hInstance = AL::System::g_hResource;
                                    psp.pszHeaderTitle = MAKEINTRESOURCE(IDS_AL_IMPORT_COMMIT_TITLE);
                                    psp.pszTemplate = MAKEINTRESOURCE(IDD_AL_IMPORT_COMMIT);
                                    psp.pfnDlgProc = _ImportCommitDlgProc;
                                    psp.lParam = (LPARAM)&session;
                                    hpsp.Add(CreatePropertySheetPage(&psp));
                                }

                                {
                                    PROPSHEETPAGE psp = {};
                                    psp.dwSize = sizeof(psp);
                                    psp.dwFlags = PSP_USEHEADERTITLE;
                                    psp.hInstance = AL::System::g_hResource;
                                    psp.pszHeaderTitle = MAKEINTRESOURCE(IDS_AL_IMPORT_FINISH_SUCCESS_TITLE);
                                    psp.pszTemplate = MAKEINTRESOURCE(IDD_AL_IMPORT_FINISH_SUCCESS);
                                    psp.pfnDlgProc = _ImportFinishSuccessDlgProc;
                                    psp.lParam = (LPARAM)&session;
                                    hpsp.Add(CreatePropertySheetPage(&psp));
                                }

                                {
                                    PROPSHEETPAGE psp = {};
                                    psp.dwSize = sizeof(psp);
                                    psp.dwFlags = PSP_USEHEADERTITLE;
                                    psp.hInstance = AL::System::g_hResource;
                                    psp.pszHeaderTitle = MAKEINTRESOURCE(IDS_AL_IMPORT_FINISH_FAILURE_TITLE);
                                    psp.pszTemplate = MAKEINTRESOURCE(IDD_AL_IMPORT_FINISH_FAILURE);
                                    psp.pfnDlgProc = _ImportFinishFailureDlgProc;
                                    psp.lParam = (LPARAM)&session;
                                    hpsp.Add(CreatePropertySheetPage(&psp));
                                }

                                INT_PTR iResult;
                                {
                                    PROPSHEETHEADER psh = { sizeof(psh) };
                                    psh.dwFlags = PSH_AEROWIZARD | PSH_WIZARD | PSH_USEICONID | PSH_USECALLBACK;
                                    psh.hInstance = AL::System::g_hResource;
                                    psh.pszIcon = MAKEINTRESOURCE(IDI_AL_IMPORT);
                                    psh.pszCaption = MAKEINTRESOURCE(IDS_AL_IMPORT_WIZARD);
                                    psh.pfnCallback = _ImportPSProc;
                                    psh.nPages = (UINT)hpsp.GetCount();
                                    psh.phpage = hpsp.GetData();
                                    iResult = PropertySheet(&psh);
                                    dwReturnCode = session.m_dwReturnCode;
                                }
                            }
                        } else {
                            AL_TRACE_ERROR(_T("CoCreateInstance(CLSID_DOMDocument30, IID_IXMLDOMDocument) failed (%x)."), hr);
                            dwReturnCode = HRESULT_CODE(hr);
                        }
                        FreeLibrary(AL::System::g_hResource);
                    } else
                        dwReturnCode = ERROR_INVALID_DATA;
                    LocalFree(pwcArglist);
                }
                AL::Heap::Done();
            }

            CoUninitialize();
        } else {
            AL_TRACE_ERROR(_T("CoInitialize failed (%x)."), hr);
            dwReturnCode = HRESULT_CODE(hr);
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// Property sheet function
//
static int CALLBACK _ImportPSProc(HWND hWnd, UINT uMsg, LPARAM lParam)
{
    if (uMsg == PSCB_INITIALIZED) {
        //
        // Use PostMessage() to set wizard buttons text.
        // PropSheet_SetButtonText macro is using SendMessage(), which doesn't work at this stage of property sheet's life-cycle.
        //
        if (!g_sTextBack.IsEmpty())
            PostMessage(hWnd, PSM_SETBUTTONTEXT, (WPARAM)PSWIZB_BACK, (LPARAM)(LPCTSTR)g_sTextBack);

        if (!g_sTextNext.IsEmpty())
            PostMessage(hWnd, PSM_SETBUTTONTEXT, (WPARAM)PSWIZB_NEXT, (LPARAM)(LPCTSTR)g_sTextNext);

        if (!g_sTextFinish.IsEmpty())
            PostMessage(hWnd, PSM_SETBUTTONTEXT, (WPARAM)PSWIZB_FINISH, (LPARAM)(LPCTSTR)g_sTextFinish);

        if (!g_sTextCancel.IsEmpty())
            PostMessage(hWnd, PSM_SETBUTTONTEXT, (WPARAM)PSWIZB_CANCEL, (LPARAM)(LPCTSTR)g_sTextCancel);
    }

    return 0;
}


//
// Dialog function for the file selection page
//
static INT_PTR CALLBACK _ImportFileDlgProc(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam)
{
    switch (uMsg) {
        case WM_INITDIALOG: {
#ifdef USE_WINXP_THEMES
            EnableThemeDialogTexture(hWnd, ETDT_ENABLEAEROWIZARDTAB);
#endif

            CImportSession *pImportSession = (CImportSession*)(((LPPROPSHEETPAGE)lParam)->lParam);
            SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pImportSession);
            return FALSE;
        }

        case WM_DESTROY: {
            CImportSession *pImportSession = (CImportSession*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

            //
            // Uninitialize data.
            //
            if (pImportSession->m_pXmlDoc)
                pImportSession->m_pXmlDoc.Detach()->Release();

            return FALSE;
        }

        case WM_SHOWWINDOW:
            if (LOWORD(wParam) == TRUE) {
                PropSheet_SetWizButtons(GetParent(hWnd), GetWindowTextLength(GetDlgItem(hWnd, IDC_AL_IMPORT_FILE_NAME)) ? PSWIZB_NEXT : 0);

                return FALSE;
            }
            break;

        case WM_NOTIFY: {
            LPNMHDR pMsgHdr = (LPNMHDR)lParam;
            switch(pMsgHdr->code) {
                case PSN_SETACTIVE: {
                    CImportSession *pImportSession = (CImportSession*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

                    //
                    // Initialize control state.
                    //
                    SetWindowText(GetDlgItem(hWnd, IDC_AL_IMPORT_FILE_NAME), pImportSession->m_sFileName);

                    SetWindowLongPtr(hWnd, DWLP_MSGRESULT, 0);
                    return TRUE;
                }

                case PSN_WIZNEXT: {
                    CImportSession *pImportSession = (CImportSession*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

                    //
                    // Copy control state to data.
                    //
                    GetWindowText(GetDlgItem(hWnd, IDC_AL_IMPORT_FILE_NAME), pImportSession->m_sFileName);

                    SetWindowLongPtr(hWnd, DWLP_MSGRESULT, _ImportFileLoad(hWnd, pImportSession) == NO_ERROR ? 0 : -1);
                    return TRUE;
                }
            }
            break;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_AL_IMPORT_FILE_NAME:
                    if (HIWORD(wParam) == EN_CHANGE)
                        SendMessage(hWnd, WM_SHOWWINDOW, TRUE, 0);
                    return FALSE;

                case IDC_AL_IMPORT_FILE_BROWSE: {
                    HRESULT hr;

                    // Create the FileOpenDialog object.
                    CComPtr<IFileOpenDialog> pFileOpen;
                    if (SUCCEEDED(hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_ALL, IID_IFileOpenDialog, reinterpret_cast<void**>(&pFileOpen)))) {
                        {
                            // Set supported file types.
                            ATL::CAtlString sFileArnesLinkProfile, sFileAll;
                            sFileArnesLinkProfile.LoadString(AL::System::g_hResource, IDS_AL_FILE_ARNESLINK_CONFIG);
                                         sFileAll.LoadString(AL::System::g_hResource, IDS_AL_FILE_ALL             );

                            COMDLG_FILTERSPEC aFileTypes[2] = {
                                { sFileArnesLinkProfile, L"*.arneslink-config-xml;*.xml" },
                                { sFileAll,              L"*.*" }
                            };
                            hr = pFileOpen->SetFileTypes(_countof(aFileTypes), aFileTypes);
                        }

                        {
                            ATL::CAtlString sTemp;

                            // Set dialog's title.
                            sTemp.LoadString(AL::System::g_hResource, IDS_AL_IMPORT_TITLE);
                            hr = pFileOpen->SetTitle(sTemp);

                            // Set OK button's title.
                            sTemp.LoadString(AL::System::g_hResource, IDS_AL_FILE_SELECT);
                            hr = pFileOpen->SetOkButtonLabel(sTemp);

                            // Set Cancel button's title.
                            CComQIPtr<IFileDialog2> pFileOpen2 = pFileOpen;
                            if (pFileOpen2)
                                pFileOpen2->SetCancelButtonLabel(g_sTextCancel);
                        }

                        // Show the Open dialog box.
                        if (SUCCEEDED(hr = pFileOpen->Show(hWnd))) {
                            // Get the file name from the dialog box.
                            CComPtr<IShellItem> pItem;
                            if (SUCCEEDED(hr = pFileOpen->GetResult(&pItem))) {
                                PWSTR pszFilePath;
                                if (SUCCEEDED(hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath))) {
                                    SetWindowTextW(GetDlgItem(hWnd, IDC_AL_IMPORT_FILE_NAME), pszFilePath);
                                    CoTaskMemFree(pszFilePath);
                                }
                            }
                        }
                    }
                    return FALSE;
                }
            }
            break;
    }

    return FALSE;
}


//
// Helper function to load XML file.
//
static DWORD _ImportFileLoad(IN HWND hWnd, IN CImportSession *pImportSession)
{
    DWORD dwReturnCode = NO_ERROR;
    HRESULT hr;

    //
    // Load XML file.
    //
    VARIANT_BOOL vbSucceeded = VARIANT_FALSE;
    if (SUCCEEDED(hr = pImportSession->m_pXmlDoc->load(CComVariant(pImportSession->m_sFileName), &vbSucceeded)) && vbSucceeded) {
        //
        // Get document root and verify its name.
        //
        CComPtr<IXMLDOMElement> pXmlElRoot;
        hr = pImportSession->m_pXmlDoc->get_documentElement(&pXmlElRoot);
        CComBSTR bstrXmlElRootName;
        hr = pXmlElRoot->get_nodeName(&bstrXmlElRootName);
        if (CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrXmlElRootName, bstrXmlElRootName.Length(), L"WLANProfile", -1, NULL, NULL, 0) == CSTR_EQUAL) {
            hr = pImportSession->m_pXmlDoc->setProperty(CComBSTR(L"SelectionNamespaces"), CComVariant(L"xmlns:eap-metadata=\"urn:ietf:params:xml:ns:yang:ietf-eap-metadata\""));

            //
            // Identify EAP method.
            //
            CComPtr<IXMLDOMElement> pXmlEapMethod;
            if ((dwReturnCode = AL::XML::SelectElement(pXmlElRoot, CComBSTR(L"MSM/security/OneX/EAPConfig/EapHostConfig/EapMethod"), &pXmlEapMethod)) == NO_ERROR) {
                //
                // Confirm ArnesLink is the EAP method vendor.
                //
                CComBSTR bstr;
                if ((dwReturnCode = AL::XML::GetElementValue(pXmlEapMethod, CComBSTR(L"AuthorId"), &bstr)) == NO_ERROR) {
                    //
                    // Is ArnesLink the vendor? Is EAP config is stored as urn:ietf:params:xml:ns:yang:ietf-eap-metadata?
                    //
                    pImportSession->m_fIsEAPMetadataDraft = wcstoul(bstr, NULL, 10) == AL_EAP_AUTHOR_ID ? TRUE : FALSE;
                } else {
                    ATL::CAtlString sFormat, sText, sCaption;
                    sFormat.LoadString(AL::System::g_hResource, IDS_AL_ERROR_IMPORT_WIZARD_CONTENT);
                    sText.FormatMessage(sFormat);
                    sCaption.LoadString(AL::System::g_hResource, IDS_AL_ERROR_ERROR);
                    MessageBox(hWnd, sText, sCaption, MB_ICONERROR | MB_OK);
                }
            } else {
                ATL::CAtlString sFormat, sText, sCaption;
                sFormat.LoadString(AL::System::g_hResource, IDS_AL_ERROR_IMPORT_WIZARD_CONTENT);
                sText.FormatMessage(sFormat);
                sCaption.LoadString(AL::System::g_hResource, IDS_AL_ERROR_ERROR);
                MessageBox(hWnd, sText, sCaption, MB_ICONERROR | MB_OK);
            }
        } else {
            ATL::CAtlString sFormat, sText, sCaption;
            sFormat.LoadString(AL::System::g_hResource, IDS_AL_ERROR_IMPORT_ROOT);
            sText.FormatMessage(sFormat, L"WLANProfile", (LPCWSTR)bstrXmlElRootName);
            sCaption.LoadString(AL::System::g_hResource, IDS_AL_ERROR_ERROR);
            MessageBox(hWnd, sText, sCaption, MB_ICONERROR | MB_OK);
            dwReturnCode = ERROR_NOT_FOUND;
        }
    } else {
        ATL::CAtlString sFormat, sText, sCaption;
        sFormat.LoadString(AL::System::g_hResource, IDS_AL_ERROR_IMPORT_WIZARD_READ);
        sText.FormatMessage(sFormat, (LPCWSTR)(pImportSession->m_sFileName), hr);
        sCaption.LoadString(AL::System::g_hResource, IDS_AL_ERROR_ERROR);
        MessageBox(hWnd, sText, sCaption, MB_ICONERROR | MB_OK);
        dwReturnCode = HRESULT_CODE(hr);
    }

    return dwReturnCode;
}


//
// Dialog function for the profile selection page
//
static INT_PTR CALLBACK _ImportProfileDlgProc(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam)
{
    switch (uMsg) {
        case WM_INITDIALOG: {
            CImportSession *pImportSession = (CImportSession*)(((LPPROPSHEETPAGE)lParam)->lParam);

#ifdef USE_WINXP_THEMES
            EnableThemeDialogTexture(hWnd, ETDT_ENABLEAEROWIZARDTAB);
#endif

            SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pImportSession);
            return FALSE;
        }

        case WM_SHOWWINDOW:
            if (LOWORD(wParam) == TRUE) {
                PropSheet_SetWizButtons(GetParent(hWnd), (SendMessage(GetDlgItem(hWnd, IDD_AL_IMPORT_PROVIDER_LIST), LB_GETCURSEL, 0, 0) != LB_ERR ? PSWIZB_NEXT : 0) | PSWIZB_BACK);

                return FALSE;
            }
            break;

        case WM_NOTIFY: {
            LPNMHDR pMsgHdr = (LPNMHDR)lParam;
            switch(pMsgHdr->code) {
                case PSN_SETACTIVE: {
                    CImportSession *pImportSession = (CImportSession*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
                    long lNumProviders = 0;

                    if (pImportSession->m_fIsEAPMetadataDraft) {
                        //
                        // Initialize controls.
                        //
                        HWND hWndList = GetDlgItem(hWnd, IDD_AL_IMPORT_PROVIDER_LIST);
                        SendMessage(hWndList, LB_RESETCONTENT, 0, 0);
                        DWORD dwReturnCode;
                        CComPtr<IXMLDOMNodeList> pXmlListProviders;
                        if ((dwReturnCode = AL::XML::SelectNodes(pImportSession->m_pXmlDoc, CComBSTR(L"WLANProfile/MSM/security/OneX/EAPConfig/EapHostConfig/Config/eap-metadata:EAPIdentityProviderList/eap-metadata:EAPIdentityProvider"), &pXmlListProviders)) == NO_ERROR) {
                            HRESULT hr;
                            hr = pXmlListProviders->get_length(&lNumProviders);
                            for (long i = 0; i < lNumProviders; i++) {
                                CComPtr<IXMLDOMNode> pXmlElProvider;
                                hr = pXmlListProviders->get_item(i, &pXmlElProvider);
                                CComBSTR bstr;
                                if ((dwReturnCode = AL::XML::GetElementValue(pXmlElProvider, CComBSTR(L"eap-metadata:ID"), &bstr)) == NO_ERROR) {
                                    LRESULT lResult;
                                    if ((lResult = SendMessage(hWndList, LB_ADDSTRING, 0, (LPARAM)(LPWSTR)bstr)) != LB_ERR && lResult != LB_ERRSPACE) {
                                        if (SendMessage(hWndList, LB_SETITEMDATA, lResult, (LPARAM)i) == LB_ERR)
                                            AL_TRACE_ERROR(_T("SendMessage(LB_SETITEMDATA) failed."));
                                    } else
                                        AL_TRACE_ERROR(_T("SendMessage(LB_ADDSTRING) failed."));
                                }
                            }
                        }
                    }

                    SetWindowLongPtr(hWnd, DWLP_MSGRESULT, lNumProviders > 1 ? 0 : -1);
                    return TRUE;
                }

                case PSN_WIZNEXT: {
                    CImportSession *pImportSession = (CImportSession*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
                    LONG lReturnCode = -1;

                    //
                    // Get selected security provider.
                    //
                    HWND hWndList = GetDlgItem(hWnd, IDD_AL_IMPORT_PROVIDER_LIST);
                    LRESULT lResult;
                    if ((lResult = SendMessage(hWndList, LB_GETCURSEL, 0, 0)) != LB_ERR) {
                        if ((lResult = SendMessage(hWndList, LB_GETITEMDATA, lResult, NULL)) != LB_ERR) {
                            //
                            // Allow to continue.
                            //
                            pImportSession->m_lSecurityProviderIndex = (long)lResult;
                            lReturnCode = 0;
                        }
                    }

                    SetWindowLongPtr(hWnd, DWLP_MSGRESULT, lReturnCode);
                    return TRUE;
                }
            }
            break;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDD_AL_IMPORT_PROVIDER_LIST:
                    if (HIWORD(wParam) == LBN_SELCHANGE) {
                        SendMessage(hWnd, WM_SHOWWINDOW, TRUE, 0);
                        return FALSE;
                    }
                    break;
            }
            break;
    }

    return FALSE;
}


//
// Dialog function for the credentials selection page
//
static INT_PTR CALLBACK _ImportCredentialsDlgProcEAP(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam)
{
    struct DLGDATA {
        CImportSession *pImportSession;
        ATL::CAtlArray<BYTE> aEAPConnectionData;
    };

    switch (uMsg) {
        case WM_INITDIALOG: {
#ifdef USE_WINXP_THEMES
            EnableThemeDialogTexture(hWnd, ETDT_ENABLEAEROWIZARDTAB);
#endif

            DLGDATA *pDlgData = new DLGDATA;
            pDlgData->pImportSession = (CImportSession*)(((LPPROPSHEETPAGE)lParam)->lParam);
            SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pDlgData);

            {
                ATL::CAtlString sTemp;
                if (sTemp.LoadString(AL::System::g_hResource, IDS_AL_IMPORT_CREDENTIALS_SET_NOTE))
                    SendMessage(GetDlgItem(hWnd, IDC_AL_IMPORT_CREDENTIALS_EAP_SET), BCM_SETNOTE, 0, (LPARAM)(LPCTSTR)sTemp);
                if (sTemp.LoadString(AL::System::g_hResource, IDS_AL_IMPORT_CREDENTIALS_CLR_NOTE))
                    SendMessage(GetDlgItem(hWnd, IDC_AL_IMPORT_CREDENTIALS_EAP_CLR), BCM_SETNOTE, 0, (LPARAM)(LPCTSTR)sTemp);
            }

            return FALSE;
        }

        case WM_DESTROY: {
            DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
            delete pDlgData;
            return FALSE;
        }

        case WM_NOTIFY: {
            LPNMHDR pMsgHdr = (LPNMHDR)lParam;
            switch(pMsgHdr->code) {
                case PSN_SETACTIVE: {
                    DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

                    if (pDlgData->pImportSession->m_fIsEAPMetadataDraft) {
                        //
                        // Initialize controls.
                        //
                        DWORD dwReturnCode;
                        CComPtr<IXMLDOMNodeList> pXmlListProviders;
                        if ((dwReturnCode = AL::XML::SelectNodes(pDlgData->pImportSession->m_pXmlDoc, CComBSTR(L"WLANProfile/MSM/security/OneX/EAPConfig/EapHostConfig/Config/eap-metadata:EAPIdentityProviderList/eap-metadata:EAPIdentityProvider"), &pXmlListProviders)) == NO_ERROR) {
                            HRESULT hr;
                            CComPtr<IXMLDOMNode> pXmlElProvider;
                            hr = pXmlListProviders->get_item(pDlgData->pImportSession->m_lSecurityProviderIndex, &pXmlElProvider);

                            {
                                //
                                // Read the EAP type.
                                //
                                CComPtr<IXMLDOMNode> pXmlElAuthenticationMethod;
                                DWORD dwEAPType, dwEAPTypeInner;
                                if ((dwReturnCode = AL::XML::SelectNode(pXmlElProvider, CComBSTR(L"eap-metadata:AuthenticationMethods/eap-metadata:AuthenticationMethod"), &pXmlElAuthenticationMethod)) != NO_ERROR ||
                                    (dwReturnCode = AL::XML::GetElementValue(pXmlElAuthenticationMethod, CComBSTR(L"eap-metadata:EAPMethod"), &dwEAPType)) != NO_ERROR ||
                                    dwEAPType != AL_EAP_TYPE_PEAP && (dwEAPType != AL_EAP_TYPE_TTLS ||
                                    (dwReturnCode = AL::XML::GetElementValue(pXmlElAuthenticationMethod, CComBSTR(L"eap-metadata:InnerAuthenticationMethod/eap-metadata:EAPMethod"), &dwEAPTypeInner)) != NO_ERROR ||
                                    dwEAPTypeInner != AL_EAP_TYPE_MSCHAPV2))
                                {
                                    //
                                    // Not using MSCHAPv2 for inner authentication method.
                                    //
                                    SetWindowLongPtr(hWnd, DWLP_MSGRESULT, -1);
                                    return TRUE;
                                }
                            }

                            //
                            // <AuthenticationMethods><AuthenticationMethod><InnerAuthenticationMethod><ClientSideCredential>
                            //
                            CComPtr<IXMLDOMNode> pXmlElClientSideCredential;
                            if ((dwReturnCode = AL::XML::SelectNode(pXmlElProvider, CComBSTR(L"eap-metadata:AuthenticationMethods/eap-metadata:AuthenticationMethod/eap-metadata:InnerAuthenticationMethod/eap-metadata:ClientSideCredential"), &pXmlElClientSideCredential)) == NO_ERROR) {
                                //
                                // <UserName>
                                //
                                dwReturnCode = AL::XML::GetElementValue(pXmlElClientSideCredential, CComBSTR(L"eap-metadata:UserName"), pDlgData->pImportSession->m_sIdentity);

                                //
                                // <Password>
                                //
                                dwReturnCode = AL::XML::GetElementBase64(pXmlElClientSideCredential, CComBSTR(L"eap-metadata:Password"), pDlgData->pImportSession->m_aEAPUserData);
                            }

                            //
                            // <AuthenticationMethods><AuthenticationMethod><InnerAuthenticationMethod><VendorSpecific>
                            //
                            CComPtr<IXMLDOMNode> pXmlElVendorSpecific;
                            if ((dwReturnCode = AL::XML::SelectNode(pXmlElProvider, CComBSTR(L"eap-metadata:AuthenticationMethods/eap-metadata:AuthenticationMethod/eap-metadata:InnerAuthenticationMethod/eap-metadata:VendorSpecific"), &pXmlElVendorSpecific)) == NO_ERROR) {
                                //
                                // <EAPConnectionData>
                                //
                                dwReturnCode = AL::XML::GetElementBase64(pXmlElVendorSpecific, CComBSTR(L"eap-metadata:EAPConnectionData"), pDlgData->aEAPConnectionData);
                            }
                        }

                        PropSheet_SetWizButtons(GetParent(hWnd), PSWIZB_BACK);

                        SetWindowLongPtr(hWnd, DWLP_MSGRESULT, 0);
                    } else
                        SetWindowLongPtr(hWnd, DWLP_MSGRESULT, -1);

                    return TRUE;
                }
            }
            break;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_AL_IMPORT_CREDENTIALS_EAP_SET: {
                    DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

                    //
                    // Query EAP DLL.
                    //
                    AL::RASEAP::CPeerData eapcfg;
                    if (eapcfg.Load(AL_EAP_TYPE_MSCHAPV2) == NO_ERROR) {
                        //
                        // Connect to EAP DLL.
                        //
                        AL::RASEAP::CPeerIdentity eap;
                        if (eap.Load(&eapcfg) == NO_ERROR) {
                            //
                            // Show user credentials dialog
                            //
                            LPBYTE pbInnerEapUserDataOut = NULL;
                            DWORD dwInnerEapUserDataOutSize = 0;
                            WCHAR *pwcInnerEapIdentityOut = NULL;
                            if (eap.RasEapGetIdentity(eapcfg.m_dwType, hWnd, 0, NULL, NULL, pDlgData->aEAPConnectionData.GetData(), (DWORD)pDlgData->aEAPConnectionData.GetCount(), pDlgData->pImportSession->m_aEAPUserData.GetData(), (DWORD)pDlgData->pImportSession->m_aEAPUserData.GetCount(), &pbInnerEapUserDataOut, &dwInnerEapUserDataOutSize, &pwcInnerEapIdentityOut) == NO_ERROR) {
                                //
                                // Copy the inner user data if any and then free it.
                                //
                                if (pbInnerEapUserDataOut) {
                                    if (pDlgData->pImportSession->m_aEAPUserData.SetCount(dwInnerEapUserDataOutSize))
                                        memcpy(pDlgData->pImportSession->m_aEAPUserData.GetData(), pbInnerEapUserDataOut, dwInnerEapUserDataOutSize);
                                } else
                                    pDlgData->pImportSession->m_aEAPUserData.RemoveAll();

                                if (pwcInnerEapIdentityOut) {
                                    pDlgData->pImportSession->m_sIdentity = pwcInnerEapIdentityOut;
                                    AL_TRACE_DEBUG(_T("pwcInnerIdentityOut: %ls"), pwcInnerEapIdentityOut);
                                }

                                PropSheet_PressButton(GetParent(hWnd), PSBTN_NEXT);
                            } else
                                AL_TRACE_ERROR(_T("RasEapGetIdentity failed."));

                            if (pbInnerEapUserDataOut)
                                eap.RasEapFreeMemory(pbInnerEapUserDataOut);
                            if (pwcInnerEapIdentityOut)
                                eap.RasEapFreeMemory((LPBYTE)pwcInnerEapIdentityOut);
                        }
                    }
                    break;
                }

                case IDC_AL_IMPORT_CREDENTIALS_EAP_CLR: {
                    DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
                    pDlgData->pImportSession->m_aEAPUserData.SetCount(0);
                    pDlgData->pImportSession->m_sIdentity.Empty();
                    PropSheet_PressButton(GetParent(hWnd), PSBTN_NEXT);
                    break;
                }
            }
            break;
    }

    return FALSE;
}


//
// Dialog function for the credentials selection page
//
static INT_PTR CALLBACK _ImportCredentialsDlgProcPAP(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam)
{
    struct DLGDATA {
        CImportSession *pImportSession;
        BOOL bPasswordChanged;
    };

    switch (uMsg) {
        case WM_INITDIALOG: {
#ifdef USE_WINXP_THEMES
            EnableThemeDialogTexture(hWnd, ETDT_ENABLEAEROWIZARDTAB);
#endif

            DLGDATA *pDlgData = new DLGDATA;
            pDlgData->pImportSession = (CImportSession*)(((LPPROPSHEETPAGE)lParam)->lParam);
            pDlgData->bPasswordChanged = FALSE;
            SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pDlgData);

            return FALSE;
        }

        case WM_DESTROY: {
            DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
            delete pDlgData;
            return FALSE;
        }

        case WM_NOTIFY: {
            LPNMHDR pMsgHdr = (LPNMHDR)lParam;
            switch(pMsgHdr->code) {
                case PSN_SETACTIVE: {
                    DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

                    if (pDlgData->pImportSession->m_fIsEAPMetadataDraft) {
                        //
                        // Initialize controls.
                        //
                        DWORD dwReturnCode;
                        CComPtr<IXMLDOMNodeList> pXmlListProviders;
                        if ((dwReturnCode = AL::XML::SelectNodes(pDlgData->pImportSession->m_pXmlDoc, CComBSTR(L"WLANProfile/MSM/security/OneX/EAPConfig/EapHostConfig/Config/eap-metadata:EAPIdentityProviderList/eap-metadata:EAPIdentityProvider"), &pXmlListProviders)) == NO_ERROR) {
                            HRESULT hr;
                            CComPtr<IXMLDOMNode> pXmlElProvider;
                            hr = pXmlListProviders->get_item(pDlgData->pImportSession->m_lSecurityProviderIndex, &pXmlElProvider);

                            {
                                //
                                // Read the EAP type.
                                //
                                CComPtr<IXMLDOMNode> pXmlElAuthenticationMethod;
                                DWORD dwEAPType;
                                CComBSTR bstrNonEAPMethod;
                                if ((dwReturnCode = AL::XML::SelectNode(pXmlElProvider, CComBSTR(L"eap-metadata:AuthenticationMethods/eap-metadata:AuthenticationMethod"), &pXmlElAuthenticationMethod)) != NO_ERROR ||
                                    (dwReturnCode = AL::XML::GetElementValue(pXmlElAuthenticationMethod, CComBSTR(L"eap-metadata:EAPMethod"), &dwEAPType)) != NO_ERROR ||
                                    dwEAPType != AL_EAP_TYPE_TTLS ||
                                    (dwReturnCode = AL::XML::GetElementValue(pXmlElAuthenticationMethod, CComBSTR(L"eap-metadata:InnerAuthenticationMethod/eap-metadata:NonEAPAuthMethod"), &bstrNonEAPMethod)) != NO_ERROR ||
                                    CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrNonEAPMethod, bstrNonEAPMethod.Length(), L"PAP", -1, NULL, NULL, 0) != CSTR_EQUAL)
                                {
                                    //
                                    // Not using PAP for inner authentication method.
                                    //
                                    SetWindowLongPtr(hWnd, DWLP_MSGRESULT, -1);
                                    return TRUE;
                                }
                            }

                            {
                                //
                                // <ProviderInfo>
                                //
                                CComPtr<IXMLDOMElement> pXmlElProviderInfo;
                                if ((dwReturnCode = AL::XML::SelectElement(pXmlElProvider, CComBSTR(L"eap-metadata:ProviderInfo"), &pXmlElProviderInfo)) == NO_ERROR) {
                                    {
                                        //
                                        // <CredentialPrompt>
                                        //
                                        CComBSTR bstr;
                                        if ((dwReturnCode = AL::XML::GetElementLocalized(pXmlElProviderInfo, CComBSTR(L"eap-metadata:CredentialPrompt"), g_sLang, &bstr)) == NO_ERROR)
                                            SetWindowText(GetDlgItem(hWnd, IDC_AL_IMPORT_CREDENTIALS_PAP_DESCRIPTION), bstr);
                                    }

                                    {
                                        //
                                        // <UserNameLabel>
                                        //
                                        CComBSTR bstr;
                                        if ((dwReturnCode = AL::XML::GetElementLocalized(pXmlElProviderInfo, CComBSTR(L"eap-metadata:UserNameLabel"), g_sLang, &bstr)) == NO_ERROR)
                                            SetWindowText(GetDlgItem(hWnd, IDC_AL_IMPORT_CREDENTIALS_PAP_USERNAME_LBL), bstr);
                                    }

                                    {
                                        //
                                        // <PasswordLabel>
                                        //
                                        CComBSTR bstr;
                                        if ((dwReturnCode = AL::XML::GetElementLocalized(pXmlElProviderInfo, CComBSTR(L"eap-metadata:PasswordLabel"), g_sLang, &bstr)) == NO_ERROR)
                                            SetWindowText(GetDlgItem(hWnd, IDC_AL_IMPORT_CREDENTIALS_PAP_PASSWORD_LBL), bstr);
                                    }
                                }
                            }

                            //
                            // <AuthenticationMethods><AuthenticationMethod><InnerAuthenticationMethod><ClientSideCredential>
                            //
                            CComPtr<IXMLDOMNode> pXmlElClientSideCredential;
                            if ((dwReturnCode = AL::XML::SelectNode(pXmlElProvider, CComBSTR(L"eap-metadata:AuthenticationMethods/eap-metadata:AuthenticationMethod/eap-metadata:InnerAuthenticationMethod/eap-metadata:ClientSideCredential"), &pXmlElClientSideCredential)) == NO_ERROR) {
                                //
                                // <UserName>
                                //
                                if ((dwReturnCode = AL::XML::GetElementValue(pXmlElClientSideCredential, CComBSTR(L"eap-metadata:UserName"), pDlgData->pImportSession->m_sIdentity)) == NO_ERROR && !pDlgData->pImportSession->m_sIdentity.IsEmpty())
                                    SetWindowText(GetDlgItem(hWnd, IDC_AL_IMPORT_CREDENTIALS_PAP_USERNAME), pDlgData->pImportSession->m_sIdentity);

                                //
                                // <Password>
                                //
                                if ((dwReturnCode = AL::XML::GetElementEncrypted(pXmlElClientSideCredential, CComBSTR(L"eap-metadata:Password"), pDlgData->pImportSession->m_sPassword)) == NO_ERROR && !pDlgData->pImportSession->m_sPassword.IsEmpty())
                                    SetWindowText(GetDlgItem(hWnd, IDC_AL_IMPORT_CREDENTIALS_PAP_PASSWORD), _T("password"));
                                pDlgData->bPasswordChanged = FALSE;
                            }
                        }

                        PropSheet_SetWizButtons(GetParent(hWnd), PSWIZB_BACK | PSWIZB_NEXT);

                        SetWindowLongPtr(hWnd, DWLP_MSGRESULT, 0);
                    } else
                        SetWindowLongPtr(hWnd, DWLP_MSGRESULT, -1);

                    return TRUE;
                }

                case PSN_WIZNEXT: {
                    DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

                    GetWindowTextW(GetDlgItem(hWnd, IDC_AL_IMPORT_CREDENTIALS_PAP_USERNAME), pDlgData->pImportSession->m_sIdentity);
                    if (pDlgData->bPasswordChanged)
                        GetWindowTextW(GetDlgItem(hWnd, IDC_AL_IMPORT_CREDENTIALS_PAP_PASSWORD), pDlgData->pImportSession->m_sPassword);

                    SetWindowLongPtr(hWnd, DWLP_MSGRESULT, 0);
                    return TRUE;
                }
            }
            break;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_AL_IMPORT_CREDENTIALS_PAP_PASSWORD:
                    if (HIWORD(wParam) == EN_CHANGE) {
                        DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
                        pDlgData->bPasswordChanged = TRUE;
                        return FALSE;
                    }
                    break;
            }
            break;
    }

    return FALSE;
}


//
// Dialog function for the import commit page
//
static INT_PTR CALLBACK _ImportCommitDlgProc(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam)
{
    struct DLGDATA {
        CImportSession *pImportSession;
        CImportCommitThreadSession ThreadSession;
        HANDLE hThread;
    };

    switch (uMsg) {
        case WM_INITDIALOG: {
#ifdef USE_WINXP_THEMES
            EnableThemeDialogTexture(hWnd, ETDT_ENABLEAEROWIZARDTAB);
#endif

            DLGDATA *pDlgData = new DLGDATA;
            pDlgData->pImportSession                 = (CImportSession*)(((LPPROPSHEETPAGE)lParam)->lParam);
            pDlgData->hThread                        = NULL;
            pDlgData->ThreadSession.m_pImportSession = (CImportSession*)(((LPPROPSHEETPAGE)lParam)->lParam);
            pDlgData->ThreadSession.m_hWndWizard     = GetParent(hWnd);
            pDlgData->ThreadSession.m_hWndProgress   = GetDlgItem(hWnd, IDC_AL_IMPORT_COMMIT_PROGRESS);
            if ((pDlgData->ThreadSession.m_hEventCancel = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL)
                AL_TRACE_ERROR(_T("CreateEvent failed (%ld)."), GetLastError());

            SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pDlgData);

            return FALSE;
        }

        case WM_DESTROY: {
            DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

            if (pDlgData->ThreadSession.m_hEventCancel)
                CloseHandle(pDlgData->ThreadSession.m_hEventCancel);

            delete pDlgData;
            return FALSE;
        }

        case WM_NOTIFY: {
            LPNMHDR pMsgHdr = (LPNMHDR)lParam;
            switch(pMsgHdr->code) {
                case PSN_SETACTIVE: {
                    DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

                    PropSheet_ShowWizButtons(GetParent(hWnd), PSWIZB_CANCEL, PSWIZB_BACK | PSWIZB_NEXT | PSWIZB_CANCEL);

                    //
                    // Spawn worker thread.
                    //
                    ResetEvent(pDlgData->ThreadSession.m_hEventCancel);
                    if ((pDlgData->hThread = CreateThread(NULL, 0, _ImportCommitThread, &(pDlgData->ThreadSession), 0, NULL)) == NULL)
                        AL_TRACE_ERROR(_T("CreateThread failed (%ld)."), GetLastError());

                    SetWindowLongPtr(hWnd, DWLP_MSGRESULT, 0);
                    return TRUE;
                }

                case PSN_QUERYCANCEL: {
                    DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

                    SetEvent(pDlgData->ThreadSession.m_hEventCancel);
                    if (pDlgData->hThread) {
                        //
                        // Wait and terminate worker thread.
                        //
                        WaitForSingleObject(pDlgData->hThread, INFINITE);
                        CloseHandle(pDlgData->hThread);
                        pDlgData->hThread = NULL;
                    }

                    return FALSE;
                }

                case PSN_WIZNEXT: {
                    DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

                    if (pDlgData->hThread) {
                        //
                        // Wait and terminate worker thread.
                        //
                        WaitForSingleObject(pDlgData->hThread, INFINITE);
                        CloseHandle(pDlgData->hThread);
                        pDlgData->hThread = NULL;
                    }

                    SetWindowLongPtr(hWnd, DWLP_MSGRESULT, 0);
                    return TRUE;
                }
            }
            break;
        }
    }

    return FALSE;
}


static DWORD WINAPI _ImportCommitThread(IN LPVOID lpThreadParameter)
{
    CImportCommitThreadSession *pThreadSession = (CImportCommitThreadSession*)lpThreadParameter;
    DWORD dwReturnCode;
    HRESULT hr;

    if (!pThreadSession)
        return ERROR_INVALID_PARAMETER;

    if (pThreadSession->m_hWndProgress) {
        SendMessage(pThreadSession->m_hWndProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 4));
        SendMessage(pThreadSession->m_hWndProgress, PBM_SETPOS  , 0, 0);
    }
    if (WaitForSingleObject(pThreadSession->m_hEventCancel, 0) == WAIT_OBJECT_0)
        return ERROR_CANCELLED;

    pThreadSession->m_pImportSession->m_dwReturnCode = NO_ERROR;

    if (pThreadSession->m_pImportSession->m_fIsEAPMetadataDraft) {
        CComPtr<IXMLDOMNode> pXmlElProvider;
        {
            //
            // Remove excess providers from profile.
            //
            CComPtr<IXMLDOMNode> pXmlElProviderList;
            if ((dwReturnCode = AL::XML::SelectNode(pThreadSession->m_pImportSession->m_pXmlDoc, CComBSTR(L"WLANProfile/MSM/security/OneX/EAPConfig/EapHostConfig/Config/eap-metadata:EAPIdentityProviderList"), &pXmlElProviderList)) == NO_ERROR) {
                CComPtr<IXMLDOMNodeList> pXmlListProviders;
                if ((dwReturnCode = AL::XML::SelectNodes(pXmlElProviderList, CComBSTR(L"eap-metadata:EAPIdentityProvider"), &pXmlListProviders)) == NO_ERROR) {
                    long lNumProviders = 0;
                    hr = pXmlListProviders->get_length(&lNumProviders);
                    for (long i = lNumProviders; i--;) {
                        if (i != pThreadSession->m_pImportSession->m_lSecurityProviderIndex) {
                            CComPtr<IXMLDOMNode> pXmlElProvider;
                            hr = pXmlListProviders->get_item(i, &pXmlElProvider);
                            hr = pXmlElProviderList->removeChild(pXmlElProvider, NULL);
                        } else
                            hr = pXmlListProviders->get_item(i, &pXmlElProvider);
                    }
                }
            }
        }
        if (pXmlElProvider) {
            if (pThreadSession->m_hWndProgress)
                SendMessage(pThreadSession->m_hWndProgress, PBM_SETPOS, 1, 0);
            if (WaitForSingleObject(pThreadSession->m_hEventCancel, 0) == WAIT_OBJECT_0)
                return ERROR_CANCELLED;

            if (!pThreadSession->m_pImportSession->m_sIdentity.IsEmpty() ||
                !pThreadSession->m_pImportSession->m_sPassword.IsEmpty() ||
                !pThreadSession->m_pImportSession->m_aEAPUserData.IsEmpty())
            {
                //
                // Inject credentials.
                //
                CComBSTR bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");

                CComPtr<IXMLDOMNodeList> pXmlListAuthenticationMethods;
                if ((dwReturnCode = AL::XML::SelectNodes(pXmlElProvider, CComBSTR(L"eap-metadata:AuthenticationMethods/eap-metadata:AuthenticationMethod"), &pXmlListAuthenticationMethods)) == NO_ERROR) {
                    long lNumMethods = 0;
                    hr = pXmlListAuthenticationMethods->get_length(&lNumMethods);
                    for (long i = 0; i < lNumMethods; i++) {
                        CComPtr<IXMLDOMNode> pXmlElAuthenticationMethod;
                        hr = pXmlListAuthenticationMethods->get_item(i, &pXmlElAuthenticationMethod);

                        CComPtr<IXMLDOMElement> pXmlElInnerAuthenticationMethod;
                        if ((dwReturnCode = AL::XML::SelectElement(pXmlElAuthenticationMethod, CComBSTR(L"eap-metadata:InnerAuthenticationMethod"), &pXmlElInnerAuthenticationMethod) == NO_ERROR ?
                            NO_ERROR : 
                            AL::XML::PutElement(pThreadSession->m_pImportSession->m_pXmlDoc, pXmlElAuthenticationMethod, CComBSTR(L"InnerAuthenticationMethod"), bstrNamespace, &pXmlElInnerAuthenticationMethod)) == NO_ERROR)
                        {
                            CComPtr<IXMLDOMElement> pXmlElClientSideCredential;
                            if ((dwReturnCode = AL::XML::SelectElement(pXmlElInnerAuthenticationMethod, CComBSTR(L"eap-metadata:ClientSideCredential"), &pXmlElClientSideCredential) == NO_ERROR ?
                                NO_ERROR : 
                                AL::XML::PutElement(pThreadSession->m_pImportSession->m_pXmlDoc, pXmlElInnerAuthenticationMethod, CComBSTR(L"ClientSideCredential"), bstrNamespace, &pXmlElClientSideCredential)) == NO_ERROR)
                            {
                                if (!pThreadSession->m_pImportSession->m_sIdentity.IsEmpty()) {
                                    //
                                    // Write <UserName>.
                                    //
                                    CComPtr<IXMLDOMNode> pXmlEl;
                                    if ((dwReturnCode = AL::XML::SelectNode(pXmlElClientSideCredential, CComBSTR(L"eap-metadata:UserName"), &pXmlEl)) == NO_ERROR)
                                        pXmlElClientSideCredential->removeChild(pXmlEl, NULL);
                                    dwReturnCode = AL::XML::PutElementValue(pThreadSession->m_pImportSession->m_pXmlDoc, pXmlElClientSideCredential, CComBSTR(L"UserName"), bstrNamespace, CComBSTR(pThreadSession->m_pImportSession->m_sIdentity));
                                }

                                if (!pThreadSession->m_pImportSession->m_sPassword.IsEmpty()) {
                                    //
                                    // Write <Password>.
                                    //
                                    CComPtr<IXMLDOMNode> pXmlEl;
                                    if ((dwReturnCode = AL::XML::SelectNode(pXmlElClientSideCredential, CComBSTR(L"eap-metadata:Password"), &pXmlEl)) == NO_ERROR)
                                        pXmlElClientSideCredential->removeChild(pXmlEl, NULL);
                                    dwReturnCode = AL::XML::PutElementEncrypted(pThreadSession->m_pImportSession->m_pXmlDoc, pXmlElClientSideCredential, CComBSTR(L"Password"), bstrNamespace, pThreadSession->m_pImportSession->m_sPassword.GetBuffer(), sizeof(WCHAR)*pThreadSession->m_pImportSession->m_sPassword.GetLength());
                                }

                                if (!pThreadSession->m_pImportSession->m_aEAPUserData.IsEmpty()) {
                                    //
                                    // Write <Password>.
                                    //
                                    CComPtr<IXMLDOMNode> pXmlEl;
                                    if ((dwReturnCode = AL::XML::SelectNode(pXmlElClientSideCredential, CComBSTR(L"eap-metadata:Password"), &pXmlEl)) == NO_ERROR)
                                        pXmlElClientSideCredential->removeChild(pXmlEl, NULL);
                                    dwReturnCode = AL::XML::PutElementBase64(pThreadSession->m_pImportSession->m_pXmlDoc, pXmlElClientSideCredential, CComBSTR(L"Password"), bstrNamespace, pThreadSession->m_pImportSession->m_aEAPUserData.GetData(), pThreadSession->m_pImportSession->m_aEAPUserData.GetCount());
                                }
                            } else
                                AL_TRACE_ERROR(_T("Creating <ClientSideCredential> failed (%ld)."), dwReturnCode);
                        } else
                            AL_TRACE_ERROR(_T("Creating <InnerAuthenticationMethod> failed (%ld)."), dwReturnCode);
                    }
                }
            }
        } else {
            pThreadSession->m_pImportSession->m_dwReturnCode = ERROR_NOT_FOUND;
            pThreadSession->m_pImportSession->m_sErrorDescription.LoadString(AL::System::g_hResource, IDS_AL_ERROR_IMPORT_WIZARD_PROFILE);
        }

        if (pThreadSession->m_hWndProgress)
            SendMessage(pThreadSession->m_hWndProgress, PBM_SETPOS, 2, 0);
        if (WaitForSingleObject(pThreadSession->m_hEventCancel, 0) == WAIT_OBJECT_0)
            return ERROR_CANCELLED;
    }

    if (pThreadSession->m_pImportSession->m_dwReturnCode == NO_ERROR) {
        //
        // Get a profile name.
        //
        CComBSTR bstrProfileName;
        if ((dwReturnCode = AL::XML::GetElementValue(pThreadSession->m_pImportSession->m_pXmlDoc, CComBSTR(L"WLANProfile/name"), &bstrProfileName)) == NO_ERROR) {
            //
            // Save XML to memory.
            //
            HGLOBAL hXML = NULL;
            {
                CComPtr<IStream> pStream;
                if (SUCCEEDED(hr = CreateStreamOnHGlobal(NULL, FALSE, &pStream))) {
                    //
                    // Fix XML header to produce UTF-16 output.
                    //
                    {
                        CComPtr<IXMLDOMNode> pXmlFirstChild;
                        CComPtr<IXMLDOMProcessingInstruction> pXmlProcInstr;
                        DOMNodeType XmlElType;

                        hr = pThreadSession->m_pImportSession->m_pXmlDoc->createProcessingInstruction(L"xml", L"version=\"1.0\" encoding=\"UTF-16\"", &pXmlProcInstr);
                        hr = pThreadSession->m_pImportSession->m_pXmlDoc->get_firstChild(&pXmlFirstChild);
                        hr = pXmlFirstChild->get_nodeType(&XmlElType);
                        if (XmlElType == NODE_PROCESSING_INSTRUCTION)
                            hr = pThreadSession->m_pImportSession->m_pXmlDoc->replaceChild(pXmlProcInstr, pXmlFirstChild, NULL);
                        else
                            hr = pThreadSession->m_pImportSession->m_pXmlDoc->insertBefore(pXmlProcInstr, CComVariant(pXmlFirstChild), NULL);
                    }

                    if (SUCCEEDED(hr = pThreadSession->m_pImportSession->m_pXmlDoc->save(CComVariant(pStream)))) {
                        ULONG ulWritten;
                        hr = pStream->Write(L"", sizeof(WCHAR), &ulWritten);
                        hr = GetHGlobalFromStream(pStream, &hXML);
                    }
                }
            }
            if (hXML) {
                LPCWSTR pszXML = (LPCWSTR)GlobalLock(hXML);

                if (pszXML[0] == 0xFEFF) {
                    // Skip UTF-16 BOM marker.
                    pszXML++;
                }

                if (pThreadSession->m_hWndProgress)
                    SendMessage(pThreadSession->m_hWndProgress, PBM_SETPOS, 3, 0);
                if (WaitForSingleObject(pThreadSession->m_hEventCancel, 0) == WAIT_OBJECT_0)
                    return ERROR_CANCELLED;

                //
                // Open WLAN handle.
                //
                DWORD dwNegotiatedVersion;
                HANDLE hClientHandle;
                if ((dwReturnCode = ::WlanOpenHandle(2, NULL, &dwNegotiatedVersion, &hClientHandle)) == NO_ERROR) {
                    //
                    // Get a list of WLAN interfaces.
                    //
                    WLAN_INTERFACE_INFO_LIST *pInterfaceList;
                    if ((dwReturnCode = ::WlanEnumInterfaces(hClientHandle, NULL, &pInterfaceList)) == NO_ERROR) {
                        for (DWORD i = 0; i < pInterfaceList->dwNumberOfItems; i++) {
                            //
                            // Check for not ready state of interface.
                            //
                            if (pInterfaceList->InterfaceInfo[i].isState != wlan_interface_state_not_ready) {
                                //
                                // Delete the profile first.
                                //
                                dwReturnCode = ::WlanDeleteProfile(hClientHandle, &(pInterfaceList->InterfaceInfo[i].InterfaceGuid), bstrProfileName, NULL);
                                if (dwReturnCode == NO_ERROR || dwReturnCode == ERROR_NOT_FOUND) {
                                    //
                                    // Set profile.
                                    //
                                    WLAN_REASON_CODE wlrc = 0;
                                    if ((dwReturnCode = ::WlanSetProfile(hClientHandle, &(pInterfaceList->InterfaceInfo[i].InterfaceGuid), 0, pszXML, NULL, TRUE, NULL, &wlrc)) == NO_ERROR) {
                                        pThreadSession->m_pImportSession->m_dwReturnCode = NO_ERROR;
                                        pThreadSession->m_pImportSession->m_sErrorDescription.Empty();
                                    } else {
                                        ATL::CAtlString sFormat, sReason;
                                        pThreadSession->m_pImportSession->m_dwReturnCode = dwReturnCode;
                                        dwReturnCode = WlanReasonCodeToString(wlrc, sReason, NULL);
                                        if (dwReturnCode != NO_ERROR) sReason.Format(L"0x%x", wlrc);
                                        sFormat.LoadString(AL::System::g_hResource, IDS_AL_ERROR_IMPORT_WIZARD_PROFILE_ADD);
                                        pThreadSession->m_pImportSession->m_sErrorDescription.FormatMessage(sFormat, pThreadSession->m_pImportSession->m_dwReturnCode, (LPCWSTR)sReason);
                                        break;
                                    }
                                } else {
                                    ATL::CAtlString sFormat;
                                    pThreadSession->m_pImportSession->m_dwReturnCode = dwReturnCode;
                                    sFormat.LoadString(AL::System::g_hResource, IDS_AL_ERROR_IMPORT_WIZARD_PROFILE_DELETE);
                                    pThreadSession->m_pImportSession->m_sErrorDescription.FormatMessage(sFormat, bstrProfileName, dwReturnCode);
                                    break;
                                }
                            }
                        }
                        ::WlanFreeMemory(pInterfaceList);
                    }
                    ::WlanCloseHandle(hClientHandle, NULL);
                }
                GlobalUnlock(hXML);
                GlobalFree(hXML);

                if (pThreadSession->m_pImportSession->m_dwReturnCode == NO_ERROR) {
                    if (pThreadSession->m_hWndProgress)
                        SendMessage(pThreadSession->m_hWndProgress, PBM_SETPOS, 4, 0);
                }
            } else {
                pThreadSession->m_pImportSession->m_dwReturnCode = ERROR_NOT_FOUND;
                pThreadSession->m_pImportSession->m_sErrorDescription.LoadString(AL::System::g_hResource, IDS_AL_ERROR_IMPORT_WIZARD_PROFILE_XML);
            }
        } else {
            pThreadSession->m_pImportSession->m_dwReturnCode = ERROR_NOT_FOUND;
            pThreadSession->m_pImportSession->m_sErrorDescription.LoadString(AL::System::g_hResource, IDS_AL_ERROR_IMPORT_WIZARD_PROFILE_NAME);
        }
    }

    if (pThreadSession->m_hWndWizard)
        PropSheet_PressButton(pThreadSession->m_hWndWizard, PSBTN_NEXT);
    return pThreadSession->m_pImportSession->m_dwReturnCode;
}


static INT_PTR CALLBACK _ImportFinishSuccessDlgProc(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam)
{
    switch (uMsg) {
        case WM_INITDIALOG: {
#ifdef USE_WINXP_THEMES
            EnableThemeDialogTexture(hWnd, ETDT_ENABLEAEROWIZARDTAB);
#endif
            CImportSession *pImportSession = (CImportSession*)(((LPPROPSHEETPAGE)lParam)->lParam);
            SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pImportSession);
            return FALSE;
        }

        case WM_NOTIFY: {
            LPNMHDR pMsgHdr = (LPNMHDR)lParam;
            switch(pMsgHdr->code) {
                case PSN_SETACTIVE: {
                    CImportSession *pImportSession = (CImportSession*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
                    HWND hWndPS = GetParent(hWnd);
                    PropSheet_ShowWizButtons(hWndPS, PSWIZB_FINISH, PSWIZB_BACK | PSWIZB_NEXT | PSWIZB_CANCEL | PSWIZB_FINISH);
                    PropSheet_SetWizButtons(hWndPS, PSWIZB_FINISH);
                    SetWindowLongPtr(hWnd, DWLP_MSGRESULT, pImportSession->m_dwReturnCode == NO_ERROR ? 0 : -1);
                    return TRUE;
                }
            }
            break;
        }
    }

    return FALSE;
}


static INT_PTR CALLBACK _ImportFinishFailureDlgProc(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam)
{
    switch (uMsg) {
        case WM_INITDIALOG: {
#ifdef USE_WINXP_THEMES
            EnableThemeDialogTexture(hWnd, ETDT_ENABLEAEROWIZARDTAB);
#endif
            CImportSession *pImportSession = (CImportSession*)(((LPPROPSHEETPAGE)lParam)->lParam);
            if (!pImportSession->m_sErrorDescription.IsEmpty())
                SetWindowText(GetDlgItem(hWnd, IDC_AL_IMPORT_FINISH_FAILURE_MSG), pImportSession->m_sErrorDescription);
            SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pImportSession);
            return FALSE;
        }

        case WM_NOTIFY: {
            LPNMHDR pMsgHdr = (LPNMHDR)lParam;
            switch(pMsgHdr->code) {
                case PSN_SETACTIVE:
                    HWND hWndPS = GetParent(hWnd);
                    PropSheet_ShowWizButtons(hWndPS, PSWIZB_FINISH, PSWIZB_BACK | PSWIZB_NEXT | PSWIZB_CANCEL | PSWIZB_FINISH);
                    PropSheet_SetWizButtons(hWndPS, PSWIZB_FINISH);
                    SetWindowLongPtr(hWnd, DWLP_MSGRESULT, 0);
                    return TRUE;
            }
            break;
        }
    }

    return FALSE;
}
