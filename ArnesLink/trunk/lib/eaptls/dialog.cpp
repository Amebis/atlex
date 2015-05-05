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
#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Cryptui.lib")
#pragma comment(lib, "msxml6.lib")
#ifdef USE_WINXP_THEMES
#pragma comment(lib, "UxTheme.lib")
#endif


#define ImageList_AddIcon(himl, hicon) ImageList_ReplaceIcon(himl, -1, hicon)
#define WM_APPLY            (WM_USER + 0x123)
#define WM_SCROLLINTOVIEW   (WM_USER + 0x124)


//
// Local data types
//
struct APPICONS {
    HICON phIconBig;
    HICON phIconSmall;
};


//
// Local function declarations
//
static INT_PTR CALLBACK _ConfigDlgProc(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam);
static LRESULT CALLBACK _SubclassScrollOnFocusProc(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam);
static inline LONG_PTR _SubclassControl(_In_ HWND hWnd, _In_ WNDPROC pNewWindowProc);
static inline VOID _LoadAppIcons(_In_ HWND hWnd, _Out_ APPICONS *pAppIcons);
static inline VOID _DestroyAppIcons(_In_ APPICONS *pAppIcons);


//
// Dialog Function for the Profile Selection Dialog
//
INT_PTR CALLBACK AL::TLS::DlgProc::Config(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam)
{
    struct DLGDATA {
        AL::TLS::CConfigData *pConfigData;
        APPICONS AppIcons;
        HWND hWndTabs[1];
    };

    switch (uMsg) {
        case WM_INITDIALOG: {
            DLGDATA *pDlgData = NULL;
            TCITEM tie;
            RECT rect;
            HWND hWndTab = GetDlgItem(hWnd, IDC_AL_CONFIG_TAB);

            AL::Heap::Alloc(sizeof(DLGDATA), (LPVOID*)&pDlgData);
            pDlgData->pConfigData = (AL::TLS::CConfigData*)lParam;
            SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pDlgData);

            _LoadAppIcons(hWnd, &(pDlgData->AppIcons));

            pDlgData->hWndTabs[0] = CreateDialogParam(AL::System::g_hResource, MAKEINTRESOURCE(IDD_AL_CONFIGCFG), hWnd, _ConfigDlgProc, (LPARAM)pDlgData->pConfigData);

            tie.mask = TCIF_TEXT | TCIF_IMAGE;
            tie.iImage = -1;
            tie.pszText = (LPTSTR)(LPCTSTR)pDlgData->pConfigData->m_sProviderID; // The tab title is the profile ID.
            TabCtrl_InsertItem(hWndTab, 0, &tie);

            // Get tab display area rectangle.
            GetClientRect(hWndTab, &rect);
            MapWindowPoints(hWndTab, hWnd, (LPPOINT)&rect, 2);
            TabCtrl_AdjustRect(hWndTab, FALSE, &rect);
            SetWindowPos(pDlgData->hWndTabs[0], NULL, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, SWP_NOACTIVATE | SWP_NOOWNERZORDER | SWP_NOZORDER);

            return FALSE;
        }

        case WM_DESTROY: {
            DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

            _DestroyAppIcons(&(pDlgData->AppIcons));

            AL::Heap::Free((LPVOID*)&pDlgData);
            return FALSE;
        }

        case WM_SHOWWINDOW:
            if (LOWORD(wParam) == TRUE) {
                DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
                int iSel = TabCtrl_GetCurSel(GetDlgItem(hWnd, IDC_AL_CONFIG_TAB));
                if (iSel < _countof(pDlgData->hWndTabs)) {
                    for (int i = 0; i < _countof(pDlgData->hWndTabs) && pDlgData->hWndTabs[i]; i++)
                        ShowWindow(pDlgData->hWndTabs[i], i == iSel ? TRUE : FALSE);
                }
                return FALSE;
            }
            break;

        case WM_NOTIFY:
            switch (wParam) {
                case IDC_AL_CONFIG_TAB:
                    switch (((NMHDR*)lParam)->code) {
                        case TCN_SELCHANGE: {
                            DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
                            int iSel = TabCtrl_GetCurSel(GetDlgItem(hWnd, IDC_AL_CONFIG_TAB));
                            if (iSel < _countof(pDlgData->hWndTabs)) {
                                for (int i = 0; i < _countof(pDlgData->hWndTabs) && pDlgData->hWndTabs[i]; i++)
                                    ShowWindow(pDlgData->hWndTabs[i], i == iSel ? TRUE : FALSE);
                            }
                            return FALSE;
                        }
                    }
                    break;
            }
            break;

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDOK: {
                    DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
                    for (int i = 0; i < _countof(pDlgData->hWndTabs) && pDlgData->hWndTabs[i]; i++) {
                        BOOL bResult;
                        if (SendMessage(pDlgData->hWndTabs[i], WM_APPLY, 0, (LPARAM)&bResult) == 0 && !bResult)
                            return FALSE;
                    }
                    EndDialog(hWnd, TRUE);
                    return TRUE;
                }

                case IDCANCEL:
                    EndDialog(hWnd, FALSE);
                    return TRUE;
            }
            break;
    }

    return FALSE;
}


//
// Dialog Function for the profile settings
//
static INT_PTR CALLBACK _ConfigDlgProc(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam)
{
    struct DLGDATA {
        AL::TLS::CConfigData *pConfigData;
        ATL::CAtlArray<BYTE> *paEAPConnectionData;
        ATL::CAtlArray<BYTE> *paEAPUserData;
        AL::RASEAP::CPeerData *pInnerEapConfigData;
        BOOL bCompPasswordChanged;
        POINT ptPos;
        SIZE szWindow;
        SIZE szTotal;
        HMODULE hShell32;
        HMODULE hCertMgr;
        HICON hIconAuth;
        HICON hIconOuterID;
        HICON hIconVerifyCert;
        HICON hIconConnection;
    };

    switch (uMsg) {
        case WM_INITDIALOG: {
            DLGDATA *pDlgData = NULL;

#ifdef _DEBUG
            //Sleep(10000);
#endif

#ifdef USE_WINXP_THEMES
            EnableThemeDialogTexture(hWnd, ETDT_ENABLETAB);
#endif

            AL::Heap::Alloc(sizeof(DLGDATA), (LPVOID*)&pDlgData);
            pDlgData->pConfigData = (AL::TLS::CConfigData*)lParam;
            pDlgData->bCompPasswordChanged = FALSE;
            SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pDlgData);

            {
                RECT rect;

                //
                // Calculate total dialog size.
                //
                GetWindowRect(hWnd, &rect);
                pDlgData->szTotal.cx = rect.right  - rect.left;
                pDlgData->szTotal.cy = rect.bottom - rect.top;

                //
                // Initial size equals total size (for now).
                //
                pDlgData->szWindow = pDlgData->szTotal;
            }

            //
            // Subclass all controls that can gain focus, to notify us to scroll them into view.
            //
            _SubclassControl(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP              ), _SubclassScrollOnFocusProc);
            _SubclassControl(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_INNER_ID     ), _SubclassScrollOnFocusProc);
            _SubclassControl(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_PASSWORD     ), _SubclassScrollOnFocusProc);
            _SubclassControl(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_MSCHAPV2         ), _SubclassScrollOnFocusProc);
            _SubclassControl(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_MSCHAPV2_CRED_SET), _SubclassScrollOnFocusProc);
            _SubclassControl(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_MSCHAPV2_CRED_CLR), _SubclassScrollOnFocusProc);
            _SubclassControl(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_MSCHAPV2_CFG     ), _SubclassScrollOnFocusProc);
            _SubclassControl(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_OUTER_ID_SAME         ), _SubclassScrollOnFocusProc);
            _SubclassControl(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_OUTER_ID_EMPTY        ), _SubclassScrollOnFocusProc);
            _SubclassControl(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_OUTER_ID_CUSTOM       ), _SubclassScrollOnFocusProc);
            _SubclassControl(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_OUTER_ID_CUSTOM_VAL   ), _SubclassScrollOnFocusProc);
            _SubclassControl(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_CA_LIST               ), _SubclassScrollOnFocusProc);
            _SubclassControl(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_CA_ADD                ), _SubclassScrollOnFocusProc);
            _SubclassControl(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_CA_REMOVE             ), _SubclassScrollOnFocusProc);
            _SubclassControl(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_VERIFY_NAME_VAL       ), _SubclassScrollOnFocusProc);
            _SubclassControl(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_ENABLE_RESUME         ), _SubclassScrollOnFocusProc);

            //
            // Determine icon size, load and set all dialog icons.
            // We use system provided icons on purpose, to allow UI to adopt Vista, Windows 7, 8 etc. styling.
            //
            SIZE sizeIcon;
            {
                RECT rect;
                if (GetClientRect(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_ICO), &rect)) {
                    sizeIcon.cx = rect.right - rect.left;
                    sizeIcon.cy = rect.bottom - rect.top;
                } else {
                    sizeIcon.cx = ::GetSystemMetrics(SM_CXICON);
                    sizeIcon.cy = ::GetSystemMetrics(SM_CYICON);
                }
            }
            if ((pDlgData->hShell32 = LoadLibraryEx(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE)) != NULL) {
                if (SUCCEEDED(::LoadIconWithScaleDown(pDlgData->hShell32, MAKEINTRESOURCE(48), sizeIcon.cx, sizeIcon.cy, &(pDlgData->hIconAuth))))
                    SendMessage(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_ICO), STM_SETICON, (WPARAM)pDlgData->hIconAuth, 0); 
                if (SUCCEEDED(::LoadIconWithScaleDown(pDlgData->hShell32, MAKEINTRESOURCE(265), sizeIcon.cx, sizeIcon.cy, &(pDlgData->hIconOuterID))))
                    SendMessage(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_OUTERID_ICO), STM_SETICON, (WPARAM)pDlgData->hIconOuterID, 0); 
                if (SUCCEEDED(::LoadIconWithScaleDown(pDlgData->hShell32, MAKEINTRESOURCE(19), sizeIcon.cx, sizeIcon.cy, &(pDlgData->hIconConnection))))
                    SendMessage(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_CONNECTION_ICO), STM_SETICON, (WPARAM)pDlgData->hIconConnection, 0); 
            } else
                AL_TRACE_ERROR(_T("LoadLibraryEx(shell32.dll) failed (%ld)."), GetLastError());

            if ((pDlgData->hCertMgr = LoadLibraryEx(_T("certmgr.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE)) != NULL) {
                if (SUCCEEDED(::LoadIconWithScaleDown(pDlgData->hCertMgr, MAKEINTRESOURCE(218), sizeIcon.cx, sizeIcon.cy, &(pDlgData->hIconVerifyCert))))
                    SendMessage(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_VERIFY_CERT_ICO), STM_SETICON, (WPARAM)pDlgData->hIconVerifyCert, 0); 
            } else
                AL_TRACE_ERROR(_T("LoadLibraryEx(certmgr.dll) failed (%ld)."), GetLastError());

            if (!pDlgData->pConfigData->m_sAltCredentialLbl.IsEmpty())
                SetWindowText(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_CRED_NOTE), pDlgData->pConfigData->m_sAltCredentialLbl);
            if (!pDlgData->pConfigData->m_sAltIdentityLbl.IsEmpty())
                SetWindowText(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_INNER_ID_LBL), pDlgData->pConfigData->m_sAltIdentityLbl);
            if (!pDlgData->pConfigData->m_sAltPasswordLbl.IsEmpty())
                SetWindowText(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_PASSWORD_LBL), pDlgData->pConfigData->m_sAltPasswordLbl);

            if (AL::EAP::g_bType == AL_EAP_TYPE_PEAP)
                EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP), FALSE);
            HWND hWndMethod = GetDlgItem(hWnd,
                AL::EAP::g_bType                   == AL_EAP_TYPE_PEAP ||
                pDlgData->pConfigData->m_InnerAuth == AL::TLS::INNERMETHOD_EAP ? IDC_AL_CONFIGCFG_AUTH_MSCHAPV2 :
                                                                                 IDC_AL_CONFIGCFG_AUTH_PAP);
            SendMessage(hWndMethod, BM_SETCHECK, BST_CHECKED, 0);
            SetFocus(hWndMethod);

            SetWindowTextW(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_INNER_ID), pDlgData->pConfigData->m_sIdentity);
            if (!pDlgData->pConfigData->m_sPassword.IsEmpty())
                SetWindowTextW(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_PASSWORD), L"password");
            pDlgData->bCompPasswordChanged = FALSE;

            pDlgData->paEAPConnectionData = new ATL::CAtlArray<BYTE>;
            pDlgData->paEAPConnectionData->Copy(pDlgData->pConfigData->m_aEAPConnectionData);
            pDlgData->paEAPUserData = new ATL::CAtlArray<BYTE>;
            pDlgData->paEAPUserData->Copy(pDlgData->pConfigData->m_aEAPUserData);
            pDlgData->pInnerEapConfigData = new AL::RASEAP::CPeerData;
            pDlgData->pInnerEapConfigData->Load(AL_EAP_TYPE_MSCHAPV2);

            if (pDlgData->pConfigData->m_sOuterIdentity.IsEmpty()) {
                SendMessage(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_OUTER_ID_SAME), BM_SETCHECK, BST_CHECKED, 0);
            } else if (pDlgData->pConfigData->m_sOuterIdentity[0] == L'@' && pDlgData->pConfigData->m_sOuterIdentity[1] == 0) {
                SendMessage(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_OUTER_ID_EMPTY), BM_SETCHECK, BST_CHECKED, 0);
            } else {
                SendMessage(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_OUTER_ID_CUSTOM), BM_SETCHECK, BST_CHECKED, 0);
                SetWindowTextW(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_OUTER_ID_CUSTOM_VAL), pDlgData->pConfigData->m_sOuterIdentity);
            }

            {
                HWND hWndList = GetDlgItem(hWnd, IDC_AL_CONFIGCFG_CA_LIST);
                if (SendMessage(hWndList, LB_RESETCONTENT, 0, 0) == LB_ERR)
                    AL_TRACE_ERROR(_T("SendMessage(LB_RESETCONTENT) failed."));

                for (POSITION pos = pDlgData->pConfigData->m_lTrustedRootCAs.GetHeadPosition(); pos; pDlgData->pConfigData->m_lTrustedRootCAs.GetNext(pos)) {
                    const ATL::Crypt::CCertContext &cc = pDlgData->pConfigData->m_lTrustedRootCAs.GetAt(pos);
                    ATL::CAtlString sSubjectName;
                    if (CertGetNameString(cc, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, sSubjectName) > 0) {
                        //
                        // Add certificate name
                        //
                        LRESULT lResult;
                        if ((lResult = SendMessage(hWndList, LB_ADDSTRING, 0, (LPARAM)(LPCTSTR)sSubjectName)) != LB_ERR && lResult != LB_ERRSPACE) {
                            //
                            // Duplicate and add certificate data.
                            //
                            PCCERT_CONTEXT pCertContext = CertDuplicateCertificateContext(cc);
                            if (SendMessage(hWndList, LB_SETITEMDATA, lResult, (LPARAM)pCertContext) == LB_ERR) {
                                CertFreeCertificateContext(pCertContext);
                                AL_TRACE_ERROR(_T("SendMessage(LB_SETITEMDATA) failed."));
                            }
                        } else
                            AL_TRACE_ERROR(_T("SendMessage(LB_ADDSTRING) failed."));
                    } else
                        AL_TRACE_ERROR(_T("CertGetNameString failed (%ld)."), GetLastError());
                }
            }
            SetWindowTextA(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_VERIFY_NAME_VAL), pDlgData->pConfigData->m_sServerName);

            SendMessage(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_ENABLE_RESUME), BM_SETCHECK, pDlgData->pConfigData->m_fUseSessionResumption ? BST_CHECKED : BST_UNCHECKED, 0);

            return FALSE;
        }

        case WM_DESTROY: {
            DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

            //
            // Free temporary memory allocated in this dialog.
            //
            {
                HWND hWndList = GetDlgItem(hWnd, IDC_AL_CONFIGCFG_CA_LIST);
                LRESULT lResult;
                if ((lResult = SendMessage(hWndList, LB_GETCOUNT, 0, 0)) != LB_ERR) {
                    for (DWORD j = 0, dwCount = (DWORD)lResult; j < dwCount; j++) {
                        if ((lResult = SendMessage(hWndList, LB_GETITEMDATA, j, NULL)) != LB_ERR)
                            CertFreeCertificateContext((PCCERT_CONTEXT)lResult);
                        else
                            AL_TRACE_ERROR(_T("SendMessage(LB_GETITEMDATA) failed."));
                    }
                } else
                    AL_TRACE_ERROR(_T("SendMessage(LB_GETCOUNT) failed."));
            }

            if (pDlgData->pInnerEapConfigData) delete pDlgData->pInnerEapConfigData;
            if (pDlgData->paEAPUserData      ) delete pDlgData->paEAPUserData;
            if (pDlgData->paEAPConnectionData) delete pDlgData->paEAPConnectionData;
            if (pDlgData->hIconConnection    ) DestroyIcon(pDlgData->hIconConnection);
            if (pDlgData->hIconVerifyCert    ) DestroyIcon(pDlgData->hIconVerifyCert);
            if (pDlgData->hIconOuterID       ) DestroyIcon(pDlgData->hIconOuterID);
            if (pDlgData->hIconAuth          ) DestroyIcon(pDlgData->hIconAuth);
            if (pDlgData->hShell32           ) FreeLibrary(pDlgData->hShell32);
            if (pDlgData->hCertMgr           ) FreeLibrary(pDlgData->hCertMgr);

            AL::Heap::Free((LPVOID*)&pDlgData);
            return FALSE;
        }

        case WM_SHOWWINDOW:
            if (LOWORD(wParam) == TRUE) {
                DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

                //
                // Enable/disable controls according to the settings.
                //
                if (AL::EAP::g_bType == AL_EAP_TYPE_PEAP || SendMessage(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_MSCHAPV2), BM_GETCHECK, 0, 0) == BST_CHECKED) {
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_MSCHAPV2_CRED_SET), TRUE);
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_MSCHAPV2_CRED_CLR), pDlgData->paEAPUserData->IsEmpty() ? FALSE : TRUE);
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_MSCHAPV2_CFG     ), TRUE);
                    if (pDlgData->pInnerEapConfigData->m_dwInvokeUsernameDlg == 1 && pDlgData->pInnerEapConfigData->m_dwInvokePasswordDlg == 1) {
                        EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_CRED_NOTE        ), TRUE);
                        EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_INNER_ID_LBL     ), TRUE);
                        EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_INNER_ID         ), TRUE);
                        EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_PASSWORD_LBL     ), TRUE);
                        EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_PASSWORD         ), TRUE);
                        EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_CRED_NOTE2       ), TRUE);
                    } else {
                        EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_CRED_NOTE        ), FALSE);
                        EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_INNER_ID_LBL     ), FALSE);
                        EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_INNER_ID         ), FALSE);
                        EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_PASSWORD_LBL     ), FALSE);
                        EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_PASSWORD         ), FALSE);
                        EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_CRED_NOTE2       ), FALSE);
                    }
                } else {
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_MSCHAPV2_CRED_SET    ), FALSE);
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_MSCHAPV2_CRED_CLR    ), FALSE);
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_MSCHAPV2_CFG         ), FALSE);
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_CRED_NOTE        ), TRUE);
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_INNER_ID_LBL     ), TRUE);
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_INNER_ID         ), TRUE);
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_PASSWORD_LBL     ), TRUE);
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_PASSWORD         ), TRUE);
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_CRED_NOTE2       ), TRUE);
                }

                if (SendMessage(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_OUTER_ID_CUSTOM), BM_GETCHECK, 0, 0) == BST_CHECKED) {
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_OUTER_ID_CUSTOM_LBL), TRUE);
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_OUTER_ID_CUSTOM_VAL), TRUE);
                } else {
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_OUTER_ID_CUSTOM_LBL), FALSE);
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_OUTER_ID_CUSTOM_VAL), FALSE);
                }

                LRESULT lResult;
                if ((lResult = SendMessage(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_CA_LIST), LB_GETSELCOUNT, 0, 0)) != LB_ERR)
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_CA_REMOVE), lResult ? TRUE : FALSE);
                else
                    AL_TRACE_ERROR(_T("SendMessage(LB_GETSELCOUNT) failed."));
                return FALSE;
            }
            break;

        case WM_SIZE: {
            DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
            SCROLLINFO si;
            LONG nMaxPos;

            pDlgData->szWindow.cx = LOWORD(lParam);
            pDlgData->szWindow.cy = HIWORD(lParam);

            nMaxPos = pDlgData->szTotal.cy - pDlgData->szWindow.cy;
            if (nMaxPos < 0) nMaxPos = 0;
            if (pDlgData->ptPos.y > nMaxPos)
                pDlgData->ptPos.y = nMaxPos;

            si.cbSize = sizeof(SCROLLINFO);
            si.fMask = SIF_POS | SIF_PAGE | SIF_RANGE | SIF_DISABLENOSCROLL;
            si.nPos = pDlgData->ptPos.y;
            si.nPage = pDlgData->szWindow.cy;
            si.nMin = 0;
            si.nMax = pDlgData->szTotal.cy - 1;
            SetScrollInfo(hWnd, SB_VERT, &si, TRUE);

            return FALSE;
        }

        case WM_VSCROLL: {
            DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
            LONG
                nPrev = pDlgData->ptPos.y,
                nMaxPos = pDlgData->szTotal.cy - pDlgData->szWindow.cy;

            if (nMaxPos < 0) nMaxPos = 0;

            switch (LOWORD(wParam)) {
            case SB_LINEDOWN: {
                RECT rectLine = { 0, 0, 10, 10 };
                MapDialogRect(hWnd, &rectLine);
                pDlgData->ptPos.y += rectLine.bottom - rectLine.top;
                if (pDlgData->ptPos.y > nMaxPos) pDlgData->ptPos.y = nMaxPos;
                break;
            }

            case SB_LINEUP: {
                RECT rectLine = { 0, 0, 10, 10 };
                MapDialogRect(hWnd, &rectLine);
                pDlgData->ptPos.y -= rectLine.bottom - rectLine.top;
                if (pDlgData->ptPos.y < 0) pDlgData->ptPos.y = 0;
                break;
            }

            case SB_PAGEDOWN:
                pDlgData->ptPos.y += MulDiv(pDlgData->szWindow.cy, 3, 4);
                if (pDlgData->ptPos.y > nMaxPos) pDlgData->ptPos.y = nMaxPos;
                break;

            case SB_PAGEUP:
                pDlgData->ptPos.y -= MulDiv(pDlgData->szWindow.cy, 3, 4);
                if (pDlgData->ptPos.y < 0) pDlgData->ptPos.y = 0;
                break;

            case SB_THUMBTRACK: {
                BOOL bDragFullWindows = FALSE;
                if (!SystemParametersInfo(SPI_GETDRAGFULLWINDOWS, 0, &bDragFullWindows, 0) || !bDragFullWindows)
                    break;
            }

            case SB_THUMBPOSITION:
                pDlgData->ptPos.y = (LONG)HIWORD(wParam);
                break;

            default:
                return FALSE;
            }

            if (pDlgData->ptPos.y != nPrev) {
                SetScrollPos(hWnd, SB_VERT, pDlgData->ptPos.y, TRUE);
                ScrollWindow(hWnd, 0, nPrev - pDlgData->ptPos.y, NULL, NULL);
            }
            return FALSE;
        }

        case WM_MOUSEWHEEL: {
            DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
            LONG
                nPrev = pDlgData->ptPos.y,
                nMaxPos = pDlgData->szTotal.cy - pDlgData->szWindow.cy;
            UINT nScrollLines;
            RECT rectLine = { 0, 0, 10, 10 };

            if (nMaxPos < 0) nMaxPos = 0;
            SystemParametersInfo(SPI_GETWHEELSCROLLLINES, 0, &nScrollLines, 0);
            MapDialogRect(hWnd, &rectLine);

            pDlgData->ptPos.y -= MulDiv(GET_WHEEL_DELTA_WPARAM(wParam), nScrollLines * (rectLine.bottom - rectLine.top), 120);
                 if (pDlgData->ptPos.y < 0      ) pDlgData->ptPos.y = 0;
            else if (pDlgData->ptPos.y > nMaxPos) pDlgData->ptPos.y = nMaxPos;
            if (pDlgData->ptPos.y != nPrev) {
                SetScrollPos(hWnd, SB_VERT, pDlgData->ptPos.y, TRUE);
                ScrollWindow(hWnd, 0, nPrev - pDlgData->ptPos.y, NULL, NULL);
            }
            return FALSE;
        }

        case WM_SCROLLINTOVIEW: {
            DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
            HWND hWndChild = (HWND)lParam;
            RECT rect;
            LONG
                nPrev = pDlgData->ptPos.y,
                nMaxPos = pDlgData->szTotal.cy - pDlgData->szWindow.cy;

            GetClientRect(hWndChild, &rect);
            MapWindowPoints(hWndChild, hWnd, (LPPOINT)&rect, 2);

            if (0 <= rect.top && rect.bottom <= pDlgData->szWindow.cy) {
                // Control is totally within viewport. Nothing to do.
                return FALSE;
            } else if (rect.top <= 0 && pDlgData->szWindow.cy <= rect.bottom) {
                // Control is too big to fit in the viewport entirely anyway.
                return FALSE;
            } else if (pDlgData->szWindow.cy < rect.bottom) {
                // Bottom of control is off the viewport.
                pDlgData->ptPos.y += rect.bottom - pDlgData->szWindow.cy;
            } else if (rect.top < 0) {
                // Top of control is off the viewport.
                pDlgData->ptPos.y += rect.top;
            } else {
                return FALSE;
            }

                 if (pDlgData->ptPos.y < 0      ) pDlgData->ptPos.y = 0;
            else if (pDlgData->ptPos.y > nMaxPos) pDlgData->ptPos.y = nMaxPos;
            SetScrollPos(hWnd, SB_VERT, pDlgData->ptPos.y, TRUE);
            ScrollWindow(hWnd, 0, nPrev - pDlgData->ptPos.y, NULL, NULL);
            return TRUE;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_AL_CONFIGCFG_AUTH_PAP:
                case IDC_AL_CONFIGCFG_AUTH_MSCHAPV2:
                case IDC_AL_CONFIGCFG_OUTER_ID_SAME:
                case IDC_AL_CONFIGCFG_OUTER_ID_EMPTY:
                case IDC_AL_CONFIGCFG_OUTER_ID_CUSTOM:
                    if (HIWORD(wParam) == BN_CLICKED) {
                        SendMessage(hWnd, WM_SHOWWINDOW, TRUE, 0);
                        return FALSE;
                    }
                    break;

                case IDC_AL_CONFIGCFG_AUTH_PAP_PASSWORD:
                    if (HIWORD(wParam) == EN_CHANGE) {
                        DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
                        pDlgData->bCompPasswordChanged = TRUE;
                        return FALSE;
                    }
                    break;

                case IDC_AL_CONFIGCFG_AUTH_MSCHAPV2_CFG: {
                    DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

                    //
                    // Connect to EAP DLL.
                    //
                    AL::RASEAP::CPeerConfigUI eap;
                    if (eap.Load(pDlgData->pInnerEapConfigData) == NO_ERROR) {
                        LPBYTE pbInnerEapConnectionData = NULL;
                        DWORD dwInnerEapConnectionDataSize = 0;
                        if (eap.RasEapInvokeConfigUI(pDlgData->pInnerEapConfigData->m_dwType, hWnd, 0, pDlgData->paEAPConnectionData->GetData(), (DWORD)pDlgData->paEAPConnectionData->GetCount(), &pbInnerEapConnectionData, &dwInnerEapConnectionDataSize) == NO_ERROR) {
                            if (pDlgData->paEAPConnectionData->SetCount(dwInnerEapConnectionDataSize))
                                memcpy(pDlgData->paEAPConnectionData->GetData(), pbInnerEapConnectionData, dwInnerEapConnectionDataSize);
                        }
                        if (pbInnerEapConnectionData)
                            eap.RasEapFreeMemory(pbInnerEapConnectionData);
                    }

                    return FALSE;
                }

                case IDC_AL_CONFIGCFG_AUTH_MSCHAPV2_CRED_SET: {
                    DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

                    //
                    // Connect to EAP DLL.
                    //
                    AL::RASEAP::CPeerIdentity eap;
                    if (eap.Load(pDlgData->pInnerEapConfigData) == NO_ERROR) {
                        //
                        // Show user credentials dialog
                        //
                        LPBYTE pbInnerEapUserDataOut = NULL;
                        DWORD dwInnerEapUserDataOutSize = 0;
                        WCHAR *pwcInnerEapIdentityOut = NULL;
                        if (eap.RasEapGetIdentity(pDlgData->pInnerEapConfigData->m_dwType, hWnd, 0, NULL, NULL, pDlgData->paEAPConnectionData->GetData(), (DWORD)pDlgData->paEAPConnectionData->GetCount(), pDlgData->paEAPUserData->GetData(), (DWORD)pDlgData->paEAPUserData->GetCount(), &pbInnerEapUserDataOut, &dwInnerEapUserDataOutSize, &pwcInnerEapIdentityOut) == NO_ERROR) {
                            //
                            // Copy the inner user data if any and then free it.
                            //
                            if (pbInnerEapUserDataOut) {
                                if (pDlgData->paEAPUserData->SetCount(dwInnerEapUserDataOutSize))
                                    memcpy(pDlgData->paEAPUserData->GetData(), pbInnerEapUserDataOut, dwInnerEapUserDataOutSize);
                            } else
                                pDlgData->paEAPUserData->RemoveAll();

                            if (pwcInnerEapIdentityOut) {
                                SetWindowTextW(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_INNER_ID), pwcInnerEapIdentityOut);
                                AL_TRACE_DEBUG(_T("pwcInnerIdentityOut: %ls"), pwcInnerEapIdentityOut);
                            }

                            SendMessage(hWnd, WM_SHOWWINDOW, TRUE, 0);
                        } else
                            AL_TRACE_ERROR(_T("RasEapGetIdentity failed."));

                        if (pbInnerEapUserDataOut)
                            eap.RasEapFreeMemory(pbInnerEapUserDataOut);
                        if (pwcInnerEapIdentityOut)
                            eap.RasEapFreeMemory((LPBYTE)pwcInnerEapIdentityOut);
                    }

                    return FALSE;
                }

                case IDC_AL_CONFIGCFG_AUTH_MSCHAPV2_CRED_CLR: {
                    DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
                    pDlgData->paEAPUserData->SetCount(0);
                    SetWindowTextW(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_INNER_ID), L"");
                    SendMessage(hWnd, WM_SHOWWINDOW, TRUE, 0);
                    return FALSE;
                }

                case IDC_AL_CONFIGCFG_CA_LIST:
                    switch (HIWORD(wParam)) {
                        case LBN_SELCHANGE:
                            SendMessage(hWnd, WM_SHOWWINDOW, TRUE, 0);
                            return FALSE;

                        case LBN_DBLCLK: {
                            HWND hWndList = GetDlgItem(hWnd, IDC_AL_CONFIGCFG_CA_LIST);
                            LRESULT lResult;
                            if ((lResult = SendMessage(hWndList, LB_GETCURSEL, 0, 0)) != LB_ERR) {
                                if ((lResult = SendMessage(hWndList, LB_GETITEMDATA, lResult, 0)) != LB_ERR)
                                    CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT, (PCCERT_CONTEXT)lResult, hWnd, NULL, 0, NULL);
                                else
                                    AL_TRACE_ERROR(_T("SendMessage(LB_GETITEMDATA) failed."));
                            } else
                                AL_TRACE_ERROR(_T("SendMessage(LB_GETCURSEL) failed."));
                            return FALSE;
                        }
                    }
                    break;

                case IDC_AL_CONFIGCFG_CA_ADD: {
                    //
                    // User wants to add certificate.
                    //
                    HRESULT hr;

                    // Create the FileOpenDialog object.
                    IFileOpenDialog *pFileOpen;
                    if (SUCCEEDED(hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_ALL, IID_IFileOpenDialog, reinterpret_cast<void**>(&pFileOpen)))) {
                        hr = pFileOpen->SetOptions(FOS_ALLOWMULTISELECT | FOS_PATHMUSTEXIST | FOS_FILEMUSTEXIST);

                        {
                            // Set supported file types.
                            WCHAR pszFileCertificate[1024], pszFileCertificateX509[1024], pszFileCertificatePKCS7[1024], pszFileAll[1024];
                            COMDLG_FILTERSPEC aFileTypes[] = {
                                { pszFileCertificate,      L"*.cer;*.crt;*.der;*.p7b;*.pem" },
                                { pszFileCertificateX509,  L"*.cer;*.crt;*.der;*.pem" },
                                { pszFileCertificatePKCS7, L"*.p7b" },
                                { pszFileAll,              L"*.*" }
                            };
                            LoadString(AL::System::g_hResource, IDS_AL_FILE_CERTIFICATE     , pszFileCertificate     , _countof(pszFileCertificate     ));
                            LoadString(AL::System::g_hResource, IDS_AL_FILE_CERTIFICATEX509 , pszFileCertificateX509 , _countof(pszFileCertificateX509 ));
                            LoadString(AL::System::g_hResource, IDS_AL_FILE_CERTIFICATEPKCS7, pszFileCertificatePKCS7, _countof(pszFileCertificatePKCS7));
                            LoadString(AL::System::g_hResource, IDS_AL_FILE_ALL             , pszFileAll             , _countof(pszFileAll             ));
                            hr = pFileOpen->SetFileTypes(_countof(aFileTypes), aFileTypes);
                        }

                        {
                            WCHAR pszTemp[1024];

                            // Set dialog's title.
                            LoadString(AL::System::g_hResource, IDS_AL_ADD_CERTIFICATE_TITLE, pszTemp, _countof(pszTemp));
                            hr = pFileOpen->SetTitle(pszTemp);

                            // Set OK button's title.
                            LoadString(AL::System::g_hResource, IDS_AL_FILE_SELECT, pszTemp, _countof(pszTemp));
                            hr = pFileOpen->SetOkButtonLabel(pszTemp);

                            // Set Cancel button's title.
                            LoadString(AL::System::g_hResource, IDS_AL_PS_CANCEL, pszTemp, _countof(pszTemp));
                            CComQIPtr<IFileDialog2> pFileOpen2 = pFileOpen;
                            if (pFileOpen2)
                                pFileOpen2->SetCancelButtonLabel(pszTemp);
                        }

                        // Show the Open dialog box.
                        if (SUCCEEDED(hr = pFileOpen->Show(hWnd))) {
                            HWND hWndList = GetDlgItem(hWnd, IDC_AL_CONFIGCFG_CA_LIST);

                            // Get the file names from the dialog box.
                            IShellItemArray *pItemArray;
                            if (SUCCEEDED(hr = pFileOpen->GetResults(&pItemArray))) {
                                DWORD dwItemCount;
                                if (SUCCEEDED(hr = pItemArray->GetCount(&dwItemCount))) {
                                    // Reset selection.
                                    BOOL bSelected = FALSE;
                                    if (SendMessage(hWndList, LB_SETSEL, FALSE, -1) == LB_ERR)
                                        AL_TRACE_ERROR(_T("SendMessage(LB_SETSEL) failed."));

                                    for (DWORD i = 0; i < dwItemCount; i ++) {
                                        IShellItem *pItem;
                                        if (SUCCEEDED(hr = pItemArray->GetItemAt(i, &pItem))) {
                                            PWSTR pszFilePath;
                                            hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
                                            if (SUCCEEDED(hr)) {
                                                // Load certificate(s) from file.
                                                ATL::Crypt::CCertStore cs;
                                                if (cs.Create(CERT_STORE_PROV_FILENAME, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, pszFilePath)) {
                                                    LRESULT lResult;
                                                    for (PCCERT_CONTEXT pCertContext = NULL;;) {
                                                        if ((pCertContext = CertEnumCertificatesInStore(cs, pCertContext)) != NULL) {
                                                            if ((lResult = SendMessage(hWndList, LB_GETCOUNT, 0, 0)) != LB_ERR) {
                                                                // Check to see if certificate is already on the list.
                                                                for (DWORD i = 0, dwCount = (DWORD)lResult; ; i++) {
                                                                    if (i < dwCount) {
                                                                        if ((lResult = SendMessage(hWndList, LB_GETITEMDATA, i, NULL)) != LB_ERR) {
                                                                            if (((PCCERT_CONTEXT)lResult)->cbCertEncoded == pCertContext->cbCertEncoded &&
                                                                                memcmp(((PCCERT_CONTEXT)lResult)->pbCertEncoded, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded) == 0)
                                                                            {
                                                                                // This certificate is already on the list.
                                                                                if (SendMessage(hWndList, LB_SETSEL, TRUE, i) != LB_ERR)
                                                                                    bSelected = TRUE;
                                                                                else
                                                                                    AL_TRACE_ERROR(_T("SendMessage(LB_SETSEL) failed."));
                                                                                break;
                                                                            }
                                                                        } else
                                                                            AL_TRACE_ERROR(_T("SendMessage(LB_GETITEMDATA) failed."));
                                                                    } else {
                                                                        ATL::CAtlString sSubjectName;
                                                                        if (CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, sSubjectName) > 0) {
                                                                            // Add certificate to the list.
                                                                            if ((lResult = SendMessage(hWndList, LB_ADDSTRING, 0, (LPARAM)(LPCTSTR)sSubjectName)) != LB_ERR && lResult != LB_ERRSPACE) {
                                                                                PCCERT_CONTEXT pCertContext2 = CertDuplicateCertificateContext(pCertContext);
                                                                                if (SendMessage(hWndList, LB_SETITEMDATA, lResult, (LPARAM)(PCCERT_CONTEXT)pCertContext2) == LB_ERR) {
                                                                                    CertFreeCertificateContext(pCertContext2);
                                                                                    AL_TRACE_ERROR(_T("SendMessage(LB_SETITEMDATA) failed."));
                                                                                }
                                                                                if (SendMessage(hWndList, LB_SETSEL, TRUE, lResult) != LB_ERR)
                                                                                    bSelected = TRUE;
                                                                                else
                                                                                    AL_TRACE_ERROR(_T("SendMessage(LB_SETSEL) failed."));
                                                                            } else
                                                                                AL_TRACE_ERROR(_T("SendMessage(LB_ADDSTRING) failed."));
                                                                        } else
                                                                            AL_TRACE_ERROR(_T("CertGetNameString failed (%ld)."), GetLastError());
                                                                        break;
                                                                    }
                                                                }
                                                            } else
                                                                AL_TRACE_ERROR(_T("SendMessage(LB_GETCOUNT) failed."));
                                                        } else
                                                            break;
                                                    }
                                                } else {
                                                    TCHAR pszText[1024], pszCaption[1024];
                                                    AL::System::FormatMsg(IDS_AL_ERROR_CERTIFICATE_FILE_READ, pszText, _countof(pszText), UINT_MAX, pszFilePath, ::GetLastError());
                                                    LoadString(AL::System::g_hResource, IDS_AL_ERROR_ERROR, pszCaption, _countof(pszCaption));
                                                    MessageBox(hWnd, pszText, pszCaption, MB_ICONERROR | MB_OK);
                                                }
                                                CoTaskMemFree(pszFilePath);
                                            }
                                            pItem->Release();
                                        } else
                                            AL_TRACE_ERROR(_T("IShellItemArray::GetItemAt failed (%x)."), hr);
                                    }
                                    EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_CA_REMOVE), bSelected);
                                } else
                                    AL_TRACE_ERROR(_T("IShellItemArray::GetCount failed (%x)."), hr);
                                pItemArray->Release();
                            } else
                                AL_TRACE_ERROR(_T("IFileOpenDialog::GetResults failed (%x)."), hr);
                        }
                        pFileOpen->Release();
                    }

                    return FALSE;
                }

                case IDC_AL_CONFIGCFG_CA_REMOVE: {
                    //
                    // User wants to remove certificate.
                    //
                    HWND hWndList = GetDlgItem(hWnd, IDC_AL_CONFIGCFG_CA_LIST);
                    LRESULT lResult;

                    if ((lResult = SendMessage(hWndList, LB_GETCOUNT, 0, 0)) != LB_ERR) {
                        for (DWORD j = (DWORD)lResult; j--;) {
                            if ((lResult = SendMessage(hWndList, LB_GETSEL, j, NULL)) != LB_ERR) {
                                if (lResult > 0) {
                                    if ((lResult = SendMessage(hWndList, LB_GETITEMDATA, j, NULL)) != LB_ERR)
                                        CertFreeCertificateContext((PCCERT_CONTEXT)lResult);
                                    else
                                        AL_TRACE_ERROR(_T("SendMessage(LB_GETITEMDATA) failed."));

                                    if ((lResult = SendMessage(hWndList, LB_DELETESTRING, j, 0)) == LB_ERR)
                                        AL_TRACE_ERROR(_T("SendMessage(LB_DELETESTRING) failed."));
                                }
                            } else
                                AL_TRACE_ERROR(_T("SendMessage(LB_GETSEL) failed."));
                        }
                        EnableWindow(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_CA_REMOVE), FALSE);
                    } else
                        AL_TRACE_ERROR(_T("SendMessage(LB_GETCOUNT) failed."));

                    return FALSE;
                }
            }
            break;

        case WM_APPLY: {
            DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

            //
            // Check to see if the user configured everything correctly.
            //
            if (SendMessage(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_CA_LIST), LB_GETCOUNT, 0, 0) == 0) {
                TCHAR pszText[1024], pszCaption[1024];
                LoadString(AL::System::g_hResource, IDS_AL_ERROR_PROFILE_NOROOTCA, pszText,    _countof(pszText));
                LoadString(AL::System::g_hResource, IDS_AL_ERROR_ALERT,            pszCaption, _countof(pszCaption));
                if (MessageBox(hWnd, pszText, pszCaption, MB_YESNO | MB_ICONWARNING) != IDYES) {
                    *(BOOL*)lParam = FALSE;
                    return FALSE;
                }
            }

            //
            // Save data.
            //
            pDlgData->pConfigData->m_InnerAuth = SendMessage(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_MSCHAPV2), BM_GETCHECK, 0, 0) == BST_CHECKED ? AL::TLS::INNERMETHOD_EAP : AL::TLS::INNERMETHOD_PAP;
            pDlgData->pConfigData->m_aEAPConnectionData.Copy(*(pDlgData->paEAPConnectionData));
            pDlgData->pConfigData->m_aEAPUserData.Copy(*(pDlgData->paEAPUserData));

            GetWindowTextW(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_INNER_ID), pDlgData->pConfigData->m_sIdentity);
            if (pDlgData->bCompPasswordChanged)
                GetWindowTextW(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_AUTH_PAP_PASSWORD), pDlgData->pConfigData->m_sPassword);

            if (SendMessage(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_OUTER_ID_SAME), BM_GETCHECK, 0, 0) == BST_CHECKED)
                pDlgData->pConfigData->m_sOuterIdentity.Empty();
            else if (SendMessage(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_OUTER_ID_EMPTY), BM_GETCHECK, 0, 0) == BST_CHECKED)
                pDlgData->pConfigData->m_sOuterIdentity = L"@";
            else
                GetWindowTextW(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_OUTER_ID_CUSTOM_VAL), pDlgData->pConfigData->m_sOuterIdentity);

            {
                HWND hWndList = GetDlgItem(hWnd, IDC_AL_CONFIGCFG_CA_LIST);
                LRESULT lResult;
                if ((lResult = SendMessage(hWndList, LB_GETCOUNT, 0, 0)) != LB_ERR) {
                    DWORD dwCertCount = (DWORD)lResult;
                    pDlgData->pConfigData->m_lTrustedRootCAs.RemoveAll();
                    for (DWORD i = 0; i < dwCertCount; i++) {
                        if ((lResult = SendMessage(hWndList, LB_GETITEMDATA, i, NULL)) != LB_ERR) {
                            ATL::Crypt::CCertContext &cc = pDlgData->pConfigData->m_lTrustedRootCAs.GetAt(pDlgData->pConfigData->m_lTrustedRootCAs.AddTail());
                            if (!cc.DuplicateAndAttach((PCCERT_CONTEXT)lResult))
                                AL_TRACE_ERROR(_T("Error duplicating certificate context."));
                        } else
                            AL_TRACE_ERROR(_T("SendMessage(LB_GETITEMDATA) failed."));
                    }
                } else
                    AL_TRACE_ERROR(_T("SendMessage(LB_GETCOUNT) failed."));
            }
            GetWindowTextA(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_VERIFY_NAME_VAL), pDlgData->pConfigData->m_sServerName);

            pDlgData->pConfigData->m_fUseSessionResumption = SendMessage(GetDlgItem(hWnd, IDC_AL_CONFIGCFG_ENABLE_RESUME  ), BM_GETCHECK, 0, 0) == BST_CHECKED ? TRUE : FALSE;

            *(BOOL*)lParam = TRUE;
            return TRUE;
        }
    }

    return FALSE;
}


//
// Dialog Function for the Credentials Dialog
//
INT_PTR CALLBACK AL::TLS::DlgProc::Credentials(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam)
{
    struct DLGDATA {
        AL::TLS::CUserData *pUserData;
        const AL::TLS::CConfigData *pConfigData;
        APPICONS AppIcons;
        BOOL bPasswordChanged;
        HMODULE hShell32;
        HICON hIconWarning;
        HICON hIconUser;
    };

    switch (uMsg) {
        case WM_INITDIALOG: {
            DLGDATA *pDlgData = NULL;

            AL::Heap::Alloc(sizeof(DLGDATA), (LPVOID*)&pDlgData);
            pDlgData->pUserData   = (      AL::TLS::CUserData  *)((LPVOID*)lParam)[0];
            pDlgData->pConfigData = (const AL::TLS::CConfigData*)((LPVOID*)lParam)[1];
            SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pDlgData);

            _LoadAppIcons(hWnd, &(pDlgData->AppIcons));

            //
            // Determine icon size, load and set all dialog icons.
            // We use system provided icons on purpose, to allow UI to adopt Vista, Windows 7, 8 etc. styling.
            //
            SIZE sizeIcon;
            {
                RECT rect;
                if (GetClientRect(GetDlgItem(hWnd, IDC_AL_CREDENTIALS_WARNING_ICO), &rect)) {
                    sizeIcon.cx = rect.right - rect.left;
                    sizeIcon.cy = rect.bottom - rect.top;
                } else {
                    sizeIcon.cx = ::GetSystemMetrics(SM_CXICON);
                    sizeIcon.cy = ::GetSystemMetrics(SM_CYICON);
                }
            }
            if ((pDlgData->hShell32 = LoadLibraryEx(_T("shell32.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE)) != NULL) {
                if (SUCCEEDED(::LoadIconWithScaleDown(pDlgData->hShell32, MAKEINTRESOURCE(161), sizeIcon.cx, sizeIcon.cy, &(pDlgData->hIconWarning))))
                    SendMessage(GetDlgItem(hWnd, IDC_AL_CREDENTIALS_WARNING_ICO), STM_SETICON, (WPARAM)pDlgData->hIconWarning, 0); 
                if (SUCCEEDED(::LoadIconWithScaleDown(pDlgData->hShell32, MAKEINTRESOURCE(269), sizeIcon.cx, sizeIcon.cy, &(pDlgData->hIconUser))))
                    SendMessage(GetDlgItem(hWnd, IDC_AL_CREDENTIALS_ICON), STM_SETICON, (WPARAM)pDlgData->hIconUser, 0); 
            } else
                AL_TRACE_ERROR(_T("LoadLibraryEx(shell32.dll) failed (%ld)."), GetLastError());

            //
            // Set custom labels.
            //
            if (!pDlgData->pConfigData->m_sAltCredentialLbl.IsEmpty())
                SetWindowText(GetDlgItem(hWnd, IDC_AL_CREDENTIALS_DESCRIPTION), pDlgData->pConfigData->m_sAltCredentialLbl);
            if (!pDlgData->pConfigData->m_sAltIdentityLbl.IsEmpty())
                SetWindowText(GetDlgItem(hWnd, IDC_AL_CREDENTIALS_USERNAME_LBL), pDlgData->pConfigData->m_sAltIdentityLbl);
            if (!pDlgData->pConfigData->m_sAltPasswordLbl.IsEmpty())
                SetWindowText(GetDlgItem(hWnd, IDC_AL_CREDENTIALS_PASSWORD_LBL), pDlgData->pConfigData->m_sAltPasswordLbl);

            //
            // Set predefined user credentials.
            //
            if (!pDlgData->pUserData->m_sIdentity.IsEmpty())
                SetWindowTextW(GetDlgItem(hWnd, IDC_AL_CREDENTIALS_USERNAME), pDlgData->pUserData->m_sIdentity);
            if (!pDlgData->pUserData->m_sPassword.IsEmpty()) {
                SetWindowTextW(GetDlgItem(hWnd, IDC_AL_CREDENTIALS_PASSWORD), L"password");
                SendMessage(GetDlgItem(hWnd, IDC_AL_CREDENTIALS_SAVE), BM_SETCHECK, BST_CHECKED, 0);
            } else
                SendMessage(GetDlgItem(hWnd, IDC_AL_CREDENTIALS_SAVE), BM_SETCHECK, BST_UNCHECKED, 0);
            pDlgData->bPasswordChanged = FALSE;

            HWND hWndFocus = GetDlgItem(hWnd, pDlgData->pUserData->m_sIdentity.IsEmpty() ? IDC_AL_CREDENTIALS_USERNAME : IDC_AL_CREDENTIALS_PASSWORD);
            SendMessage(hWndFocus, EM_SETSEL, (WPARAM) 0, (LPARAM)-1);
            SetFocus(hWndFocus);

            return FALSE;
        }

        case WM_DESTROY: {
            DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

            if (pDlgData->hIconUser)
                DestroyIcon(pDlgData->hIconUser);
            if (pDlgData->hIconWarning)
                DestroyIcon(pDlgData->hIconWarning);
            if (pDlgData->hShell32)
                FreeLibrary(pDlgData->hShell32);

            _DestroyAppIcons(&(pDlgData->AppIcons));

            AL::Heap::Free((LPVOID*)&pDlgData);
            return FALSE;
        }

        case WM_SHOWWINDOW:
            if (LOWORD(wParam) == TRUE) {
                EnableWindow(GetDlgItem(hWnd, IDOK), GetWindowTextLength(GetDlgItem(hWnd, IDC_AL_CREDENTIALS_USERNAME)) > 0 && GetWindowTextLength(GetDlgItem(hWnd, IDC_AL_CREDENTIALS_PASSWORD)) > 0);
                return FALSE;
            }
            break;

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_AL_CREDENTIALS_USERNAME:
                    if (HIWORD(wParam) == EN_CHANGE) {
                        SendMessage(hWnd, WM_SHOWWINDOW, TRUE, 0);
                        return FALSE;
                    }
                    break;

                case IDC_AL_CREDENTIALS_PASSWORD:
                    if (HIWORD(wParam) == EN_CHANGE) {
                        DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
                        pDlgData->bPasswordChanged = TRUE;
                        SendMessage(hWnd, WM_SHOWWINDOW, TRUE, 0);
                        return FALSE;
                    }
                    break;

                case IDOK: {
                    DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

                    GetWindowTextW(GetDlgItem(hWnd, IDC_AL_CREDENTIALS_USERNAME), pDlgData->pUserData->m_sIdentity);
                    if (pDlgData->bPasswordChanged)
                        GetWindowTextW(GetDlgItem(hWnd, IDC_AL_CREDENTIALS_PASSWORD), pDlgData->pUserData->m_sPassword);
                    pDlgData->pUserData->m_fSaveCredentials = SendMessage(GetDlgItem(hWnd, IDC_AL_CREDENTIALS_SAVE), BM_GETCHECK, 0, 0) == BST_CHECKED ? TRUE : FALSE;

                    EndDialog(hWnd, TRUE);
                    return TRUE;
                }

                case IDCANCEL:
                    EndDialog(hWnd, FALSE);
                    return TRUE;
            }
            break;
    }

    return FALSE;
}


//
// Dialog Function for the "Untrusted Server" Dialog
//
INT_PTR CALLBACK AL::TLS::DlgProc::ServerUntrusted(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam)
{
    struct DLGDATA {
        const ATL::CAtlList<ATL::Crypt::CCertContext> *plCertificateChain;
        AL::TLS::CCertList *plTrustedRootCAs;
        APPICONS AppIcons;
        HFONT hFontBold;
        HIMAGELIST hImageList;
        HMODULE hCertMgr;
        HICON hIconTrusted;
        HICON hIconUntrusted;
    };

    switch (uMsg) {
        case WM_INITDIALOG: {
            DLGDATA *pDlgData = NULL;

            AL::Heap::Alloc(sizeof(DLGDATA), (LPVOID*)&pDlgData);
            pDlgData->plCertificateChain = (const ATL::CAtlList<ATL::Crypt::CCertContext>*)((LPVOID*)lParam)[0];
            pDlgData->plTrustedRootCAs   = (      AL::TLS::CCertList                     *)((LPVOID*)lParam)[1];
            SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pDlgData);

            _LoadAppIcons(hWnd, &(pDlgData->AppIcons));

            //
            // Make heading text bold.
            //
            HFONT hFontWnd;
            if ((hFontWnd = (HFONT)::SendMessage(hWnd, WM_GETFONT, 0, 0)) != NULL) {
                LOGFONT lf;
                ::GetObject(hFontWnd, sizeof(lf), &lf);
                lf.lfWeight = FW_BOLD;
                if ((pDlgData->hFontBold = ::CreateFontIndirect(&lf)) != NULL)
                    ::SendMessage(GetDlgItem(hWnd, IDC_AL_UNTRUSTEDCERT_TXT), WM_SETFONT, (WPARAM)(pDlgData->hFontBold), FALSE);
                else
                    AL_TRACE_ERROR(_T("CreateFontIndirect failed (%ld)."), GetLastError());
            } else
                AL_TRACE_ERROR(_T("SendMessage(WM_GETFONT) failed (%ld)."), GetLastError());

            //
            // Create image list for tree view control and add icons to the images list.
            //
            SIZE sizeIcon;
            sizeIcon.cx = ::GetSystemMetrics(SM_CXSMICON);
            sizeIcon.cy = ::GetSystemMetrics(SM_CYSMICON);
            if ((pDlgData->hImageList = ImageList_Create(sizeIcon.cx, sizeIcon.cy, ILC_COLOR32, 2, 2)) != NULL) {
                if ((pDlgData->hCertMgr = LoadLibraryEx(_T("certmgr.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE)) != NULL) {
                    if (SUCCEEDED(::LoadIconWithScaleDown(pDlgData->hCertMgr, MAKEINTRESOURCE(218), sizeIcon.cx, sizeIcon.cy, &(pDlgData->hIconTrusted))))
                        ImageList_AddIcon(pDlgData->hImageList, pDlgData->hIconTrusted);
                    if (SUCCEEDED(::LoadIconWithScaleDown(pDlgData->hCertMgr, MAKEINTRESOURCE(328), sizeIcon.cx, sizeIcon.cy, &(pDlgData->hIconUntrusted))))
                        ImageList_AddIcon(pDlgData->hImageList, pDlgData->hIconUntrusted);
                } else
                    AL_TRACE_ERROR(_T("LoadLibraryEx(certmgr.dll) failed (%ld)."), GetLastError());
            }

            //
            // Add all the certificates in the list to the list box
            // starting with the root CA.
            //
            HWND hWndTree = GetDlgItem(hWnd, IDC_AL_UNTRUSTEDCERT_TREE);
            TreeView_SetImageList(hWndTree, pDlgData->hImageList, TVSIL_NORMAL);
            if (TreeView_DeleteItem(hWndTree, TVI_ROOT)) {
                TVINSERTSTRUCT tvInsertStruct;
                ATL::CAtlString sSubjectName;

                tvInsertStruct.hParent             = NULL;
                tvInsertStruct.item.mask           = TVIF_TEXT | TVIF_PARAM;
                tvInsertStruct.item.iImage         = 0;
                tvInsertStruct.item.iSelectedImage = 0;

                for (POSITION pos = pDlgData->plCertificateChain->GetTailPosition(); pos; pDlgData->plCertificateChain->GetPrev(pos)) {
                    const ATL::Crypt::CCertContext &cc = pDlgData->plCertificateChain->GetAt(pos);

                    //
                    // Get SubjectName.
                    //
                    if (CertGetNameString(cc, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, sSubjectName) > 0) {
                        AL_TRACE_INFO(_T("certificate name: %s"), (LPCTSTR)sSubjectName);
                        tvInsertStruct.item.pszText = (LPTSTR)(LPCTSTR)sSubjectName;
                        tvInsertStruct.item.lParam  = (LPARAM)pos;
                        if ((tvInsertStruct.hParent = TreeView_InsertItem(hWndTree, &tvInsertStruct)) == NULL)
                            AL_TRACE_ERROR(_T("TreeView_InsertItem failed (%ld)."), GetLastError());
                    } else
                        AL_TRACE_ERROR(_T("CertGetNameString failed (%ld)."), GetLastError());
                }

                //
                // Expand tree.
                //
                for (HTREEITEM hTreeItem = TreeView_GetRoot(hWndTree); hTreeItem != NULL; hTreeItem = TreeView_GetNextItem(hWndTree, hTreeItem, TVGN_CHILD))
                    TreeView_Expand(hWndTree, hTreeItem, TVM_EXPAND);
            }

            SetFocus(hWndTree);

            return FALSE;
        }

        case WM_DESTROY: {
            DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

            if (pDlgData->hIconUntrusted) DestroyIcon(pDlgData->hIconUntrusted);
            if (pDlgData->hIconTrusted  ) DestroyIcon(pDlgData->hIconTrusted);
            if (pDlgData->hCertMgr      ) FreeLibrary(pDlgData->hCertMgr);
            if (pDlgData->hImageList    ) ImageList_Destroy(pDlgData->hImageList);
            if (pDlgData->hFontBold     ) DeleteObject(pDlgData->hFontBold);

            _DestroyAppIcons(&(pDlgData->AppIcons));

            AL::Heap::Free((LPVOID*)&pDlgData);
            return FALSE;
        }

        case WM_SHOWWINDOW:
            if (LOWORD(wParam) == TRUE) {
                DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

                //
                // Check every certificate to see if we trust it or not.
                //
                HWND hWndTree = GetDlgItem(hWnd, IDC_AL_UNTRUSTEDCERT_TREE);
                BOOL bTrustOK = TRUE;
                TVITEM tvItem = { TVIF_PARAM | TVIF_IMAGE | TVIF_SELECTEDIMAGE };
                for (tvItem.hItem = TreeView_GetRoot(hWndTree); tvItem.hItem;) {
                    if (TreeView_GetItem(hWndTree, &tvItem)) {
                        if (tvItem.lParam) {
                            DWORD dwReturnCode = NO_ERROR;
                            HTREEITEM hTreeItemNext = TreeView_GetNextItem(hWndTree, tvItem.hItem, TVGN_CHILD);

                            dwReturnCode = AL::TLS::Cert::VerifyChain(pDlgData->plTrustedRootCAs, pDlgData->plCertificateChain, (POSITION)tvItem.lParam);

                            if (dwReturnCode == NO_ERROR) {
                                tvItem.iImage         = 0;
                                tvItem.iSelectedImage = 0;
                            } else {
                                tvItem.iImage         = 1;
                                tvItem.iSelectedImage = 1;
                                bTrustOK = FALSE;
                            }

                            TreeView_SetItem(hWndTree, &tvItem);
                            tvItem.hItem = hTreeItemNext;
                        }
                    } else
                        AL_TRACE_ERROR(_T("TreeView_GetItem failed (%ld)."), GetLastError());
                }

                HTREEITEM hSelectedItem;
                if ((hSelectedItem = TreeView_GetSelection(hWndTree)) != NULL) {
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_UNTRUSTEDCERT_VIEW   ), TRUE);

#ifdef AL_ALLOW_CA_TRUST_ON_THE_FLY
                    TVITEM tvItem = { TVIF_CHILDREN, hSelectedItem };
                    if (TreeView_GetItem(hWndTree, &tvItem))
                        EnableWindow(GetDlgItem(hWnd, IDC_AL_UNTRUSTEDCERT_TRUST), tvItem.cChildren);
                    else {
                        EnableWindow(GetDlgItem(hWnd, IDC_AL_UNTRUSTEDCERT_TRUST), FALSE);
                        AL_TRACE_ERROR(_T("TreeView_GetItem failed (%ld)."), GetLastError());
                    }
#endif
                } else {
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_UNTRUSTEDCERT_VIEW ), FALSE);
#ifdef AL_ALLOW_CA_TRUST_ON_THE_FLY
                    EnableWindow(GetDlgItem(hWnd, IDC_AL_UNTRUSTEDCERT_TRUST), FALSE);
#endif
                }

                EnableWindow(GetDlgItem(hWnd, IDOK), bTrustOK);
                return FALSE;
            }
            break;

        case WM_NOTIFY:
            switch (wParam) {
                case IDC_AL_UNTRUSTEDCERT_TREE:
                    switch (((NMHDR*)lParam)->code) {
                        case TVN_SELCHANGED:
                            SendMessage(hWnd, WM_SHOWWINDOW, TRUE, 0);
                            return FALSE;
                    }
                    break;
            }
            break;

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_AL_UNTRUSTEDCERT_VIEW: {
                    DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
                    HTREEITEM hSelectedItem;
                    HWND hWndTree = GetDlgItem(hWnd, IDC_AL_UNTRUSTEDCERT_TREE);
                    if ((hSelectedItem = TreeView_GetSelection(hWndTree)) != NULL) {
                        TVITEM tvItem = { TVIF_PARAM, hSelectedItem };
                        if (TreeView_GetItem(hWndTree, &tvItem)) {
                            const ATL::Crypt::CCertContext &cc = pDlgData->plCertificateChain->GetAt((POSITION)tvItem.lParam);
                            CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT, cc, hWnd, NULL, 0, NULL);
                        }
                        else
                            AL_TRACE_ERROR(_T("TreeView_GetItem failed (%ld)."), GetLastError());
                    } else
                        AL_TRACE_ERROR(_T("TreeView_GetSelection failed (%ld)."), GetLastError());

                    return FALSE;
                }

#ifdef AL_ALLOW_CA_TRUST_ON_THE_FLY
                case IDC_AL_UNTRUSTEDCERT_TRUST: {
                    DLGDATA *pDlgData = (DLGDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
                    HWND hWndTree = GetDlgItem(hWnd, IDC_AL_UNTRUSTEDCERT_TREE);
                    HTREEITEM hSelectedItem;

                    if ((hSelectedItem = TreeView_GetSelection(hWndTree)) != NULL) {
                        TVITEM tvItem = { TVIF_PARAM, hSelectedItem };
                        if (TreeView_GetItem(hWndTree, &tvItem)) {
                            const ATL::Crypt::CCertContext &cc = pDlgData->plCertificateChain->GetAt((POSITION)tvItem.lParam);
                            pDlgData->plTrustedRootCAs->AddCertificate(cc->dwCertEncodingType, cc->pbCertEncoded, cc->cbCertEncoded);
                        } else
                            AL_TRACE_ERROR(_T("TreeView_GetItem failed (%ld)."), GetLastError());
                    } else
                        AL_TRACE_ERROR(_T("TreeView_GetSelection failed (%ld)."), GetLastError());

                    SendMessage(hWnd, WM_SHOWWINDOW, TRUE, 0);
                    return FALSE;
                }

                case IDOK: {
                    EndDialog(hWnd, TRUE);
                    return TRUE;
                }
#endif

                case IDCANCEL:
                    EndDialog(hWnd, FALSE);
                    return TRUE;
            }
            break;
    }

    return FALSE;
}


//
// Subclass procedure to scroll control into view each time it gains focus
//
static LRESULT CALLBACK _SubclassScrollOnFocusProc(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam)
{
    if (uMsg == WM_SETFOCUS) {
        //
        // The control was focused. Notify parent, to scroll this control into view.
        //
        SendMessage(GetParent(hWnd), WM_SCROLLINTOVIEW, 0, (LPARAM)hWnd);
    }

    return CallWindowProc((WNDPROC)GetWindowLongPtr(hWnd, GWLP_USERDATA), hWnd, uMsg, wParam, lParam); 
}


//
// Helper function to subcalss control and store previous window function to GWLP_USERDATA
//
static inline LONG_PTR _SubclassControl(_In_ HWND hWnd, _In_ WNDPROC pNewWindowProc)
{
    return SetWindowLongPtr(hWnd, GWLP_USERDATA, SetWindowLongPtr(hWnd, GWLP_WNDPROC, (LONG_PTR)_SubclassScrollOnFocusProc));
}


static inline VOID _LoadAppIcons(_In_ HWND hWnd, _Out_ APPICONS *pAppIcons)
{
    //
    // Load and set application icon.
    //
    if (SUCCEEDED(::LoadIconWithScaleDown(AL::System::g_hResource, MAKEINTRESOURCE(IDI_AL_LOGO), ::GetSystemMetrics(SM_CXICON), ::GetSystemMetrics(SM_CYICON), &(pAppIcons->phIconBig))))
        SendMessage(hWnd, WM_SETICON, ICON_BIG, (LPARAM)(pAppIcons->phIconBig));
    if (SUCCEEDED(::LoadIconWithScaleDown(AL::System::g_hResource, MAKEINTRESOURCE(IDI_AL_LOGO), ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON), &(pAppIcons->phIconSmall))))
        SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM)(pAppIcons->phIconSmall));
}


static inline VOID _DestroyAppIcons(_In_ APPICONS *pAppIcons)
{
    if (pAppIcons->phIconSmall)
        DestroyIcon(pAppIcons->phIconSmall);
    if (pAppIcons->phIconBig)
        DestroyIcon(pAppIcons->phIconBig);
}
