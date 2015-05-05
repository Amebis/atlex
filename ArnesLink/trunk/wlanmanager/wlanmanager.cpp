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
#pragma comment(lib, "Wlanapi.lib")
#pragma comment(lib, "Wlanui.lib")


//
// Global data
//
HINSTANCE AL::System::g_hInstance = NULL;
HINSTANCE AL::System::g_hResource = NULL;


//
// Main function
//
int CALLBACK WinMain(_In_ HINSTANCE hInstance, _In_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::System::g_hInstance = hInstance;
    AL::Trace::Init(_T("AL-WLANMANAGER"));
    {
        AL_TRACEFN_INFO(dwReturnCode);

#ifdef USE_WINXP_THEMES
        {
            //
            // Initialize Windows XP visual styles
            //
            INITCOMMONCONTROLSEX icc;
            icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
            icc.dwICC = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES | ICC_LINK_CLASS;
            InitCommonControlsEx(&icc);
        }
#endif

        if ((dwReturnCode = AL::Heap::Init()) == NO_ERROR) {
            int nArgs;
            LPWSTR *pwcArglist;
            if ((pwcArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs)) != NULL) {
                AL_TRACE_INFO(_T("arguments (%ld)."), nArgs);

                if (nArgs >= 3) {
                    if (_wcsicmp(pwcArglist[1], L"profile") == 0) {
                        if (nArgs >= 3) {
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
                                        // Check for not ready state in interface.
                                        //
                                        if (pInterfaceList->InterfaceInfo[i].isState != wlan_interface_state_not_ready) {
                                            //
                                            // Launch WLAN profile config dialog.
                                            // Note: When a debugger is attached to this process the WlanUIEditProfile() will raise an exception and fail.
                                            //
                                            WLAN_REASON_CODE wlrc;
                                            if ((dwReturnCode = ::WlanUIEditProfile(WLAN_UI_API_VERSION, pwcArglist[2], &(pInterfaceList->InterfaceInfo[i].InterfaceGuid), NULL, WLSecurityPage, NULL, &wlrc)) == NO_ERROR) {
                                                if (wlrc == WLAN_REASON_CODE_SUCCESS) {
                                                    AL_TRACE_INFO(_T("WlanUIEditProfile succeeded."));
                                                    break;
                                                } else
                                                    AL_TRACE_ERROR(_T("WlanUIEditProfile failed (reason code: %ld)."), wlrc);
                                            } else
                                                AL_TRACE_ERROR(_T("WlanUIEditProfile failed (%ld)."), dwReturnCode);
                                        }
                                    }
                                    ::WlanFreeMemory(pInterfaceList);
                                }

                                ::WlanCloseHandle(hClientHandle, NULL);
                            } else
                                AL_TRACE_ERROR(_T("WlanOpenHandle failed (%ld)."), dwReturnCode);
                        } else {
                            AL_TRACE_ERROR(_T("Not enough arguments to \"%ls\" command (expected: %ld, provided: %ld)."), pwcArglist[1], 3, nArgs);
                            dwReturnCode = ERROR_INVALID_DATA;
                        }
                    } else {
                        AL_TRACE_ERROR(_T("Unknown command (%ls)."), pwcArglist[1]);
                        dwReturnCode = ERROR_INVALID_DATA;
                    }
                } else
                    dwReturnCode = ERROR_INVALID_DATA;

                LocalFree(pwcArglist);
            }

            AL::Heap::Done();
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}
