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
#ifdef USE_WINXP_THEMES
#pragma comment(lib, "UxTheme.lib")
#endif

//
// Local constants
//
#define ID_AL_MONITOR_ICON                  1

#define ID_AL_MONITOR_ICON_SESSION          0
#define ID_AL_MONITOR_ICON_SUCCESS          1
#define ID_AL_MONITOR_ICON_ERROR            2
#ifdef AL_MONITOR_INFO_ICON
#define ID_AL_MONITOR_ICON_INFO             3
#else
#define ID_AL_MONITOR_ICON_INFO             I_IMAGENONE
#endif

#define AL_MONITOR_SHUTDOWN_TIMER_ID        1
#define AL_MONITOR_SHUTDOWN_TIMER_PERIOD    5000


//
// Messages
//
const UINT WM_AL_MONITOR_START   = ::RegisterWindowMessage(_T("ALMonitorStart")  ); // Monitor sends this message to notify us about session start.
const UINT WM_AL_MONITOR_END     = ::RegisterWindowMessage(_T("ALMonitorEnd")    ); // Monitor sends this message to notify us about session end.
const UINT WM_AL_MONITOR_INFO    = ::RegisterWindowMessage(_T("ALMonitorInfo")   ); // Monitor sends this message to notify us about a message.
const UINT WM_AL_MONITOR_SUCCESS = ::RegisterWindowMessage(_T("ALMonitorSuccess")); // Monitor sends this message to notify us about a success.
const UINT WM_AL_MONITOR_ERROR   = ::RegisterWindowMessage(_T("ALMonitorError")  ); // Monitor sends this message to notify us about an error.


//
// Global data
//
HINSTANCE AL::System::g_hInstance = NULL;
HINSTANCE AL::System::g_hResource = NULL;


//
// Local Types
//
struct AL_MONITOR_MSG {
    LPCWSTR pszTitle;
    LPCWSTR pszDescription;
};


struct AL_MONITOR_RECORD {
    LPCTSTR pszTooltip;
    LPCTSTR pszLogFile;
};


#pragma pack(push, 1)

struct DLGTEMPLATEEX
{
    WORD  dlgVer;
    WORD  signature;
    DWORD helpID;
    DWORD exStyle;
    DWORD style;
    WORD  cDlgItems;
    short x;
    short y;
    short cx;
    short cy;

    // Everything else in this structure is variable length,
    // and therefore must be determined dynamically

    // sz_Or_Ord menu;        // name or ordinal of a menu resource
    // sz_Or_Ord windowClass; // name or ordinal of a window class
    // WCHAR title[titleLen]; // title string of the dialog box
    // short pointsize;       // only if DS_SETFONT is set
    // short weight;          // only if DS_SETFONT is set
    // short bItalic;         // only if DS_SETFONT is set
    // WCHAR font[fontLen];   // typeface name, if DS_SETFONT is set
};

#pragma pack(pop)


//
// Local data
//
static HINSTANCE g_hInstanceShell32 = NULL;


//
// Local function declarations
//
static LRESULT CALLBACK _MonitorWndProc(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam);
static INT_PTR CALLBACK _MonitorDlgProc(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam);
static inline HTREEITEM _RecordSession(_In_z_count_(iSessionIdLenZ) LPCTSTR szSessionId, _In_ int iSessionIdLenZ, _In_opt_z_ LPCTSTR szLogFile, _In_ HWND hWndTree, _In_opt_ HTREEITEM hParent = TVI_ROOT);
static inline HTREEITEM _RecordMessage(_In_z_count_(iNameLenZ) LPCTSTR szName, _In_ int iNameLenZ, _In_z_count_(iTooltipLen) LPCTSTR szTooltip, _In_ int iTooltipLen, _In_ int iImage, _In_ HWND hWndTree, _In_opt_ HTREEITEM hParent = TVI_ROOT);
static void _TreeView_DestroyChildren(_In_ HWND hWndTree, _In_ HTREEITEM hParent);
static SIZE_T _TreeView_MakeReport(_In_ HWND hWndTree, _In_ HTREEITEM hParent, _In_ int iIdent, _Out_z_capcount_(nOutputLen) LPTSTR szOutput, _In_ SIZE_T nOutputLen);
static inline SIZE_T _sz_Or_Ord_len(_In_ const LPWORD pData);


//
// Main function
//
int CALLBACK WinMain(_In_ HINSTANCE hInstance, _In_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
    DWORD dwReturnCode = NO_ERROR;

    AL::System::g_hInstance = hInstance;
    AL::Trace::Init(_T("AL-MONITOR"));
    {
        AL_TRACEFN_INFO(dwReturnCode);

#ifdef USE_WINXP_THEMES
        {
            //
            // Initialize Windows XP visual styles
            //
            INITCOMMONCONTROLSEX icc;
            icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
            icc.dwICC = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES | ICC_TREEVIEW_CLASSES | ICC_LINK_CLASS;
            InitCommonControlsEx(&icc);
        }
#endif

        if ((dwReturnCode = AL::Heap::Init()) == NO_ERROR) {
            int nArgs;
            LPWSTR *pwcArglist;
            if ((pwcArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs)) != NULL) {
                AL_TRACE_INFO(_T("arguments (%ld)."), nArgs);

                //
                // Get Shell32.dll version, since different versions accept different NOTIFYICONDATA structure size.
                //
                g_hInstanceShell32 = LoadLibrary(_T("shell32.dll"));
                if (g_hInstanceShell32) {
                    if ((AL::System::g_hResource = AL::System::LoadLibrary(AL::System::g_hInstance, _T("al_res.dll"), LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE)) != NULL) {
                        AL_TRACE_INFO(_T("Loaded resource."));

                        HRSRC hResInfo;
                        if ((hResInfo = ::FindResource(AL::System::g_hResource, MAKEINTRESOURCE(IDD_AL_MONITOR), RT_DIALOG)) != NULL) {
                            HGLOBAL hResource;
                            if ((hResource = ::LoadResource(AL::System::g_hResource, hResInfo)) != NULL) {
                                DLGTEMPLATEEX *pDlgTemplate;
                                if ((pDlgTemplate = (DLGTEMPLATEEX*)::LockResource(hResource)) != NULL) {
                                    if (pDlgTemplate->dlgVer == 1 && pDlgTemplate->signature == 0xFFFF) {
                                        LPWORD pData = (LPWORD)(pDlgTemplate + 1); // Skip DLGTEMPLATEEX fixed part
                                        pData += _sz_Or_Ord_len(pData); // Skip menu
                                        pData += _sz_Or_Ord_len(pData); // Skip windowClass
                                        LPCWSTR pszMonitorDlgTitle = pData[0] != 0 ? (LPCWSTR)pData : NULL;

                                        if (nArgs == 1) {
                                            //
                                            // No parameters: This is the main process.
                                            //
                                            HWND hWnd;
                                            if ((hWnd = ::FindWindow(_T("#32770"), pszMonitorDlgTitle)) == NULL) {
                                                if ((hWnd = ::CreateDialog(AL::System::g_hResource, MAKEINTRESOURCE(IDD_AL_MONITOR), NULL, _MonitorDlgProc)) != NULL) {
                                                    static ACCEL s_accel[] = {{ FCONTROL | FVIRTKEY, 'C', IDC_AL_MONITOR_COPY }};
                                                    HACCEL hAccel;
                                                    if ((hAccel = CreateAcceleratorTable(s_accel, _countof(s_accel))) != NULL) {
                                                        ShowWindow(hWnd, nCmdShow);
                                                        UpdateWindow(hWnd);
                                                        MSG msg;
                                                        while (::GetMessage(&msg, NULL, 0, 0) > 0) {
                                                            if (::TranslateAccelerator(hWnd, hAccel, &msg))
                                                                continue;
                                                            if (::IsDialogMessage(hWnd, &msg))
                                                                continue;

                                                            ::TranslateMessage(&msg);
                                                            ::DispatchMessage(&msg);
                                                        }
                                                        dwReturnCode = (DWORD)msg.wParam;
                                                        DestroyAcceleratorTable(hAccel);
                                                    } else
                                                        AL_TRACE_ERROR(_T("CreateAcceleratorTable failed (%ld)."), dwReturnCode = GetLastError());
                                                } else
                                                    AL_TRACE_ERROR(_T("CreateDialogParam failed (%ld)."), dwReturnCode = GetLastError());
                                            } else {
                                                // The monitor is already started.
                                                dwReturnCode = NO_ERROR;
                                            }
                                        } else if (nArgs >= 3) {
                                            HWND hWnd;
                                            if ((hWnd = ::FindWindow(_T("#32770"), pszMonitorDlgTitle)) != NULL) {
                                                //
                                                // Get the process of monitor window.
                                                //
                                                DWORD dwMonitorPID;
                                                ::GetWindowThreadProcessId(hWnd, &dwMonitorPID);
                                                HANDLE hMonitorProcess;
                                                if ((hMonitorProcess = ::OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, 0, dwMonitorPID)) != NULL) {
                                                    //
                                                    // Copy session ID text to monitor process's address space.
                                                    //
                                                    SIZE_T nSize = (wcslen(pwcArglist[1]) + 1) * sizeof(WCHAR);
                                                    LPVOID hSessionID;
                                                    if ((hSessionID = VirtualAllocEx(hMonitorProcess, NULL, nSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != NULL) {
                                                        if (WriteProcessMemory(hMonitorProcess, hSessionID, pwcArglist[1], nSize, NULL)) {
                                                            UINT uMessage;
                                                            if (_wcsicmp(pwcArglist[2], L"begin") == 0) {
                                                                if (nArgs >= 4) {
                                                                    //
                                                                    // Session starting.
                                                                    //
                                                                    AL_TRACE_INFO(_T("Starting EAP session."));

                                                                    //
                                                                    // Copy log ID to monitor process's address space.
                                                                    //
                                                                    nSize = (wcslen(pwcArglist[3]) + 1) * sizeof(WCHAR);
                                                                    LPVOID hTraceId;
                                                                    if ((hTraceId = VirtualAllocEx(hMonitorProcess, NULL, nSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != NULL) {
                                                                        if (WriteProcessMemory(hMonitorProcess, hTraceId, pwcArglist[3], nSize, NULL)) {
                                                                            //
                                                                            // Send the message.
                                                                            //
                                                                            SendMessage(hWnd, WM_AL_MONITOR_START, (WPARAM)hSessionID, (LPARAM)hTraceId);
                                                                        } else
                                                                            AL_TRACE_ERROR(_T("WriteProcessMemory failed (%ld)."), dwReturnCode = GetLastError());
                                                                        VirtualFreeEx(hMonitorProcess, hTraceId, 0, MEM_RELEASE);
                                                                    } else
                                                                        AL_TRACE_ERROR(_T("VirtualAllocEx failed (%ld)."), dwReturnCode = GetLastError());
                                                                } else {
                                                                    AL_TRACE_ERROR(_T("Not enough arguments to \"%ls\" command (expected: %ld, provided: %ld)."), pwcArglist[2], 4, nArgs);
                                                                    dwReturnCode = ERROR_INVALID_DATA;
                                                                }
                                                            } else if (_wcsicmp(pwcArglist[2], L"end") == 0) {
                                                                //
                                                                // Session ended.
                                                                //
                                                                AL_TRACE_INFO(_T("Ending EAP session."));

                                                                //
                                                                // Send the message.
                                                                //
                                                                SendMessage(hWnd, WM_AL_MONITOR_END, (WPARAM)hSessionID, 0);
                                                            } else if (
                                                                _wcsicmp(pwcArglist[2], L"info"   ) == 0 && (uMessage = WM_AL_MONITOR_INFO,    TRUE) ||
                                                                _wcsicmp(pwcArglist[2], L"success") == 0 && (uMessage = WM_AL_MONITOR_SUCCESS, TRUE) ||
                                                                _wcsicmp(pwcArglist[2], L"error"  ) == 0 && (uMessage = WM_AL_MONITOR_ERROR,   TRUE))
                                                            {
                                                                if (nArgs >= 4) {
                                                                    //
                                                                    // A message/error received.
                                                                    //
                                                                    AL_TRACE_INFO(_T("Received a message/error."));

                                                                    AL_MONITOR_MSG msg;

                                                                    //
                                                                    // Copy message title to monitor process's address space.
                                                                    //
                                                                    ATL::CAtlStringW sTitle;
                                                                    AL::Buffer::CommandLine::Decode(pwcArglist[3], sTitle);
                                                                    nSize = (sTitle.GetLength() + 1) * sizeof(WCHAR);
                                                                    if ((msg.pszTitle = (LPCWSTR)VirtualAllocEx(hMonitorProcess, NULL, nSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != NULL) {
                                                                        if (WriteProcessMemory(hMonitorProcess, (LPVOID)msg.pszTitle, (LPCWSTR)sTitle, nSize, NULL)) {
                                                                            if (nArgs >= 5) {
                                                                                //
                                                                                // Copy message tooltip to monitor process's address space.
                                                                                //
                                                                                ATL::CAtlStringW sDescription;
                                                                                AL::Buffer::CommandLine::Decode(pwcArglist[4], sDescription);
                                                                                nSize = (sDescription.GetLength() + 1) * sizeof(WCHAR);
                                                                                if ((msg.pszDescription = (LPCWSTR)VirtualAllocEx(hMonitorProcess, NULL, nSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != NULL) {
                                                                                    if (!WriteProcessMemory(hMonitorProcess, (LPVOID)msg.pszDescription, (LPCWSTR)sDescription, nSize, NULL)) {
                                                                                        AL_TRACE_ERROR(_T("WriteProcessMemory failed (%ld)."), dwReturnCode = GetLastError());
                                                                                        VirtualFreeEx(hMonitorProcess, (LPVOID)msg.pszDescription, 0, MEM_RELEASE);
                                                                                        msg.pszDescription = NULL;
                                                                                    }
                                                                                } else
                                                                                    AL_TRACE_ERROR(_T("VirtualAllocEx failed (%ld)."), dwReturnCode = GetLastError());
                                                                            } else
                                                                                msg.pszDescription = NULL;

                                                                            //
                                                                            // Copy message descriptor to monitor process's address space.
                                                                            //
                                                                            LPVOID hMsg;
                                                                            if ((hMsg = VirtualAllocEx(hMonitorProcess, NULL, sizeof(msg), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != NULL) {
                                                                                if (WriteProcessMemory(hMonitorProcess, hMsg, &msg, sizeof(msg), NULL)) {
                                                                                    //
                                                                                    // Send the message.
                                                                                    //
                                                                                    SendMessage(hWnd, uMessage, (WPARAM)hSessionID, (LPARAM)hMsg);
                                                                                } else
                                                                                    AL_TRACE_ERROR(_T("WriteProcessMemory failed (%ld)."), dwReturnCode = GetLastError());
                                                                                VirtualFreeEx(hMonitorProcess, hMsg, 0, MEM_RELEASE);
                                                                            } else
                                                                                AL_TRACE_ERROR(_T("VirtualAllocEx failed (%ld)."), dwReturnCode = GetLastError());

                                                                            if (msg.pszDescription)
                                                                                VirtualFreeEx(hMonitorProcess, (LPVOID)msg.pszDescription, 0, MEM_RELEASE);
                                                                        } else
                                                                            AL_TRACE_ERROR(_T("WriteProcessMemory failed (%ld)."), dwReturnCode = GetLastError());
                                                                        VirtualFreeEx(hMonitorProcess, (LPVOID)msg.pszTitle, 0, MEM_RELEASE);
                                                                    } else
                                                                        AL_TRACE_ERROR(_T("VirtualAllocEx failed (%ld)."), dwReturnCode = GetLastError());
                                                                } else {
                                                                    AL_TRACE_ERROR(_T("Not enough arguments to \"%ls\" command (expected: %ld, provided: %ld)."), pwcArglist[2], 4, nArgs);
                                                                    dwReturnCode = ERROR_INVALID_DATA;
                                                                }
                                                            } else {
                                                                AL_TRACE_ERROR(_T("Unknown command (%ls)."), pwcArglist[2]);
                                                                dwReturnCode = ERROR_INVALID_DATA;
                                                            }
                                                        } else
                                                            AL_TRACE_ERROR(_T("WriteProcessMemory failed (%ld)."), dwReturnCode = GetLastError());
                                                        VirtualFreeEx(hMonitorProcess, hSessionID, 0, MEM_RELEASE);
                                                    } else
                                                        AL_TRACE_ERROR(_T("VirtualAllocEx failed (%ld)."), dwReturnCode = GetLastError());
                                                    CloseHandle(hMonitorProcess);
                                                } else
                                                    AL_TRACE_ERROR(_T("OpenProcess failed (%ld)."), dwReturnCode = GetLastError());
                                            } else {
                                                // The monitor was not found (not running?).
                                                dwReturnCode = NO_ERROR;
                                            }
                                        } else
                                            dwReturnCode = ERROR_INVALID_DATA;
                                    } else {
                                        AL_TRACE_ERROR(_T("Invalid dialog resource."));
                                        dwReturnCode = ERROR_INTERNAL_ERROR;
                                    }
                                } else {
                                    AL_TRACE_ERROR(_T("LockResource failed."));
                                    dwReturnCode = ERROR_INTERNAL_ERROR;
                                }
                            } else
                                AL_TRACE_ERROR(_T("LoadResource failed (%ld)."), dwReturnCode = GetLastError());
                        } else
                            AL_TRACE_ERROR(_T("FindResourceEx failed (%ld)."), dwReturnCode = GetLastError());

                        FreeLibrary(AL::System::g_hResource);
                    } else
                        dwReturnCode = ERROR_INVALID_DATA;
                } else
                    AL_TRACE_ERROR(_T("LoadLibrary(SHELL32.DLL) failed (%ld)."), dwReturnCode = GetLastError());

                LocalFree(pwcArglist);
            }

            AL::Heap::Done();
        }
    }
    AL::Trace::Done();

    return dwReturnCode;
}


//
// Dialog function for the monitor window
//
static INT_PTR CALLBACK _MonitorDlgProc(IN HWND hWnd, IN UINT uMsg, IN WPARAM wParam, IN LPARAM lParam)
{
    struct WNDDATA {
        HIMAGELIST hImageList;
#ifdef AL_MONITOR_FONT_LARGE
        HFONT hFontLarge;
#endif
        HICON hIconNormal;
        HICON hIconSmall;
        HMENU hMenu;
        RECT rectTreeMargin;
        RECT rectCopyRel;
        LONG nFooterHeight;
        SIZE szMinTrack;
        BOOL bPlacementRestored;
    };

    switch (uMsg) {
        case WM_INITDIALOG: {
            WNDDATA *pWndData;

            //
            // Create and initialize window data.
            //
            if (AL::Heap::Alloc(sizeof(WNDDATA), (LPVOID*)&pWndData) != NO_ERROR)
                return -1;
            SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pWndData);

            {
                //
                // Create image list for tree view control and add icons to the images list.
                //
                SIZE sizeIcon;
                sizeIcon.cx = ::GetSystemMetrics(SM_CXSMICON);
                sizeIcon.cy = ::GetSystemMetrics(SM_CYSMICON);
                if ((pWndData->hImageList = ImageList_Create(sizeIcon.cx, sizeIcon.cy, ILC_COLOR32, 4, 2)) != NULL) {
                    HINSTANCE hInstanceIEFrame;
                    if ((hInstanceIEFrame = LoadLibraryEx(_T("ieframe.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE)) != NULL) {
                        HRESULT hResult;
                        HICON hIcon;

                        //
                        // Load and add session icon.
                        //
                        if (FAILED(hResult = LoadIconWithScaleDown(hInstanceIEFrame, MAKEINTRESOURCEW(10399), sizeIcon.cx, sizeIcon.cy, &hIcon))) {
                            AL_TRACE_ERROR(_T("LoadIconWithScaleDown failed (%ld)."), hResult);
                            return -1;
                        } else if (hIcon == NULL) {
                            AL_TRACE_ERROR(_T("LoadIconWithScaleDown returned NULL icon."));
                            return -1;
                        } else {
                            ImageList_AddIcon(pWndData->hImageList, hIcon);
                            DestroyIcon(hIcon);
                        }

                        //
                        // Load and add success icon.
                        //
                        if (FAILED(hResult = LoadIconWithScaleDown(hInstanceIEFrame, MAKEINTRESOURCEW(18211), sizeIcon.cx, sizeIcon.cy, &hIcon))) {
                            AL_TRACE_ERROR(_T("LoadIconWithScaleDown failed (%ld)."), hResult);
                            return -1;
                        } else if (hIcon == NULL) {
                            AL_TRACE_ERROR(_T("LoadIconWithScaleDown returned NULL icon."));
                            return -1;
                        } else {
                            ImageList_AddIcon(pWndData->hImageList, hIcon);
                            DestroyIcon(hIcon);
                        }

                        //
                        // Load and add error icon.
                        //
                        if (FAILED(hResult = LoadIconWithScaleDown(hInstanceIEFrame, MAKEINTRESOURCEW(41755), sizeIcon.cx, sizeIcon.cy, &hIcon))) {
                            AL_TRACE_ERROR(_T("LoadIconWithScaleDown failed (%ld)."), hResult);
                            return -1;
                        } else if (hIcon == NULL) {
                            AL_TRACE_ERROR(_T("LoadIconWithScaleDown returned NULL icon."));
                            return -1;
                        } else {
                            ImageList_AddIcon(pWndData->hImageList, hIcon);
                            DestroyIcon(hIcon);
                        }

#ifdef AL_MONITOR_INFO_ICON
                        //
                        // Load and add info icon.
                        //
                        if (FAILED(hResult = LoadIconWithScaleDown(g_hInstanceShell32, MAKEINTRESOURCEW(16800), sizeIcon.cx, sizeIcon.cy, &hIcon))) {
                            AL_TRACE_ERROR(_T("LoadIconWithScaleDown failed (%ld)."), hResult);
                            return -1;
                        } else if (hIcon == NULL) {
                            AL_TRACE_ERROR(_T("LoadIconWithScaleDown returned NULL icon."));
                            return -1;
                        } else {
                            ImageList_AddIcon(pWndData->hImageList, hIcon);
                            DestroyIcon(hIcon);
                        }
#endif

                        FreeLibrary(hInstanceIEFrame);
                    } else
                        AL_TRACE_ERROR(_T("LoadLibraryEx(ieframe.dll) failed (%ld)."), GetLastError());
                }
            }

            HWND hWndTree = GetDlgItem(hWnd, IDC_AL_MONITOR_TREE);
            {
#ifdef AL_MONITOR_FONT_LARGE
                //
                // Make large fonts.
                //
                HFONT hFontWnd;
                if ((hFontWnd = (HFONT)::SendMessage(hWnd, WM_GETFONT, 0, 0)) != NULL) {
                    LOGFONT lf;
                    ::GetObject(hFontWnd, sizeof(lf), &lf);
                    lf.lfHeight = MulDiv(lf.lfHeight, 110, 100);
                    if ((pWndData->hFontLarge = ::CreateFontIndirect(&lf)) != NULL)
                        ::SendMessage(hWndTree, WM_SETFONT, (WPARAM)(pWndData->hFontLarge), FALSE);
                    else
                        AL_TRACE_ERROR(_T("CreateFontIndirect failed (%ld)."), GetLastError());
                } else
                    AL_TRACE_ERROR(_T("SendMessage(WM_GETFONT) failed (%ld)."), GetLastError());
#endif

#ifdef USE_WINXP_THEMES
                SetWindowTheme(hWndTree, L"Explorer", NULL);
#endif
                TreeView_SetImageList(hWndTree, pWndData->hImageList, TVSIL_NORMAL);
                SetFocus(GetDlgItem(hWnd, IDC_AL_MONITOR_TREE));
            }

            {
                //
                // Set icon(s).
                //
                HRESULT hResult;
                if (FAILED(hResult = LoadIconWithScaleDown(AL::System::g_hInstance, MAKEINTRESOURCEW(IDI_ICON1), ::GetSystemMetrics(SM_CXICON), ::GetSystemMetrics(SM_CYICON), &(pWndData->hIconNormal))))
                    AL_TRACE_ERROR(_T("LoadIconWithScaleDown failed (%ld)."), hResult);
                else if (pWndData->hIconNormal == NULL)
                    AL_TRACE_ERROR(_T("LoadIconWithScaleDown returned NULL icon."));
                else
                    ::SendMessage(hWnd, WM_SETICON, TRUE, (LPARAM)pWndData->hIconNormal);

                if (FAILED(hResult = LoadIconWithScaleDown(AL::System::g_hInstance, MAKEINTRESOURCEW(IDI_ICON1), ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON), &(pWndData->hIconSmall))))
                    AL_TRACE_ERROR(_T("LoadIconWithScaleDown failed (%ld)."), hResult);
                else if (pWndData->hIconSmall == NULL)
                    AL_TRACE_ERROR(_T("LoadIconWithScaleDown returned NULL icon."));
                else
                    ::SendMessage(hWnd, WM_SETICON, FALSE, (LPARAM)pWndData->hIconSmall);
            }

            //
            // Prepare menu.
            //
            if ((pWndData->hMenu = LoadMenu(AL::System::g_hResource, MAKEINTRESOURCE(IDM_AL_MONITOR))) == NULL) {
                AL_TRACE_ERROR(_T("LoadMenu failed (%ld)."), ::GetLastError());
                return -1;
            }

            {
                //
                // Measure and save control positions & dimensions for proper dialog resizing.
                //
                RECT rectParent, rect;
                ::GetClientRect(hWnd, &rectParent);
                pWndData->szMinTrack.cx = rectParent.right  - rectParent.left;
                pWndData->szMinTrack.cy = rectParent.bottom - rectParent.top;

                ::GetClientRect(hWndTree, &rect);
                ::MapWindowPoints(hWndTree, hWnd, (LPPOINT)&rect, 2);
                pWndData->rectTreeMargin.left   = rect.left   - rectParent.left;
                pWndData->rectTreeMargin.top    = rect.top    - rectParent.top;
                pWndData->rectTreeMargin.right  = rect.right  - rectParent.right;
                pWndData->rectTreeMargin.bottom = rect.bottom - rectParent.bottom;

                HWND hWndFooter = GetDlgItem(hWnd, IDC_AL_MONITOR_FOOTER);
                ::GetClientRect(hWndFooter, &rect);
                ::MapWindowPoints(hWndFooter, hWnd, (LPPOINT)&rect, 2);
                pWndData->nFooterHeight = rectParent.bottom - rect.top;

                HWND hWndCopy = GetDlgItem(hWnd, IDC_AL_MONITOR_COPY);
                ::GetClientRect(hWndCopy, &rect);
                ::MapWindowPoints(hWndCopy, hWnd, (LPPOINT)&rect, 2);
                pWndData->rectCopyRel.left   = rect.left   - rectParent.left;
                pWndData->rectCopyRel.top    = rect.top    - rectParent.bottom;
                pWndData->rectCopyRel.right  = rect.right  - rectParent.right;
                pWndData->rectCopyRel.bottom = rect.bottom - rectParent.bottom;
            }

            return TRUE;
        }

        case WM_SHOWWINDOW: {
            if (wParam && !IsWindowVisible(hWnd)) {
                WNDDATA *pWndData = (WNDDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
                if (!pWndData->bPlacementRestored) {
                    pWndData->bPlacementRestored = TRUE; // Prevents resetting window placement on every hide=>show, and an endless loop (SetWindowPlacement() triggers nested WM_SHOWWINDOW message).

                    //
                    // Load and set the window placement.
                    //
                    HKEY hKey;
                    if (::RegOpenKeyEx(HKEY_CURRENT_USER, _T("SOFTWARE\\ArnesLink\\Monitor"), 0, KEY_READ, &hKey) == NO_ERROR) {
                        WINDOWPLACEMENT wp;
                        DWORD dwType, dwSize = sizeof(wp);
                        if (::RegQueryValueEx(hKey, _T("WindowPlacement"), 0, &dwType, (LPBYTE)&wp, &dwSize) == NO_ERROR && dwType == REG_BINARY && dwSize >= sizeof(wp.length) && dwSize >= wp.length)
                            ::SetWindowPlacement(hWnd, &wp);
                        ::RegCloseKey(hKey);
                    }
                }
            }

            return FALSE;
        }

        case WM_CLOSE:
            DestroyWindow(hWnd);
            return FALSE;

        case WM_DESTROY: {
            WNDDATA *pWndData = (WNDDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

            {
                //
                // Get and save the window placement.
                //
                WINDOWPLACEMENT wp = { sizeof(wp) };
                if (::GetWindowPlacement(hWnd, &wp)) {
                    HKEY hKey;
                    if (::RegCreateKeyEx(HKEY_CURRENT_USER, _T("SOFTWARE\\ArnesLink\\Monitor"), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == NO_ERROR) {
                        ::RegSetValueEx(hKey, _T("WindowPlacement"), 0, REG_BINARY, (LPBYTE)&wp, sizeof(wp));
                        ::RegCloseKey(hKey);
                    }
                }
            }

            //
            // Destroy menu.
            //
            if (pWndData->hMenu)
                DestroyMenu(pWndData->hMenu);

            _TreeView_DestroyChildren(GetDlgItem(hWnd, IDC_AL_MONITOR_TREE), TVI_ROOT);

            if (pWndData->hIconSmall)
                ::DestroyIcon(pWndData->hIconSmall);

            if (pWndData->hIconNormal)
                ::DestroyIcon(pWndData->hIconNormal);

#ifdef AL_MONITOR_FONT_LARGE
            if (pWndData->hFontLarge)
                DeleteObject(pWndData->hFontLarge);
#endif

            if (pWndData->hImageList)
                ImageList_Destroy(pWndData->hImageList);

            AL::Heap::Free((LPVOID*)&pWndData);
            PostQuitMessage(0);
            return FALSE;
        }

#ifdef USE_WINXP_THEMES
        case WM_ERASEBKGND: {
            if (::IsThemeActive()) {
                HTHEME hTheme;
                if ((hTheme = ::OpenThemeData(hWnd, VSCLASS_FLYOUT)) != NULL) {
                    RECT rectParent;
                    ::GetClientRect(hWnd, &rectParent);

                    HWND hWndFooter;
                    if ((hWndFooter = GetDlgItem(hWnd, IDC_AL_MONITOR_FOOTER)) != NULL) {
                        RECT rectBody, rectFooter;
                        ::GetClientRect(hWndFooter, &rectFooter);
                        ::MapWindowPoints(hWndFooter, hWnd, (LPPOINT)&rectFooter, 2);
                        SubtractRect(&rectBody, &rectParent, &rectFooter);

                        ::DrawThemeBackground(hTheme, (HDC)wParam, FLYOUT_WINDOW,   0, &rectBody,   NULL);
                        ::DrawThemeBackground(hTheme, (HDC)wParam, FLYOUT_LINKAREA, 0, &rectFooter, NULL);
                    } else {
                        AL_TRACE_WARNING(_T("IDC_AL_MONITOR_FOOTER control not found."));
                        ::DrawThemeBackground(hTheme, (HDC)wParam, FLYOUT_WINDOW,   0, &rectParent,  NULL);
                    }

                    ::CloseThemeData(hTheme);
                    return TRUE;
                }
            }

            break;
        }
#endif

        case WM_GETMINMAXINFO: {
            WNDDATA *pWndData = (WNDDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
            LPMINMAXINFO pMinMaxInfo = (LPMINMAXINFO)lParam;
            pMinMaxInfo->ptMinTrackSize.x = pWndData->szMinTrack.cx;
            pMinMaxInfo->ptMinTrackSize.y = pWndData->szMinTrack.cy;
            return FALSE;
        }

        case WM_SIZE: {
            WNDDATA *pWndData = (WNDDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
            LONG cx = LOWORD(lParam), cy = HIWORD(lParam);

            //
            // Resize IDC_AL_MONITOR_TREE (relative to lower right corner of the dialog).
            //
            ::MoveWindow(GetDlgItem(hWnd, IDC_AL_MONITOR_TREE),
                     pWndData->rectTreeMargin.left,
                     pWndData->rectTreeMargin.top,
                cx + pWndData->rectTreeMargin.right  - pWndData->rectTreeMargin.left,
                cy + pWndData->rectTreeMargin.bottom - pWndData->rectTreeMargin.top,
                FALSE);

            //
            // Move and resize IDC_AL_MONITOR_FOOTER (relative to lower right corner of the dialog).
            //
            ::MoveWindow(GetDlgItem(hWnd, IDC_AL_MONITOR_FOOTER),
                0,
                cy - pWndData->nFooterHeight,
                cx,
                pWndData->nFooterHeight,
                FALSE);

            //
            // Move IDC_AL_MONITOR_COPY (relative to lower left corner of the dialog).
            //
            ::MoveWindow(GetDlgItem(hWnd, IDC_AL_MONITOR_COPY),
                pWndData->rectCopyRel.left   + 0,
                pWndData->rectCopyRel.top    + cy,
                pWndData->rectCopyRel.right  + cx - pWndData->rectCopyRel.left,
                pWndData->rectCopyRel.bottom - pWndData->rectCopyRel.top,
                FALSE);

            InvalidateRect(hWnd, NULL, TRUE);

            return FALSE;
        }

        case WM_NOTIFY: {
            LPNMHDR pMsgHdr = (LPNMHDR)lParam;
            switch (pMsgHdr->idFrom) {
                case IDC_AL_MONITOR_COPY:
                    switch (pMsgHdr->code) {
                        case NM_CLICK:
                        case NM_RETURN:
                            if (_tcsicmp(_T("clipboard:copy"), ((PNMLINK)lParam)->item.szUrl) == 0) {
                                SendMessage(hWnd, WM_COMMAND, MAKEWPARAM(IDC_AL_MONITOR_COPY, 1), 0);
                                return TRUE;
                            }
                            break;
                    }
                    break;

                case IDC_AL_MONITOR_TREE: {
                    switch (pMsgHdr->code) {
                        case TVN_GETINFOTIP: {
                            LPNMTVGETINFOTIP pnmtvGetInfoTip = (LPNMTVGETINFOTIP)lParam;
                            if (pnmtvGetInfoTip->lParam) {
                                const AL_MONITOR_RECORD *pData = (const AL_MONITOR_RECORD*)pnmtvGetInfoTip->lParam;
                                if (pData->pszTooltip)
                                    _tcsncpy_s(pnmtvGetInfoTip->pszText, pnmtvGetInfoTip->cchTextMax, pData->pszTooltip, _TRUNCATE);
                                else if (pnmtvGetInfoTip->cchTextMax > 0)
                                    pnmtvGetInfoTip->pszText[0] = 0;
                                return TRUE;
                            }
                            break;
                        }

                        case NM_RCLICK: {
                            //
                            // Get item under mouse cursor.
                            //
                            HWND hWndTree = GetDlgItem(hWnd, IDC_AL_MONITOR_TREE);
                            POINT pt;
                            GetCursorPos(&pt);
                            TVHITTESTINFO ht = { pt };
                            ScreenToClient(hWndTree, &(ht.pt));
                            if (TreeView_HitTest(hWndTree, &ht) != NULL && (ht.flags & TVHT_ONITEM) != 0) {
                                TVITEM tvItem;
                                tvItem.hItem = ht.hItem;
                                tvItem.mask  = TVIF_PARAM;
                                if (TreeView_GetItem(hWndTree, &tvItem)) {
                                    const AL_MONITOR_RECORD *pData = (const AL_MONITOR_RECORD*)tvItem.lParam;
                                    if (pData->pszLogFile) {
                                        //
                                        // Show menu.
                                        //
                                        WNDDATA *pWndData = (WNDDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
                                        if ((UINT)TrackPopupMenu(::GetSubMenu(pWndData->hMenu, 0), TPM_RETURNCMD, pt.x, pt.y, 0, hWnd, NULL) == ID_AL_MONITOR_SHOW_LOG)
                                            ::ShellExecute(NULL, L"open", pData->pszLogFile, NULL, NULL, SW_SHOW);

                                        return TRUE;
                                    }
                                }
                            }
                            break;
                        }

                        case TVN_KEYDOWN: {
                            LPNMTVKEYDOWN pMsgKeyDown = (LPNMTVKEYDOWN)lParam;
                            if (pMsgKeyDown->wVKey == VK_APPS) {
                                //
                                // Get selected item.
                                //
                                HWND hWndTree = GetDlgItem(hWnd, IDC_AL_MONITOR_TREE);
                                TVITEM tvItem;
                                tvItem.mask = TVIF_PARAM;
                                if ((tvItem.hItem = TreeView_GetSelection(hWndTree)) != NULL) {
                                    if (TreeView_GetItem(hWndTree, &tvItem)) {
                                        const AL_MONITOR_RECORD *pData = (const AL_MONITOR_RECORD*)tvItem.lParam;
                                        if (pData->pszLogFile) {
                                            //
                                            // Calculate menu position.
                                            //
                                            POINT pt;
                                            RECT rect;
                                            if (TreeView_GetItemRect(hWndTree, tvItem.hItem, &rect, TRUE)) {
                                                pt.x = rect.left;
                                                pt.y = rect.bottom;
                                                ClientToScreen(hWndTree, &pt);
                                            } else {
                                                pt.x = 0;
                                                pt.y = 0;
                                            }

                                            //
                                            // Show menu.
                                            //
                                            WNDDATA *pWndData = (WNDDATA*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
                                            if ((UINT)TrackPopupMenu(::GetSubMenu(pWndData->hMenu, 0), TPM_RETURNCMD, pt.x, pt.y, 0, hWnd, NULL) == ID_AL_MONITOR_SHOW_LOG)
                                                ::ShellExecute(NULL, L"open", pData->pszLogFile, NULL, NULL, SW_SHOW);

                                            return TRUE;
                                        }
                                    }
                                }
                                return FALSE;
                            }
                            break;
                        }
                    }
                    break;
                }
            }
            break;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_AL_MONITOR_COPY: {
                    TCHAR szTemp[8192] = _T("--- BEGIN TRACE ---\r\n");
                    SIZE_T nTempLen = 21;
                    nTempLen += _TreeView_MakeReport(GetDlgItem(hWnd, IDC_AL_MONITOR_TREE), TVI_ROOT, 0, szTemp + nTempLen, _countof(szTemp) - nTempLen);
                    wmemcpy(szTemp + nTempLen, _T("--- END TRACE ---\r\n"), min(20, _countof(szTemp) - nTempLen));

                    if (OpenClipboard(hWnd)) {
                        EmptyClipboard();

                        SIZE_T nTextLenZ = _tcsnlen(szTemp, _countof(szTemp)) + 1;
                        HGLOBAL hglbCopy;
                        if ((hglbCopy = GlobalAlloc(GMEM_MOVEABLE, nTextLenZ * sizeof(TCHAR))) != NULL) {
                            LPTSTR szText;
                            if ((szText = (LPTSTR)GlobalLock(hglbCopy)) != NULL) {
                                memcpy(szText, szTemp, nTextLenZ * sizeof(TCHAR));
                                GlobalUnlock(hglbCopy);
                            } else
                                AL_TRACE_ERROR(_T("GlobalLock failed (%ld)."), GetLastError());

                            SetClipboardData(
#ifdef _UNICODE
                                CF_UNICODETEXT,
#else
                                CF_TEXT,
#endif
                                hglbCopy);
                        } else
                            AL_TRACE_ERROR(_T("GlobalAlloc failed (%ld)."), GetLastError());

                        CloseClipboard();
                    } else
                        AL_TRACE_ERROR(_T("OpenClipboard failed (%ld)."), GetLastError());

                    return TRUE;
                }

                case IDCANCEL:
                    //
                    // User pressed Esc or CTRL+F4 key. Dismiss the monitor ...
                    //
                    SendMessage(hWnd, WM_CLOSE, 0, 0);
                    return TRUE;
            }
            break;
    }

    if (uMsg == WM_AL_MONITOR_START) {
        LPCWSTR pszSessionId = (LPCWSTR)wParam;
        HWND hWndTree = GetDlgItem(hWnd, IDC_AL_MONITOR_TREE);

        //
        // Prepare session record.
        //
        HTREEITEM hSession;
        {
            ATL::CAtlString sTemp;
            AL::Trace::GetFilePath((LPCTSTR)lParam, sTemp);
            hSession = _RecordSession(pszSessionId, INT_MAX, sTemp, hWndTree);
        }
        if (hSession != NULL) {
            //
            // Record message.
            //
            TCHAR pszTemp[1024];
            if (AL::System::FormatMsg(IDS_AL_MSG_MONITOR_SESSION_BEGIN, pszTemp, _countof(pszTemp)) == NO_ERROR)
                _RecordMessage(pszTemp, _countof(pszTemp), NULL, 0, ID_AL_MONITOR_ICON_INFO, hWndTree, hSession);
        }

        return FALSE;
    } else if (uMsg == WM_AL_MONITOR_END) {
        LPCWSTR pszSessionId = (LPCWSTR)wParam;
        HWND hWndTree = GetDlgItem(hWnd, IDC_AL_MONITOR_TREE);

        HTREEITEM hSession;
        if ((hSession = _RecordSession(pszSessionId, INT_MAX, NULL, hWndTree)) != NULL) {
            //
            // Record message.
            //
            TCHAR pszTemp[1024];
            if (AL::System::FormatMsg(IDS_AL_MSG_MONITOR_SESSION_END, pszTemp, _countof(pszTemp)) == NO_ERROR)
                _RecordMessage(pszTemp, _countof(pszTemp), NULL, 0, ID_AL_MONITOR_ICON_INFO, hWndTree, hSession);
        }

        return FALSE;
    } else if (
        uMsg == WM_AL_MONITOR_INFO    ||
        uMsg == WM_AL_MONITOR_SUCCESS ||
        uMsg == WM_AL_MONITOR_ERROR)
    {
        LPCWSTR pszSessionId = (LPCWSTR)wParam;
        const AL_MONITOR_MSG *pMsg = (const AL_MONITOR_MSG*)lParam;
        HWND hWndTree = GetDlgItem(hWnd, IDC_AL_MONITOR_TREE);

        HTREEITEM hSession;
        if ((hSession = _RecordSession(pszSessionId, INT_MAX, NULL, hWndTree)) != NULL) {
            //
            // Record message.
            //
            _RecordMessage(pMsg->pszTitle, INT_MAX, pMsg->pszDescription, INT_MAX,
                uMsg == WM_AL_MONITOR_SUCCESS ? ID_AL_MONITOR_ICON_SUCCESS :
                uMsg == WM_AL_MONITOR_ERROR   ? ID_AL_MONITOR_ICON_ERROR   :
                                                ID_AL_MONITOR_ICON_INFO,
                hWndTree, hSession);
        }

        return FALSE;
    }

    return FALSE;
}


static inline HTREEITEM _RecordSession(_In_z_count_(iSessionIdLenZ) LPCTSTR szSessionId, _In_ int iSessionIdLenZ, _In_opt_z_ LPCTSTR szLogFile, _In_ HWND hWndTree, _In_opt_ HTREEITEM hParent)
{
    // Sanity check
    if (szSessionId == NULL || iSessionIdLenZ == 0) {
        AL_TRACE_ERROR(_T("Session ID is missing."));
        return NULL;
    } else if (!IsWindow(hWndTree)) {
        AL_TRACE_ERROR(_T("Tree control does not exist."));
        return NULL;
    }

    {
        //
        // Find the session if already present
        //
        TVITEM tvItem;
        TCHAR szTemp[1024];
        tvItem.mask       = TVIF_TEXT;
        tvItem.pszText    = szTemp;
        tvItem.cchTextMax = _countof(szTemp);
        int iSessionIdLen = (int)_tcsnlen(szSessionId, iSessionIdLenZ);
        for (tvItem.hItem = TreeView_GetChild(hWndTree, hParent); tvItem.hItem; tvItem.hItem = TreeView_GetNextItem(hWndTree, tvItem.hItem, TVGN_NEXT)) {
            if (TreeView_GetItem(hWndTree, &tvItem)) {
                if (tvItem.pszText && CompareStringEx(LOCALE_NAME_USER_DEFAULT, NORM_IGNORECASE, szSessionId, iSessionIdLen, tvItem.pszText, (int)_tcsnlen(tvItem.pszText, tvItem.cchTextMax), NULL, NULL, 0) == CSTR_EQUAL)
                    return tvItem.hItem;
            } else
                AL_TRACE_ERROR(_T("TreeView_GetItem failed (%ld)."), GetLastError());
        }
    }

    HTREEITEM hItem;
    {
        //
        // Add a session node.
        //
        TVINSERTSTRUCT tvis;
        tvis.hParent             = hParent;
        tvis.hInsertAfter        = TVI_LAST;
        tvis.item.mask           = TVIF_TEXT | TVIF_PARAM | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_STATE;
        tvis.item.pszText        = (LPTSTR)szSessionId;
        tvis.item.cchTextMax     = iSessionIdLenZ;
        tvis.item.iImage         = ID_AL_MONITOR_ICON_SESSION;
        tvis.item.iSelectedImage = ID_AL_MONITOR_ICON_SESSION;
        AL_MONITOR_RECORD *pData;
        if (AL::Heap::Alloc(sizeof(AL_MONITOR_RECORD), (LPVOID*)&pData) == NO_ERROR) {
            size_t nLogFileLenZ = _tcslen(szLogFile) + 1;
            if (nLogFileLenZ > 1) {
                if (AL::Heap::Alloc(nLogFileLenZ * sizeof(TCHAR), (LPVOID*)&(pData->pszLogFile)) == NO_ERROR)
                    _tcscpy_s((LPTSTR)(pData->pszLogFile), nLogFileLenZ, szLogFile);
                else
                    pData->pszLogFile = NULL;
            }
            tvis.item.lParam = (LPARAM)pData;
        } else
            tvis.item.lParam = NULL;
        tvis.item.stateMask      = TVIS_EXPANDED;
        tvis.item.state          = TVIS_EXPANDED;
        if ((hItem = TreeView_InsertItem(hWndTree, &tvis)) != NULL) {
            //
            // Bring node into view and select it.
            //
            TreeView_EnsureVisible(hWndTree, hItem);
            TreeView_SelectItem(hWndTree, hItem);
        }
    }

    return hItem;
}


//
// Helper function to add ArnesLink message to hierarhic list
//
static inline HTREEITEM _RecordMessage(_In_z_count_(iNameLenZ) LPCTSTR szName, _In_ int iNameLenZ, _In_z_count_(iTooltipLen) LPCTSTR szTooltip, _In_ int iTooltipLen, _In_ int iImage, _In_ HWND hWndTree, _In_opt_ HTREEITEM hParent)
{
    // Sanity check
    if (!IsWindow(hWndTree)) {
        AL_TRACE_ERROR(_T("Tree control does not exist."));
        return NULL;
    }

    //
    // Add message node.
    //
    TVINSERTSTRUCT tvis;
    tvis.hParent             = hParent;
    tvis.hInsertAfter        = TVI_LAST;
    tvis.item.mask           = TVIF_TEXT | TVIF_PARAM | TVIF_IMAGE | TVIF_SELECTEDIMAGE;
    tvis.item.pszText        = (LPTSTR)szName;
    tvis.item.cchTextMax     = iNameLenZ;
    tvis.item.iImage         = iImage;
    tvis.item.iSelectedImage = iImage;
    AL_MONITOR_RECORD *pData;
    if (AL::Heap::Alloc(sizeof(AL_MONITOR_RECORD), (LPVOID*)&pData) == NO_ERROR) {
        size_t nTooltipLenZ = _tcsnlen(szTooltip, iTooltipLen) + 1;
        if (nTooltipLenZ > 1) {
            if (AL::Heap::Alloc(nTooltipLenZ * sizeof(TCHAR), (LPVOID*)&(pData->pszTooltip)) == NO_ERROR)
                _tcsncpy_s((LPTSTR)(pData->pszTooltip), nTooltipLenZ, szTooltip, iTooltipLen);
            else
                pData->pszTooltip = NULL;
        }
        tvis.item.lParam = (LPARAM)pData;
    } else
        tvis.item.lParam = NULL;
    HTREEITEM hItem;
    if ((hItem = TreeView_InsertItem(hWndTree, &tvis)) != NULL) {
        //
        // Bring node into view and select it.
        //
        TreeView_EnsureVisible(hWndTree, hItem);
        TreeView_SelectItem(hWndTree, hItem);
    }

    return hItem;
}


//
// Helper function to free ArnesLink hierarhic message list
//
static void _TreeView_DestroyChildren(_In_ HWND hWndTree, _In_ HTREEITEM hParent)
{
    TVITEM tvItem;
    tvItem.mask = TVIF_PARAM;

    for (tvItem.hItem = TreeView_GetChild(hWndTree, hParent); tvItem.hItem; tvItem.hItem = TreeView_GetNextItem(hWndTree, tvItem.hItem, TVGN_NEXT)) {
        _TreeView_DestroyChildren(hWndTree, tvItem.hItem);

        if (TreeView_GetItem(hWndTree, &tvItem)) {
            if (tvItem.lParam) {
                AL_MONITOR_RECORD *pData = (AL_MONITOR_RECORD*)tvItem.lParam;
                if (pData->pszLogFile)
                    AL::Heap::Free((LPVOID*)&(pData->pszLogFile));
                if (pData->pszTooltip)
                    AL::Heap::Free((LPVOID*)&(pData->pszTooltip));
                AL::Heap::Free((LPVOID*)&pData);
            }
        } else
            AL_TRACE_ERROR(_T("TreeView_GetItem failed (%ld)."), GetLastError());
    }
}


//
// Helper function to convert ArnesLink hierarhic message list to plain text
//
static SIZE_T _TreeView_MakeReport(_In_ HWND hWndTree, _In_ HTREEITEM hParent, _In_ int iIdent, _Out_z_capcount_(nOutputLen) LPTSTR szOutput, _In_ SIZE_T nOutputLen)
{
    SIZE_T nLen = 0;

    TVITEM tvItem;
    tvItem.mask = TVIF_TEXT | TVIF_PARAM;

    for (tvItem.hItem = TreeView_GetChild(hWndTree, hParent); tvItem.hItem; tvItem.hItem = TreeView_GetNextItem(hWndTree, tvItem.hItem, TVGN_NEXT)) {
        {
            TCHAR szTemp[1024];
            tvItem.pszText = szTemp, tvItem.cchTextMax = _countof(szTemp);
            if (TreeView_GetItem(hWndTree, &tvItem)) {

                //
                // Add message text.
                //
                if (nLen < nOutputLen)
                    nLen += _stprintf_s(szOutput + nLen, nOutputLen - nLen, _T("%*s%.*s\r\n"), iIdent, _T(""), tvItem.cchTextMax, tvItem.pszText);

                if (tvItem.lParam && ((AL_MONITOR_RECORD*)tvItem.lParam)->pszTooltip && ((AL_MONITOR_RECORD*)tvItem.lParam)->pszTooltip[0]) {
                    LPCTSTR pszTooltip = ((AL_MONITOR_RECORD*)tvItem.lParam)->pszTooltip;

                    //
                    // Add message description.
                    // Apply ident to all line-breaks, convert LF to CRLF on the fly.
                    //
                    for (;;) {
                        if (nLen < nOutputLen)
                            nLen += _stprintf_s(szOutput + nLen, nOutputLen - nLen, _T("%*s"), iIdent + 3, _T(""));
                        if (pszTooltip[0] == 0) {
                            if (nLen < nOutputLen)
                                nLen += _stprintf_s(szOutput + nLen, nOutputLen - nLen, _T("\r\n"));
                            break;
                        }

                        if (nLen < nOutputLen) {
                            SIZE_T nLineLen;
                            LPCTSTR szEndOfLine = _tcschr(pszTooltip, _T('\n'));

                            if (szEndOfLine) {
                                // LF found.
                                nLineLen = szEndOfLine - pszTooltip;
                                if (nLineLen && szEndOfLine[-1] == _T('\r')) {
                                    // Preceding CR found too; strip it.
                                    nLineLen--;
                                }
                            } else
                                nLineLen = _tcslen(pszTooltip);

                            // Copy line text.
                            if (nLineLen > nOutputLen - nLen) nLineLen = nOutputLen - nLen;
                            memcpy(szOutput + nLen, pszTooltip, nLineLen * sizeof(TCHAR));
                            nLen += nLineLen;

                            // Append CRLF.
                            if (nLen < nOutputLen)
                                nLen += _stprintf_s(szOutput + nLen, nOutputLen - nLen, _T("\r\n"));

                            if (szEndOfLine) {
                                // Continue with the next line.
                                pszTooltip = szEndOfLine + 1;
                            } else {
                                // This was last/single line of text.
                                break;
                            }
                        } else
                            break;
                    }
                }
            } else
                AL_TRACE_ERROR(_T("TreeView_GetItem failed (%ld)."), GetLastError());
        }

        nLen += _TreeView_MakeReport(hWndTree, tvItem.hItem, iIdent + 1, szOutput + nLen, nOutputLen - nLen);
    }

    return nLen;
}


//
// Helper function to determine sz_Or_Ord resource data record length in WORDs
//
static inline SIZE_T _sz_Or_Ord_len(_In_ const LPWORD pData)
{
    switch (pData[0]) {
        case 0x0000:
            // If the first element of this array is 0x0000, the array has no other elements.
            return 1;

        case 0xFFFF:
            // If the first element is 0xFFFF, the array has one additional element that specifies the ordinal value of a resource in an executable file.
            return 2;

        default:
            // If the first element has any other value, the system treats the array as a null-terminated Unicode string that specifies the name of a resource in an executable file.
            return wcslen((LPCWSTR)pData) + 1;
    }
}
