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
#pragma comment(lib, "Version.lib")


//
// Global information
//
HINSTANCE      AL::System::g_hInstance      = NULL;
HINSTANCE      AL::System::g_hResource      = NULL;
ULARGE_INTEGER AL::System::g_uliVerEap3Host = {{ 0, 0 }};


//
// Main dll function
//
BOOL AL::EAP::DllMainImpl(_In_ HINSTANCE hInstance, _In_ DWORD dwReason, _In_ LPVOID pReserved)
{
    DWORD dwReturnCode = NO_ERROR;

    if (dwReason == DLL_PROCESS_ATTACH) {
#ifdef _DEBUG
        //Sleep(10000);
#endif

        AL::System::g_hInstance = hInstance;

        //
        // Create the heap we'll be using for memory allocations.
        //
        if ((dwReturnCode = AL::Heap::Init()) == NO_ERROR) {
            //
            // Load default resources.
            //
            if ((AL::System::g_hResource = AL::System::LoadLibrary(hInstance, _T("al_res.dll"), LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE)) != NULL) {
                //
                // Get Eap3Host.exe path.
                //
                ATL::CAtlString sFilePath;
                ExpandEnvironmentStrings(_T("%SystemRoot%\\system32\\Eap3Host.exe"), sFilePath);

                //
                // Read version info.
                //
                ATL::CAtlArray<BYTE> aVersionInfo;
                if (::GetFileVersionInfo(sFilePath, 0, aVersionInfo)) {
                    // Get the value for translation.
                    VS_FIXEDFILEINFO *lpVSFixedFileInfo = NULL;
                    UINT uiLen;
                    if (::VerQueryValue(aVersionInfo.GetData(), _T("\\"), (LPVOID*)&lpVSFixedFileInfo, &uiLen) && uiLen != 0) {
                        //
                        // Save version numbers.
                        //
                        AL::System::g_uliVerEap3Host.HighPart = lpVSFixedFileInfo->dwFileVersionMS;
                        AL::System::g_uliVerEap3Host.LowPart  = lpVSFixedFileInfo->dwFileVersionLS;
                    }
                }
            } else
                dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

            if (dwReturnCode != NO_ERROR)
                AL::Heap::Done();
        }
    } else if (dwReason == DLL_PROCESS_DETACH) {
        if (AL::System::g_hResource)
            FreeLibrary(AL::System::g_hResource);

        AL::Heap::Done();
    }

    return dwReturnCode == NO_ERROR ? TRUE : FALSE;
}
