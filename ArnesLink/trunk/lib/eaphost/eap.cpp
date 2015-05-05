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
// Allocate a EAP_ERROR and fill it according to dwErrorCode
//
DWORD AL::EAP::RecordError(_Out_ EAP_ERROR **ppEapError, _In_ DWORD dwErrorCode, _In_ DWORD dwReasonCode, _In_ LPCGUID pRootCauseGuid, _In_ LPCGUID pRepairGuid, _In_ LPCGUID pHelpLinkGuid, _In_z_ LPCWSTR pszRootCauseString, _In_z_ LPCWSTR pszRepairString)
{
    DWORD dwReturnCode;

    // Sanity check
    if (!ppEapError) {
        AL_TRACE_ERROR(_T("ppEapError is NULL."));
        dwReturnCode = ERROR_INVALID_PARAMETER;
        goto ErrFinish;
    }

    if (*ppEapError) {
        //
        // ppEapError contains another error description already.
        // Do not overwrite. Log to trace file only.
        //
        if (pszRootCauseString != NULL && pszRootCauseString[0])
            AL::Trace::Output(AL::Trace::LEVEL_ERROR, _T("  %ls"), pszRootCauseString);

        if (pszRepairString != NULL && pszRepairString[0])
            AL::Trace::Output(AL::Trace::LEVEL_ERROR, _T("  %ls"), pszRepairString);

        dwReturnCode = NO_ERROR;
        goto ErrFinish;
    }

    //
    // Allocate memory for EAP error.
    //
    if ((dwReturnCode = AL::Heap::Alloc(sizeof(EAP_ERROR), (LPVOID*)ppEapError)) != NO_ERROR) {
        AL_TRACE_ERROR(_T("Error allocating memory for ppEapError."));
        goto ErrFinish;
    }

    //
    // Assign the Win32 Error Code
    //
    (*ppEapError)->dwWinError = dwErrorCode;

    //
    // Assign the EAP_METHOD_TYPE to indicate which EAP Method send the error.
    //
    (*ppEapError)->type.eapType.type = AL::EAP::g_bType;
    (*ppEapError)->type.dwAuthorId   = AL_EAP_AUTHOR_ID;

    //
    // Assign the reason code
    //
    (*ppEapError)->dwReasonCode = dwReasonCode;

    //
    // Assign the RootCause GUID
    //
    if (pRootCauseGuid != NULL)
        memcpy(&((*ppEapError)->rootCauseGuid), pRootCauseGuid, sizeof(GUID));

    //
    // Assign the Repair GUID
    //
    if (pRepairGuid != NULL)
        memcpy(&((*ppEapError)->repairGuid), pRepairGuid, sizeof(GUID));

    //
    // Assign the HelpLink GUID
    //
    if (pHelpLinkGuid!= NULL)
        memcpy(&((*ppEapError)->helpLinkGuid), pHelpLinkGuid, sizeof(GUID));

    if (pszRootCauseString != NULL && pszRootCauseString[0]) {
        //
        // Assign the Root Cause String
        //
        SIZE_T nLenZ = wcslen(pszRootCauseString) + 1;
        if ((dwReturnCode = AL::Heap::Alloc(nLenZ * sizeof(WCHAR), (LPVOID*)&((*ppEapError)->pRootCauseString))) != NO_ERROR) {
            AL_TRACE_ERROR(_T("Error allocating memory for ppEapError->pRootCauseString."));
            goto ErrCleanup;
        }
        wmemcpy((*ppEapError)->pRootCauseString, pszRootCauseString, nLenZ);
        AL::Trace::Output(AL::Trace::LEVEL_ERROR, _T("  %ls"), pszRootCauseString);
    }

    if (pszRepairString != NULL && pszRepairString[0]) {
        //
        // Assign the Repair String
        //
        SIZE_T nLenZ = wcslen(pszRepairString) + 1;
        if ((dwReturnCode = AL::Heap::Alloc(nLenZ * sizeof(WCHAR), (LPVOID*)&((*ppEapError)->pRepairString))) != NO_ERROR) {
            AL_TRACE_ERROR(_T("Error allocating memory for ppEapError->pRepairString."));
            goto ErrCleanupRootCauseString;
        }
        wmemcpy((*ppEapError)->pRepairString, pszRepairString, nLenZ);
        AL::Trace::Output(AL::Trace::LEVEL_ERROR, _T("  %ls"), pszRepairString);
    }

    return NO_ERROR;

ErrCleanupRootCauseString:
    AL::Heap::Free((LPVOID*)&((*ppEapError)->pRootCauseString));
ErrCleanup:
    AL::Heap::Free((LPVOID*)ppEapError);
ErrFinish:
    return dwReturnCode;
}


//
// Free EAP_ERROR
//
DWORD AL::EAP::FreeError(_Inout_ EAP_ERROR **ppEapError)
{
    //
    // If RootCauseString in EapError, free it.
    //
    if ((*ppEapError)->pRootCauseString)
        AL::Heap::Free((LPVOID*)&((*ppEapError)->pRootCauseString));

    //
    // If error string in EapError, free it.
    //
    if ((*ppEapError)->pRepairString)
        AL::Heap::Free((LPVOID*)&((*ppEapError)->pRepairString));

    //
    // Finally, free the EapError structure.
    //
    return AL::Heap::Free((LPVOID*)ppEapError);
}
