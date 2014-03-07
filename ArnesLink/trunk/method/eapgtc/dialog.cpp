/*
    SecureW2, Copyright (C) SecureW2 B.V.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  

    See the GNU General Public License for more details, included in the file 
    LICENSE which you should have received along with this program.

    If you did not receive a copy of the GNU General Public License, 
    write to the Free Software Foundation, Inc., 675 Mass Ave, 
    Cambridge, MA 02139, USA.

    SecureW2 B.V. can be contacted at http://www.securew2.com
*/

#include "stdafx.h"

#ifdef _WIN32_WCE
//
// Name: SW2_CreateCommandBar
// Description: In Windows CE this function makes the window 
//				work with the Windows CE interface
// Author: Tom Rixom
// Created: 12 May 2004
//
HWND SW2_CreateCommandBar( HWND hWnd )
{
	SHMENUBARINFO mbi;

	memset( &mbi, 0, sizeof( SHMENUBARINFO ) );
	mbi.cbSize     = sizeof( SHMENUBARINFO );
	mbi.hwndParent = hWnd;
	mbi.hInstRes   = g_hResource;
	mbi.nBmpId     = 0;
	mbi.cBmpImages = 0;
	mbi.dwFlags = SHCMBF_EMPTYBAR;
	//mbi.nToolBarId = IDM_MENU;

	if( !SHCreateMenuBar( &mbi ) ) 
		return NULL;

	return mbi.hwndMB;
}
#endif // _WIN32_WCE

//
// Handle identity dialog
//
INT_PTR CALLBACK SW2IdentityDlgProc(IN  HWND    hWnd,
								   IN  UINT    unMsg,
								   IN  WPARAM  wParam,
								   IN  LPARAM  lParam)
{
	WCHAR			pwcTemp[1024];
#ifdef _WIN32_WCE
	SHINITDLGINFO	shidi;
#endif //  _WIN32_WCE
   PSW2_USER_DATA	pUserData;

    switch( unMsg )
    {
		case WM_INITDIALOG:
        
			pUserData = ( PSW2_USER_DATA ) lParam;

			//
			// Set the identity if available
			//
			if( pUserData->pwcIdentity &&
				wcslen( pUserData->pwcIdentity ) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_IDENTITY_FIELD ), pUserData->pwcIdentity );

			// set language specific info
			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_WINDOW_IDENTITY, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(hWnd, pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_IDENTITY, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_IDENTITY_CAPTION), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_OK, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDOK), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_CANCEL, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDCANCEL), pwcTemp);

			SetFocus( GetDlgItem( hWnd, IDC_IDENTITY_FIELD ) );

#ifdef _WIN32_WCE
			// Create a Done button and size it.  
			shidi.dwMask = SHIDIM_FLAGS;
			shidi.dwFlags = SHIDIF_DONEBUTTON | SHIDIF_SIPDOWN |SHIDIF_SIZEDLGFULLSCREEN;
			shidi.hDlg = hWnd;

			SHInitDialog( &shidi );

			SW2_CreateCommandBar( hWnd );

			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pUserData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pUserData );
#endif // _WIN32_WCE

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDOK:

#ifdef _WIN32_WCE
					pUserData = ( PSW2_USER_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pUserData = ( PSW2_USER_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					//
					// retrieve the user identity
					//
					if (GetWindowTextLength(GetDlgItem(hWnd, IDC_IDENTITY_FIELD)) > 0)
					{
						GetWindowText(GetDlgItem(hWnd, IDC_IDENTITY_FIELD), 
								pUserData->pwcIdentity, sizeof(pUserData->pwcIdentity));
						
						EndDialog(hWnd, TRUE);
					}

#ifdef _WIN32_WCE
					SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pUserData );
#else
					SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pUserData );
#endif // _WIN32_WCE

					return TRUE;

				break;

				case IDCANCEL:

					EndDialog(hWnd, FALSE);

				default:

					return FALSE;

				break;

			}

		break;

		default:

			return FALSE;

		break;

    }

	return FALSE;
}

//
// Handle response dialog
//
INT_PTR CALLBACK SW2ResponseDlgProc(IN  HWND    hWnd,
									IN  UINT    unMsg,
									IN  WPARAM  wParam,
									IN  LPARAM  lParam)
{
	DWORD			dwReturnCode;
	WCHAR			pwcTemp[1024];
	WCHAR			pwcResponse[PWLEN];
	PCHAR			pcResponse;
	DWORD			ccResponse;
	PCHAR			pcChallenge;
	DWORD			ccChallenge;
	PWCHAR			pwcChallenge;
#ifdef _WIN32_WCE
	SHINITDLGINFO	shidi;
#endif //  _WIN32_WCE
	PSW2_USER_DATA	pUserData;

   dwReturnCode = NO_ERROR;

    switch( unMsg )
    {
		case WM_INITDIALOG:
        
			pUserData = ( PSW2_USER_DATA ) lParam;

			ccChallenge = pUserData->cbChallenge + 1;

			//
			// Convert PBYTE to 0 terminated PCHAR
			//
			if ((dwReturnCode = SW2AllocateMemory(ccChallenge, (PVOID*)&pcChallenge))==NO_ERROR)
			{
				memcpy(pcChallenge, 
						pUserData->pbChallenge, 
						ccChallenge);

				if ((dwReturnCode = SW2AllocateMemory(ccChallenge*sizeof(WCHAR), 
													(PVOID*)&pwcChallenge))==NO_ERROR)
				{
					//
					// Convert PCHAR to WCHAR
					//
					if (MultiByteToWideChar( CP_ACP, 0, 
											pcChallenge, -1, 
											pwcChallenge, ccChallenge) > 0)

					{
						//
						// Set the challenge
						//
						SetWindowText(GetDlgItem(hWnd, IDC_CHALLENGE_CAPTION),
										pwcChallenge);

						// set language specific info
						memset(pwcTemp, 0, sizeof(pwcTemp));
						LoadString( g_hLanguage, IDS_WINDOW_RESPONSE, pwcTemp, sizeof( pwcTemp ) );
						SetWindowText(hWnd, pwcTemp);

						memset(pwcTemp, 0, sizeof(pwcTemp));
						LoadString( g_hLanguage, IDS_LABEL_RESPONSE, pwcTemp, sizeof( pwcTemp ) );
						SetWindowText(GetDlgItem(hWnd, IDC_RESPONSE_CAPTION), pwcTemp);

						memset(pwcTemp, 0, sizeof(pwcTemp));
						LoadString( g_hLanguage, IDS_LABEL_OK, pwcTemp, sizeof( pwcTemp ) );
						SetWindowText(GetDlgItem(hWnd, IDOK), pwcTemp);

						memset(pwcTemp, 0, sizeof(pwcTemp));
						LoadString( g_hLanguage, IDS_LABEL_CANCEL, pwcTemp, sizeof( pwcTemp ) );
						SetWindowText(GetDlgItem(hWnd, IDCANCEL), pwcTemp);
					}
					else
						dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

					SW2FreeMemory((PVOID*)&pwcChallenge);
				}

				SW2FreeMemory((PVOID*)&pcChallenge);
			}


#ifdef _WIN32_WCE
			// Create a Done button and size it.  
			shidi.dwMask = SHIDIM_FLAGS;
			shidi.dwFlags = SHIDIF_DONEBUTTON | SHIDIF_SIPDOWN |SHIDIF_SIZEDLGFULLSCREEN;
			shidi.hDlg = hWnd;

			SHInitDialog( &shidi );

			SW2_CreateCommandBar( hWnd );

			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pUserData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pUserData );
#endif // _WIN32_WCE

			SetFocus( GetDlgItem( hWnd, IDC_RESPONSE_FIELD ) );

			if (dwReturnCode != NO_ERROR)
				EndDialog(hWnd, FALSE);
			else
				return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDOK:

#ifdef _WIN32_WCE
					pUserData = ( PSW2_USER_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pUserData = ( PSW2_USER_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					//
					// Retrieve user response
					//
					if (GetWindowTextLength(GetDlgItem(hWnd, IDC_RESPONSE_FIELD)) > 0)
					{
						GetWindowText(GetDlgItem(hWnd, IDC_RESPONSE_FIELD), 
								pwcResponse, sizeof(pwcResponse));
						
						ccResponse = (DWORD) wcslen(pwcResponse) + 1;

						if ((dwReturnCode = SW2AllocateMemory(ccResponse, 
															(PVOID*)&pcResponse))==NO_ERROR)
						{
							if ((WideCharToMultiByte(CP_ACP, 
													0, 
													pwcResponse, -1, 
													pcResponse, 
													ccResponse, 
													NULL, NULL)) > 0)
							{
								pUserData->cbResponse = ccResponse -1;

								memcpy_s(pUserData->pbResponse, 
										sizeof(pUserData->pbResponse),
										pcResponse, 
										pUserData->cbResponse);
							}

							SW2FreeMemory((PVOID*)&pcResponse);
						}
					}

#ifdef _WIN32_WCE
					SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pUserData );
#else
					SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pUserData );
#endif // _WIN32_WCE

					if (dwReturnCode == NO_ERROR)
					{
						EndDialog(hWnd, TRUE);

						return TRUE;
					}
					else
						return FALSE;

				break;

				case IDCANCEL:

					EndDialog(hWnd, FALSE);

				default:

					return FALSE;

				break;

			}

		break;

		default:

			return FALSE;

		break;

    }

	return FALSE;
}