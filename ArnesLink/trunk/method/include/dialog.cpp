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
//
// Name: Dialog.c
// Description: Contains the dialog functionality for the module
// Author: Tom Rixom
// Created: 17 December 2002
// Version: 1.0

#include "stdafx.h"
#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Version.lib")

#define     ImageList_AddIcon(himl, hicon) ImageList_ReplaceIcon(himl, -1, hicon)

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
// Name: CredentialsDlgProc
// Description: Dialog Function for the Credentials Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
CredentialsDlgProc(	IN  HWND    hWnd,
					IN  UINT    unMsg,
					IN  WPARAM  wParam,
					IN  LPARAM  lParam )
{
   PSW2_USER_DATA	pUserData;
   WCHAR			pwcTemp[1024];
#ifdef _WIN32_WCE
	SHINITDLGINFO	shidi;
#endif //  _WIN32_WCE

    switch( unMsg )
    {

		case WM_INITDIALOG:
        
			pUserData = ( PSW2_USER_DATA ) lParam;

			// load language specific info
			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_PROFILE_DESC, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CRED_DESCRIPTION), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_USERNAME, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CRED_USERNAME_LABEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_PASSWORD, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CRED_PASSWORD_LABEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_DOMAIN, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CRED_DOMAIN_LABEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_SAVECREDENTIALS, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CRED_SAVECREDENTIALS), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_OK, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDOK), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_CANCEL, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDCANCEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_WINDOW_CREDENTIALS, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(hWnd, pwcTemp);

			if( wcslen( pUserData->pwcUsername ) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_CRED_USERNAME ), pUserData->pwcUsername );

			if( wcslen( pUserData->pwcDomain ) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_CRED_DOMAIN ), pUserData->pwcDomain );

			if ( wcslen(pUserData->pwcPassword ) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_CRED_PASSWORD ), L"This is not my password" );
			else
				SetWindowText( GetDlgItem( hWnd, IDC_CRED_PASSWORD ), L"" );

			// CUSTOM DIALOG
			// Contributed by Wyman Miles (Cornell University)
			//
#ifndef _WIN32_WCE
			if ( pUserData->bAllowCachePW == FALSE ) 
			{
				EnableWindow( GetDlgItem( hWnd, IDC_CRED_SAVECREDENTIALS ), FALSE );
				pUserData->bSaveUserCredentials = FALSE;
			}
			if ( wcslen( pUserData->pwcAltUsernameStr ) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_CRED_USERNAME_LABEL ), pUserData->pwcAltUsernameStr );
			if ( wcslen ( pUserData->pwcAltPasswordStr ) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_CRED_PASSWORD_LABEL ), pUserData->pwcAltPasswordStr );
			if ( wcslen ( pUserData->pwcAltDomainStr) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_CRED_DOMAIN_LABEL), pUserData->pwcAltDomainStr );
			if ( wcslen ( pUserData->pwcProfileDescription) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_CRED_DESCRIPTION), pUserData->pwcProfileDescription );

			if ( wcslen ( pUserData->pwcAltCredsTitle ) > 0 ) 
				SetWindowText( hWnd, pUserData -> pwcAltCredsTitle );
#endif // _WIN32_WCE

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

			SetFocus( GetDlgItem( hWnd, IDC_CRED_USERNAME ) );

			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::CredentialsDlgProc:: WM_INITDIALOG:: returning" ) );

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDC_CRED_USERNAME:

					if( HIWORD( wParam ) == EN_CHANGE )
					{
						if( GetWindowText( GetDlgItem( hWnd, IDC_CRED_USERNAME ), pwcTemp, UNLEN ) > 0 )
						{
							if( wcschr( pwcTemp, '@' ) )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CRED_DOMAIN_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CRED_DOMAIN ), FALSE );
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CRED_DOMAIN_LABEL ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CRED_DOMAIN ), TRUE );
							}
						}
					}

					return FALSE;

				break;

				case IDOK:

					SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::CredentialsDlgProc::IDOK" ) );

#ifdef _WIN32_WCE
					pUserData = ( PSW2_USER_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pUserData = ( PSW2_USER_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE
					//
					// Both the username and password must be filled in, domain is optional
					//
					//
					// Username
					//
					if( GetWindowTextLength( GetDlgItem( hWnd, IDC_CRED_USERNAME ) ) > 0 )
					{
						memset( pUserData->pwcUsername, 0, UNLEN );

						GetWindowText( GetDlgItem( hWnd, IDC_CRED_USERNAME ), pUserData->pwcUsername, UNLEN );

						//
						// Password
						//
						if( GetWindowTextLength( GetDlgItem( hWnd, IDC_CRED_PASSWORD ) ) > 0 )
						{
							memset( pUserData->pwcPassword, 0, PWLEN );

							GetWindowText( GetDlgItem( hWnd, IDC_CRED_PASSWORD ), pUserData->pwcPassword, PWLEN );

							//
							// Domain
							//
							memset( pUserData->pwcDomain, 0, UNLEN );

							GetWindowText( GetDlgItem( hWnd, IDC_CRED_DOMAIN ), pUserData->pwcDomain, UNLEN );
						}

						pUserData->bSaveUserCredentials = FALSE;

						if( SendMessage( GetDlgItem( hWnd, IDC_CRED_SAVECREDENTIALS ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						{
							pUserData->bSaveUserCredentials = TRUE;
						}

						EndDialog( hWnd, TRUE );
					}

					return TRUE;

				break;

				case IDCANCEL:

					EndDialog( hWnd, FALSE );

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
// Name: ConfigAdvancedDlgProc
// Description: Dialog Function for the Advanced Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ConfigAdvancedDlgProc(	IN  HWND    hWnd,
					IN  UINT    unMsg,
					IN  WPARAM  wParam,
					IN  LPARAM  lParam )
{
    PSW2_PROFILE_DATA		pProfileData;
	WCHAR					pwcTemp[1024];
	static BOOL				bPasswordChanged;
#ifdef _WIN32_WCE
	SHINITDLGINFO			shidi;
#endif //  _WIN32_WCE
	DWORD					dwErr = NO_ERROR;
	
    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::ConfigAdvancedDlgProc:: WM_INITDIALOG" ) );

			//
			// Only administrators can access this dialog
			//
			if( !SW2_IsAdmin() )
				EndDialog( hWnd, FALSE );

			pProfileData = ( PSW2_PROFILE_DATA ) lParam;

#ifdef _WIN32_WCE
			// Create a Done button and size it.  
			shidi.dwMask = SHIDIM_FLAGS;
			shidi.dwFlags = SHIDIF_DONEBUTTON | SHIDIF_SIPDOWN |SHIDIF_SIZEDLGFULLSCREEN;
			shidi.hDlg = hWnd;

			SHInitDialog( &shidi );

			SW2_CreateCommandBar( hWnd );
#endif // _WIN32_WCE

			// load language specific info
			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_USECOMPCRED, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_USE_COMPUTER_CRED), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_USERNAME, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_COMP_USERNAME_LABEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_PASSWORD, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_COMP_PASSWORD_LABEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_DOMAIN, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_COMP_DOMAIN_LABEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_SERVERCERTLOCAL, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_SERVER_CERT_LOCAL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_MS_EXTENSION, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_VERIFY_MS_EXTENSION), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_ALLOWNEWCONN, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_ALLOW_NEW_CONNECTION), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_USEALTEREMPTYID, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_USE_ALTERNATE_EMPTY), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_RENEWIP, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_RENEW_IP), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_OK, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDOK), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_CANCEL, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDCANCEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_WINDOW_ADVANCED, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(hWnd, pwcTemp);

#ifndef _WIN32_WCE
			if( pProfileData->bUseAlternateComputerCred )
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_COMPUTER_CRED ), BM_SETCHECK, BST_CHECKED, 0 );

			SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME ), pProfileData->pwcCompName );

			if( wcslen( pProfileData->pwcCompPassword ) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD ), L"This is not my password" );

			SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN ), pProfileData->pwcCompDomain );

			bPasswordChanged = FALSE;

			if( pProfileData->bUseAlternateComputerCred )
			{
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME_LABEL ), TRUE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME ), TRUE );

				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD_LABEL ), TRUE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD ), TRUE );

				if( ( wcslen( pProfileData->pwcCompName ) > 0 ) && 
					( wcschr( pProfileData->pwcCompName, '@' ) == NULL ) )
				{
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN_LABEL ), TRUE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN ), TRUE );
				}
			}
			else
			{
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME_LABEL ), FALSE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME ), FALSE );

				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD_LABEL ), FALSE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD ), FALSE );

				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN_LABEL ), FALSE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN ), FALSE );
			}
#endif // _WIN32_WCE
			
			if( pProfileData->bServerCertificateLocal )
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_SERVER_CERT_LOCAL ), BM_SETCHECK, BST_CHECKED, 0 );

			if( pProfileData->bVerifyMSExtension )
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_MS_EXTENSION ), BM_SETCHECK, BST_CHECKED, 0 );

			if( pProfileData->bAllowNewConnection )
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_ALLOW_NEW_CONNECTION ), BM_SETCHECK, BST_CHECKED, 0 );

			if( pProfileData->bUseEmptyIdentity )
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_EMPTY ), BM_SETCHECK, BST_CHECKED, 0 );

#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pProfileData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pProfileData );
#endif // _WIN32_WCE

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDC_CONFIG_COMP_PASSWORD:

					if( HIWORD( wParam ) == EN_CHANGE )
						bPasswordChanged = TRUE;

					return FALSE;

				break;

#ifndef _WIN32_WCE
				case IDC_CONFIG_USE_COMPUTER_CRED:

					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );

					switch( HIWORD( wParam ) )
					{
						case BN_CLICKED:

							if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_COMPUTER_CRED ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
				 			{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME_LABEL ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME ), TRUE );

								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD_LABEL ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD ), TRUE );

								if( ( wcslen( pProfileData->pwcCompName ) > 0 ) && 
									( wcschr( pProfileData->pwcCompName, '@' ) == NULL ) )
								{
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN_LABEL ), TRUE );
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN ), TRUE );
								}
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME ), FALSE );

								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD ), FALSE );

								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN ), FALSE );
							}

						break;
					}

					return FALSE;

				break;
#endif // _WIN32_WCE
				case IDOK:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

#ifndef _WIN32_WCE
					pProfileData->bUseAlternateComputerCred = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_COMPUTER_CRED ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bUseAlternateComputerCred = TRUE;

					memset( pProfileData->pwcCompName,
							0, 
							sizeof( pProfileData->pwcCompName ) );

					GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME ), 
									pProfileData->pwcCompName, 
									UNLEN );

					if( bPasswordChanged )
					{
						memset( pProfileData->pwcCompPassword, 
								0, 
								sizeof( pProfileData->pwcCompPassword ) );

						GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD ), pProfileData->pwcCompPassword, PWLEN );
					}

					memset( pProfileData->pwcCompDomain, 0, sizeof( pProfileData->pwcCompDomain ) );

					GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN ), pProfileData->pwcCompDomain, UNLEN );
#endif // _WIN32_WCE
					pProfileData->bServerCertificateLocal = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_SERVER_CERT_LOCAL ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bServerCertificateLocal = TRUE;

					pProfileData->bVerifyMSExtension = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_MS_EXTENSION ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bVerifyMSExtension = TRUE;

					pProfileData->bAllowNewConnection = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_ALLOW_NEW_CONNECTION ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bAllowNewConnection = TRUE;
					
					pProfileData->bUseEmptyIdentity = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_EMPTY ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bUseEmptyIdentity = TRUE;
#ifndef _WIN32_WCE
					pProfileData->bRenewIP = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_RENEW_IP ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bRenewIP = TRUE;
#endif // _WIN32_WCE

					EndDialog( hWnd, TRUE );

					return TRUE;

				break;

				case IDCANCEL:

					EndDialog( hWnd, FALSE );

				break;

#ifndef _WIN32_WCE
				case IDC_CONFIG_COMP_USERNAME:

					if( HIWORD( wParam ) == EN_CHANGE )
					{
						if( GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME ), pwcTemp, UNLEN ) > 0 )
						{
							if( wcschr( pwcTemp, '@' ) )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN ), FALSE );
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN_LABEL ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN ), TRUE );
							}
						}
						else
						{
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN_LABEL ), TRUE );
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN ), TRUE );
						}
					}

					return FALSE;

				break;

#endif // _WIN32_WCE
				
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
// Name: ConfigUserDlgProc
// Description: Dialog Function for the User Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ConfigUserDlgProc(	IN  HWND    hWnd,
					IN  UINT    unMsg,
					IN  WPARAM  wParam,
					IN  LPARAM  lParam )
{
    PSW2_PROFILE_DATA		pProfileData;
	WCHAR					pwcTemp[UNLEN];
	static BOOL				bPasswordChanged;
	DWORD					dwErr = NO_ERROR;
	
    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
			pProfileData = ( PSW2_PROFILE_DATA ) lParam;

			// load language specific info
			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_PROMPT_USER, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_PROMPT_USER), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_USERNAME, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_USERNAME_LABEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_PASSWORD, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_PASSWORD_LABEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_DOMAIN, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_DOMAIN_LABEL), pwcTemp);

#ifndef _WIN32_WCE
			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_USERCOMPUTER, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_USER_COMPUTER), pwcTemp);
#endif // _WIN32_WCE

			SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), pProfileData->pwcUserName );

#ifndef _WIN32_WCE
			//
			// CUSTOM DIALOG
			// Contributed by Wyman Miles (Cornell University)
			//
			if ( wcslen( pProfileData->pwcAltUsernameStr ) )
				SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME_LABEL ), 
							pProfileData->pwcAltUsernameStr );

			if ( wcslen( pProfileData->pwcAltPasswordStr ) )
				SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD_LABEL ), 
							pProfileData->pwcAltPasswordStr);
				
			if ( wcslen( pProfileData->pwcAltDomainStr ) )
				SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL), 
							pProfileData->pwcAltDomainStr);
#endif // _WIN32_WCE

			if( wcslen( pProfileData->pwcUserPassword ) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD ), L"This is not my password" );

			SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), pProfileData->pwcUserDomain );

			bPasswordChanged = FALSE;

			if( pProfileData->bPromptUser )
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROMPT_USER ), BM_SETCHECK, BST_CHECKED, 0 );

#ifndef _WIN32_WCE
			if( pProfileData->bUseUserCredentialsForComputer)
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), BM_SETCHECK, BST_CHECKED, 0 );
#endif // _WIN32_WCE

			//
			// Only Administrator can decide if user credentials are used
			// for everyone
			//
#ifndef _WIN32_WCE
			if( !SW2_IsAdmin() )
			{
				ShowWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), SW_HIDE  );
			}
#endif // _WIN32_WCE
			if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROMPT_USER ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
			{
				//
				// If we are to prompt user then disable all except control option
				//
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROMPT_USER ), TRUE );

				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME_LABEL ), FALSE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), FALSE );

				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD_LABEL ), FALSE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD ), FALSE );

				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), FALSE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), FALSE );
#ifndef _WIN32_WCE
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), FALSE );
#endif // _WIN32_WCE
			}
			else
			{
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROMPT_USER ), TRUE );

				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME_LABEL ), TRUE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), TRUE );

				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD_LABEL ), TRUE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD ), TRUE );

				if( ( wcslen( pProfileData->pwcUserName ) > 0 ) && 
					( wcschr( pProfileData->pwcUserName, '@' ) == NULL ) )
				{
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), TRUE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), TRUE );
				}
				else
				{
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), FALSE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), FALSE );
				}
#ifndef _WIN32_WCE
				if( pProfileData->bUseAlternateComputerCred )
				{
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), FALSE );
				}
				else
				{
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), TRUE );
				}
#endif // _WIN32_WCE
			}
			
#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pProfileData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pProfileData );
#endif // _WIN32_WCE

			return FALSE;

		break;

		case WM_SHOWWINDOW:

			switch( LOWORD( wParam ) )
			{
				case TRUE:

					SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::ConfigUserDlgProc:: WM_SHOWWINDOW" ) );

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROMPT_USER ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
					{
						//
						// If we are to prompt user then disable all except control option
						//
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROMPT_USER ), TRUE );

						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME_LABEL ), FALSE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), FALSE );

						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD_LABEL ), FALSE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD ), FALSE );

						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), FALSE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), FALSE );

#ifndef _WIN32_WCE
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), FALSE );
#endif // _WIN32_WCE
					}
					else
					{
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROMPT_USER ), TRUE );

						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME_LABEL ), TRUE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), TRUE );

						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD_LABEL ), TRUE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD ), TRUE );

						if( ( wcslen( pProfileData->pwcUserName ) > 0 ) && 
							( wcschr( pProfileData->pwcUserName, '@' ) == NULL ) )
						{
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), TRUE );
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), TRUE );
						}
						else
						{
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), FALSE );
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), FALSE );
						}
#ifndef _WIN32_WCE
						if( pProfileData->bUseAlternateComputerCred )
						{
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), FALSE );
						}
						else
						{
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), TRUE );
						}
#endif // _WIN32_WCE
					}

				break;

				default:

				break;
			}

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDC_CONFIG_USER_PASSWORD:

					if( HIWORD( wParam ) == EN_CHANGE )
						bPasswordChanged = TRUE;

					return FALSE;

				break;

				case IDOK:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					pProfileData->bPromptUser = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROMPT_USER ), 
																	BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bPromptUser = TRUE;

					memset( pProfileData->pwcUserName, 
							0, 
							sizeof( pProfileData->pwcUserName ) );

					GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), 
																	pProfileData->pwcUserName, UNLEN );

					if( bPasswordChanged )
					{
						memset( pProfileData->pwcUserPassword, 
								0, 
								sizeof( pProfileData->pwcUserPassword ) );

						GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD ), 
																pProfileData->pwcUserPassword, PWLEN );
					}

					memset( pProfileData->pwcUserDomain, 0, sizeof( pProfileData->pwcUserDomain ) );

					GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), 
																	pProfileData->pwcUserDomain, UNLEN );

#ifndef _WIN32_WCE
					pProfileData->bUseUserCredentialsForComputer = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), 
																	BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bUseUserCredentialsForComputer = TRUE;
#endif // _WIN32_WCE

					return TRUE;

				break;

				case IDC_CONFIG_USER_USERNAME:

					if( HIWORD( wParam ) == EN_CHANGE )
					{
						if( GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), pwcTemp, UNLEN ) > 0 )
						{
							if( wcschr( pwcTemp, '@' ) )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), FALSE );
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), TRUE );
							}
						}
						else
						{
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), TRUE );
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), TRUE );
						}
					}
	
					return FALSE;

				break;
				
				case IDC_CONFIG_PROMPT_USER:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					switch( HIWORD( wParam ) )
					{
						case BN_CLICKED:

							if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROMPT_USER ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), FALSE );

#ifndef _WIN32_WCE
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), FALSE );
#endif // _WIN32_WCE
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME_LABEL ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), TRUE );

								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD_LABEL ), TRUE );

								if( GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), pwcTemp, UNLEN ) > 0 )
								{
									if( !wcschr( pwcTemp, '@' ) )
									{
										EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), TRUE );
										EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), TRUE );
									}
								}
								else
								{
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), TRUE );
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), TRUE );
								}
#ifndef _WIN32_WCE
								if( pProfileData->bUseAlternateComputerCred )
								{
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), FALSE );
								}
								else
								{
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), TRUE );
								}
#endif // _WIN32_WCE
							}

						break;
					}

				break;

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
// Name: ConfigAuthDlgProc
// Description: Dialog Function for the Authentication Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ConfigAuthDlgProc(	IN  HWND    hWnd,
					IN  UINT    unMsg,
					IN  WPARAM  wParam,
					IN  LPARAM  lParam )
{
	WCHAR						pwcTemp[1024];
	PSW2_PROFILE_DATA			pProfileData;
	HKEY						hKey;
	HKEY						hEapMethodKey;
	WCHAR						pwcKey[MAX_PATH];
	DWORD						ccKey;
	FILETIME					ftLastWriteTime;
	DWORD						dwType;
	SW2_INNER_EAP_CONFIG_DATA	InnerEapConfigData;
	PINNEREAPINVOKECONFIGUI		pInnerEapInvokeConfigUI;
	PINNEREAPFREEMEMORY			pInnerEapFreeMemory;
	HINSTANCE					hEapInstance;
	PBYTE						pbInnerEapConnectionData;
	DWORD						cbInnerEapConnectionData;
	DWORD						dwSelectedInnerEapType = 0;
	DWORD						dwInnerAuthSize;
	WCHAR						pwcInnerAuth[UNLEN];
	DWORD						dwErr;
	int							i;
	DWORD						dwSelected;
	DWORD						dwReturnCode = NO_ERROR;
	
    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
			pProfileData = ( PSW2_PROFILE_DATA ) lParam;

			// load specific language info
			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_AUTHTYPE, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_INNER_AUTH_LABEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_EAPTYPE, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_INNER_EAP_LABEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_CONFIGURE, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_INNER_EAP_CONFIG), pwcTemp);

			//
			// Add Inner Auths
			// Only add RADIUS authentication methods for TTLS
			//
			if (EAPTYPE==21)
			{
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), CB_ADDSTRING, 0, ( LPARAM ) L"PAP" );
			}

			SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), CB_ADDSTRING, 0, ( LPARAM ) L"EAP" );
#ifdef SW2_EAP_HOST
			SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), CB_ADDSTRING, 0, ( LPARAM ) L"EAPHOST" );
#endif // SW2_EAP_HOST

			//
			// Currently for PEAP we only use EAP, but if this is an old TTLS profile it can be PAP so
			// always select EAP
			//
			if (EAPTYPE==25)
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), 
							CB_SELECTSTRING, 
							-1, 
							( LPARAM ) L"EAP" );
			else
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), 
							CB_SELECTSTRING, 
							-1, 
							( LPARAM ) pProfileData->pwcInnerAuth );

			//
			// Add EAP Inner Auth Friendly Names
			//
			if( RegOpenKeyEx( HKEY_LOCAL_MACHINE,
								EAP_EAP_METHOD_LOCATION,
								0,
								KEY_READ,
								&hKey ) == ERROR_SUCCESS )
			{
				dwErr = ERROR_SUCCESS;

				//
				// FIXME: Add EAPHost methods
				//

				//
				// Loop through all the keys in this registry entry
				// Ignore errors except of course RegEnumKeyEx
				//
				for( i = 0; dwErr == ERROR_SUCCESS; i++) 
				{ 
					ccKey = sizeof( pwcKey );

					if ( ( dwErr = RegEnumKeyEx( hKey, 
												i, 
												pwcKey,
												&ccKey, 
												NULL, 
												NULL, 
												NULL, 
												&ftLastWriteTime ) )  == ERROR_SUCCESS )
					{
						//
						// Skip EAP-PEAP/EAP-TTLS through EAP-PEAP/EAP-TTLS for now ;)
						//
						if( wcscmp( pwcKey, L"21" ) != 0 
							|| wcscmp( pwcKey, L"25" ) != 0)
						{
							if( ( RegOpenKeyEx( hKey,
												pwcKey,
												0,
												KEY_READ,
												&hEapMethodKey ) == ERROR_SUCCESS ) )
							{
								dwType = 0;

								if( ( dwReturnCode = SW2_ReadInnerEapMethod( _wtol( pwcKey ), 
																	pProfileData->pwcCurrentProfileId,
																	&InnerEapConfigData ) ) == NO_ERROR )
								{
									dwSelected = ( DWORD ) SendMessage( 
															GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), 
															CB_ADDSTRING, 
															0, 
															( LPARAM ) InnerEapConfigData.pwcEapFriendlyName );

									SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), 
												CB_SETITEMDATA, 
												dwSelected, 
												( LPARAM ) InnerEapConfigData.dwEapType );
								}

								RegCloseKey( hEapMethodKey );
							}
						}
					}
				} // for

				RegCloseKey( hKey );
			}

			if( wcscmp( pProfileData->pwcInnerAuth, L"EAP" ) == 0 )
			{
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_LABEL ), TRUE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), TRUE );

				if( pProfileData->dwCurrentInnerEapMethod > 0 )
				{
					if( ( dwReturnCode = SW2_ReadInnerEapMethod( pProfileData->dwCurrentInnerEapMethod, 
															pProfileData->pwcCurrentProfileId,
															&InnerEapConfigData ) ) == NO_ERROR )
					{
						//
						// Select current EAP method
						//
						SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), 
										CB_SELECTSTRING, 
										-1, 
										( LPARAM ) InnerEapConfigData.pwcEapFriendlyName );

						//
						// If the EAP method has a ConfigUI then enable configure button
						//
						if( wcslen( InnerEapConfigData.pwcEapConfigUiPath ) > 0 )
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_CONFIG ), TRUE );
					}
				}
			}

#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pProfileData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pProfileData );
#endif // _WIN32_WCE

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDC_CONFIG_INNER_AUTH:

					if( HIWORD( wParam ) == LBN_SELCHANGE )
					{
#ifdef _WIN32_WCE
						pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
						pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

						if( ( dwSelected = ( DWORD ) SendMessage( 
							GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), CB_GETCURSEL, 0, 0 ) ) != CB_ERR )
						{
							if( ( dwInnerAuthSize = 
								( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), 
															CB_GETLBTEXTLEN, dwSelected, 0 ) ) != CB_ERR )
							{
								SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::ConfigAuthDlgProc::CB_GETLBTEXTLEN: %d" ), dwSelected );

								if( ( dwInnerAuthSize > 0 ) && ( dwInnerAuthSize <= sizeof( pwcInnerAuth ) ) )
								{
									memset( pwcInnerAuth, 0, sizeof( pwcInnerAuth ) );
									
									dwErr = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), CB_GETLBTEXT, dwSelected, ( LPARAM ) pwcInnerAuth );
								}
								else
								{
									SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigAuthDlgProc::dwSelected: %d, too big" ), dwSelected );

									dwErr = CB_ERR;
								}
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigAuthDlgProc::SendMessage( CB_GETLBTEXTLEN ) Failed: %d" ), GetLastError() );

								dwErr = CB_ERR;
							}
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigAuthDlgProc::SendMessage( CB_GETCURSEL ) Failed: %d" ), GetLastError() );

							dwErr = CB_ERR;
						}

						if( dwErr != CB_ERR )
						{
							if( wcscmp( pwcInnerAuth, L"EAP" ) == 0 )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_LABEL ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), TRUE );

								if( pProfileData->dwCurrentInnerEapMethod > 0 )
								{
									if( ( dwReturnCode = SW2_ReadInnerEapMethod( pProfileData->dwCurrentInnerEapMethod, 
																		pProfileData->pwcCurrentProfileId,
																		&InnerEapConfigData ) ) == NO_ERROR )
									{
										//
										// Select current EAP method
										//
										SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), 
														CB_SELECTSTRING, 
														-1, 
														( LPARAM ) InnerEapConfigData.pwcEapFriendlyName );

										//
										// If the EAP method has a ConfigUI then enable configure button
										//
										if( wcslen( InnerEapConfigData.pwcEapConfigUiPath ) > 0 )
											EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_CONFIG ), TRUE );
									}
								}
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_CONFIG ), FALSE );
							}
						}
					}

					return FALSE;

				break;

				case IDC_CONFIG_INNER_EAP:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( HIWORD( wParam ) == LBN_SELCHANGE )
					{
						if( ( dwSelected = ( DWORD ) SendMessage( 
											GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), 
											CB_GETCURSEL, 
											0, 
											0 ) ) != CB_ERR )
						{
							if( ( dwSelectedInnerEapType = 
									( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP), 
															CB_GETITEMDATA, 
															dwSelected, 
															0 ) ) != CB_ERR )
							{
								if( ( dwReturnCode = SW2_ReadInnerEapMethod( dwSelectedInnerEapType, 
																	pProfileData->pwcCurrentProfileId,
																	&InnerEapConfigData ) ) == NO_ERROR )
								{
									if( wcslen( InnerEapConfigData.pwcEapConfigUiPath ) > 0 )
										EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_CONFIG ), 
																							TRUE );
									else
										EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_CONFIG ), 
																						FALSE );
								}
							}
						}
					}

					return FALSE;

				break;

				case IDC_CONFIG_INNER_EAP_CONFIG:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE


					if( ( dwSelected = ( DWORD ) SendMessage( 
										GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), 
										CB_GETCURSEL, 
										0, 
										0 ) ) != CB_ERR )
					{
						if( ( dwSelectedInnerEapType = 
								( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP), 
														CB_GETITEMDATA, 
														dwSelected, 
														0 ) ) != CB_ERR )
						{
							dwReturnCode = SW2_ReadInnerEapMethod( dwSelectedInnerEapType, 
															pProfileData->pwcCurrentProfileId,
															&InnerEapConfigData );
						}
					}

					if( dwReturnCode == NO_ERROR )
					{
						//
						// Connect to EAP DLL
						//
						if( ( hEapInstance = LoadLibrary( InnerEapConfigData.pwcEapConfigUiPath ) ) )
						{
#ifndef _WIN32_WCE
							if( ( pInnerEapInvokeConfigUI = 
								( PINNEREAPINVOKECONFIGUI ) GetProcAddress( hEapInstance, 
																			"RasEapInvokeConfigUI" ) ) )
#else
							if( ( pInnerEapInvokeConfigUI = 
								( PINNEREAPINVOKECONFIGUI ) GetProcAddress( hEapInstance, 
																			L"RasEapInvokeConfigUI" ) ) )
#endif // _WIN32_WCE
							{
								if( ( pInnerEapInvokeConfigUI( InnerEapConfigData.dwEapType,
																hWnd,
																0,
																InnerEapConfigData.pbConnectionData,
																InnerEapConfigData.cbConnectionData,
																&pbInnerEapConnectionData,
																&cbInnerEapConnectionData ) ) == NO_ERROR )
								{
#ifndef _WIN32_WCE
									if( ( pInnerEapFreeMemory = ( PINNEREAPFREEMEMORY ) 
										GetProcAddress( hEapInstance, "RasEapFreeMemory" ) ) )
#else
									if( ( pInnerEapFreeMemory = ( PINNEREAPFREEMEMORY ) 
										GetProcAddress( hEapInstance, L"RasEapFreeMemory" ) ) )
#endif // _WIN32_WCE
									{
										if( cbInnerEapConnectionData <= EAP_MAX_INNER_CONNECTION_DATA )
										{
											InnerEapConfigData.cbConnectionData = cbInnerEapConnectionData;

											memcpy( InnerEapConfigData.pbConnectionData, 
													pbInnerEapConnectionData, 
													InnerEapConfigData.cbConnectionData );

											dwReturnCode = SW2_WriteInnerEapMethod(dwSelectedInnerEapType, 
																			pProfileData->pwcCurrentProfileId,
																			InnerEapConfigData.pbConnectionData,
																			InnerEapConfigData.cbConnectionData);

										}
										else
										{
											dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
										}

										//
										// Free up Inner EAP module memory
										//
										pInnerEapFreeMemory( pbInnerEapConnectionData );
									}
									else
									{
										SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigAuthDlgProc::GetProcAddress (RasEapFreeMemory) FAILED" ) );

										dwReturnCode = ERROR_DLL_INIT_FAILED;
									}
								}
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigAuthDlgProc::GetProcAddress (RasEapInvokeConfigUI) FAILED" ) );

								dwReturnCode = ERROR_DLL_INIT_FAILED;
							}

							FreeLibrary( hEapInstance );
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigAuthDlgProc:: LoadLibrary FAILED" ) );

							dwReturnCode = ERROR_DLL_INIT_FAILED;
						}
					}
						
				break;

				case IDOK:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( ( dwSelected = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), CB_GETCURSEL, 0, 0 ) ) != CB_ERR )
					{
						if( ( dwInnerAuthSize = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), CB_GETLBTEXTLEN, dwSelected, 0 ) ) != CB_ERR )
						{
							if( ( dwInnerAuthSize > 0 ) && ( dwInnerAuthSize <= sizeof( pProfileData->pwcInnerAuth ) ) )
							{
								SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::ConfigAuthDlgProc::copying InnerAuth: %d" ), dwInnerAuthSize );

								memset( pProfileData->pwcInnerAuth, 0, sizeof( pProfileData->pwcInnerAuth ) );
								
								dwErr = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), CB_GETLBTEXT, dwSelected, ( LPARAM ) pProfileData->pwcInnerAuth );
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigAuthDlgProc::dwSelected: %d, too big" ), dwSelected );

								dwErr = CB_ERR;
							}
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigAuthDlgProc::SendMessage( CB_GETLBTEXTLEN ) Failed: %d" ), GetLastError() );

							dwErr = CB_ERR;
						}
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigAuthDlgProc::SendMessage( CB_GETCURSEL ) Failed: %d" ), GetLastError() );

						dwErr = CB_ERR;
					}

					if( ( dwSelected = ( DWORD ) SendMessage( 
										GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), 
										CB_GETCURSEL, 
										0, 
										0 ) ) != CB_ERR )
					{
						if( ( dwSelectedInnerEapType = 
								( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP), 
														CB_GETITEMDATA, 
														dwSelected, 
														0 ) ) != CB_ERR )
						{
							if( ( dwReturnCode = SW2_ReadInnerEapMethod( dwSelectedInnerEapType, 
																pProfileData->pwcCurrentProfileId,
																&InnerEapConfigData ) ) == NO_ERROR )
							{
								if( wcslen( InnerEapConfigData.pwcEapConfigUiPath ) > 0 )
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_CONFIG ), 
																						TRUE );
								else
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_CONFIG ), 
																					FALSE );
							}
						}
					}

					pProfileData->dwCurrentInnerEapMethod = dwSelectedInnerEapType;

					if( dwErr == CB_ERR )
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigAuthDlgProc::retreiving InnerAuth Failed" ) );

						if (EAPTYPE==21)
#ifndef _WIN32_WCE
							wcscpy_s( pProfileData->pwcInnerAuth, sizeof( pProfileData->pwcInnerAuth )/sizeof(WCHAR), L"PAP" );
#else
							wcscpy( pProfileData->pwcInnerAuth, L"PAP" );
#endif // _WIN32_WCE
						else
#ifndef _WIN32_WCE
							wcscpy_s( pProfileData->pwcInnerAuth, sizeof( pProfileData->pwcInnerAuth )/sizeof(WCHAR), L"EAP" );
#else
							wcscpy( pProfileData->pwcInnerAuth, L"EAP" );
#endif // _WIN32_WCE
					}

					return TRUE;

				break;

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
// Name: ConfigCADlgProc
// Description: Dialog Function for the CA certificate dialog allowing the user
//				to choose a trusted CA
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ConfigCADlgProc(	IN  HWND    hWnd,
					IN  UINT    unMsg,
					IN  WPARAM  wParam,
					IN  LPARAM  lParam )
{
	WCHAR				pwcTemp[1024];
#ifdef _WIN32_WCE
	SHINITDLGINFO		shidi;
#endif //  _WIN32_WCE

	PSW2_PROFILE_DATA	pProfileData;
	DWORD				dwSelected;
	
    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
#ifdef _WIN32_WCE
			shidi.dwMask = SHIDIM_FLAGS;
			shidi.dwFlags = SHIDIF_DONEBUTTON | SHIDIF_SIPDOWN |SHIDIF_SIZEDLGFULLSCREEN;
			shidi.hDlg = hWnd;

			SHInitDialog( &shidi );

			SW2_CreateCommandBar( hWnd );

#endif // _WIN32_WCE

			pProfileData = ( PSW2_PROFILE_DATA ) lParam;

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_AVAILABLEROOTCA, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_AVAILABLE_ROOTCA_LABEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_ADDCA, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_ADDCERT_ADD), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_CANCEL, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDCANCEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_WINDOW_ADDCA, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(hWnd, pwcTemp);

			SW2_CertGetRootCAList( GetDlgItem( hWnd, IDC_CONFIG_ROOTCA ),
									pProfileData->pbTrustedRootCAList,
									pProfileData->dwNrOfTrustedRootCAInList);

#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pProfileData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pProfileData );
#endif // _WIN32_WCE

			return FALSE;

		break;

		case WM_SHOWWINDOW:

			switch( LOWORD( wParam ) )
			{
				case TRUE:
#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					SW2_CertGetRootCAList( GetDlgItem( hWnd, IDC_CONFIG_ROOTCA ),
											pProfileData->pbTrustedRootCAList,
											pProfileData->dwNrOfTrustedRootCAInList);

				break;

				default:

				break;
			}

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDC_CONFIG_ADDCERT_ADD:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( ( dwSelected = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_ROOTCA ), LB_GETCURSEL, 0, 0 ) ) != CB_ERR )
					{
						if( ( dwSelected = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_ROOTCA ), LB_GETITEMDATA, dwSelected, 0 ) ) != CB_ERR )
						{
							SW2_CertAddTrustedRootCA( dwSelected,  
													pProfileData->pbTrustedRootCAList, 
													&pProfileData->dwNrOfTrustedRootCAInList );
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, 
								TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigCADlgProc::SendMessage( CB_GETCURSEL ) Failed: %d" ), GetLastError() );
						}
					}

					EndDialog( hWnd, TRUE );

					return FALSE;

				break;

				case IDCANCEL:

					EndDialog( hWnd, FALSE );

				break;

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
// Name: ConfigCertDlgProc
// Description: Dialog Function for the Certificate Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ConfigCertDlgProc(	IN  HWND    hWnd,
					IN  UINT    unMsg,
					IN  WPARAM  wParam,
					IN  LPARAM  lParam )
{
	WCHAR					pwcTemp[1024];
	PSW2_PROFILE_DATA		pProfileData;
	DWORD					dwSelected;
	
    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
			pProfileData = ( PSW2_PROFILE_DATA ) lParam;

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_VERIFYSERVERCERT, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_VERIFY_SERVER_CERT), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_TRUSTEDROOTCA, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_TRUSTED_ROOTCA_LABEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_ADDCA, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_CERT_ADD), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_REMOVECA, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_CERT_REMOVE), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_VERIFYSERVERNAME, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_VERIFY_SERVER_NAME), pwcTemp);

			//
			// Verify server certificate
			//
			if( pProfileData->bVerifyServerCertificate )
			{
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_CERT ), BM_SETCHECK, BST_CHECKED, 0 );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_TRUSTEDROOTCA ), TRUE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_NAME ), TRUE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_CERT_ADD ), TRUE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_CERT_REMOVE ), TRUE );
			}

			//
			// Verify server domain
			//
			if( pProfileData->bVerifyServerName )
			{
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_NAME ), BM_SETCHECK, BST_CHECKED, 0 );

				if( pProfileData->bVerifyServerCertificate )
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_SERVER_NAME ), TRUE );
			}

			//
			// server domain
			//
			SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_SERVER_NAME ), pProfileData->pwcServerName );

			//
			// Verify Server name
			//
			if( pProfileData->bVerifyServerName )
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_NAME ), BM_SETCHECK, BST_CHECKED, 0 );

			//
			// Update trusted CAs
			//
			SW2_CertGetTrustedRootCAList( GetDlgItem( hWnd, IDC_CONFIG_TRUSTEDROOTCA ), 
										pProfileData->pbTrustedRootCAList, 
										pProfileData->dwNrOfTrustedRootCAInList );
#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pProfileData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pProfileData );
#endif // _WIN32_WCE

			return FALSE;

		break;

		case WM_SHOWWINDOW:

			switch( LOWORD( wParam ) )
			{
				case TRUE:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					//
					// Update trusted CAs
					//
					SW2_CertGetTrustedRootCAList( GetDlgItem( hWnd, IDC_CONFIG_TRUSTEDROOTCA ), 
												pProfileData->pbTrustedRootCAList, 
												pProfileData->dwNrOfTrustedRootCAInList );

				break;

				default:

				break;
			}

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDC_CONFIG_VERIFY_SERVER_CERT:

					switch( HIWORD( wParam ) )
					{
						case BN_CLICKED:

							if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_CERT ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_NAME ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_TRUSTEDROOTCA ), TRUE );

								if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_NAME ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
								{
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_SERVER_NAME ), TRUE );
								}
								else
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_SERVER_NAME ), FALSE );

								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_CERT_ADD ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_CERT_REMOVE ), TRUE );
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_NAME ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_TRUSTEDROOTCA ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_SERVER_NAME ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_CERT_ADD ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_CERT_REMOVE ), FALSE );
							}

						break;

						default:
						break;
					}

				break;

				case IDC_CONFIG_CERT_ADD:

					//
					// User wishes to add certificate so show dialog
					//

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( DialogBoxParam( g_hResource,
										MAKEINTRESOURCE(IDD_CONFIG_CA_DLG),
										hWnd,
										ConfigCADlgProc,
										( LPARAM ) pProfileData ) )
					{
						SendMessage( hWnd, WM_SHOWWINDOW, TRUE, 0 );
					}

					return FALSE;

				break;

				case IDC_CONFIG_CERT_REMOVE:

					//
					// User wishes to add certificate so show dialog
					//

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( ( dwSelected = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_TRUSTEDROOTCA ), LB_GETCURSEL, 0, 0 ) ) != CB_ERR )
					{
						if( ( dwSelected = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_TRUSTEDROOTCA ), LB_GETITEMDATA, dwSelected, 0 ) ) != CB_ERR )
						{
							SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::ConfigCertDlgProc::LB_GETITEMDATA: %ld" ), dwSelected );

							SW2_CertRemoveTrustedRootCA( dwSelected,  
														pProfileData->pbTrustedRootCAList, 
														&pProfileData->dwNrOfTrustedRootCAInList );

							SendMessage( hWnd, WM_SHOWWINDOW, TRUE, 0 );
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, 
								TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigCertDlgProc::SendMessage( CB_GETCURSEL ) Failed: %d" ), GetLastError() );
						}
					}
					
					return FALSE;

				break;

				case IDC_CONFIG_VERIFY_SERVER_NAME:

					switch( HIWORD( wParam ) )
					{
						case BN_CLICKED:

							if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_NAME ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_SERVER_NAME ), TRUE );
							else
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_SERVER_NAME ), FALSE );

						break;

						default:
						break;
					}

				break;

				case IDOK:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					//
					// Verify server certificate
					//
					pProfileData->bVerifyServerCertificate = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_CERT ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bVerifyServerCertificate = TRUE;

					//
					// Verify server domain
					//
					pProfileData->bVerifyServerName = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_NAME ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bVerifyServerName = TRUE;

					memset( pProfileData->pwcServerName, 0, UNLEN );

					GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_SERVER_NAME ), pProfileData->pwcServerName, UNLEN );

					return TRUE;

				break;

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
// Name: ConfigConnDlgProc
// Description: Dialog Function for the Connection Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ConfigConnDlgProc(	IN  HWND    hWnd,
					IN  UINT    unMsg,
					IN  WPARAM  wParam,
					IN  LPARAM  lParam )
{
	WCHAR					pwcTemp[1024];
	PSW2_PROFILE_DATA		pProfileData;
	
    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
			pProfileData = ( PSW2_PROFILE_DATA ) lParam;

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_USEALTEROUTERID, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_USE_ALTERNATE_OUTER), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_USEANONOUTERID, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_USE_ALTERNATE_ANONYMOUS), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_SPECALTEROUTERID, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_USE_ALTERNATE_SPECIFY), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_ENABLESESSRES, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_ENABLE_SESSION_RESUMPTION), pwcTemp);

			//
			// Use alternate outer identity
			//
			if( pProfileData->bUseAlternateIdentity)
			{
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_OUTER ), BM_SETCHECK, BST_CHECKED, 0 );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_ANONYMOUS ), TRUE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_SPECIFY ), TRUE );
			}

			//
			// Use anonymous outer identity
			//
			if( pProfileData->bUseAnonymousIdentity )
			{
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_ANONYMOUS ), BM_SETCHECK, BST_CHECKED, 0 );
			}
			else
			{
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_SPECIFY ), BM_SETCHECK, BST_CHECKED, 0 );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_ALTERNATE_OUTER ), TRUE );
			}

			//
			// Alternate identity
			//
			SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_ALTERNATE_OUTER ), pProfileData->pwcAlternateIdentity );

			//
			// Enable session resumption
			//
			if( pProfileData->bUseSessionResumption )
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_ENABLE_SESSION_RESUMPTION ), BM_SETCHECK, BST_CHECKED, 0 );

#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pProfileData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pProfileData );
#endif // _WIN32_WCE

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDC_CONFIG_USE_ALTERNATE_ANONYMOUS:

					switch( HIWORD( wParam ) )
					{
						case BN_CLICKED:

							if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_ANONYMOUS ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_ALTERNATE_OUTER ), FALSE );
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_ALTERNATE_OUTER ), TRUE );
							}

						break;

						default:
						break;
					}

				break;

				case IDC_CONFIG_USE_ALTERNATE_SPECIFY:

					switch( HIWORD( wParam ) )
					{
						case BN_CLICKED:

							if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_SPECIFY ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_ALTERNATE_OUTER ), TRUE );
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_ALTERNATE_OUTER ), FALSE );
							}

						break;

						default:
						break;
					}

				break;

				case IDC_CONFIG_USE_ALTERNATE_OUTER:

					switch( HIWORD( wParam ) )
					{
						case BN_CLICKED:

							if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_OUTER ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_ANONYMOUS ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_SPECIFY ), TRUE );

								if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_SPECIFY ), BM_GETCHECK, 0 , 0 ) == BST_CHECKED )
                                    EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_ALTERNATE_OUTER ), TRUE );
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_SPECIFY ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_ALTERNATE_OUTER ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_ANONYMOUS ), FALSE );
							}

						break;

						default:
						break;
					}

				break;

				case IDOK:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					//
					// Use alternate outer identity
					//
					pProfileData->bUseAlternateIdentity = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_OUTER ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bUseAlternateIdentity = TRUE;

					//
					// Use anonymous outer identity
					//
					pProfileData->bUseAnonymousIdentity = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_ANONYMOUS ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bUseAnonymousIdentity = TRUE;
					
					//
					// Specified alternate identity
					//
					GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_ALTERNATE_OUTER ), pProfileData->pwcAlternateIdentity, UNLEN );

					//
					// Enable quick connect?
					//
					pProfileData->bUseSessionResumption = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_ENABLE_SESSION_RESUMPTION ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bUseSessionResumption = TRUE;

					return TRUE;

				break;

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
// Name: ConfigProfileNewDlgProc
// Description: Dialog Function for the New Profile Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ConfigProfileNewDlgProc(IN  HWND    hWnd,
						IN  UINT    unMsg,
						IN  WPARAM  wParam,
						IN  LPARAM  lParam )
{
	WCHAR					pwcTemp[1024];
    WCHAR					*pwcProfileID;
#ifdef _WIN32_WCE
	SHINITDLGINFO			shidi;
#endif //  _WIN32_WCE

	DWORD					dwErr = NO_ERROR;
	
    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
			pwcProfileID = ( WCHAR* ) lParam;

#ifdef _WIN32_WCE
			shidi.dwMask = SHIDIM_FLAGS;
			shidi.dwFlags = SHIDIF_DONEBUTTON | SHIDIF_SIPDOWN |SHIDIF_SIZEDLGFULLSCREEN;
			shidi.hDlg = hWnd;

			SHInitDialog( &shidi );

			SW2_CreateCommandBar( hWnd );

#endif // _WIN32_WCE

			// set language specific info
			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_WINDOW_NEWPROFILE, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(hWnd, pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_PROFILE, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_PROFILE_ID_LABEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_OK, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDOK), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_CANCEL, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDCANCEL), pwcTemp);

			SetFocus( GetDlgItem( hWnd, IDC_PROFILE_ID ) );

#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pwcProfileID );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pwcProfileID );
#endif // _WIN32_WCE

			return FALSE;

		break;


	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDOK:

#ifdef _WIN32_WCE
					pwcProfileID = ( WCHAR* ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pwcProfileID = ( WCHAR*) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( GetDlgItemText( hWnd, IDC_PROFILE_ID, pwcProfileID, UNLEN ) > 0 )
					{
						EndDialog( hWnd, TRUE );
					}

					return TRUE;

				break;

				case IDCANCEL:

					EndDialog( hWnd, FALSE );

				break;
			
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
// Name: ConfigProfileDlgProc
// Description: Dialog Function for the Profile Configuration Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ConfigProfileDlgProc(	IN  HWND    hWnd,
						IN  UINT    unMsg,
						IN  WPARAM  wParam,
						IN  LPARAM  lParam )
{
	PSW2_CONFIG_DATA	pConfigData;
	SW2_PROFILE_DATA	ProfileData;
	WCHAR				pwcTemp[1024];
	WCHAR				pwcTemp1[UNLEN];
	WCHAR				pwcTemp2[UNLEN];
	WCHAR				pwcProfileID[UNLEN];
	DWORD				dwSelectedInnerEapType = 0;
	HKEY				hKeyLM;
	FILETIME			ftLastWriteTime;
	DWORD				dwErr;
	WCHAR				pwcKey[MAX_PATH*2];
	DWORD				cwcKey;
	int					i;
	DWORD				dwProfileIDSize;
	DWORD				dwSelected;
	BOOL				bDefaultProfile;
	BOOL				bIsAdmin;
	DWORD				dwReturnCode = NO_ERROR;
	
    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
			pConfigData = ( PSW2_CONFIG_DATA ) lParam;

			// set language specific info
			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_PROFILE, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_PROFILES_LABEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_NEW, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_PROFILE_NEW), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_CONFIGURE, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_PROFILE_CONFIGURE), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_DELETE, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_PROFILE_DELETE), pwcTemp);

			bDefaultProfile = FALSE;

			bIsAdmin = SW2_IsAdmin();

			//
			// Read in all profiles, computer profile are leading
			//
			if( ( dwReturnCode = RegOpenKeyEx( HKEY_LOCAL_MACHINE,	
										SW2_METHOD_PROFILE_LOCATION, 
										0, 
										KEY_READ,
										&hKeyLM ) ) == NO_ERROR )
			{
				//
				// If we are not an administrator disable the write options
				//
				if( !bIsAdmin )
				{			
					//
					// Only admins can select, create and delete profiles
					//
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_NEW ), FALSE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), FALSE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_DELETE ), FALSE );
				}

				dwErr = ERROR_SUCCESS;

				for( i = 0; dwErr == ERROR_SUCCESS; i++) 
				{ 
					cwcKey = sizeof( pwcKey );

					if ( ( dwErr = RegEnumKeyEx( hKeyLM, 
												i, 
												pwcKey,
												&cwcKey, 
												NULL, 
												NULL, 
												NULL, 
												&ftLastWriteTime ) )  == ERROR_SUCCESS )
					{
						//
						// Check for DEFAULT profile
						//
						if( wcscmp( TEXT( "DEFAULT" ), pwcKey ) == 0 )
							bDefaultProfile = TRUE;

						dwSelected = ( DWORD ) SendMessage( 
												GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
												CB_ADDSTRING, 
												0, 
												( LPARAM ) pwcKey );
					}
				}
					
				//
				// DEFAULT must always be available
				//
				if( !bDefaultProfile )
				{
					dwSelected = ( DWORD ) SendMessage( 
											GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
											CB_ADDSTRING, 
											0, 
											( LPARAM ) L"DEFAULT" );
				}

				RegCloseKey( hKeyLM );
			}
			else
			{
				//
				// Could not find any profiles so add the DEFAULT profile
				//
				dwSelected = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
													CB_ADDSTRING, 
													0, 
													( LPARAM ) TEXT( "DEFAULT" ) );
			}

			//
			// Select the current profile, if it fails try and select DEFAULT profile
			//
			if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), CB_SELECTSTRING, -1, 
													( LPARAM ) pConfigData->pwcProfileId  ) != CB_ERR )
			{
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_CONFIGURE ), TRUE );

				if( wcscmp( pConfigData->pwcProfileId, L"DEFAULT" ) != 0 && bIsAdmin )
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_DELETE ), TRUE );
			}
			else if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), CB_SELECTSTRING, -1, 
													( LPARAM ) TEXT( "DEFAULT" ) ) != CB_ERR )
			{
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_CONFIGURE ), TRUE );
			}

#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pConfigData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pConfigData );
#endif // _WIN32_WCE

			return FALSE;

		break;

		case WM_SHOWWINDOW:

			switch( LOWORD( wParam ) )
			{
				case TRUE:

#ifdef _WIN32_WCE
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					dwSelected = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
														CB_RESETCONTENT, 
														0, 
														( LPARAM ) 0 );
					//
					// Read in all profiles
					//
					if( RegOpenKeyEx( HKEY_LOCAL_MACHINE,
										SW2_METHOD_PROFILE_LOCATION,
										0,
										KEY_READ,
										&hKeyLM ) == ERROR_SUCCESS )
					{
						dwErr = ERROR_SUCCESS;

						bDefaultProfile = FALSE;

						for( i = 0; dwErr == ERROR_SUCCESS; i++) 
						{ 
							cwcKey = sizeof( pwcKey );

							if ( ( dwErr = RegEnumKeyEx( hKeyLM, 
														i, 
														pwcKey,
														&cwcKey, 
														NULL, 
														NULL, 
														NULL, 
														&ftLastWriteTime ) )  == ERROR_SUCCESS )
							{
								//
								// Check for DEFAULT profile
								//
								if( wcscmp( TEXT( "DEFAULT" ), pwcKey ) == 0 )
									bDefaultProfile = TRUE;

								dwSelected = ( DWORD ) SendMessage( 
														GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
														CB_ADDSTRING, 
														0, 
														( LPARAM ) pwcKey );
							}
						}

						RegCloseKey( hKeyLM );
					}
					else
					{
						//
						// Could not find any profiles so add the DEFAULT profile
						//
						dwSelected = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
															CB_ADDSTRING, 
															0, 
															( LPARAM ) TEXT( "DEFAULT" ) );
					}

					//
					// DEFAULT must always be available
					//
					if( !bDefaultProfile )
					{
						dwSelected = ( DWORD ) SendMessage( 
												GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
												CB_ADDSTRING, 
												0, 
												( LPARAM ) L"DEFAULT" );
					}

					//
					// Select current profile, if not available select DEFAULT
					//
					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), CB_SELECTSTRING, -1, 
															( LPARAM ) pConfigData->pwcProfileId  ) != CB_ERR )
					{
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_CONFIGURE ), TRUE );

						if( wcscmp( pConfigData->pwcProfileId, L"DEFAULT" ) != 0 )
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_DELETE ), TRUE );
						else
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_DELETE ), FALSE );

					}
					else if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), CB_SELECTSTRING, -1, 
															( LPARAM ) TEXT( "DEFAULT" ) ) != CB_ERR )
					{
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_CONFIGURE ), TRUE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_DELETE ), FALSE );
					}

				break;
	
				default:

				break;
			}

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDC_CONFIG_PROFILES:

					if( HIWORD( wParam ) == LBN_SELCHANGE )
					{
#ifdef _WIN32_WCE
						pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
						pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

						if( ( dwSelected = ( DWORD ) SendMessage( 
								GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), CB_GETCURSEL, 0, 0 ) ) != CB_ERR )
						{
							if( ( dwProfileIDSize = 
								( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
															CB_GETLBTEXTLEN, dwSelected, 0 ) ) != CB_ERR )
							{
								if( ( dwProfileIDSize > 0 ) && 
									( dwProfileIDSize <= sizeof( pConfigData->pwcProfileId ) ) )
								{
									memset( pwcProfileID, 
											0, 
											sizeof( pwcProfileID ) );
									
									dwErr = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
																	CB_GETLBTEXT, 
																	dwSelected, 
																	( LPARAM ) pwcProfileID );

								}
								else
								{
									SW2Trace( SW2_TRACE_LEVEL_ERROR, 
										TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigProfileDlgProc::dwSelected: %ld, too big" ), dwSelected );

									dwErr = CB_ERR;
								}
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, 
									TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigProfileDlgProc::SendMessage( CB_GETLBTEXTLEN ) Failed: %d" ), GetLastError() );

								dwErr = CB_ERR;
							}
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, 
								TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigProfileDlgProc::SendMessage( CB_GETCURSEL ) Failed: %d" ), GetLastError() );

							dwErr = CB_ERR;
						}

						if( dwErr != CB_ERR )
						{
							wcscpy( pConfigData->pwcProfileId, pwcProfileID );

							if( wcscmp( pConfigData->pwcProfileId, L"DEFAULT" ) != 0 )
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_DELETE ), TRUE );
							else
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_DELETE ), FALSE );
						}

					}

					return FALSE;

				break;

				case IDC_CONFIG_PROFILE_NEW:

#ifdef _WIN32_WCE
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( DialogBoxParam( g_hResource,
										MAKEINTRESOURCE(IDD_PROFILE_NEW_DLG),
										hWnd,
										ConfigProfileNewDlgProc,
										( LPARAM ) pwcProfileID ) )
					{
						//
						// Verify if profile exists
						//
						wsprintf( pwcTemp, 
								L"%s\\%s", 
								SW2_METHOD_PROFILE_LOCATION,
								pwcProfileID );

						if( ( wcscmp( pwcProfileID, L"DEFAULT" ) == 0 ) ||
							RegOpenKeyEx( HKEY_LOCAL_MACHINE,
										pwcTemp,
										0,
										KEY_READ,
										&hKeyLM ) == ERROR_SUCCESS )
						{							
							//
							// existing profile
							//
							RegCloseKey( hKeyLM );

							memset( pwcTemp1, 0, sizeof( pwcTemp1 ) );
							memset( pwcTemp2, 0, sizeof( pwcTemp2 ) );

							LoadString( g_hLanguage, IDS_ERROR_PROFILE_EXISTS, pwcTemp1, sizeof( pwcTemp1 ) );
							LoadString( g_hLanguage, IDS_ERROR_SW2_ERROR, pwcTemp2, sizeof( pwcTemp2 ) );

							MessageBox( hWnd, pwcTemp1, pwcTemp2, MB_OK | MB_ICONEXCLAMATION );
					
							dwReturnCode = NO_ERROR;
						}
						else
						{
							//
							// new profile
							//
							SW2_InitDefaultProfile( &ProfileData, EAPTYPE );

#ifndef _WIN32_WCE
						wcscpy_s( ProfileData.pwcCurrentProfileId, 
										sizeof( ProfileData.pwcCurrentProfileId )/sizeof(WCHAR),
										pwcProfileID );
#else
						wcscpy( ProfileData.pwcCurrentProfileId, 
										pwcProfileID );
#endif // _WIN32_WCE

						

							if( DialogBoxParam( g_hResource,
												MAKEINTRESOURCE(IDD_PROFILE_DLG),
												hWnd,
												ProfileDlgProc,
												( LPARAM ) &ProfileData ) )
							{
								//
								// Write profile
								//
								SW2_WriteUserProfile( pwcProfileID, NULL, ProfileData );
								SW2_WriteComputerProfile( pwcProfileID, NULL, ProfileData );

								//
								// Select new Profile
								//
								wcscpy( pConfigData->pwcProfileId, pwcProfileID );

								//
								// Reset screen
								//
								SendMessage( hWnd, WM_SHOWWINDOW, TRUE, 0 );
							}
							else
								dwReturnCode = GetLastError();
						}
					}
					else
						dwReturnCode = GetLastError();
					
					return TRUE;

				break;

				case IDC_CONFIG_PROFILE_CONFIGURE:

#ifdef _WIN32_WCE
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( ( dwSelected = ( DWORD ) SendMessage( 
							GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), CB_GETCURSEL, 0, 0 ) ) != CB_ERR )
					{
						if( ( dwProfileIDSize = 
							( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
														CB_GETLBTEXTLEN, dwSelected, 0 ) ) != CB_ERR )
						{
							if( ( dwProfileIDSize > 0 ) && 
								( dwProfileIDSize <= sizeof( pConfigData->pwcProfileId ) ) )
							{
								memset( pwcProfileID, 
										0, 
										sizeof( pwcProfileID ) );
								
								dwErr = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
																CB_GETLBTEXT, 
																dwSelected, 
																( LPARAM ) pwcProfileID );

								SW2Trace( SW2_TRACE_LEVEL_ERROR, 
									TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigProfileDlgProc::dwSelected: %s" ), pwcProfileID );
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, 
									TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigProfileDlgProc::dwSelected: %ld, too big" ), dwSelected );

								dwErr = CB_ERR;
							}
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, 
								TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigProfileDlgProc::SendMessage( CB_GETLBTEXTLEN ) Failed: %d" ), GetLastError() );

							dwErr = CB_ERR;
						}
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigProfileDlgProc::SendMessage( CB_GETCURSEL ) Failed: %d" ), GetLastError() );

						dwErr = CB_ERR;
					}

					if( dwErr != CB_ERR )
					{
						//
						// Load in configuration data
						//

						//
						// If configuration fails load default profile
						//
						if (SW2_ReadProfile( pwcProfileID, NULL, &ProfileData ) != NO_ERROR)
						{
							SW2_InitDefaultProfile(&ProfileData, EAPTYPE);
						}

						if (dwReturnCode == NO_ERROR)
						{
							if( DialogBoxParam( g_hResource,
												MAKEINTRESOURCE(IDD_PROFILE_DLG),
												hWnd,
												&ProfileDlgProc,
												( LPARAM ) &ProfileData ) )
							{
								SW2_WriteUserProfile( pwcProfileID, NULL, ProfileData );
								SW2_WriteComputerProfile( pwcProfileID, NULL, ProfileData );

								//
								// Reset screen
								//
								SendMessage( hWnd, WM_SHOWWINDOW, TRUE, 0 );
							}
							else
								SW2Trace( SW2_TRACE_LEVEL_ERROR, 
								TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigProfileDlgProc::failed to create dialog(ProfileDlgProc): %d" ), GetLastError() );
						}
					}

					return TRUE;

				break;

				case IDC_CONFIG_PROFILE_DELETE:

#ifdef _WIN32_WCE
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( ( dwSelected = ( DWORD ) SendMessage( 
							GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), CB_GETCURSEL, 0, 0 ) ) != CB_ERR )
					{
						if( ( dwProfileIDSize = 
							( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
														CB_GETLBTEXTLEN, dwSelected, 0 ) ) != CB_ERR )
						{
							if( ( dwProfileIDSize > 0 ) && 
								( dwProfileIDSize <= sizeof( pConfigData->pwcProfileId ) ) )
							{
								memset( pwcProfileID, 
										0, 
										sizeof( pwcProfileID ) );
								
								dwErr = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
																CB_GETLBTEXT, 
																dwSelected, 
																( LPARAM ) pwcProfileID );
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, 
									TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigProfileDlgProc::dwSelected: %ld, too big" ), dwSelected );

								dwErr = CB_ERR;
							}
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, 
								TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigProfileDlgProc::SendMessage( CB_GETLBTEXTLEN ) Failed: %d" ), GetLastError() );

							dwErr = CB_ERR;
						}
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigProfileDlgProc::SendMessage( CB_GETCURSEL ) Failed: %d" ), GetLastError() );

						dwErr = CB_ERR;
					}

					if( dwErr != CB_ERR )
					{
						if( wcscmp( pwcProfileID, TEXT( "DEFAULT" ) ) != 0 )
						{
							memset( pwcTemp1, 0, sizeof( pwcTemp1 ) );
							memset( pwcTemp2, 0, sizeof( pwcTemp2 ) );

							LoadString( g_hLanguage, IDS_ERROR_PROFILE_DELETE, pwcTemp1, sizeof( pwcTemp1 ) );
							LoadString( g_hLanguage, IDS_ERROR_SW2_ALERT, pwcTemp2, sizeof( pwcTemp2 ) );

							if( MessageBox( hWnd, pwcTemp1, pwcTemp2, MB_YESNO | MB_ICONQUESTION ) == IDYES )
							{
								SW2_DeleteProfile( pwcProfileID );

								//
								// Reset screen
								//
								SendMessage( hWnd, WM_SHOWWINDOW, TRUE, 0 );
							}
						}
						else
						{
							memset( pwcTemp1, 0, sizeof( pwcTemp1 ) );
							memset( pwcTemp2, 0, sizeof( pwcTemp2 ) );

							LoadString( g_hLanguage, IDS_ERROR_PROFILE_DELETEDEFAULT, pwcTemp1, sizeof( pwcTemp1 ) );
							LoadString( g_hLanguage, IDS_ERROR_SW2_ALERT, pwcTemp2, sizeof( pwcTemp2 ) );

							MessageBox( hWnd, pwcTemp1, pwcTemp2, MB_OK | MB_ICONEXCLAMATION );
						}
					}

					return TRUE;

				break;

				case IDOK:

#ifdef _WIN32_WCE
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( ( dwSelected = ( DWORD ) SendMessage( 
							GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), CB_GETCURSEL, 0, 0 ) ) != CB_ERR )
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::ConfigProfileDlgProc::dwSelected: %d" ), dwSelected );

						if( ( dwProfileIDSize = 
							( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
														CB_GETLBTEXTLEN, dwSelected, 0 ) ) != CB_ERR )
						{
							if( ( dwProfileIDSize > 0 ) && 
								( dwProfileIDSize <= sizeof( pConfigData->pwcProfileId ) ) )
							{
								memset( pConfigData->pwcProfileId, 
										0, 
										sizeof( pConfigData->pwcProfileId ) );
								
								dwErr = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
																CB_GETLBTEXT, 
																dwSelected, 
																( LPARAM ) pConfigData->pwcProfileId );

							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigProfileDlgProc::dwSelected: %ld, too big" ), dwSelected );

								dwErr = CB_ERR;
							}
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigProfileDlgProc::SendMessage( CB_GETLBTEXTLEN ) Failed: %d" ), GetLastError() );

							dwErr = CB_ERR;
						}
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigProfileDlgProc::SendMessage( CB_GETCURSEL ) Failed: %d" ), GetLastError() );

						dwErr = CB_ERR;
					}

					return TRUE;

				break;

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
// Name: ProfileDlgProc
// Description: Dialog Function for the Profile Selection Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ProfileDlgProc(	IN  HWND    hWnd,
				IN  UINT    unMsg,
				IN  WPARAM  wParam,
				IN  LPARAM  lParam )
{
    PSW2_PROFILE_DATA		pProfileData;
	WCHAR					pwcTemp[1024];
	WCHAR					pwcTemp2[1024];
	BOOL					bContinue;
#ifdef _WIN32_WCE
	static HWND				hWndCB;
	static SHACTIVATEINFO	hSHActInfo;
	static WCHAR			pwcTempPassword[PWLEN];
	SHINITDLGINFO			shidi;
#endif // _WIN32_WCE
	int						iSel;
	TCITEM					tie; 
	DWORD					dwErr = NO_ERROR;
	NMHDR					*pnmH;
	
    switch( unMsg )
    {
		case WM_INITDIALOG:

			pProfileData = ( PSW2_PROFILE_DATA ) lParam;

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_ADVANCED, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CONFIG_USER_ADVANCED), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_OK, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDOK), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_CANCEL, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDCANCEL), pwcTemp);

#ifndef _WIN32_WCE
			swprintf_s( pwcTemp, 
						sizeof(pwcTemp)/sizeof(WCHAR),
						pProfileData->pwcCurrentProfileId );
#else
			swprintf( pwcTemp, pProfileData->pwcCurrentProfileId );
#endif

			SetWindowText( hWnd, pwcTemp );

#ifdef _WIN32_WCE
			shidi.dwMask = SHIDIM_FLAGS;
			shidi.dwFlags = SHIDIF_DONEBUTTON | SHIDIF_SIPDOWN |SHIDIF_SIZEDLGFULLSCREEN;
			shidi.hDlg = hWnd;

			SHInitDialog( &shidi );

			SW2_CreateCommandBar( hWnd );

#endif // _WIN32_WCE

			//
			// Only Administrators can see the full configuration
			//
			if( SW2_IsAdmin() )
			{
				tie.mask = TCIF_TEXT | TCIF_IMAGE; 
				tie.iImage = -1; 

				memset(pwcTemp, 0, sizeof(pwcTemp));
				LoadString( g_hLanguage, IDS_TAB_CONNECTION, pwcTemp, sizeof( pwcTemp ) );

				tie.pszText = pwcTemp; 
 
				TabCtrl_InsertItem( GetDlgItem( hWnd, IDC_PROFILE_TAB ), 0, &tie );

				memset(pwcTemp, 0, sizeof(pwcTemp));
				LoadString( g_hLanguage, IDS_TAB_CERTIFICATES, pwcTemp, sizeof( pwcTemp ) );

				tie.pszText = pwcTemp; 
	 
				TabCtrl_InsertItem( GetDlgItem( hWnd, IDC_PROFILE_TAB ), 1, &tie );

				memset(pwcTemp, 0, sizeof(pwcTemp));
				LoadString( g_hLanguage, IDS_TAB_AUTHENTICATION, pwcTemp, sizeof( pwcTemp ) );

				tie.pszText = pwcTemp; 

				TabCtrl_InsertItem( GetDlgItem( hWnd, IDC_PROFILE_TAB ), 2, &tie );

				memset(pwcTemp, 0, sizeof(pwcTemp));
				LoadString( g_hLanguage, IDS_TAB_USERACCOUNT, pwcTemp, sizeof( pwcTemp ) );

				tie.pszText = pwcTemp; 

				TabCtrl_InsertItem( GetDlgItem( hWnd, IDC_PROFILE_TAB ), 3, &tie );
			
				pProfileData->hWndTabs[0] = CreateDialogParam( g_hResource, 
															MAKEINTRESOURCE(IDD_CONFIG_CON_DLG),
															hWnd,
															ConfigConnDlgProc,
															( LPARAM ) pProfileData ); 

				pProfileData->hWndTabs[1] = CreateDialogParam( g_hResource, 
															MAKEINTRESOURCE(IDD_CONFIG_CERT_DLG),
															hWnd,
															ConfigCertDlgProc,
															( LPARAM ) pProfileData ); 

				pProfileData->hWndTabs[2] = CreateDialogParam( g_hResource, 
															MAKEINTRESOURCE(IDD_CONFIG_AUTH_DLG),
															hWnd,
															ConfigAuthDlgProc,
															( LPARAM ) pProfileData ); 

				pProfileData->hWndTabs[3] = CreateDialogParam( g_hResource, 
															MAKEINTRESOURCE(IDD_CONFIG_USER_DLG),
															hWnd,
															ConfigUserDlgProc,
															( LPARAM ) pProfileData ); 

				SetWindowPos( pProfileData->hWndTabs[0], HWND_TOP, 0,0,0,0, SWP_SHOWWINDOW | SWP_NOSIZE |SWP_NOMOVE );
				SetWindowPos( pProfileData->hWndTabs[1], HWND_TOP, 0,0,0,0, SWP_HIDEWINDOW | SWP_NOSIZE |SWP_NOMOVE );
				SetWindowPos( pProfileData->hWndTabs[2], HWND_TOP, 0,0,0,0, SWP_HIDEWINDOW | SWP_NOSIZE |SWP_NOMOVE );
				SetWindowPos( pProfileData->hWndTabs[3], HWND_TOP, 0,0,0,0, SWP_HIDEWINDOW | SWP_NOSIZE |SWP_NOMOVE );

			}
			else
			{
				tie.mask = TCIF_TEXT | TCIF_IMAGE; 
				tie.iImage = -1; 
				tie.pszText = L"User account";
	 
				TabCtrl_InsertItem( GetDlgItem( hWnd, IDC_PROFILE_TAB ), 1, &tie );
			
				pProfileData->hWndTabs[0] = CreateDialogParam( g_hResource, 
															MAKEINTRESOURCE(IDD_CONFIG_USER_DLG),
															hWnd,
															ConfigUserDlgProc,
															( LPARAM ) pProfileData ); 

				SetWindowPos( pProfileData->hWndTabs[0], HWND_TOP, 0,0,0,0, SWP_SHOWWINDOW | SWP_NOSIZE |SWP_NOMOVE );
			}

			//
			// Only admins can see and access the advanced options
			//
			if( !SW2_IsAdmin() )
			{
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_ADVANCED ), FALSE );

				ShowWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_ADVANCED ), SW_HIDE );
			}

#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pProfileData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pProfileData );
#endif // _WIN32_WCE

			return FALSE;

		break;

		case WM_SHOWWINDOW:

			switch( LOWORD( wParam ) )
			{
				case TRUE:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( ( iSel = TabCtrl_GetCurSel( GetDlgItem( hWnd, IDC_PROFILE_TAB ) ) ) < SW2_MAX_CONFIG_TAB )
					{
						ShowWindow( pProfileData->hWndTabs[0], FALSE );

						if( SW2_IsAdmin() )
						{
							ShowWindow( pProfileData->hWndTabs[1], FALSE );
							ShowWindow( pProfileData->hWndTabs[2], FALSE );
							ShowWindow( pProfileData->hWndTabs[3], FALSE );
						}

						ShowWindow( pProfileData->hWndTabs[iSel], TRUE );
					}

				break;

				default:

				break;
			}

			return FALSE;

		break;

		case WM_NOTIFY:

			switch( wParam )
			{
				case IDC_PROFILE_TAB:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					pnmH = ( NMHDR * ) lParam;

					switch( pnmH->code )
					{
						case TCN_SELCHANGE:

							if( ( iSel = TabCtrl_GetCurSel( GetDlgItem( hWnd, IDC_PROFILE_TAB ) ) ) < SW2_MAX_CONFIG_TAB )
							{
								ShowWindow( pProfileData->hWndTabs[0], FALSE );

								if( SW2_IsAdmin() )
								{
									ShowWindow( pProfileData->hWndTabs[1], FALSE );
									ShowWindow( pProfileData->hWndTabs[2], FALSE );
									ShowWindow( pProfileData->hWndTabs[3], FALSE );
								}

								ShowWindow( pProfileData->hWndTabs[iSel], TRUE );
							}

							return FALSE;

						break;
					}

				break;

				default:

						return FALSE;

				break;
			}

		break;

	    case WM_COMMAND:

			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::ProfileDlgProc::WM_COMMAND: %ld" ), LOWORD( wParam ) );

			switch( LOWORD( wParam ) )
			{
				case IDC_CONFIG_USER_ADVANCED:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( DialogBoxParam( g_hResource,
										MAKEINTRESOURCE(IDD_CONFIG_ADVANCED_DLG),
										hWnd,
										ConfigAdvancedDlgProc,
										( LPARAM ) pProfileData ) )
					{
						SendMessage( hWnd, WM_SHOWWINDOW, TRUE, 0 );
					}

					return FALSE;

				break;

				case IDOK:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					SendMessage( pProfileData->hWndTabs[0], WM_COMMAND, IDOK, 0 );
					
					if( SW2_IsAdmin() )
					{
						SendMessage( pProfileData->hWndTabs[1], WM_COMMAND, IDOK, 0 );
						SendMessage( pProfileData->hWndTabs[2], WM_COMMAND, IDOK, 0 );
						SendMessage( pProfileData->hWndTabs[3], WM_COMMAND, IDOK, 0 );

					}

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					bContinue = TRUE;

					//
					// Check to see if the user configured everything correctly
					//
					if (pProfileData->dwNrOfTrustedRootCAInList == 0&&
						pProfileData->bVerifyServerCertificate)
					{
						bContinue = FALSE;

						memset(pwcTemp, 0, sizeof(pwcTemp));

						LoadString(g_hLanguage, IDS_ERROR_PROFILE_NOROOTCA, pwcTemp, sizeof(pwcTemp));
						LoadString(g_hLanguage, IDS_ERROR_SW2_ALERT, pwcTemp2, sizeof( pwcTemp2 ) );

						if (MessageBox(hWnd, pwcTemp, pwcTemp2, MB_OKCANCEL | MB_ICONEXCLAMATION) == IDOK)
						{
							bContinue = TRUE;
						}
					}

					if (bContinue)
					{


						EndDialog( hWnd, TRUE );
					}

					return FALSE;

				break;

				case IDCANCEL:

					SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::ProfileDlgProc::IDCANCEL" ) );

					EndDialog( hWnd, FALSE );

					return TRUE;

				break;

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
// Name: ConfigDlgProc
// Description: Dialog Function for the main SecureW2 Configuration Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ConfigDlgProc(	IN  HWND    hWnd,
				IN  UINT    unMsg,
				IN  WPARAM  wParam,
				IN  LPARAM  lParam )
{
	DWORD					dwReturnCode;
    PSW2_CONFIG_DATA		pConfigData;
	WCHAR					pwcTemp[1024];
	WCHAR					pwcVersionFile[256];
	VS_FIXEDFILEINFO*		pvsFileInfo;
	DWORD					dwvsFileInfoSize;
	PBYTE					pbVersion;
	DWORD					dwHandle = 0;
	DWORD					cbVersion;
#ifdef _WIN32_WCE
	static HWND				hWndCB;
	static SHACTIVATEINFO	hSHActInfo;
	static WCHAR			pwcTempPassword[PWLEN];
	SHINITDLGINFO			shidi;
#endif // _WIN32_WCE
	int						iSel;
	TCITEM					tie; 
	DWORD					dwErr = NO_ERROR;
	NMHDR					*pnmH;
	
	dwReturnCode = NO_ERROR;

    switch( unMsg )
    {
		case WM_INITDIALOG:

			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::ConfigDlgProc:: WM_INITDIALOG" ) );

			pConfigData = ( PSW2_CONFIG_DATA ) lParam;

#ifdef _WIN32_WCE
			shidi.dwMask = SHIDIM_FLAGS;
			shidi.dwFlags = SHIDIF_DONEBUTTON | SHIDIF_SIPDOWN |SHIDIF_SIZEDLGFULLSCREEN;
			shidi.hDlg = hWnd;

			SHInitDialog( &shidi );

			SW2_CreateCommandBar( hWnd );

#endif // _WIN32_WCE

			tie.mask = TCIF_TEXT | TCIF_IMAGE; 
			tie.iImage = -1; 
				
			LoadString( g_hLanguage, IDS_TAB_PROFILE, pwcTemp, sizeof( pwcTemp ) );

			tie.pszText = pwcTemp; 

			TabCtrl_InsertItem( GetDlgItem( hWnd, IDC_CONFIG_TAB ), 0, &tie );

			// set language specific info
			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_WINDOW_CONFIGURATION, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(hWnd, pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_OK, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDOK), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_CANCEL, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDCANCEL), pwcTemp);

			pConfigData->hWndTabs[0] = CreateDialogParam( g_hResource, 
														MAKEINTRESOURCE(IDD_CONFIG_PROFILE_DLG),
														hWnd,
														ConfigProfileDlgProc,
														( LPARAM ) pConfigData ); 

			SetWindowPos( pConfigData->hWndTabs[0], 
							HWND_TOP, 0,0,0,0, 
							SWP_SHOWWINDOW | SWP_NOSIZE |SWP_NOMOVE );

			SetWindowPos( hWnd, 
						HWND_TOP, 
						0,0,0,0, 
						SWP_SHOWWINDOW | SWP_NOSIZE |SWP_NOMOVE );

			if (EAPTYPE==21)
#ifdef _WIN32_WCE
				swprintf(pwcVersionFile, L"sw2_ttls.dll");
#else
				swprintf_s(pwcVersionFile, sizeof(pwcVersionFile)/sizeof(WCHAR), L"sw2_ttls.dll");
#endif
			else if (EAPTYPE=25)
#ifdef _WIN32_WCE
				swprintf(pwcVersionFile, L"sw2_peap.dll");
#else
				swprintf_s(pwcVersionFile, sizeof(pwcVersionFile)/sizeof(WCHAR), L"sw2_peap.dll");
#endif
			else
				dwReturnCode = ERROR_INVALID_DATA;

			if (dwReturnCode == NO_ERROR)
			{
				cbVersion = GetFileVersionInfoSize(pwcVersionFile, &dwHandle );

				if (SW2AllocateMemory(cbVersion, (PVOID*) &pbVersion) == NO_ERROR)
				{
					if (GetFileVersionInfo(pwcVersionFile,
												0,
												cbVersion,
												pbVersion ) )
					{
						dwvsFileInfoSize = 0;

						if (VerQueryValue( pbVersion, L"\\", ( LPVOID*) &pvsFileInfo, (PUINT) &dwvsFileInfoSize))
						{
							memset(pwcTemp, 0, sizeof(pwcTemp));
#ifdef _WIN32_WCE
							swprintf(pwcTemp,
#else
							swprintf_s(pwcTemp, sizeof(pwcTemp)/sizeof(WCHAR), 
#endif
								L"%ld.%ld.%ld (%ld)", 
								pvsFileInfo->dwProductVersionMS >> 16, 
								pvsFileInfo->dwProductVersionMS & 0xFFFF, 
								pvsFileInfo->dwProductVersionLS >> 16, 
								pvsFileInfo->dwProductVersionLS & 0xFFFF);

							SetWindowText(GetDlgItem(hWnd, IDC_VERSION), pwcTemp);
						}
					}

					SW2FreeMemory((PVOID*)&pbVersion);
				}
			}
			else
				SetWindowText(GetDlgItem(hWnd, IDC_VERSION), L"0.0.0 (0)");

#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pConfigData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pConfigData );
#endif // _WIN32_WCE

			return FALSE;

		break;

		case WM_NOTIFY:

			switch( wParam )
			{
				case IDC_CONFIG_TAB:

#ifdef _WIN32_WCE
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					pnmH = ( NMHDR * ) lParam;

					switch( pnmH->code )
					{
						case TCN_SELCHANGE:

							if( ( iSel = TabCtrl_GetCurSel( GetDlgItem( hWnd, IDC_CONFIG_TAB ) ) ) < SW2_MAX_CONFIG_TAB )
							{
								ShowWindow( pConfigData->hWndTabs[0], FALSE );
#ifndef _WIN32_WCE
								if( SW2_IsAdmin() )
								{
									ShowWindow( pConfigData->hWndTabs[1], FALSE );
								}
#endif // _WIN32_WCE

								ShowWindow( pConfigData->hWndTabs[iSel], TRUE );
							}

							return FALSE;

						break;
					}

				break;

				default:

						return FALSE;

				break;
			}

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDOK:

#ifdef _WIN32_WCE
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					SendMessage( pConfigData->hWndTabs[0], WM_COMMAND, IDOK, 0 );
#ifndef _WIN32_WCE
					if( SW2_IsAdmin() )
					{
						SendMessage( pConfigData->hWndTabs[1], WM_COMMAND, IDOK, 0 );
					}
#endif // _WIN32_WCE

					EndDialog( hWnd, TRUE );

					return FALSE;

				break;

				case IDCANCEL:

					EndDialog( hWnd, FALSE );

					return TRUE;

				break;

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
// Name: TLSServerTrustDlgProc
// Description: Dialog Function for the "Untrusted Server" Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
TLSServerTrustDlgProc(	IN  HWND    hWnd,
							IN  UINT    unMsg,
							IN  WPARAM  wParam,
							IN  LPARAM  lParam )
{
#ifdef _WIN32_WCE
	SHINITDLGINFO				shidi;
#endif //  _WIN32_WCE
	PSW2_SESSION_DATA			pSessionData;
	PCCERT_CONTEXT				pCertContext;
	SHELLEXECUTEINFO			ExecInfo;
#ifndef _WIN32_WCE
	HANDLE						hFile;
	DWORD						dwNumberOfBytesWritten;
	WCHAR						pwcTempPath[MAX_PATH];
	WCHAR						pwcTempFileName[MAX_PATH];
	WCHAR						pwcParameters[MAX_PATH*2];
	DWORD						iCertType;
	HKEY						hKey;
	PBYTE						pbData;
	DWORD						cbData;
#endif // _WIN32_WCE
	CHAR						pcTemp[UNLEN];
	WCHAR						pwcTemp[MAX_PATH*2];
	WCHAR						pwcTemp1[UNLEN];
	WCHAR						pwcTemp2[UNLEN];
	HCERTSTORE					hCertStore;
	HIMAGELIST					hImageList;
	HTREEITEM					hSelectedItem;
	TVITEM						tvItem;
	HCRYPTPROV					hCSP;
	PBYTE						pbSHA1;
	DWORD						cbSHA1;
	FILE						*pFile;
	int							i;
	DWORD						dwReturnCode = NO_ERROR;

    switch( unMsg )
    {
		case WM_INITDIALOG:
        
			pSessionData = ( PSW2_SESSION_DATA ) lParam;

#ifdef _WIN32_WCE
			// Create a Done button and size it.  
			shidi.dwMask = SHIDIM_FLAGS;
			shidi.dwFlags = SHIDIF_DONEBUTTON | SHIDIF_SIPDOWN |SHIDIF_SIZEDLGFULLSCREEN;
			shidi.hDlg = hWnd;

			SHInitDialog( &shidi );

			SW2_CreateCommandBar( hWnd );

#endif // _WIN32_WCE
			
			// set language specific info
			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_WINDOW_UNTRUSTEDSERVER, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(hWnd, pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_CERT_HIERARCHY, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_CERT_HIERARCHY), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_CERT_INSTALL, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDINSTALLCERT), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_CERT_INSTALLALL, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDINSTALLCERTS), pwcTemp);

#ifndef _WIN32_WCE
			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_CERT_VIEW, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDVIEWCERT), pwcTemp);
#endif // _WIN32_WCE
			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_OK, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDOK), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_CANCEL, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDCANCEL), pwcTemp);

			//
			// If this is not an administrator then we cannot install certificates
			// can only connect using temp trust
			//
			if( !SW2_IsAdmin() )
			{
				//
				// Disable install button
				//
				EnableWindow( GetDlgItem( hWnd, IDINSTALLCERT ), FALSE );
				EnableWindow( GetDlgItem( hWnd, IDINSTALLCERTS ), FALSE );
			}

			//
			// Create image list for tree view control and add icons to 
			// the images list
			//
			hImageList = ImageList_Create( 16, 16, TRUE, 2, 2 );

			ImageList_AddIcon( hImageList, LoadIcon( g_hResource, MAKEINTRESOURCE( IDI_CERT_ICON ) ) );
			ImageList_AddIcon( hImageList, LoadIcon( g_hResource, MAKEINTRESOURCE( IDI_CERT_ICON_ERROR ) ) );

			TreeView_SetImageList( GetDlgItem( hWnd, IDC_CERT_TREE ), hImageList, TVSIL_NORMAL);

			ConfigUpdateCertificateView( hWnd, pSessionData );

#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pSessionData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pSessionData );
#endif // _WIN32_WCE
			
			return FALSE;

		break;

	    case WM_COMMAND: 

			switch( LOWORD( wParam ) )
			{
				case IDINSTALLCERTS:

					SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSServerTrustDlgProc:: IDINSTALLCERTS" ) );

#ifdef _WIN32_WCE
					pSessionData = ( PSW2_SESSION_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pSessionData = ( PSW2_SESSION_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					for( i=0; ( DWORD ) i < pSessionData->TLSSession.dwCertCount; i++ )
					{
						if( ( pCertContext = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
																			pSessionData->TLSSession.pbCertificate[i], 
																			pSessionData->TLSSession.cbCertificate[i]) ) )
						{
							//
							// If this is the first certificate in line (server certificate) then 
							// put it in the MY store, else in the ROOT (CA certificate
							//
							if( i == 0 )
							{
								hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM,
															X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
															( HCRYPTPROV  ) NULL, 
															CERT_SYSTEM_STORE_LOCAL_MACHINE,
															L"MY" );
							}
							else
							{
								hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM,
															X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
															( HCRYPTPROV  ) NULL, 
															CERT_SYSTEM_STORE_LOCAL_MACHINE,
															L"ROOT" );
							}

							if( hCertStore )
							{
								if( !CertAddCertificateContextToStore( hCertStore, 
																		pCertContext, 
																		CERT_STORE_ADD_REPLACE_EXISTING, 
																		NULL ) )
								{
									SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSServerTrustDlgProc::IDINSTALLCERTS::CertAddCertificateContextToStore(), FAILED: %x" ), GetLastError() );

									dwReturnCode = CERT_E_UNTRUSTEDROOT;
								}

								CertCloseStore( hCertStore, CERT_CLOSE_STORE_FORCE_FLAG );
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSServerTrustDlgProc::IDINSTALLCERTS::CertOpenSystemStore(), FAILED: %x" ), GetLastError() );

								dwReturnCode = CERT_E_UNTRUSTEDROOT;
							}

							if( i == ( int ) ( pSessionData->TLSSession.dwCertCount - 1 ) )
							{
								//
								// Also add last certificate to our CA list
								//
								if ((dwReturnCode = SW2_CryptAcquireDefaultContext(&hCSP,
																NULL))==NO_ERROR)
								{
				
									//
									// Get HASH of certificate
									//
									if( ( dwReturnCode = TLSGetSHA1( hCSP, 
																pSessionData->TLSSession.pbCertificate[i], 
																pSessionData->TLSSession.cbCertificate[i], 
																&pbSHA1, 
																&cbSHA1 ) ) == NO_ERROR )
									{
										//
										// If not in list then add it
										//
										if( SW2_VerifyCertificateInList( pSessionData->ProfileData, pbSHA1 ) != NO_ERROR )
										{
											memcpy( pSessionData->ProfileData.pbTrustedRootCAList[pSessionData->ProfileData.dwNrOfTrustedRootCAInList], 
												pbSHA1, 
												cbSHA1 );

											pSessionData->ProfileData.dwNrOfTrustedRootCAInList++;

											dwReturnCode = SW2_WriteCertificates( 
												pSessionData->ProfileData.pwcCurrentProfileId,
												pSessionData->ProfileData );
										}

										SW2FreeMemory((PVOID*)&pbSHA1 );
									}

									CryptReleaseContext( hCSP, 0 );
								}
							}

							CertFreeCertificateContext( pCertContext );

							pCertContext = NULL;
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, 
								TEXT( "SW2_TRACE_LEVEL_ERROR::TLSServerTrustDlgProc::IDINSTALLCERTS::CertCreateCertificateContext(), FAILED: %x" ), GetLastError() );

							dwReturnCode = CERT_E_UNTRUSTEDROOT;
						}
						
						if( dwReturnCode != NO_ERROR )
							break;
					}

					memset( pwcTemp1, 0, sizeof( pwcTemp1 ) );
					memset( pwcTemp2, 0, sizeof( pwcTemp2 ) );

					if( dwReturnCode == NO_ERROR )
					{
						LoadString( g_hLanguage, IDS_ERROR_CERTIFICATES_SUCCESS, pwcTemp1, sizeof( pwcTemp1 ) );
						LoadString( g_hLanguage, IDS_ERROR_SW2_CERTIFICATE, pwcTemp2, sizeof( pwcTemp2 ) );

						MessageBox( hWnd, pwcTemp1, pwcTemp2, MB_OK );
					}
					else
					{
						LoadString( g_hLanguage, IDS_ERROR_CERTIFICATES_FAILED, pwcTemp1, sizeof( pwcTemp1 ) );
						LoadString( g_hLanguage, IDS_ERROR_SW2_ERROR, pwcTemp2, sizeof( pwcTemp2 ) );

						MessageBox( hWnd, pwcTemp1, pwcTemp2, MB_ICONERROR | MB_OK );
					}

					ConfigUpdateCertificateView( hWnd, pSessionData );

					return FALSE;

				break;

				case IDINSTALLCERT:

#ifdef _WIN32_WCE
					pSessionData = ( PSW2_SESSION_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pSessionData = ( PSW2_SESSION_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( ( hSelectedItem = TreeView_GetSelection( GetDlgItem( hWnd, IDC_CERT_TREE ) ) ) )
					{
						tvItem.mask = TVIF_PARAM;
						tvItem.hItem = hSelectedItem;

						if( TreeView_GetItem( GetDlgItem( hWnd, IDC_CERT_TREE ), &tvItem ) )
						{
#ifndef _WIN32_WCE
							//
							// Get temporary file name
							//
							if( GetTempPath( sizeof( pwcTempPath ), pwcTempPath ) > 0 )
							{
								if( GetTempFileName( pwcTempPath, 
														L"SW2",
														0,
														pwcTempFileName ) == 0 )
									dwReturnCode = GetLastError();
							}

							//
							// Write certificate information
							//
							if( dwReturnCode == NO_ERROR )
							{
								if( ( hFile = CreateFile(	pwcTempFileName,
															GENERIC_WRITE|GENERIC_READ,
															0,
															NULL,
															CREATE_ALWAYS,
															FILE_ATTRIBUTE_NORMAL,
															NULL ) ) )
								{
									if( !WriteFile( hFile,
												pSessionData->TLSSession.pbCertificate[( int ) tvItem.lParam],
												pSessionData->TLSSession.cbCertificate[( int ) tvItem.lParam],
												&dwNumberOfBytesWritten,
												NULL ) )
									{
										dwReturnCode = GetLastError();

										SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSServerTrustDlgProc::IDINSTALLCERT::WriteFile Failed (%ld)" ), dwReturnCode );
									}								

									CloseHandle( hFile );
								}
								else
								{
									dwReturnCode = GetLastError();
									SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSServerTrustDlgProc::IDINSTALLCERT::CreateFile Failed (%ld)" ), dwReturnCode );
								}
							}

							if( dwReturnCode == NO_ERROR )
							{
								//
								// Set Certificate Type
								// 0 = server
								// 1 = sub CA
								// 2 = root CA
								//
								if( ( int ) tvItem.lParam == 0 )
									iCertType = 0;
								else if( ( int ) tvItem.lParam == ( int ) ( pSessionData->TLSSession.dwCertCount - 1 ) )
									iCertType = 2;
								else
									iCertType = 1;

								swprintf_s( pwcParameters, 
											sizeof(pwcParameters)/sizeof(WCHAR), 
											TEXT( "certificate \"%s\" %ld %s" ),
											pSessionData->pwcCurrentProfileId,
											iCertType,
											pwcTempFileName );

								ZeroMemory( &ExecInfo, sizeof(ExecInfo) );

								ExecInfo.cbSize = sizeof( ExecInfo );
								ExecInfo.hwnd = hWnd;
								ExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
								ExecInfo.lpDirectory = NULL;
								if (EAPTYPE == EAP_TYPE_PEAP)
									ExecInfo.lpFile = L"sw2_peap_manager.exe";
								else
									ExecInfo.lpFile = L"sw2_ttls_manager.exe";
								ExecInfo.lpParameters = pwcParameters;
								ExecInfo.nShow = SW_SHOWNORMAL;

								if( ShellExecuteEx( &ExecInfo ) )
								{								
									WaitForSingleObject( ExecInfo.hProcess, INFINITE );
									CloseHandle( ExecInfo.hProcess );
								}
								else
								{
									dwReturnCode = GetLastError();

									SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSServerTrustDlgProc::IDINSTALLCERT:: creating process failed: %ld" ), dwReturnCode );
								}

								//
								// Read manager result from registry
								//
								if( dwReturnCode == NO_ERROR )
								{
									if( ( dwReturnCode = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
																SW2_MANAGER_LOCATION,
																0,
																KEY_READ,
																&hKey ) ) == ERROR_SUCCESS )
									{
										cbData = sizeof( dwReturnCode );

										if( ( dwReturnCode = SW2_RegGetValue( hKey, 
																	L"Error", 
																	&pbData, 
																	&cbData ) ) == NO_ERROR )
										{
											memcpy( &dwReturnCode, pbData, sizeof( dwReturnCode ) );

											SW2FreeMemory((PVOID*)&pbData );
										}

										RegCloseKey( hKey );
									}
								}
							}

							//
							// Re-read profile configuration to refresh certificate view
							//
							if (dwReturnCode == NO_ERROR)
							{
								dwReturnCode = SW2_ReadProfile(
									pSessionData->pwcCurrentProfileId, 
									NULL, 
									&(pSessionData->ProfileData));
							}

							SW2Trace(SW2_TRACE_LEVEL_DEBUG, TEXT("TLSServerTrustDlgProc::deleting file"));

							//
							// Delete file, if any
							//
							DeleteFile( pwcTempFileName );
#else
							if( ( pCertContext = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
																				pSessionData->TLSSession.pbCertificate[( int ) tvItem.lParam], 
																				pSessionData->TLSSession.cbCertificate[( int ) tvItem.lParam]) ) )
							{
								if( ( int ) tvItem.lParam == 0 )
								{
									hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM,
																X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
																( HCRYPTPROV  ) NULL, 
																CERT_SYSTEM_STORE_LOCAL_MACHINE,
																L"MY" );
								}
								else
								{
									hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM,
																X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
																( HCRYPTPROV  ) NULL, 
																CERT_SYSTEM_STORE_LOCAL_MACHINE,
																L"ROOT" );
								}

								if( hCertStore )
								{
									if( !CertAddCertificateContextToStore( hCertStore, 
																			pCertContext, 
																			CERT_STORE_ADD_REPLACE_EXISTING, 
																			NULL ) )
									{
										SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSServerTrustDlgProc:: IDINSTALLCERT::CertAddCertificateContextToStore(), FAILED: %x" ), GetLastError() );

										dwReturnCode = CERT_E_UNTRUSTEDROOT;
									}

									CertCloseStore( hCertStore, CERT_CLOSE_STORE_FORCE_FLAG );
								}
								else
								{
									SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSServerTrustDlgProc:: IDINSTALLCERT::CertOpenSystemStore(), FAILED: %x" ), GetLastError() );

									dwReturnCode = CERT_E_UNTRUSTEDROOT;
								}

								if( ( int ) tvItem.lParam == ( int ) ( pSessionData->TLSSession.dwCertCount - 1 ) )
								{
									//
									// Also add last certificate to our CA list
									//
									if ((dwReturnCode = SW2_CryptAcquireDefaultContext(&hCSP,
																						NULL))==NO_ERROR)
									{				
										//
										// Get HASH of certificate
										//
										if( ( dwReturnCode = TLSGetSHA1( hCSP, 
																	pSessionData->TLSSession.pbCertificate[( int ) tvItem.lParam], 
																	pSessionData->TLSSession.cbCertificate[( int ) tvItem.lParam], 
																	&pbSHA1, 
																	&cbSHA1 ) ) == NO_ERROR )
										{
											//
											// If not in list then add
											//
											if( SW2_VerifyCertificateInList( pSessionData->ProfileData, pbSHA1 ) != NO_ERROR )
											{
												SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSServerTrustDlgProc:: IDINSTALLCERT: pSessionData->ProfileData.dwNrOfTrustedRootCAInList: %ld" ), pSessionData->ProfileData.dwNrOfTrustedRootCAInList );

												memcpy( pSessionData->ProfileData.pbTrustedRootCAList[pSessionData->ProfileData.dwNrOfTrustedRootCAInList], 
														pbSHA1, 
														cbSHA1 );

												pSessionData->ProfileData.dwNrOfTrustedRootCAInList++;

												dwReturnCode = SW2_WriteCertificates( pSessionData->ProfileData.pwcCurrentProfileId,
																				pSessionData->ProfileData );
											}

											SW2FreeMemory((PVOID*)&pbSHA1);
										}
										else
										{
											SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSServerTrustDlgProc:: IDINSTALLCERT:: TLSGetMD5 FAILED: %ld" ), dwReturnCode );
										}

										CryptReleaseContext( hCSP, 0 );
									}
								}

								CertFreeCertificateContext( pCertContext );
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSServerTrustDlgProc:: IDINSTALLCERT::CertCreateCertificateContext(), FAILED: %x" ), GetLastError() );

								dwReturnCode = CERT_E_UNTRUSTEDROOT;
							}
#endif // _WIN32_WCE
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSServerTrustDlgProc::ERROR::TreeView_GetItem() Failed: %d" ), GetLastError() );

							dwReturnCode = CERT_E_UNTRUSTEDROOT;
						}
					}
					else
					{

						SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSServerTrustDlgProc::ERROR::TreeView_GetSelection() Failed: %d" ), GetLastError() );

						dwReturnCode = CERT_E_UNTRUSTEDROOT;
					}

					memset( pwcTemp1, 0, sizeof( pwcTemp1 ) );
					memset( pwcTemp2, 0, sizeof( pwcTemp2 ) );

					if( dwReturnCode == NO_ERROR )
					{
						LoadString( g_hLanguage, IDS_ERROR_CERTIFICATE_SUCCESS, pwcTemp1, sizeof( pwcTemp1 ) );
						LoadString( g_hLanguage, IDS_ERROR_SW2_CERTIFICATE, pwcTemp2, sizeof( pwcTemp2 ) );

						MessageBox( hWnd, pwcTemp1, pwcTemp2, MB_OK );
					}
					else
					{
						LoadString( g_hLanguage, IDS_ERROR_CERTIFICATE_FAILED, pwcTemp1, sizeof( pwcTemp1 ) );
						LoadString( g_hLanguage, IDS_ERROR_SW2_ERROR, pwcTemp2, sizeof( pwcTemp2 ) );

						MessageBox( hWnd, pwcTemp1, pwcTemp2, MB_ICONERROR | MB_OK );
					}

					ConfigUpdateCertificateView( hWnd, pSessionData );

					return FALSE;

				break;

				case IDVIEWCERT:

#ifdef _WIN32_WCE
					pSessionData = ( PSW2_SESSION_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pSessionData = ( PSW2_SESSION_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( ( hSelectedItem = TreeView_GetSelection( GetDlgItem( hWnd, IDC_CERT_TREE ) ) ) )
					{
						tvItem.mask = TVIF_PARAM;
						tvItem.hItem = hSelectedItem;

						if( TreeView_GetItem( GetDlgItem( hWnd, IDC_CERT_TREE ), &tvItem ) )
						{
							memset( pwcTemp, 0, sizeof( pwcTemp ) );
#ifdef _WIN32_WCE
							wcscpy( pwcTemp, L"\\Temp" );
#else
							if( GetEnvironmentVariable( L"TMP", pwcTemp, ( sizeof( pwcTemp ) / sizeof( WCHAR ) ) ) == 0 )
							{
								if( GetEnvironmentVariable( L"TEMP", pwcTemp, ( sizeof( pwcTemp ) / sizeof( WCHAR ) ) ) == 0 )
									wcscpy( pwcTemp, L"c:\\" );
							}
#endif

							wcscat( pwcTemp, L"\\aa.cer" );

							WideCharToMultiByte( CP_ACP, 0, pwcTemp, -1, pcTemp, sizeof( pcTemp ), NULL, NULL );

							if( ( pFile = fopen( pcTemp, "w+b" ) ) )
							{
								fwrite( pSessionData->TLSSession.pbCertificate[( int ) tvItem.lParam], sizeof( BYTE ), pSessionData->TLSSession.cbCertificate[( int ) tvItem.lParam], pFile );

								fflush( pFile );

								fclose( pFile );

								memset( &ExecInfo, 0, sizeof( ExecInfo ) );

								ExecInfo.cbSize = sizeof( ExecInfo );
								ExecInfo.fMask = SEE_MASK_FLAG_NO_UI;
								ExecInfo.hwnd = hWnd;
								ExecInfo.lpVerb = L"open";
								ExecInfo.lpFile = pwcTemp;
								ExecInfo.nShow = SW_SHOWNORMAL;

								ShellExecuteEx( &ExecInfo );
//								ShellExecute( hWnd, L"open", pwcTemp, NULL, NULL, SW_SHOWNORMAL );
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSServerTrustDlgProc::ERROR:could not create certificate temp file: c:\\servercert.cer" ) );
							}
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSServerTrustDlgProc::ERROR::TreeView_GetItem() Failed: %d" ), GetLastError() );
						}
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSServerTrustDlgProc::ERROR::TreeView_GetSelection() Failed: %d" ), GetLastError() );
					}

					return FALSE;

				break;

#ifdef _WIN32_WCE
				case IDOK:

					SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSServerTrustDlgProc:: IDOK" ) );

					return TRUE;

				break;

				case IDOK2:

					SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSServerTrustDlgProc:: IDOK2" ) );

#else // _WIN32_WCE

				case IDOK:

#endif // _WIN32_WCE

#ifdef _WIN32_WCE
					pSessionData = ( PSW2_SESSION_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pSessionData = ( PSW2_SESSION_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE
/*
					if( SendMessage( GetDlgItem( hWnd, IDC_TEMP_CHECK ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pSessionData->bUITempCertTrust = TRUE;
					else
						pSessionData->bUITempCertTrust = FALSE;
*/
					EndDialog( hWnd, TRUE );

					return TRUE;

				break;

				case IDCANCEL:

					EndDialog( hWnd, FALSE );

					return TRUE;

				break;

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
// Name: ConfigUpdateCertificateView
// Description: Helper Function for Certificate Dialog to add
//				Certificates to the Certificate List
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
ConfigUpdateCertificateView( IN HWND hWnd, IN PSW2_SESSION_DATA pSessionData )
{
	WCHAR						pwcItemText[256];
	WCHAR						pwcSubjectName[TLS_MAX_CERT_NAME];
	DWORD						cwcSubjectName;
	PCCERT_CONTEXT				pCertContext;
    TVINSERTSTRUCT 				tvInsertStruct;
	HTREEITEM					hPreviousItem;
	HTREEITEM					hTreeRoot;
	BOOL						bTrustOK;
	int							i;
	DWORD						dwReturnCode;
	
	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::ConfigUpdateCertificateView()" ) );

	//
	// Add all the certificates in the list to the list box
	// starting with the root CA. Check every certificate to see if we trust it or
	// not
	//
	hPreviousItem = NULL;

	if( !TreeView_DeleteItem( GetDlgItem( hWnd, IDC_CERT_TREE ), TVI_ROOT ) )
		return ERROR_NOT_ENOUGH_MEMORY;

	//
	// This will be used to check if we can enable the OK button
	//
	bTrustOK = TRUE;

	for( i=pSessionData->TLSSession.dwCertCount-1; i > -1; i-- )
	{
		//
		// Just to make sure
		//
		if( pSessionData->TLSSession.pbCertificate[i] && pSessionData->TLSSession.cbCertificate[i] > 0 )
		{
			//
			// Convert raw certificate into x509 cert context
			//
			if( ( pCertContext = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
																pSessionData->TLSSession.pbCertificate[i], 
																pSessionData->TLSSession.cbCertificate[i] ) ) )
			{
				//
				// Get SubjectName
				//
				memset( pwcSubjectName, 0, sizeof( pwcSubjectName ) );

				if( ( cwcSubjectName = CertGetNameString( pCertContext,
														CERT_NAME_SIMPLE_DISPLAY_TYPE,
														0,
														NULL,
														pwcSubjectName,
														TLS_MAX_CERT_NAME ) ) > 0 )
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::ConfigUpdateCertificateView(), certificate name: %s" ), pwcSubjectName );

					tvInsertStruct.hParent = hPreviousItem;
					tvInsertStruct.item.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_PARAM;

					memset( pwcItemText, 0, sizeof( pwcItemText ) );

					tvInsertStruct.item.pszText = pwcSubjectName;

					tvInsertStruct.item.iImage = 0;
					tvInsertStruct.item.iSelectedImage = 0;

					//
					// Verify certificate
					//
					if( i == 0 )
					{
						if( dwReturnCode == NO_ERROR )
						{
							//
							// If required verify MS Extensions
							//
							if( pSessionData->bVerifyMSExtension )
								dwReturnCode = SW2_CertCheckEnhkeyUsage( pCertContext );
						}

						if( ( dwReturnCode = SW2_VerifyCertificateChain( pSessionData, pCertContext ) ) == NO_ERROR )
						{
							//
							// If required verify if certificate is installed locally
							//
							if (pSessionData->bServerCertificateLocal)
							{
								dwReturnCode = SW2_VerifyCertificateInStore(pCertContext);
							}
						}

						if( dwReturnCode != NO_ERROR )
						{
							bTrustOK = FALSE;

							tvInsertStruct.item.iImage = 1;
							tvInsertStruct.item.iSelectedImage = 1;
						}
					}
					else if( SW2_VerifyCertificateChain( pSessionData, pCertContext ) != NO_ERROR )
					{
						bTrustOK = FALSE;

						tvInsertStruct.item.iImage = 1;
						tvInsertStruct.item.iSelectedImage = 1;
					}

					tvInsertStruct.item.lParam = i;

					hPreviousItem = TreeView_InsertItem( GetDlgItem( hWnd, IDC_CERT_TREE ), &tvInsertStruct );
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigUpdateCertificateView(), CertNameToStr(pwcSubjectName), FAILED: %x" ), GetLastError() );

					dwReturnCode = CERT_E_UNTRUSTEDROOT;
				}

				CertFreeCertificateContext( pCertContext );
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigUpdateCertificateView(), CertCreateCertificateContext(), FAILED: %x" ), GetLastError() );

				dwReturnCode = ERROR_INTERNAL_ERROR;
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigUpdateCertificateView(), pbCertificate[%d] == NULL or 0" ), i );

			dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
		}
	} // for

	if( bTrustOK )
#ifdef _WIN32_WCE
		EnableWindow( GetDlgItem( hWnd, IDOK2 ), TRUE );
#else
		EnableWindow( GetDlgItem( hWnd, IDOK ), TRUE );
#endif //  _WIN32_WCE

	hTreeRoot = TreeView_GetRoot( GetDlgItem( hWnd, IDC_CERT_TREE ) );
	TreeView_Expand( GetDlgItem( hWnd, IDC_CERT_TREE ), hTreeRoot, TVM_EXPAND );

	while( hTreeRoot = TreeView_GetNextItem( GetDlgItem( hWnd, IDC_CERT_TREE ),
											hTreeRoot,
											TVGN_CHILD ) )
	{
		TreeView_Expand( GetDlgItem( hWnd, IDC_CERT_TREE ), hTreeRoot, TVM_EXPAND );
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::ConfigUpdateCertificateView(), returning %ld" ), dwReturnCode );

	return dwReturnCode;
}
