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

//
// Handle identity dialog
//
INT_PTR CALLBACK SW2IdentityDlgProc(IN  HWND    hWnd,
								   IN  UINT    unMsg,
								   IN  WPARAM  wParam,
								   IN  LPARAM  lParam)
{
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

			SetFocus( GetDlgItem( hWnd, IDC_IDENTITY_FIELD ) );

			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pUserData );

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDOK:

					pUserData = ( PSW2_USER_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );

					//
					// retrieve the user identity
					//
					if (GetWindowTextLength(GetDlgItem(hWnd, IDC_IDENTITY_FIELD)) > 0)
					{
						GetWindowText(GetDlgItem(hWnd, IDC_IDENTITY_FIELD), 
								pUserData->pwcIdentity, sizeof(pUserData->pwcIdentity));
						
						EndDialog(hWnd, TRUE);
					}

					SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pUserData );

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
	PSW2_USER_DATA	pUserData;

    switch( unMsg )
    {
		case WM_INITDIALOG:
        
			pUserData = ( PSW2_USER_DATA ) lParam;

			//
			// Set the challenge
			//
			if( pUserData->pwcChallenge &&
				wcslen( pUserData->pwcChallenge ) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_CHALLENGE_CAPTION ), pUserData->pwcChallenge );

			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pUserData );

			SetFocus( GetDlgItem( hWnd, IDC_RESPONSE_FIELD ) );

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDOK:

					pUserData = ( PSW2_USER_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );

					//
					// Retrieve user response
					//
					if (GetWindowTextLength(GetDlgItem(hWnd, IDC_RESPONSE_FIELD)) > 0)
					{
						GetWindowText(GetDlgItem(hWnd, IDC_RESPONSE_FIELD), 
								pUserData->pwcResponse, sizeof(pUserData->pwcResponse));
						
						EndDialog(hWnd, TRUE);
					}

					SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pUserData );

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
// Name: CredentialsDlgProc
// Description: Dialog Function for the Credentials Dialog
// Author: Tom Rixom
// Created: 26 May 2008
//
INT_PTR
CALLBACK
SW2CredentialsDlgProc(	IN  HWND    hWnd,
					IN  UINT    unMsg,
					IN  WPARAM  wParam,
					IN  LPARAM  lParam )
{
   PSW2_USER_DATA	pUserData;

    switch( unMsg )
    {

		case WM_INITDIALOG:

			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "CredentialsDlgProc:: WM_INITDIALOG" ) );

			pUserData = ( PSW2_USER_DATA ) lParam;

			SetFocus( GetDlgItem( hWnd, IDC_CRED_IDENTITY) );

			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "CredentialsDlgProc:: WM_INITDIALOG:: returning" ) );

			return FALSE;

		break;

		case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDOK:

					SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "CredentialsDlgProc::IDOK" ) );

					pUserData = ( PSW2_USER_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );


					//
					// Identity
					//
					if( GetWindowTextLength( GetDlgItem( hWnd, IDC_CRED_IDENTITY ) ) > 0 )
					{
						memset(pUserData->pwcIdentity, 0, sizeof(pUserData->pwcIdentity));

						GetWindowText( GetDlgItem( hWnd, IDC_CRED_IDENTITY), pUserData->pwcIdentity, sizeof(pUserData->pwcIdentity));

						//
						// Password
						//
						if( GetWindowTextLength( GetDlgItem( hWnd, IDC_CRED_PASSWORD ) ) > 0 )
						{
							memset( pUserData->pwcPassword, 0, sizeof(pUserData->pwcPassword) );

							GetWindowText( GetDlgItem( hWnd, IDC_CRED_PASSWORD ), pUserData->pwcPassword, sizeof(pUserData->pwcPassword) );
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
