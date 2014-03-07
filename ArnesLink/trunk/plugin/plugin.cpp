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
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Setupapi.lib")
#ifndef _WIN32_WCE
#pragma comment(lib, "Wlanapi.lib")
#endif

//
// Global information
//
HINSTANCE	g_hResource = NULL;
HINSTANCE	g_hLanguage = NULL;
DWORD		g_dwMajorVersion = 0;
DWORD		g_dwMinorVersion = 0;
#ifndef _WIN32_WCE
DWORD		g_dwSW2TraceId = INVALID_TRACEID;
#endif // _WIN32_WCE
HANDLE		g_localHeap = NULL;

BYTE		EAPTYPE = NULL;

PWCHAR		SW2_METHOD_PROFILE_LOCATION	= L"SOFTWARE\\SecureW2\\Methods\\Default\\Profiles";

//
// External interface context pointer
//
PSW2_RES_CONTEXT		 g_ResContext = NULL;

DWORD
SW2InstallCertificate( HINF hInf, WCHAR *pwcCertificate, DWORD iCount )
{
	HANDLE			hFile;
	PCCERT_CONTEXT	pCertContext;
	HCERTSTORE		hCertStore;
	WCHAR			pwcLocation[1024];
	DWORD			cwcLocation;
	BYTE			pbBuffer[8096];
	DWORD			cbBuffer;
	DWORD			dwRet, dwErr;

	dwRet = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2InstallCertificate::%s", pwcCertificate );

	if (SetupGetLineText( NULL,
							hInf,
							L"Certificates",
							pwcCertificate,
							pwcLocation,
							sizeof( pwcLocation ),
							&cwcLocation ) )
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2InstallCertificate::found [Certificates]");

		if ((hFile = CreateFile( pwcLocation,
								GENERIC_READ,
								0,
								NULL,
								OPEN_EXISTING,
								FILE_ATTRIBUTE_NORMAL,
								NULL ) ) != INVALID_HANDLE_VALUE )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2InstallCertificate::CreateFile succesfull");

			cbBuffer = 0;

			memset( pbBuffer, 0, sizeof( pbBuffer ) );

			if (ReadFile( hFile,
							pbBuffer,
							sizeof( pbBuffer ),
							&cbBuffer,
							NULL ) )
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2InstallCertificate::ReadFile succesfull: %ld", cbBuffer);

				if ((pCertContext = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
																pbBuffer, 
																cbBuffer) ) )
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2InstallCertificate::CertCreateCertificateContext succesfull");

					//
					// If this is the first certificate in line (server certificate) then 
					// put it in the MY store, else in the ROOT (CA certificate
					//
					if (iCount == 0 )
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2InstallCertificate::server certificate, installing in MY store");

						hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM,
													X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
													( HCRYPTPROV  ) NULL, 
													CERT_SYSTEM_STORE_LOCAL_MACHINE,
													L"MY" );
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2InstallCertificate::(Sub)CA certificate, installing in ROOT store");

						hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM,
													X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
													( HCRYPTPROV  ) NULL, 
													CERT_SYSTEM_STORE_LOCAL_MACHINE,
													L"ROOT" );
					}

					if (hCertStore )
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2InstallCertificate::CertAddCertificateContextToStore succesfull");

						if (!CertAddCertificateContextToStore( hCertStore, 
																pCertContext, 
																CERT_STORE_ADD_NEW, 
																NULL ) )
						{
							dwErr = GetLastError();

							SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2InstallCertificate::CertAddCertificateContextToStore FAILED (%ld)", dwErr );

							if (dwErr ==  CRYPT_E_EXISTS )
							{
								//
								// Certificate already exists
								//
							}
							else
								dwRet = ERROR_CANTREAD;
						}

						CertCloseStore( hCertStore, CERT_CLOSE_STORE_FORCE_FLAG );
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2InstallCertificate::CertCreateCertificateContext FAILED (%ld)", GetLastError() );

						dwRet = ERROR_CANTREAD;
					}

					CertFreeCertificateContext( pCertContext );

					pCertContext = NULL;
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2InstallCertificate::CertCreateCertificateContext FAILED (%ld)", GetLastError() );

					dwRet = ERROR_CANTREAD;
				}
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2InstallCertificate::ReadFile FAILED (%ld)", GetLastError() );

				dwRet = ERROR_CANTREAD;
			}

			CloseHandle( hFile );
		}
		else
		{
			dwRet = ERROR_CANTOPEN;
		}
	}
	else
	{
		//
		// If this was a Certificate.0 operation this may fail when
		// trying to open as it is not necesarry to install the server certificate
		//
		if (iCount > 0 )
			dwRet = ERROR_NO_DATA;
	}

	return dwRet;
}

INT_PTR
CALLBACK
InstallDlgProc(	IN  HWND    hWnd,
					IN  UINT    unMsg,
					IN  WPARAM  wParam,
					IN  LPARAM  lParam )
{
   PSW2_PROFILE_DATA	pProfileData;
   WCHAR				pwcTemp[UNLEN];
   WCHAR				pwcPassword2[PWLEN];

    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
			pProfileData = ( PSW2_PROFILE_DATA ) lParam;

			SetWindowText( GetDlgItem( hWnd, IDC_INSTALL_PROFILE ), pProfileData->pwcCurrentProfileId );

			// load language specific info
			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_PROFILE_DESC, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_PROFILE_DESCRIPTION), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_PROFILE, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_INSTALL_PROFILE_LABEL), pwcTemp);			

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_USERNAME, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_INSTALL_USERNAME_LABEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_PASSWORD, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_INSTALL_PASSWORD_LABEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_REPASSWORD, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_INSTALL_PASSWORD_LABEL2), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_DOMAIN, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDC_INSTALL_DOMAIN_LABEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_OK, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDOK), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_LABEL_CANCEL, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(GetDlgItem(hWnd, IDCANCEL), pwcTemp);

			memset(pwcTemp, 0, sizeof(pwcTemp));
			LoadString( g_hLanguage, IDS_WINDOW_CONFIGURATION, pwcTemp, sizeof( pwcTemp ) );
			SetWindowText(hWnd, pwcTemp);

			// 
			//
			// CUSTOM DIALOG
			// Contributed by Wyman Miles (Cornell University)
			//
			if ( wcslen( pProfileData->pwcAltUsernameStr ) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_INSTALL_USERNAME_LABEL ), pProfileData->pwcAltUsernameStr );

			if ( wcslen ( pProfileData->pwcAltPasswordStr ) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_INSTALL_PASSWORD_LABEL ), pProfileData->pwcAltPasswordStr );

			if ( wcslen ( pProfileData->pwcAltRePasswordStr ) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_INSTALL_PASSWORD_LABEL2 ), pProfileData->pwcAltRePasswordStr );

			if ( wcslen ( pProfileData->pwcAltDomainStr ) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_INSTALL_DOMAIN_LABEL ), pProfileData->pwcAltDomainStr );

			if ( wcslen ( pProfileData->pwcAltCredsTitle ) > 0 ) 
				SetWindowText( hWnd, pProfileData->pwcAltCredsTitle );

			if ( wcslen( pProfileData->pwcAltProfileStr ) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_INSTALL_PROFILE_LABEL), pProfileData->pwcAltProfileStr );

			if (wcslen( pProfileData->pwcProfileDescription ) > 0 )
			{
				SetWindowText( GetDlgItem( hWnd, IDC_PROFILE_DESCRIPTION ), pProfileData->pwcProfileDescription );
			}

			SetWindowText( GetDlgItem( hWnd, IDC_INSTALL_DOMAIN ), pProfileData->pwcUserDomain );

			SetFocus( GetDlgItem( hWnd, IDC_INSTALL_USERNAME ) );

			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pProfileData );

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDC_INSTALL_USERNAME:

					if (HIWORD( wParam ) == EN_CHANGE )
					{
						if (GetWindowText( GetDlgItem( hWnd, IDC_INSTALL_USERNAME ), pwcTemp, UNLEN ) > 0 )
						{
							if (wcschr( pwcTemp, '@' ) )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_INSTALL_DOMAIN_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_INSTALL_DOMAIN ), FALSE );
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_INSTALL_DOMAIN_LABEL ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_INSTALL_DOMAIN ), TRUE );
							}
						}
					}

					return FALSE;

				break;

				case IDOK:

					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );


					//
					//
					// Both the username and password must be filled in, domain is optional
					//
					//
					// Username
					//
					if (GetWindowTextLength( GetDlgItem( hWnd, IDC_INSTALL_USERNAME ) ) > 0 )
					{
						GetWindowText( GetDlgItem( hWnd, IDC_INSTALL_USERNAME ), pProfileData->pwcUserName, UNLEN );

						//
						// Password
						//
						if (GetWindowTextLength( GetDlgItem( hWnd, IDC_INSTALL_PASSWORD2 ) ) > 0 )
						{
							GetWindowText( GetDlgItem( hWnd, IDC_INSTALL_PASSWORD ), pProfileData->pwcUserPassword, PWLEN );

							if (GetWindowTextLength( GetDlgItem( hWnd, IDC_INSTALL_PASSWORD2 ) ) > 0 )
							{
								GetWindowText( GetDlgItem( hWnd, IDC_INSTALL_PASSWORD2 ), pwcPassword2, PWLEN );							

								if (wcscmp( pProfileData->pwcUserPassword, pwcPassword2 ) == 0 )
								{
									//
									// Domain
									//
									GetWindowText( GetDlgItem( hWnd, IDC_INSTALL_DOMAIN ), pProfileData->pwcUserDomain, UNLEN );

									EndDialog( hWnd, TRUE );
								}
								else
								{
									memset(pwcTemp, 0, sizeof(pwcTemp));
									LoadString( g_hLanguage, IDS_ERROR_PASSWORD_MISMATCH, pwcTemp, sizeof( pwcTemp ) );

									MessageBox( hWnd, pwcTemp, L"SecureW2", MB_OK | MB_ICONWARNING );
								}
							}
						}
						else
						{
							memset(pwcTemp, 0, sizeof(pwcTemp));
							LoadString( g_hLanguage, IDS_ERROR_REENTER_PASSWORD, pwcTemp, sizeof( pwcTemp ) );

							MessageBox( hWnd, pwcTemp, L"SecureW2", MB_OK | MB_ICONWARNING );
						}
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

DWORD
SW2_ReadProfileConfig( HWND hWnd, HINF hInf, WCHAR *pwcProfile )
{
	PBYTE				pbData;
	WCHAR				pwcBuffer[1024];
	WCHAR				pwcTemp[1024];	
	CHAR				pcBuffer[1024];
	DWORD				cwcBuffer = 0;
	SW2_PROFILE_DATA	SW2ProfileData;
	int					i = 0;
	DWORD				dwRet;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadProfileConfig: %s", pwcProfile );

	dwRet = NO_ERROR;

	//
	// Profile Name
	//
	SW2_InitDefaultProfile( &SW2ProfileData, NULL );

	cwcBuffer = sizeof( SW2ProfileData.pwcCurrentProfileId );

	if (SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"Name",
							SW2ProfileData.pwcCurrentProfileId,
							sizeof( SW2ProfileData.pwcCurrentProfileId ),
							&cwcBuffer ) )
	{
		memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

		cwcBuffer = sizeof( SW2ProfileData.pwcProfileDescription );

		//
		// Description
		//
		SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"Description",
							SW2ProfileData.pwcProfileDescription,
							sizeof( SW2ProfileData.pwcProfileDescription ),
							&cwcBuffer );

		//
		// Connection configuration
		//

		cwcBuffer = sizeof( pwcBuffer );

		//
		// UseAlternateIdentity
		//
		if (SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"UseAlternateOuterIdentity",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&cwcBuffer ) )
		{
			_wcsupr_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR) );

			if (wcscmp( pwcBuffer, L"TRUE" ) == 0 )
				SW2ProfileData.bUseAlternateIdentity = TRUE;
			else
				SW2ProfileData.bUseAlternateIdentity = FALSE;
		}

		memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

		cwcBuffer = sizeof( pwcBuffer );

		//
		// UseAnonymousIdentity (old configuration)
		//
		if (SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"UseAnonymousOuterIdentity",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&cwcBuffer ) )
		{
			_wcsupr_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR) );

			if (wcscmp( pwcBuffer, L"TRUE" ) == 0 )
				SW2ProfileData.bUseAnonymousIdentity = TRUE;
			else
				SW2ProfileData.bUseAnonymousIdentity = FALSE;
		}

		cwcBuffer = sizeof( pwcBuffer );

		//
		// UseEmptyIdentity 
		//
		if (SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"UseEmptyOuterIdentity",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&cwcBuffer ) )
		{
			_wcsupr_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR) );

			if (wcscmp( pwcBuffer, L"TRUE" ) == 0 )
				SW2ProfileData.bUseEmptyIdentity = TRUE;
			else
				SW2ProfileData.bUseEmptyIdentity = FALSE;
		}

		cwcBuffer = sizeof( SW2ProfileData.pwcAlternateIdentity );

		//
		// AlternateOuterIdentity  
		//
		if (!SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"AlternateOuterIdentity",
							SW2ProfileData.pwcAlternateIdentity,
							sizeof( SW2ProfileData.pwcAlternateIdentity ),
							&cwcBuffer ) )
			memset( SW2ProfileData.pwcAlternateIdentity, 0, sizeof( SW2ProfileData.pwcAlternateIdentity ) );

		memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

		cwcBuffer = sizeof( pwcBuffer );

		//
		// EnableSessionResumption (old configuration)
		//
		if (SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"EnableSessionResumption",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&cwcBuffer ) )
		{
			_wcsupr_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR) );

			if (wcscmp( pwcBuffer, L"TRUE" ) == 0 )
				SW2ProfileData.bUseSessionResumption = TRUE;
			else
				SW2ProfileData.bUseSessionResumption = FALSE;
		}

		//
		// EnableSessionResumption 
		//
		if (SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"UseSessionResumption",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&cwcBuffer ) )
		{
			_wcsupr_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR) );

			if (wcscmp( pwcBuffer, L"TRUE" ) == 0 )
				SW2ProfileData.bUseSessionResumption = TRUE;
			else
				SW2ProfileData.bUseSessionResumption = FALSE;
		}

		memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

		cwcBuffer = sizeof( pwcBuffer );

		//
		// VerifyServerCertificate
		//
		if (SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"VerifyServerCertificate",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&cwcBuffer ) )
		{
			_wcsupr_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR) );

			if (wcscmp( pwcBuffer, L"TRUE" ) == 0 )
				SW2ProfileData.bVerifyServerCertificate = TRUE;
			else
				SW2ProfileData.bVerifyServerCertificate = FALSE;
		}

		SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadProfileConfig::reading certificates");

		SW2ProfileData.dwNrOfTrustedRootCAInList = 0;

		for( i=0; i < SW2_MAX_CA; i++ )
		{
			memset( pwcBuffer, 0, sizeof( pwcBuffer ) );
			cwcBuffer = sizeof( pwcBuffer );

			memset(pwcTemp, 0, sizeof(pwcTemp));

			swprintf_s( pwcTemp, sizeof(pwcTemp)/sizeof(WCHAR), L"TrustedRootCA.%d", i );

			//
			// TrustedRootAuthorities
			//
			if (SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								pwcTemp,
								pwcBuffer,
								sizeof( pwcBuffer ),
								&cwcBuffer ) )
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadProfileConfig::found certificate: %s", pwcBuffer);

				//
				// Is a hex representation of a 20 byte SHA1 has of the CA certificate
				//
				if ((WideCharToMultiByte( CP_ACP, 0, pwcBuffer, -1, pcBuffer, sizeof( pcBuffer ), NULL, NULL ) ) > 0 )
				{
					if (SW2_HexToByte( ( PCHAR )pcBuffer, &cwcBuffer, &pbData)==NO_ERROR)
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadProfileConfig::converted hex certificate fingerprint to byte");

						memcpy( SW2ProfileData.pbTrustedRootCAList[i], pbData, sizeof( SW2ProfileData.pbTrustedRootCAList[i] ) );

						SW2ProfileData.dwNrOfTrustedRootCAInList++;

						SW2FreeMemory((PVOID*)&pbData);
					}
				}
			}
		}

		SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadProfileConfig::found %ld CA certificates", SW2ProfileData.dwNrOfTrustedRootCAInList );

		cwcBuffer = sizeof( SW2ProfileData.pwcServerName );

		//
		// ServerName 
		//
		if (SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"ServerName",
							SW2ProfileData.pwcServerName,
							sizeof( SW2ProfileData.pwcServerName ),
							&cwcBuffer ) )
		{
			SW2ProfileData.bVerifyServerName = TRUE;
		}
		else
			memset( SW2ProfileData.pwcServerName, 0, sizeof( SW2ProfileData.pwcServerName ) );

		cwcBuffer = sizeof( SW2ProfileData.pwcInnerAuth );

		//
		// AuthenticationMethod  
		//
		if (!SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"AuthenticationMethod",
							SW2ProfileData.pwcInnerAuth,
							sizeof( SW2ProfileData.pwcInnerAuth ),
							&cwcBuffer ) )
			wcscpy_s( SW2ProfileData.pwcInnerAuth, sizeof( SW2ProfileData.pwcInnerAuth )/sizeof( WCHAR ), L"PAP" );

		memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

		cwcBuffer = sizeof( pwcBuffer );

		//
		// EAPType
		//
		if (SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"EAPType",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&cwcBuffer ) )
		{
			SW2ProfileData.dwCurrentInnerEapMethod = _wtol( pwcBuffer );
		}
		else
			SW2ProfileData.dwCurrentInnerEapMethod = 0;


		//
		// User account
		//

		memset( pwcBuffer, 0, sizeof( pwcBuffer ) );
		cwcBuffer = sizeof( pwcBuffer );

		//
		// CUSTOM DIALOG
		// Contributed by Wyman Miles (Cornell University)
		//
		// Password dialog tweaks && password caching
		//

		// can the user cache their creds?

		if (SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"AllowCachePW",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&cwcBuffer ) )
		{
			_wcsupr_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR) );

			if (wcscmp( pwcBuffer, L"TRUE" ) == 0 )
				SW2ProfileData.bAllowCachePW = TRUE;
			else
				SW2ProfileData.bAllowCachePW = FALSE;
		}
		
		memset( pwcBuffer, 0, sizeof( pwcBuffer ) );
		cwcBuffer = sizeof( pwcBuffer );

		// custom "Username:" prompt
		
		SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"AltUsernameString",
							SW2ProfileData.pwcAltUsernameStr,
							sizeof( SW2ProfileData.pwcAltUsernameStr ),
							&cwcBuffer );

		// custom "Password:" prompt

		SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"AltPasswordStr",
							SW2ProfileData.pwcAltPasswordStr,
							sizeof( SW2ProfileData.pwcAltPasswordStr ),
							&cwcBuffer );

		SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"AltRePasswordStr",
							SW2ProfileData.pwcAltRePasswordStr,
							sizeof( SW2ProfileData.pwcAltRePasswordStr ),
							&cwcBuffer );

		// custom "Domain:" prompt

		SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"AltDomainStr",
							SW2ProfileData.pwcAltDomainStr,
							sizeof( SW2ProfileData.pwcAltDomainStr ),
							&cwcBuffer );

		SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadProfileConfig::AltDomainStr: %s", SW2ProfileData.pwcAltDomainStr );

		// custom title bar on the creds dialog

		SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"AltCredsTitle",
							SW2ProfileData.pwcAltCredsTitle,
							sizeof ( SW2ProfileData.pwcAltCredsTitle ),
							&cwcBuffer );

		SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadProfileConfig::AltCredsTitle: %s", SW2ProfileData.pwcAltCredsTitle );

		SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"AltProfileStr",
							SW2ProfileData.pwcAltProfileStr,
							sizeof ( SW2ProfileData.pwcAltProfileStr ),
							&cwcBuffer );

		SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadProfileConfig::AltProfileStr: %s", SW2ProfileData.pwcAltProfileStr );

		//
		// PromptUserForCredentials (previous configuration)
		//
		if (SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"PromptUserForCredentials",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&cwcBuffer ) )
		{
			_wcsupr_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR) );

			if (wcscmp( pwcBuffer, L"TRUE" ) == 0 )
				SW2ProfileData.bPromptUser = TRUE;
			else
				SW2ProfileData.bPromptUser = FALSE;
		}

		//
		// PromptUser
		//
		if (SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"PromptUser",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&cwcBuffer ) )
		{
			_wcsupr_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR) );

			if (wcscmp( pwcBuffer, L"TRUE" ) == 0 )
				SW2ProfileData.bPromptUser = TRUE;
			else
				SW2ProfileData.bPromptUser = FALSE;
		}

		cwcBuffer = sizeof( SW2ProfileData.pwcUserName );

		//
		// UserName 
		//
		if (!SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"UserName",
							SW2ProfileData.pwcUserName,
							sizeof( SW2ProfileData.pwcUserName ),
							&cwcBuffer ) )
			memset( SW2ProfileData.pwcUserName, 0, sizeof( SW2ProfileData.pwcUserName ) );

		cwcBuffer = sizeof( SW2ProfileData.pwcUserDomain );

		//
		// UserDomain 
		//
		if (!SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"UserDomain",
							SW2ProfileData.pwcUserDomain,
							sizeof( SW2ProfileData.pwcUserDomain ),
							&cwcBuffer ) )
			memset( SW2ProfileData.pwcUserDomain, 0, sizeof( SW2ProfileData.pwcUserDomain ) );

		SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadProfileConfig::pwcUserName: %s", SW2ProfileData.pwcUserName );

		if (wcscmp( SW2ProfileData.pwcUserName, L"PROMPTUSER" ) == 0 )
		{
			if (!DialogBoxParam( g_hResource,
								MAKEINTRESOURCE( IDD_INSTALL_DLG ),
								hWnd,
								InstallDlgProc,
								( LPARAM ) &SW2ProfileData ) )
			{
				dwRet = ERROR_CANCELLED;
			}

			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadProfileConfig::DialogBoxParam returned %ld", dwRet );

		}
		else
		{
			cwcBuffer = sizeof( SW2ProfileData.pwcUserPassword );

			//
			// UserPassword 
			//
			if (!SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"UserPassword",
								SW2ProfileData.pwcUserPassword,
								sizeof( SW2ProfileData.pwcUserPassword ),
								&cwcBuffer ) )
				memset( SW2ProfileData.pwcUserPassword, 0, sizeof( SW2ProfileData.pwcUserPassword ) );
		}

		if (dwRet == NO_ERROR )
		{
			cwcBuffer = sizeof( pwcBuffer );

			//
			// UseUserCredentialsForComputer  
			//
			if (SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"UseUserCredentialsForComputer",
								pwcBuffer,
								sizeof( pwcBuffer ),
								&cwcBuffer ) )
			{
			_wcsupr_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR) );

			if (wcscmp( pwcBuffer, L"TRUE" ) == 0 )
					SW2ProfileData.bUseUserCredentialsForComputer = TRUE;
				else
					SW2ProfileData.bUseUserCredentialsForComputer = FALSE;
			}

			memset( pwcBuffer, 0, sizeof( pwcBuffer ) );
			cwcBuffer = sizeof( pwcBuffer );

			//
			// UseAlternateComputerCredentials
			//
			if (SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"UseAlternateComputerCredentials",
								pwcBuffer,
								sizeof( pwcBuffer ),
								&cwcBuffer ) )
			{
				_wcsupr_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR) );

				if (wcscmp( pwcBuffer, L"TRUE" ) == 0 )
					SW2ProfileData.bUseAlternateComputerCred = TRUE;
				else
					SW2ProfileData.bUseAlternateComputerCred = FALSE;
			}

			//
			// Computer account
			//
			cwcBuffer = sizeof( SW2ProfileData.pwcCompName );

			//
			// ComputerName
			//
			if (!SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"ComputerName",
								SW2ProfileData.pwcCompName,
								sizeof( SW2ProfileData.pwcCompName ),
								&cwcBuffer ) )
				memset( SW2ProfileData.pwcCompName, 0, sizeof( SW2ProfileData.pwcCompName ) );

			cwcBuffer = sizeof( SW2ProfileData.pwcCompPassword );

			//
			// ComputerPassword 
			//
			if (!SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"ComputerPassword",
								SW2ProfileData.pwcCompPassword,
								sizeof( SW2ProfileData.pwcCompPassword ),
								&cwcBuffer ) )
				memset( SW2ProfileData.pwcCompPassword, 0, sizeof( SW2ProfileData.pwcCompPassword ) );

			cwcBuffer = sizeof( SW2ProfileData.pwcCompDomain );

			//
			// ComputerDomain 
			//
			if (!SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"ComputerDomain",
								SW2ProfileData.pwcCompDomain,
								sizeof( SW2ProfileData.pwcCompDomain ),
								&cwcBuffer ) )
				memset( SW2ProfileData.pwcCompDomain, 0, sizeof( SW2ProfileData.pwcCompDomain ) );

			memset( pwcBuffer, 0, sizeof( pwcBuffer ) );
			cwcBuffer = sizeof( pwcBuffer );

			//
			// ServerCertificateOnLocalComputer	 
			//
			if (SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"ServerCertificateOnLocalComputer",
								pwcBuffer,
								sizeof( pwcBuffer ),
								&cwcBuffer ) )
			{
				_wcsupr_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR) );

				if (wcscmp( pwcBuffer, L"TRUE" ) == 0 )
					SW2ProfileData.bServerCertificateLocal = TRUE;
				else
					SW2ProfileData.bServerCertificateLocal = FALSE;
			}

			memset( pwcBuffer, 0, sizeof( pwcBuffer ) );
			cwcBuffer = sizeof( pwcBuffer );

			//
			// CheckForMicrosoftExtension  
			//
			if (SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"CheckForMicrosoftExtension",
								pwcBuffer,
								sizeof( pwcBuffer ),
								&cwcBuffer ) )
			{
				_wcsupr_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR) );

				if (wcscmp( pwcBuffer, L"TRUE" ) == 0 )
					SW2ProfileData.bVerifyMSExtension = TRUE;
				else
					SW2ProfileData.bVerifyMSExtension = FALSE;
			}

			memset( pwcBuffer, 0, sizeof( pwcBuffer ) );
			cwcBuffer = sizeof( pwcBuffer );

			//
			// AllowNewConnections   
			//
			if (SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"AllowNewConnections",
								pwcBuffer,
								sizeof( pwcBuffer ),
								&cwcBuffer ) )
			{
				_wcsupr_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR) );

				if (wcscmp( pwcBuffer, L"TRUE" ) == 0 )
					SW2ProfileData.bAllowNewConnection = TRUE;
				else
					SW2ProfileData.bAllowNewConnection = FALSE;
			}

			dwRet = SW2_WriteUserProfile( SW2ProfileData.pwcCurrentProfileId, NULL, SW2ProfileData );

			if (dwRet == NO_ERROR )
				dwRet = SW2_WriteComputerProfile( SW2ProfileData.pwcCurrentProfileId, NULL, SW2ProfileData );

		}
	}
	else
		dwRet = ERROR_NO_DATA;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadProfileConfig::returning: %ld", dwRet );

	return dwRet;
}

#ifndef _WIN32_WCE
DWORD
SW2_ReadSSIDConfig( HINF hInf, WCHAR *pwcSSIDProfile, BOOL bStartup )
{
	WCHAR						pwcServiceName[UNLEN];
	WCHAR						pwcSSID[32];
	WCHAR						pwcWLANProfile[UNLEN];
	WCHAR						pwcProfile[UNLEN];
	WCHAR						pwcAuthenticationMode[UNLEN];
	WCHAR						pwcEncryptionType[UNLEN];
	WCHAR						pwcNonBroadcast[UNLEN];
	WCHAR						pwcConnectionType[UNLEN];
	WCHAR						pwcConnectionMode[UNLEN];
	WCHAR						pwcAutoSwitch[UNLEN];
	WCHAR						pwcEAPType[UNLEN];
	WCHAR						pwcBuffer[UNLEN];
	DWORD						cwcBuffer;	
	int							i;
	DWORD						dw8021XFlags;
#ifdef SW2_WZC_LIB_VISTA
	HANDLE						hClientHandle;
	WLAN_INTERFACE_INFO_LIST	*pInterfaceList;
	DWORD						dwNegotiatedVersion;
	DWORD						dwReasonCode;
	WCHAR						*pwcXMLTemplate;
	DWORD						cwcXMLTemplate;
	WCHAR						*pwcSW2ConfigData;
	SW2_CONFIG_DATA				SW2ConfigData;
	WCHAR						pwcTemp[1024];
	WCHAR						pwcAuthMode[UNLEN];
#else
	PSW2_WZC_LIB_CONTEXT			pWZCContext;
	SW2_WZC_LIB_ADAPTERS			Adapters;
	WZC_WLAN_CONFIG				WZCCfg;
#endif // SW2_WZC_LIB_VISTA
	DWORD					dwRet;
	
	dwRet = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig: %s", pwcSSIDProfile );

	//
	// if we are running on Vista then we should use WLANSVC else use WZCSVC
	//
	if (g_dwMajorVersion > 5)
		swprintf_s(pwcServiceName, sizeof(pwcServiceName)/sizeof(WCHAR),L"WLANSVC");
	else
		swprintf_s(pwcServiceName, sizeof(pwcServiceName)/sizeof(WCHAR),L"WZCSVC");

	//
	// Check for "SSID" property (New configuration)
	// If available then use "SSID" as XML ssid and check for "Name" property for XML profile name
	// If not available continue as usual and use "Name" property as XML ssid (Old configuration)
	//
	cwcBuffer = sizeof( pwcSSID );

	if (SetupGetLineText( NULL,
							hInf,
							pwcSSIDProfile,
							L"SSID",
							pwcSSID,
							sizeof( pwcSSID ),
							&cwcBuffer ) )
	{
		memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

		cwcBuffer = sizeof(pwcWLANProfile);

		if (!SetupGetLineText( NULL,
								hInf,
								pwcSSIDProfile,
								L"Name",
								pwcWLANProfile,
								sizeof(pwcWLANProfile),
								&cwcBuffer ) )
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				L"SW2_TRACE_LEVEL_ERROR::SW2_ReadSSIDConfig:found \"SSID\" property but could not find \"NAME\" property");
			dwRet = ERROR_NO_DATA;
		}
	}
	else if (SetupGetLineText( NULL,
							hInf,
							pwcSSIDProfile,
							L"Name",
							pwcSSID,
							sizeof(pwcSSID),
							&cwcBuffer ) )
	{
		//
		// Copy the SSID property to the WLAN profile name
		//
		memset(pwcWLANProfile, 0, sizeof(pwcWLANProfile));
		wcscpy_s(pwcWLANProfile, sizeof(pwcWLANProfile)/sizeof(WCHAR),pwcSSID);
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2_ReadSSIDConfig:could not find \"SSID\" and \"NAME\" property");
		dwRet = dwRet = ERROR_NO_DATA;
	}

	if (dwRet==NO_ERROR)
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig::SSID: %s", pwcSSID );
		SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig::WLANName: %s", pwcWLANProfile );

		cwcBuffer = sizeof( pwcProfile );

		if (SetupGetLineText( NULL,
								hInf,
								pwcSSIDProfile,
								L"Profile",
								pwcProfile,
								sizeof( pwcProfile ),
								&cwcBuffer ) )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig::SSID: %s", pwcProfile );

			memset( pwcAuthenticationMode, 0, sizeof( pwcAuthenticationMode ) );

			cwcBuffer = sizeof( pwcAuthenticationMode );

			if (!SetupGetLineText( NULL,
							hInf,
							pwcSSIDProfile,
							L"AuthenticationMode",
							pwcAuthenticationMode,
							sizeof( pwcAuthenticationMode ),
							&cwcBuffer ) )
			{
				// DEFAULT value
				swprintf_s( pwcAuthenticationMode, sizeof( pwcAuthenticationMode ) / sizeof( WCHAR ), L"open" );
			}

			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig::AuthenticationMode: %s", pwcAuthenticationMode );

			memset( pwcEncryptionType, 0, sizeof( pwcEncryptionType ) );

			cwcBuffer = sizeof( pwcEncryptionType );

			if (!SetupGetLineText( NULL,
								hInf,
								pwcSSIDProfile,
								L"EncryptionType",
								pwcEncryptionType,
								sizeof( pwcEncryptionType ),
								&cwcBuffer ) )
			{
				// DEFAULT value
				swprintf_s( pwcEncryptionType, sizeof( pwcEncryptionType ) / sizeof( WCHAR ), L"WEP" );
			}

			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig::EncryptionType: %s", pwcEncryptionType );

			memset( pwcNonBroadcast, 0, sizeof( pwcNonBroadcast ) );

			cwcBuffer = sizeof( pwcNonBroadcast );

			if (!SetupGetLineText( NULL,
								hInf,
								pwcSSIDProfile,
								L"NonBroadcast",
								pwcNonBroadcast,
								sizeof( pwcNonBroadcast ),
								&cwcBuffer ) )
			{
				// DEFAULT value
				swprintf_s( pwcNonBroadcast, sizeof( pwcNonBroadcast ) / sizeof( WCHAR ), L"false" );
			}

			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig::NonBroadcast: %s", pwcNonBroadcast );

			memset( pwcConnectionMode, 0, sizeof( pwcConnectionMode) );

			cwcBuffer = sizeof( pwcConnectionMode );

			if (!SetupGetLineText( NULL,
								hInf,
								pwcSSIDProfile,
								L"ConnectionMode",
								pwcConnectionMode,
								sizeof( pwcConnectionMode ),
								&cwcBuffer ) )
			{
				// DEFAULT value
				swprintf_s( pwcConnectionMode, sizeof( pwcConnectionMode ) / sizeof( WCHAR ), L"auto" );
			}

			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig::ConnectionMode: %s", pwcConnectionMode );

			memset( pwcConnectionType, 0, sizeof( pwcConnectionType) );

			cwcBuffer = sizeof( pwcConnectionType );

			if (!SetupGetLineText( NULL,
								hInf,
								pwcSSIDProfile,
								L"ConnectionType",
								pwcConnectionType,
								sizeof( pwcConnectionType ),
								&cwcBuffer ) )
			{
				// DEFAULT value
				swprintf_s( pwcConnectionType, sizeof( pwcConnectionType ) / sizeof( WCHAR ), L"ESS" );
			}

			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig::ConnectionType: %s", pwcConnectionType );

			memset( pwcAutoSwitch, 0, sizeof( pwcAutoSwitch ) );

			cwcBuffer = sizeof( pwcAutoSwitch );

			if (!SetupGetLineText( NULL,
								hInf,
								pwcSSIDProfile,
								L"AutoSwitch",
								pwcAutoSwitch,
								sizeof( pwcAutoSwitch ),
								&cwcBuffer ) )
			{
				// DEFAULT value
				swprintf_s( pwcAutoSwitch, sizeof( pwcAutoSwitch ) / sizeof( WCHAR ), L"false" );
			}

			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig::AutoSwitch: %s", pwcAutoSwitch );

			memset( pwcEAPType, 0, sizeof( pwcEAPType ) );

			cwcBuffer = sizeof( pwcEAPType );

			if (!SetupGetLineText( NULL,
								hInf,
								pwcSSIDProfile,
								L"EAPType",
								pwcEAPType,
								sizeof( pwcEAPType ),
								&cwcBuffer ) )
			{
				// DEFAULT value
				swprintf_s( pwcEAPType, sizeof( pwcEAPType ) / sizeof( WCHAR ), L"21" );
			}

			//
			// 0x00 disable                                    
			// 0x80 enable (DEFAULT)
			// 0x40 computer credentials (DEFAULT)
			// 0x20 guest credentials              
			//
			dw8021XFlags = 0x80;
		
			cwcBuffer = sizeof(pwcBuffer);

			memset(pwcBuffer, 0, cwcBuffer);

			//
			// UseComputerCredentials
			//
			if (SetupGetLineText( NULL,
								hInf,
								pwcSSIDProfile,
								L"UseComputerCredentials",
								pwcBuffer,
								sizeof( pwcBuffer ),
								&cwcBuffer ) )
			{
				_wcsupr_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR) );

				if (wcscmp( pwcBuffer, L"TRUE" ) == 0 )
					dw8021XFlags |= 0x40;
			}
			else
			{
				//
				// Use default setting
				//
				dw8021XFlags |= 0x40;
			}

			cwcBuffer = sizeof(pwcBuffer);

			memset(pwcBuffer, 0, cwcBuffer);

			//
			// UseGuestCredentials
			//
			if (SetupGetLineText( NULL,
								hInf,
								pwcSSIDProfile,
								L"UseGuestCredentials",
								pwcBuffer,
								sizeof( pwcBuffer ),
								&cwcBuffer ) )
			{
				_wcsupr_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR) );

				if (wcscmp( pwcBuffer, L"TRUE" ) == 0 )
					dw8021XFlags |= 0x20;
			}

#ifdef SW2_WZC_LIB_VISTA

			switch(dw8021XFlags)
			{
				case 0x80:

					swprintf_s(pwcAuthMode, sizeof(pwcAuthMode)/sizeof(WCHAR), L"user");
						
				break;

				case 0xC0:

					swprintf_s(pwcAuthMode, sizeof(pwcAuthMode)/sizeof(WCHAR), L"machineOrUser");

				break;

				case 0xA0:

					swprintf_s(pwcAuthMode, sizeof(pwcAuthMode)/sizeof(WCHAR), L"guest");

				break;

				case 0xE0:

					swprintf_s(pwcAuthMode, sizeof(pwcAuthMode)/sizeof(WCHAR), L"machineOrUser");

				break;

				default:

					swprintf_s(pwcAuthMode, sizeof(pwcAuthMode)/sizeof(WCHAR), L"machineOrUser");

				break;
			}

			if ((dwRet = WlanOpenHandle( 2,
										NULL,
										&dwNegotiatedVersion,
										&hClientHandle ) ) == ERROR_SUCCESS )
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig::WlanOpenHandle succeeded");

				if ((dwRet = WlanEnumInterfaces( hClientHandle,
												NULL,
												&pInterfaceList ) ) == ERROR_SUCCESS )
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig::WlanEnumInterfaces succeeded %ld nr of interfaces", pInterfaceList->dwNumberOfItems );

					memset( &SW2ConfigData, 0, sizeof( SW2ConfigData ) );

					wcscpy_s( SW2ConfigData.pwcProfileId, 
								sizeof(SW2ConfigData.pwcProfileId)/sizeof(WCHAR),
								pwcProfile );

					if ((dwRet = SW2_ByteToHex( sizeof( SW2ConfigData ), ( PBYTE ) &SW2ConfigData, &pwcSW2ConfigData ) ) == NO_ERROR )
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig::pcSW2ConfigData(%ld)", wcslen( pwcSW2ConfigData ) );

						cwcXMLTemplate = ( ( ( ( DWORD ) wcslen( L"<?xml version=\"1.0\"?><WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\"><name></name><SSIDConfig><SSID><name></name></SSID><nonBroadcast></nonBroadcast></SSIDConfig><connectionType></connectionType><connectionMode></connectionMode><autoSwitch></autoSwitch><MSM><security><authEncryption><authentication></authentication><encryption></encryption><useOneX>true</useOneX></authEncryption><OneX xmlns=\"http://www.microsoft.com/networking/OneX/v1\"><authMode></authMode><EAPConfig><EapHostConfig xmlns=\"http://www.microsoft.com/provisioning/EapHostConfig\"><EapMethod><Type xmlns=\"http://www.microsoft.com/provisioning/EapCommon\"></Type><VendorId xmlns=\"http://www.microsoft.com/provisioning/EapCommon\">0</VendorId><VendorType xmlns=\"http://www.microsoft.com/provisioning/EapCommon\">0</VendorType><AuthorId xmlns=\"http://www.microsoft.com/provisioning/EapCommon\">29114</AuthorId></EapMethod><ConfigBlob></ConfigBlob></EapHostConfig></EAPConfig></OneX></security></MSM></WLANProfile>" ) )
							+ (DWORD)wcslen( pwcWLANProfile ) // profilename
							+ (DWORD)wcslen( pwcSSID ) // ssid
							+ (DWORD)wcslen( pwcNonBroadcast ) // true/false
							+ (DWORD)wcslen( pwcConnectionType )
							+ (DWORD)wcslen( pwcConnectionMode )
							+ (DWORD)wcslen( pwcAutoSwitch )
							+ (DWORD)wcslen( pwcAuthenticationMode )
							+ (DWORD)wcslen( pwcEncryptionType )
							+ (DWORD)wcslen( pwcAuthMode )
							+ (DWORD)wcslen( pwcEAPType )
							+ (DWORD)wcslen( pwcSW2ConfigData ) + 1) * (DWORD) sizeof( WCHAR ) );
									
						SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig::allocating %ld bytes for pwcXMLTemplate", cwcXMLTemplate );

						if ((dwRet = SW2AllocateMemory(cwcXMLTemplate, (PVOID*) &pwcXMLTemplate)) == NO_ERROR)
						{
							memset( pwcXMLTemplate, 0, cwcXMLTemplate );

							swprintf_s( pwcXMLTemplate, 
								cwcXMLTemplate/sizeof(CHAR),
								L"<?xml version=\"1.0\"?><WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\"><name>%s</name><SSIDConfig><SSID><name>%s</name></SSID><nonBroadcast>%s</nonBroadcast></SSIDConfig><connectionType>%s</connectionType><connectionMode>%s</connectionMode><autoSwitch>%s</autoSwitch><MSM><security><authEncryption><authentication>%s</authentication><encryption>%s</encryption><useOneX>true</useOneX></authEncryption><OneX xmlns=\"http://www.microsoft.com/networking/OneX/v1\"><authMode>%s</authMode><EAPConfig><EapHostConfig xmlns=\"http://www.microsoft.com/provisioning/EapHostConfig\"><EapMethod><Type xmlns=\"http://www.microsoft.com/provisioning/EapCommon\">%s</Type><VendorId xmlns=\"http://www.microsoft.com/provisioning/EapCommon\">0</VendorId><VendorType xmlns=\"http://www.microsoft.com/provisioning/EapCommon\">0</VendorType><AuthorId xmlns=\"http://www.microsoft.com/provisioning/EapCommon\">29114</AuthorId></EapMethod><ConfigBlob>%s</ConfigBlob></EapHostConfig></EAPConfig></OneX></security></MSM></WLANProfile>",
								pwcWLANProfile,
								pwcSSID,
								pwcNonBroadcast,
								pwcConnectionType,
								pwcConnectionMode,
								pwcAutoSwitch,
								pwcAuthenticationMode,
								pwcEncryptionType,
								pwcAuthMode,
								pwcEAPType,
								pwcSW2ConfigData );

							SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig::XML:%s", pwcXMLTemplate );

							for( i=0; ( DWORD ) i < pInterfaceList->dwNumberOfItems; i++ )
							{
								// check for not ready state in adapter
								if (pInterfaceList->InterfaceInfo[i].isState != wlan_interface_state_not_ready)
								{
									dwRet = WlanSetProfile( hClientHandle,
															&(pInterfaceList->InterfaceInfo[i].InterfaceGuid),
															0,
															pwcXMLTemplate,
															NULL,
															TRUE,
															NULL,
															&dwReasonCode );	

									SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig::WlanSetProfile returned %ld, %ld", dwRet, dwReasonCode );

									if (dwRet != ERROR_SUCCESS )
									{
										if (WlanReasonCodeToString(  dwReasonCode,
																	sizeof( pwcTemp )/sizeof(WCHAR),
																	pwcTemp,
																	NULL ) == ERROR_SUCCESS )
										{
											SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig::WlanSetProfile returned reason: \"%s\"", pwcTemp );
										}
										else
										{
											SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig::WlanSetProfile returned unknown reason");
										}
									}
								}
							}

							SW2FreeMemory((PVOID*)&pwcXMLTemplate);
						}
						else
							dwRet = ERROR_NOT_ENOUGH_MEMORY;

						SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig::freeing pcSW2ConfigData");

						SW2FreeMemory((PVOID*)&pwcSW2ConfigData);
					}
					else
						dwRet = ERROR_NOT_ENOUGH_MEMORY;

					WlanFreeMemory( pInterfaceList );
				}

				WlanCloseHandle( hClientHandle, NULL );
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2_ReadSSIDConfig::WlanOpenHandle FAILED: %ld", dwRet);
			}
#else
			if ((dwRet = WZCInit( &pWZCContext ) ) == NO_ERROR )
			{
				if ((dwRet = WZCEnumAdapters( pWZCContext, &Adapters ) ) == NO_ERROR )
				{
					if ((dwRet = WZCInitConfig( pWZCContext, 
												&WZCCfg, 
												pwcSSID, 
												Ndis802_11Infrastructure ) ) == NO_ERROR )
					{
						if (wcslen( pwcEncryptionType ) > 0 )
						{
							// leverage old WZCCfg privacy value
							// WEP  privacy = 0
							// None privacy = 1 
							// TKIP privacy = 2 (SecureW2 only)
							// AES  privacy = 3 (SecureW2 only)
							if (wcscmp( pwcEncryptionType, L"TKIP" ) == 0 )
								WZCCfg.Privacy = 2;
							else if (wcscmp( pwcEncryptionType, L"AES" ) == 0 )
								WZCCfg.Privacy = 3;
						}

						if (wcslen( pwcAuthenticationMode ) > 0 )
						{
							//Ndis802_11AuthModeOpen,
							//Ndis802_11AuthModeShared,
							//Ndis802_11AuthModeAutoSwitch,
							//Ndis802_11AuthModeWPA,
							//Ndis802_11AuthModeWPAPSK,
							//Ndis802_11AuthModeWPANone,
							//Ndis802_11AuthModeMax
							// added for WPA2:
							//Ndis802_11AuthModeWPA2 = 6,
							//Ndis802_11AuthModeWPA2PSK,

							if (wcscmp( pwcAuthenticationMode, L"WPA" ) == 0 )
								WZCCfg.AuthenticationMode = Ndis802_11AuthModeWPA;
							else if (wcscmp( pwcAuthenticationMode, L"WPA2" ) == 0 )
								WZCCfg.AuthenticationMode = Ndis802_11AuthModeWPA2;
						}

#ifndef SW2_WZC_LIB_2K_XP_SP0
#ifndef SW2_WZC_LIB_XP_SP1
						if (wcslen( pwcConnectionMode ) > 0 )
						{
							if (wcscmp( pwcConnectionMode, L"auto" ) == 0 )
								WZCCfg.dwCtlFlags = 0;
							else if (wcscmp( pwcConnectionMode, L"manual" ) == 0 )
								WZCCfg.dwCtlFlags = 0x100;
						}

						if (wcslen( pwcConnectionType ) > 0 )
						{
							if (wcscmp(pwcConnectionType, L"ESS") == 0)
								WZCCfg.ConnectionType = Ndis802_11ConnectionTypeESS;
							else if (wcscmp(pwcConnectionType, L"IBSS") == 0)
								WZCCfg.ConnectionType = Ndis802_11ConnectionTypeIBSS;
						}
#endif // SW2_WZC_LIB_2K_XP_SP0
#endif // SW2_WZC_LIB_XP_SP1
						//
						// First stop WZCSVC
						// Remove SSID config from all adapters in list
						// Start WZCSVC (with configured startup type)
						//
						if ((dwRet = SW2_StopSVC(pwcServiceName) ) == NO_ERROR)
						{
							for( i=0; ( DWORD ) i < Adapters.dwNumGUID; i++ )
							{
								WZCRemovePreferedConfig(pWZCContext,
														Adapters.pwcGUID[i],
														WZCCfg );
							}

							dwRet = SW2_StartSVC(pwcServiceName, bStartup);

							//
							// Should be possible but check anyway
							//
							if (dwRet = ERROR_SERVICE_ALREADY_RUNNING )
								dwRet = NO_ERROR;
						}

						if (dwRet == NO_ERROR )
						{
							for( i=0; ( DWORD ) i < Adapters.dwNumGUID; i++ )
							{
								//
								// remove any previous configurations for the current SSID
								//
								if ((dwRet = WZCAddPreferedConfig( pWZCContext, 
																	Adapters.pwcGUID[i], 
																	WZCCfg, 
																	SW2_WZC_LIB_CONFIG_PREF | SW2_WZC_LIB_CONFIG_WEP,
																	TRUE,
																	TRUE ) ) == NO_ERROR )
								{
									SW2_CONFIG_DATA SW2ConfigData;

									memset( &SW2ConfigData, 0, sizeof( SW2ConfigData ) );

									wcscpy_s( SW2ConfigData.pwcProfileId, 
												sizeof(SW2ConfigData.pwcProfileId)/sizeof(WCHAR),
												pwcProfile );

									dwRet = WZCSetConfigEapData( pWZCContext, 
																Adapters.pwcGUID[i], 
																pwcSSID, 
																21, 
																dw8021XFlags,
																( PBYTE ) &SW2ConfigData, 
																sizeof( SW2ConfigData ) );
								}
							} // for
						}
					}
				}

				WZCEnd( pWZCContext );
			}
#endif // SW2_WZC_LIB_VISTA
		}
		else
			dwRet = ERROR_INVALID_DATA;
	}
	else
		dwRet = ERROR_NO_DATA;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_ReadSSIDConfig returning: %ld", dwRet );

	return dwRet;
}
#endif // _WIN32_WCE

DWORD
SW2_Install(HWND hwndParent)
{
	HINF					hInf;
	WCHAR					pwcWZCServiceName[1024];
	WCHAR					pwcBuffer[1024];
	WCHAR					pwcVersion[256];
	WCHAR					pwcTemp[1024];
	DWORD					cwcBuffer = 0;
#ifdef SW2_WZC_LIB_VISTA
	BOOL					bStartupDOT3SVC;
#endif // SW2_WZC_LIB_VISTA
	BOOL					bStartupWZCSVC;
	DWORD					dwError;
	int						i = 0;
	DWORD					dwRet;
	
	dwRet = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_Install");

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_Install::looking for SecureW2.inf file");

	//
	// if we are running on Vista then we should use WLANSVC else use WZCSVC
	//
	if (g_dwMajorVersion > 5)
		swprintf_s(pwcWZCServiceName, sizeof(pwcWZCServiceName)/sizeof(WCHAR),L"WLANSVC");
	else
		swprintf_s(pwcWZCServiceName, sizeof(pwcWZCServiceName)/sizeof(WCHAR),L"WZCSVC");


	if ((hInf = SetupOpenInfFile( L".\\SecureW2.inf", 
						NULL,
						INF_STYLE_WIN4,
						(PUINT)&dwError ) ) != INVALID_HANDLE_VALUE )
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_Install::Opened SecureW2.inf");

		memset(pwcTemp, 0, sizeof(pwcTemp));

		//
		// Read version and see if we are compatible
		//
		swprintf_s( pwcVersion, 
			sizeof( pwcVersion ) / sizeof( WCHAR ),
			L"%ld", 
			SW2_CONFIG_VERSION );

		if (SetupGetLineText( NULL,
							hInf,
							L"Version",
							L"Config",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&cwcBuffer ) )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_Install::Found version");

			if (!wcscmp( pwcBuffer, pwcVersion ) )
			{
				//
				// We are compatible
				//
				memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

#ifdef SW2_WZC_LIB_VISTA

				//
				// How do we start DOT3SVC?
				//
				if (SetupGetLineText( NULL,
									hInf,
									L"DOT3SVC",
									L"Startup",
									pwcBuffer,
									sizeof( pwcBuffer ),
									&cwcBuffer ) )
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_Install::found DOT3SVC section");

					bStartupDOT3SVC = TRUE;

					_wcsupr_s( pwcBuffer, sizeof( pwcBuffer )/sizeof( WCHAR));

					if (wcscmp( pwcBuffer, L"DISABLED" ) == 0 )
					{
						bStartupDOT3SVC = FALSE;
					}
					else if (wcscmp( pwcBuffer, L"NORMAL" ) == 0 )
					{
						bStartupDOT3SVC  = FALSE;
					}
					else if (wcscmp( pwcBuffer, L"AUTO" ) == 0 )
					{
						bStartupDOT3SVC = TRUE;
					}

					memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

					if (SetupGetLineText( NULL,
										hInf,
										L"DOT3SVC",
										L"Restart",
										pwcBuffer,
										sizeof( pwcBuffer ),
										&cwcBuffer ) )
					{
						_wcsupr_s( pwcBuffer, sizeof( pwcBuffer )/sizeof( WCHAR));

						//
						// If we are required to restart the DOT3 service, simply stop the service
						// and it will be started later on, thus being a restart...
						//
						if (wcscmp( pwcBuffer, L"TRUE" ) == 0 )
						{
							SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_Install::Stopping DOT3SVC for restart");

							SW2_StopSVC(L"DOT3SVC");
						}
					}

					if ((dwRet = SW2_StartSVC(L"DOT3SVC", bStartupDOT3SVC) ) != NO_ERROR )
					{
						if (dwRet == ERROR_SERVICE_ALREADY_RUNNING)
							dwRet = NO_ERROR;
						else
						{
							swprintf_s( pwcTemp, sizeof(pwcTemp)/sizeof(WCHAR), L"Could not start Wired Auto Config Service (%ld)", dwRet );

							MessageBox( hwndParent, pwcTemp, L"SecureW2 Install Error", MB_OK | MB_ICONERROR );
						}
					}
				}
#endif // SW2_WZC_LIB_VISTA

				memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

				//
				// How do we start WZCSVC?
				//
				if (SetupGetLineText( NULL,
									hInf,
									L"WZCSVC",
									L"Startup",
									pwcBuffer,
									sizeof( pwcBuffer ),
									&cwcBuffer ) )
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_Install::found WZCSVC section");

					_wcsupr_s( pwcBuffer, sizeof( pwcBuffer )/sizeof( WCHAR));

					bStartupWZCSVC = TRUE;

					_wcsupr_s( pwcBuffer, sizeof( pwcBuffer )/sizeof( WCHAR));

					if (wcscmp( pwcBuffer, L"DISABLED" ) == 0 )
					{
						bStartupWZCSVC = FALSE;
					}
					else if (wcscmp( pwcBuffer, L"NORMAL" ) == 0 )
					{
						bStartupWZCSVC  = FALSE;
					}
					else if (wcscmp( pwcBuffer, L"AUTO" ) == 0 )
					{
						bStartupWZCSVC = TRUE;
					}

					if (SetupGetLineText( NULL,
										hInf,
										L"WZCSVC",
										L"Restart",
										pwcBuffer,
										sizeof( pwcBuffer ),
										&cwcBuffer ) )
					{
						_wcsupr_s( pwcBuffer, sizeof( pwcBuffer )/sizeof( WCHAR));

						//
						// If we are required to restart the DOT3 service, simply stop the service
						// and it will be started later on, thus being a restart...
						//
						if (wcscmp( pwcBuffer, L"TRUE" ) == 0 )
						{
							SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_Install::Stopping WZCSVC for restart");

							SW2_StopSVC(pwcWZCServiceName);
						}
					}

					if ((dwRet = SW2_StartSVC(pwcWZCServiceName, bStartupWZCSVC)) != NO_ERROR)
					{
						if (dwRet == ERROR_SERVICE_ALREADY_RUNNING)
							dwRet = NO_ERROR;
						else
						{
							swprintf_s( pwcTemp, sizeof(pwcTemp)/sizeof(WCHAR), L"Could not start Wireless Zero Config Service (%ld)", dwRet );

							MessageBox( hwndParent, pwcTemp, L"SecureW2 Install Error", MB_OK | MB_ICONERROR );
						}
					}
				}

				if (dwRet == NO_ERROR )
				{
					//
					// Read and install certificates
					//
					for( i=0; dwRet == NO_ERROR; i++ )
					{
						swprintf_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR), L"Certificate.%d", i );

						dwRet = SW2InstallCertificate( hInf, pwcBuffer, i );
					}

					//
					// Did we fail because we don't have any more profiles?
					//
					if (dwRet != NO_ERROR )
					{
						if (dwRet == ERROR_NO_DATA )
							dwRet = NO_ERROR;
						else
						{
							swprintf_s( pwcTemp, sizeof(pwcTemp)/sizeof(WCHAR), L"Failed to install certificate \"%ws\" (%ld)", pwcBuffer, dwRet );

							MessageBox( hwndParent, pwcTemp, L"SecureW2 Install Error", MB_OK | MB_ICONERROR );
						}
					}
				}

				if (dwRet == NO_ERROR )
				{
					memset( pwcBuffer, 0, sizeof( pwcBuffer ) );
				
					//
					// Profiles
					//
					for( i=1; dwRet == NO_ERROR; i++ )
					{
						swprintf_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR), L"Profile.%d", i );

						dwRet = SW2_ReadProfileConfig( hwndParent, hInf, pwcBuffer );
					}

					//
					// Did we fail because we don't have any more profiles?
					//
					if (dwRet != NO_ERROR )
					{
						if (dwRet == ERROR_NO_DATA)
							dwRet = NO_ERROR;
						else if (dwRet != ERROR_CANCELLED)
						{
							swprintf_s( pwcTemp, sizeof(pwcTemp)/sizeof(WCHAR), L"Failed reading config profile \"%ws\" (%ld)", pwcBuffer, dwRet );

							MessageBox( hwndParent, pwcTemp, L"SecureW2 Install Error", MB_OK | MB_ICONERROR );
						}
					}
#ifndef _WIN32_WCE
					if (dwRet == NO_ERROR )
					{
						//
						// SSIDs
						//
						for( i=1; dwRet == NO_ERROR; i++ )
						{
							swprintf_s( pwcBuffer, sizeof(pwcBuffer)/sizeof(WCHAR), L"SSID.%d", i );

							dwRet = SW2_ReadSSIDConfig( hInf, pwcBuffer, bStartupWZCSVC );
						}

						if (dwRet == ERROR_NO_DATA )
							dwRet = NO_ERROR;
						else if (dwRet == ERROR_NOT_SUPPORTED )
						{
							dwRet = NO_ERROR;

							swprintf_s( pwcTemp, sizeof( pwcTemp )/sizeof(WCHAR), L"This installer does not support Service Pack 2. Please configure SecureW2 manually" );

							MessageBox( hwndParent, pwcTemp, L"SecureW2 Install Alert", MB_OK | MB_ICONINFORMATION );
						}
						else
						{
							swprintf_s( pwcTemp, sizeof( pwcTemp )/sizeof(WCHAR), L"Failed setting SSID configuration (%ld)", dwRet );

							MessageBox( hwndParent, pwcTemp, L"SecureW2 Install Error", MB_OK | MB_ICONERROR );
						}
					}
				}
#endif // _WIN32_WCE
			}
			else
			{
				swprintf_s( pwcTemp, sizeof(pwcTemp)/sizeof(WCHAR), L"Incorrect configuration version: \"%ws\", require version \"%ld\". Please verify your configuration file.", pwcBuffer, SW2_CONFIG_VERSION );

				MessageBox( hwndParent, pwcTemp, L"SecureW2 Install Error", MB_OK | MB_ICONERROR );

				dwRet = ERROR_INVALID_DATA;
			}
		}
		else
		{
			MessageBox( hwndParent, L"Could not find required parameter \"Config\" in section \"Version\". Please verify your configuration file.", L"SecureW2 Install Error", MB_OK | MB_ICONERROR );

			dwRet = ERROR_INVALID_DATA;
		}

		SetupCloseInfFile( hInf );
	}
	else
		SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_Install::SecureW2.inf not found (%ld, %ld)", dwError, GetLastError() );

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2_Install::returning %ld", dwRet );

	return dwRet;
}

int 
WINAPI 
WinMain(	HINSTANCE hInstance, 
			HINSTANCE hPrevInstance, 
			LPSTR lpCmdLine, 
			int nShowCmd	)
{
	DWORD		dwReturnCode = NO_ERROR;
	DWORD		dwVersion;

#ifndef _WIN32_WCE
	g_dwSW2TraceId = TraceRegister(L"SECUREW2PLUGIN");
#endif // _WIN32_WCE

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::WinMain" );

	if ((g_hResource = LoadLibrary( L"sw2_res_default.dll" )))
	{
		if ((g_hLanguage = LoadLibrary( L"sw2_lang.dll" )))
		{
			// Create the heap we'll be using for memory allocations.
			if ((dwReturnCode = SW2InitializeHeap())==NO_ERROR)
			{
				// retrieve windows version, used to distinct between Vista and others
				dwVersion = GetVersion();
				 
				g_dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
				g_dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

				dwReturnCode = SW2_Install(GetDesktopWindow());

				// Clean up our internal heap.
				SW2DeInitializeHeap();
			}

			FreeLibrary(g_hLanguage);
		}

		if (g_hResource)
			FreeLibrary(g_hResource);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::WinMain::returning %ld", dwReturnCode );

#ifndef _WIN32_WCE
	TraceDeregister(g_dwSW2TraceId);
#endif // _WIN32_WCE

	if (dwReturnCode != NO_ERROR)
		return FALSE;
	else
		return TRUE;
}
