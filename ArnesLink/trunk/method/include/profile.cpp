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
#ifndef _WIN32_WCE
#include <shlwapi.h>
#include <aclapi.h>
#include <Sddl.h>
#endif // _WIN32_WCE

//
// Name: SW2_InitDefaultProfile
// Description: Initializes a ProfileData to the Default values
// Author: Tom Rixom
// Created: 12 May 2004
//
VOID
SW2_InitDefaultProfile( IN PSW2_PROFILE_DATA pProfileData, IN BYTE bEAPID)
{
	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_InitDefaultProfile" ) );

	memset( pProfileData, 0, sizeof( SW2_PROFILE_DATA ) );

	//
	// Select DEFAULT authentication method depending on EAP type
	//
	if (bEAPID == NULL)
		wcscpy_s(pProfileData->pwcInnerAuth, sizeof(pProfileData->pwcInnerAuth), L"PAP" );
	else if (bEAPID == 21) // TTLS
		wcscpy_s(pProfileData->pwcInnerAuth, sizeof(pProfileData->pwcInnerAuth), L"PAP" );
	else if (bEAPID == 25) // PEAP
		wcscpy_s(pProfileData->pwcInnerAuth, sizeof(pProfileData->pwcInnerAuth), L"EAP" );
	else
		wcscpy_s(pProfileData->pwcInnerAuth, sizeof(pProfileData->pwcInnerAuth), L"PAP" );

	//
	// Select default inner EAP method, EAP-MSCHAPV2
	//
	pProfileData->dwCurrentInnerEapMethod = 26;
	
	pProfileData->bVerifyServerCertificate = TRUE;
	pProfileData->bPromptUser = TRUE;
	pProfileData->bUseAlternateIdentity = TRUE;
	pProfileData->bUseAnonymousIdentity = TRUE;
#ifndef _WIN32_WCE
	pProfileData->bAllowNotifications = TRUE;
#endif // _WIN32_WCE

	wcscpy_s(pProfileData->pwcCurrentProfileId, sizeof(pProfileData->pwcCurrentProfileId), L"DEFAULT");

	pProfileData->bAllowCachePW = TRUE;

#ifndef _WIN32_WCE
	pProfileData->bRenewIP = FALSE;
#endif // _WIN32_WCE
	pProfileData->iVersion = SW2_CONFIG_VERSION;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_InitDefaultProfile::returning" ) );
}

//
// Name: SW2_CreateProfile
// Description: Create a profile in the registry using the pwcProfileID
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
SW2_CreateProfile( IN WCHAR *pwcProfileID )
{
	HKEY	hKey;
	DWORD	dwDisposition = 0;
	DWORD	dwReturnCode;
	WCHAR	pwcTemp[1024];

	dwReturnCode = NO_ERROR;

	wsprintf( pwcTemp, TEXT( "%s\\%s"), SW2_METHOD_PROFILE_LOCATION, pwcProfileID );

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CreateProfile: Path: %s" ), pwcTemp );

	if( ( dwReturnCode = SW2_CreateSecureKey( HKEY_LOCAL_MACHINE, pwcTemp, &hKey, &dwDisposition ) ) == NO_ERROR )
	{
		if( dwDisposition != REG_CREATED_NEW_KEY )
			dwReturnCode = ERROR_ALREADY_EXISTS;

		RegCloseKey( hKey );
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CreateProfile::returning: %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_DeleteProfile
// Description: Remove a profile from the registry using the pwcProfileID
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
SW2_DeleteProfile( IN WCHAR	*pwcProfileID )
{
	WCHAR	pwcTemp[MAX_PATH*2];
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	wsprintf( pwcTemp, TEXT( "%s\\%s"), SW2_METHOD_PROFILE_LOCATION, pwcProfileID );

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_DeleteProfile: Path: %s" ), pwcTemp );

#ifdef _WIN32_WCE
	dwReturnCode = RegDeleteKey( HKEY_LOCAL_MACHINE, pwcTemp );
#else
	dwReturnCode = SHDeleteKey( HKEY_LOCAL_MACHINE, pwcTemp );
#endif // _WIN32_WCE

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_DeleteProfile: returning: %ld" ), dwReturnCode );

	return dwReturnCode;
}

DWORD
SW2_ReadProfile(	IN WCHAR					*pwcProfileID,
					IN HANDLE					hTokenImpersonateUser,
					IN OUT PSW2_PROFILE_DATA	pProfileData )
{
	HKEY	hKeyLM;
	HKEY	hKeyCU = NULL;
	HANDLE	hToken = NULL;
	WCHAR	pwcTemp[MAX_PATH*2];
	int		i = 0;
	PBYTE	pbData;
	DWORD	cbData = 0;
	DWORD	dwType;
#ifndef _WIN32_WCE
	PBYTE	pbCompPassword;
#endif // _WIN32_WCE
	PBYTE	pbUserPassword;
	DWORD	dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: %s" ), pwcProfileID );

	dwReturnCode = NO_ERROR;

	//
	// Start out with default profile
	//
	SW2_InitDefaultProfile( pProfileData, EAPTYPE );

#ifndef _WIN32_WCE
	if( pwcProfileID )
		swprintf_s( pwcTemp, 
					sizeof( pwcTemp )/sizeof(WCHAR),
					TEXT( "%s\\%s" ), 
					SW2_METHOD_PROFILE_LOCATION,
					pwcProfileID );
	else
		swprintf_s( pwcTemp, 
					sizeof(pwcTemp)/sizeof(WCHAR),
					TEXT( "%s\\DEFAULT" ), 
					SW2_METHOD_PROFILE_LOCATION );
#else
	if( pwcProfileID )
		swprintf( pwcTemp, 
					TEXT( "%s\\%s" ), 
					SW2_METHOD_PROFILE_LOCATION,
					pwcProfileID );
	else
		swprintf( pwcTemp, 
					TEXT( "%s\\DEFAULT" ), 
					SW2_METHOD_PROFILE_LOCATION );

#endif // _WIN32_WCE

	for( i=0; i < SW2_MAX_CA; i++ )
		memset( pProfileData->pbTrustedRootCAList[i], 0, 20 );

	if( ( dwReturnCode = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
							pwcTemp,
							0,
							KEY_READ,
							&hKeyLM ) ) == NO_ERROR )
	{
		memset( pProfileData, 0, sizeof( pProfileData ) );

		//
		// Version
		//
		cbData = sizeof( pProfileData->iVersion );

		dwReturnCode = RegQueryValueEx( hKeyLM, 
								L"Version", 
								0,
								&dwType,
								(PBYTE)&( pProfileData->iVersion ),
								&cbData );

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read Version %d"), pProfileData->iVersion);

			//
			// AllowCachePW
			//
			cbData = sizeof( pProfileData->bAllowCachePW );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"AllowCachePW", 
									0,
									&dwType,
									(PBYTE)&( pProfileData->bAllowCachePW ),
									&cbData );
		}
#ifndef _WIN32_WCE
		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read AllowCachePW %d"), pProfileData->bAllowCachePW);

			//
			// AltUsernameStr
			//
			cbData = sizeof( pProfileData->pwcAltUsernameStr );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"AltUsernameStr", 
									0,
									&dwType,
									(PBYTE)pProfileData->pwcAltUsernameStr,
									&cbData );
		}

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read AltUsernameStr %s"), pProfileData->pwcAltUsernameStr);

			//
			// AltPasswordStr
			//
			cbData = sizeof( pProfileData->pwcAltPasswordStr );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"AltPasswordStr", 
									0,
									&dwType,
									(PBYTE)pProfileData->pwcAltPasswordStr,
									&cbData );
		}

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read AltPasswordStr %s"), pProfileData->pwcAltPasswordStr);

			//
			// AltRePasswordStr
			//
			cbData = sizeof( pProfileData->pwcAltRePasswordStr );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"AltRePasswordStr", 
									0,
									&dwType,
									(PBYTE)pProfileData->pwcAltRePasswordStr,
									&cbData );
		}

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read AltRePasswordStr %s"), pProfileData->pwcAltRePasswordStr);

			//
			// AltDomainStr
			//
			cbData = sizeof( pProfileData->pwcAltDomainStr );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"AltDomainStr", 
									0,
									&dwType,
									(PBYTE)pProfileData->pwcAltDomainStr,
									&cbData );
		}

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read AltDomainStr %s"), pProfileData->pwcAltDomainStr);

			//
			// AltCredsTitle
			//
			cbData = sizeof( pProfileData->pwcAltCredsTitle );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"AltCredsTitle", 
									0,
									&dwType,
									(PBYTE)pProfileData->pwcAltCredsTitle,
									&cbData );
		}
#endif // _WIN32_WCE

		if( dwReturnCode == NO_ERROR )
		{
#ifndef _WIN32_WCE
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read AltCredsTitle %s"), pProfileData->pwcAltCredsTitle);
#endif // _WIN32_WCE

			//
			// UseAlternateIdentity
			//
			cbData = sizeof( pProfileData->bUseAlternateIdentity);

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"UseAlternateOuterIdentity", 
									0,
									&dwType,
									(PBYTE)&(pProfileData->bUseAlternateIdentity),
									&cbData );
		}


		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read UseAlternateOuterIdentity %d"), pProfileData->bUseAlternateIdentity);

			//
			// UseAnonymousIdentity
			//
			cbData = sizeof( pProfileData->bUseAnonymousIdentity );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"UseAnonymousOuterIdentity", 
									0,
									&dwType,
									(PBYTE)&(pProfileData->bUseAnonymousIdentity),
									&cbData );
		}

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read UseAnonymousOuterIdentity %d"), pProfileData->bUseAnonymousIdentity);

			//
			// AlternateIdentity
			//
			cbData = sizeof( pProfileData->pwcAlternateIdentity );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"AlternateOuterIdentity", 
									0,
									&dwType,
									(PBYTE)pProfileData->pwcAlternateIdentity,
									&cbData );
		}

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read AlternateOuterIdentity %s"), pProfileData->pwcAlternateIdentity);

			//
			// UseSessionResumption
			//
			cbData = sizeof( pProfileData->bUseSessionResumption );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"UseSessionResumption", 
									0,
									&dwType,
									(PBYTE)&(pProfileData->bUseSessionResumption),
									&cbData );
		}

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read UseSessionResumption %d"), pProfileData->bUseSessionResumption);

			//
			// VerifyServer
			//
			cbData = sizeof( pProfileData->bVerifyServerCertificate );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"VerifyServerCertificate", 
									0,
									&dwType,
									(PBYTE)&(pProfileData->bVerifyServerCertificate),
									&cbData );
		}

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read VerifyServerCertificate %d"), pProfileData->bVerifyServerCertificate);

			//
			// VerifyServerName
			//
			cbData = sizeof( pProfileData->bVerifyServerName );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"VerifyServerName", 
									0,
									&dwType,
									(PBYTE)&(pProfileData->bVerifyServerName),
									&cbData );
		}

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read VerifyServerName %d"), pProfileData->bVerifyServerName);

			//
			// ServerName
			//
			cbData = sizeof( pProfileData->pwcServerName );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"ServerName", 
									0,
									&dwType,
									(PBYTE)pProfileData->pwcServerName,
									&cbData );
		}

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read ServerName %s"), pProfileData->pwcServerName);

			//
			// InnerAuth
			//
			cbData = sizeof( pProfileData->pwcInnerAuth );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"InnerAuth", 
									0,
									&dwType,
									(PBYTE)pProfileData->pwcInnerAuth,
									&cbData );
		}

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read InnerAuth %s"), pProfileData->pwcInnerAuth);

			//
			// CurrentInnerEapMethod
			//
			cbData = sizeof( pProfileData->dwCurrentInnerEapMethod );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"CurrentInnerEapMethod", 
									0,
									&dwType,
									(PBYTE)&(pProfileData->dwCurrentInnerEapMethod),
									&cbData );
		}

#ifndef _WIN32_WCE

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read CurrentInnerEapMethod %ld"), pProfileData->dwCurrentInnerEapMethod);

			//
			// UseUserCredentialsForComputer
			//
			cbData = sizeof( pProfileData->bUseUserCredentialsForComputer );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"UseUserCredentialsForComputer", 
									0,
									&dwType,
									(PBYTE)&(pProfileData->bUseUserCredentialsForComputer),
									&cbData );
		}

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read UseUserCredentialsForComputer %d"), pProfileData->bUseUserCredentialsForComputer);

			//
			// UseAlternateComputerCred
			//
			cbData = sizeof( pProfileData->bUseAlternateComputerCred );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"UseAlternateComputerCred", 
									0,
									&dwType,
									(PBYTE)&(pProfileData->bUseAlternateComputerCred),
									&cbData );
		}

#endif // _WIN32_WCE

		if( dwReturnCode == NO_ERROR )
		{
#ifndef _WIN32_WCE
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read UseAlternateComputerCred %d"), pProfileData->bUseAlternateComputerCred);
#endif // _WIN32_WCE
			//
			// ServerCertificateLocal
			//
			cbData = sizeof( pProfileData->bServerCertificateLocal );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"ServerCertificateLocal", 
									0,
									&dwType,
									(PBYTE)&(pProfileData->bServerCertificateLocal),
									&cbData );
		}

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read ServerCertificateLocal %d"), pProfileData->bServerCertificateLocal);

			//
			// CheckForMicrosoftExtension
			//
			cbData = sizeof( pProfileData->bVerifyMSExtension );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"CheckForMicrosoftExtension", 
									0,
									&dwType,
									(PBYTE)&(pProfileData->bVerifyMSExtension),
									&cbData );
		}

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read VerifyMSExtension %d"), pProfileData->bVerifyMSExtension);

			//
			// UseEmptyOuterIdentity
			//
			cbData = sizeof( pProfileData->bUseEmptyIdentity );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"UseEmptyOuterIdentity", 
									0,
									&dwType,
									(PBYTE)&(pProfileData->bUseEmptyIdentity),
									&cbData );
		}

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read UseEmptyOuterIdentity %d"), pProfileData->bUseEmptyIdentity);

			//
			// AllowNewConnection
			//
			cbData = sizeof( pProfileData->bAllowNewConnection );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"AllowNewConnections", 
									0,
									&dwType,
									(PBYTE)&(pProfileData->bAllowNewConnection),
									&cbData );
		}

#ifndef _WIN32_WCE

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read AllowNewConnections %d"), 
				pProfileData->bAllowNewConnection);

			//
			// AllowNotifications
			//
			cbData = sizeof( pProfileData->bAllowNotifications );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"AllowNotifications", 
									0,
									&dwType,
									(PBYTE)&(pProfileData->bAllowNotifications),
									&cbData );
		}

		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read bAllowNotifications %d"), 
				pProfileData->bAllowNotifications);

			//
			// RenewIP
			//
			cbData = sizeof( pProfileData->bRenewIP );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"RenewIP", 
									0,
									&dwType,
									(PBYTE)&(pProfileData->bRenewIP),
									&cbData );
		}

#endif // _WIN32_WCE

		if( dwReturnCode == NO_ERROR )
		{
#ifndef _WIN32_WCE
			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read RenewIP %d"), pProfileData->bRenewIP);
#endif // _WIN32_WCE
			//
			// CurrentProfileId
			//
			cbData = sizeof( pProfileData->pwcCurrentProfileId );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"CurrentProfileId", 
									0,
									&dwType,
									(PBYTE)pProfileData->pwcCurrentProfileId,
									&cbData );
		}

#ifndef _WIN32_WCE
		if( dwReturnCode == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read CurrentProfileId %s"), 
				pProfileData->pwcCurrentProfileId);

			//
			// ProfileDescription
			//
			cbData = sizeof( pProfileData->pwcProfileDescription );

			dwReturnCode = RegQueryValueEx( hKeyLM, 
									L"ProfileDescription", 
									0,
									&dwType,
									(PBYTE)pProfileData->pwcProfileDescription,
									&cbData );
		}
#endif // _WIN32_WCE

		RegCloseKey( hKeyLM );
	}

	//
	// Read certificate config
	//
	if( dwReturnCode == NO_ERROR )
	{
#ifndef _WIN32_WCE
			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT("SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: read ProfileDescription %s"), 
				pProfileData->pwcProfileDescription);
#endif // _WIN32_WCE

		dwReturnCode = SW2_ReadCertificates( pwcProfileID, pProfileData );
	}

	//
	// Read computer credentials
	//
	if( dwReturnCode == NO_ERROR )
	{
#ifndef _WIN32_WCE
		if( pwcProfileID )
			swprintf_s( pwcTemp, 
						sizeof( pwcTemp )/sizeof(WCHAR),
						TEXT( "%s\\%s\\Credentials" ),
						SW2_METHOD_PROFILE_LOCATION,
						pwcProfileID );
		else
			swprintf_s( pwcTemp, 
						sizeof(pwcTemp)/sizeof(WCHAR),
						TEXT( "%s\\DEFAULT\\Credentials" ), 
						SW2_METHOD_PROFILE_LOCATION );
#else
		if( pwcProfileID )
			swprintf( pwcTemp, 
						TEXT( "%s\\%s\\Credentials" ),
						SW2_METHOD_PROFILE_LOCATION,
						pwcProfileID );
		else
			swprintf( pwcTemp, 
						TEXT( "%s\\DEFAULT\\Credentials" ), 
						SW2_METHOD_PROFILE_LOCATION );

#endif // _WIN32_WCE

#ifndef _WIN32_WCE

		//
		// Now try and read out the computer credentials
		// ignore any errors
		//
		if( dwReturnCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
							pwcTemp,
							0,
							KEY_READ,
							&hKeyLM ) == NO_ERROR )
		{
			//
			// ComputerName
			//
			cbData = sizeof( pProfileData->pwcCompName );

			if ((dwReturnCode = RegQueryValueEx( hKeyLM, 
												L"CompName", 
												0,
												&dwType,
												(PBYTE)pProfileData->pwcCompName,
												&cbData ))==NO_ERROR)
			{
				if( SW2_RegGetValue( hKeyLM, 
									L"CompPassword", 
									&pbData,
									&cbData ) == NO_ERROR )
				{
					if( ( dwReturnCode = SW2_XorData( pbData, 
										cbData, 
										(PBYTE)SW2_XOR, 
										( DWORD ) strlen( SW2_XOR ),
										&pbCompPassword ) ) == NO_ERROR )
					{
						memset( pProfileData->pwcCompPassword, 0, sizeof( pProfileData->pwcCompPassword ) );

						memcpy( pProfileData->pwcCompPassword,
								pbCompPassword,
								cbData );

						SW2FreeMemory((PVOID*)&pbCompPassword);
					}

					SW2FreeMemory((PVOID*)&pbData);
				}
			}

			if( dwReturnCode == NO_ERROR )
			{
				cbData = sizeof( pProfileData->pwcCompDomain );

				dwReturnCode = RegQueryValueEx( hKeyLM, 
										L"CompDomain", 
										0,
										&dwType,
										(PBYTE)pProfileData->pwcCompDomain,
										&cbData );
			}

			RegCloseKey( hKeyLM );
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_WARNING, 
				TEXT( "SW2_TRACE_LEVEL_WARNING::SW2_ReadProfile: could not open key (HKEY_LOCAL_MACHINE\\%s): %ld" ), 
				pwcTemp, dwReturnCode );
		}

		//
		// Error in credentials is ignored
		//
		dwReturnCode = NO_ERROR;
	}

	//
	// Read user credentials
	//
	if( dwReturnCode == NO_ERROR )
	{
		//
		// Check if we have a user token so we can read out Sid
		//
		if( hTokenImpersonateUser )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: using provided impersonate token" ) );

			hToken = hTokenImpersonateUser;
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: using token provided by thread" ) );

			if( !OpenThreadToken( GetCurrentThread(),
									TOKEN_QUERY,
									TRUE,
									&hToken ) )
			{
				SW2Trace( SW2_TRACE_LEVEL_WARNING, 
					TEXT( "SW2_TRACE_LEVEL_WARNING::SW2_ReadProfile: FAILED to read user thread token: %ld" ), 
					GetLastError() );

				hToken = NULL;

				//
				// Try by process
				//
				if( !OpenProcessToken( GetCurrentThread(),
										TOKEN_QUERY,
										&hToken ) )
				{
					SW2Trace( SW2_TRACE_LEVEL_WARNING, 
						TEXT( "SW2_TRACE_LEVEL_WARNING::SW2_ReadProfile: FAILED to read user process token: %ld" ), 
						GetLastError() );

					hToken = NULL;
				}
			}
		}

		if( hToken )
		{
			PBYTE		pbData;
			DWORD		cbData;
			PTOKEN_USER	pTokenUser;
			WCHAR		pwcSid[UNLEN];
			DWORD		cwcSid;

			cbData = 0;
						
			GetTokenInformation( hToken, 
									TokenUser,
									NULL,
									0,
									&cbData );

			if ((dwReturnCode = SW2AllocateMemory(cbData, (PVOID*) &pbData)) == NO_ERROR)
			{
				if( GetTokenInformation( hToken, 
										TokenUser,
										pbData,
										cbData,
										&cbData ) )
				{
					cwcSid = sizeof( pwcSid );

					pTokenUser = ( PTOKEN_USER ) pbData;

					if( SW2_GetTextualSid( pTokenUser->User.Sid,
										pwcSid,
										&cwcSid ) )
					{
						if( pwcProfileID )
							swprintf_s( pwcTemp, 
										sizeof( pwcTemp )/sizeof(WCHAR),
										TEXT( "%s\\%s\\%s\\Credentials" ), 
										pwcSid,
										SW2_METHOD_PROFILE_LOCATION,
										pwcProfileID );
						else
							swprintf_s( pwcTemp, 
										sizeof( pwcTemp )/sizeof(WCHAR),
										TEXT( "%s\\%s\\DEFAULT\\Credentials" ), 
										pwcSid,
										SW2_METHOD_PROFILE_LOCATION );

						dwReturnCode = RegOpenKeyEx( HKEY_USERS,
											pwcTemp,
											0,
											KEY_READ,
											&hKeyCU );
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_ReadProfile: SW2_GetTextualSid FAILED: %ld" ), 
							GetLastError() );		
						dwReturnCode = ERROR_CANTOPEN;
					}
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
						TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_ReadProfile: GetTokenInformation FAILED: %ld" ), 
						GetLastError() );		
					dwReturnCode = ERROR_CANTOPEN;
				}

				SW2FreeMemory((PVOID*)&pbData);
			}

			if( !hTokenImpersonateUser )
				CloseHandle( hToken );
		}
		else
		{
			dwReturnCode = RegOpenKeyEx( HKEY_CURRENT_USER,
								pwcTemp,
								0,
								KEY_READ,
								&hKeyCU );
		}

		if( dwReturnCode == NO_ERROR )
		{
#else
		if( ( dwReturnCode =  RegOpenKeyEx( HKEY_CURRENT_USER,
									pwcTemp,
									0,
									KEY_READ,
									&hKeyCU ) ) == ERROR_SUCCESS )
		{
#endif // _WIN32_WCE

			//
			// PromptUser
			//
			cbData = 1;

			dwReturnCode = RegQueryValueEx( hKeyCU, 
									L"PromptUser", 
									0,
									&dwType,
									(PBYTE)&(pProfileData->bPromptUser),
									&cbData );

			SW2Trace( SW2_TRACE_LEVEL_INFO,
				TEXT( "SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: RegQueryValueEx(PromptUser)(%ld): (%x)" ),
				dwReturnCode, pProfileData->bPromptUser );

			//
			// UserName
			//
			cbData = sizeof( pProfileData->pwcUserName );

			dwReturnCode = RegQueryValueEx( hKeyCU, 
									L"UserName", 
									0,
									&dwType,
									(PBYTE)pProfileData->pwcUserName,
									&cbData );

			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: RegQueryValueEx(UserName)(%ld): (%s)" ), 
				dwReturnCode, pProfileData->pwcUserName );

			if( dwReturnCode == NO_ERROR )
			{
				//
				// UserPassword
				//
				if( SW2_RegGetValue( hKeyCU, 
									L"UserPassword", 
									&pbData,
									&cbData ) == NO_ERROR )
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, 
						TEXT( "SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: UserPassword" ) );

					if( ( dwReturnCode = SW2_XorData( pbData, 
										cbData, 
										(PBYTE)SW2_XOR, 
										( DWORD ) strlen( SW2_XOR ),
										&pbUserPassword ) ) == NO_ERROR )
					{
						memset( pProfileData->pwcUserPassword, 0, sizeof( pProfileData->pwcUserPassword ) );

						memcpy( pProfileData->pwcUserPassword,
								pbUserPassword,
								cbData );

						SW2FreeMemory((PVOID*)&pbUserPassword);
					}

					SW2FreeMemory((PVOID*)&pbData);
				}
			}

			if( dwReturnCode == NO_ERROR )
			{
				//
				// UserDomain
				//
				cbData = sizeof( pProfileData->pwcUserDomain );

				dwReturnCode = RegQueryValueEx( hKeyCU, 
										L"UserDomain", 
										0,
										&dwType,
										(PBYTE)pProfileData->pwcUserDomain,
										&cbData );
			}

			RegCloseKey( hKeyCU );
		}

		//
		// Errors during user credentials are ignored
		//
		dwReturnCode = NO_ERROR;
	}

	if( pwcProfileID )
		wcscpy_s( pProfileData->pwcCurrentProfileId, 
			sizeof(pProfileData->pwcCurrentProfileId), 
			pwcProfileID );
	else
		wcscpy_s( pProfileData->pwcCurrentProfileId, 
			sizeof(pProfileData->pwcCurrentProfileId), 
			L"DEFAULT" );

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::SW2_ReadProfile: returning: %ld" ), 
		dwReturnCode );

	return dwReturnCode;
}

DWORD
SW2_ReadCertificates( IN WCHAR *pwcProfileID, IN OUT PSW2_PROFILE_DATA pProfileData )
{
	HKEY	hKeyLM;
	PBYTE	pbCertificate;
	WCHAR	pwcTemp[MAX_PATH*2];
	WCHAR	pwcTemp2[MAX_PATH*2];
	DWORD	i;
	PBYTE	pbData;
	DWORD	cbData;
	DWORD	dwDisposition = 0;
	DWORD	dwReturnCode = 0;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_ReadCertificates()") );

	//
	// Certificates
	//
	if( pwcProfileID )
		wsprintf( pwcTemp, 
					TEXT( "%s\\%s\\RootCACert" ), 
					SW2_METHOD_PROFILE_LOCATION,
					pwcProfileID );
	else
		wsprintf( pwcTemp, 
					TEXT( "%s\\DEFAULT\\RootCACert" ), 
					SW2_METHOD_PROFILE_LOCATION );


	pProfileData->dwNrOfTrustedRootCAInList = 0;

	if( ( RegOpenKeyEx( HKEY_LOCAL_MACHINE,
						pwcTemp,
						0,
						KEY_READ,
						&hKeyLM ) == ERROR_SUCCESS ) )
	{
		//
		// Now try and read the root certificates
		// ignore any errors
		//
		memset( pwcTemp2, 0, sizeof( pwcTemp2 ) );

		wsprintf( pwcTemp2, TEXT( "Certificate.0" ) );

		i = 1;

		while( (SW2_RegGetValue( hKeyLM, 
							pwcTemp2, 
							&pbData,
							&cbData ) == NO_ERROR ) &&
							i < SW2_MAX_CA)
		{
			if( ( dwReturnCode = SW2_XorData( pbData, 
								cbData, 
								(PBYTE)SW2_XOR, 
								( DWORD ) strlen( SW2_XOR ),
								&pbCertificate ) ) == NO_ERROR )
			{
				memcpy( pProfileData->pbTrustedRootCAList[pProfileData->dwNrOfTrustedRootCAInList],
						pbCertificate,
						cbData );

				pProfileData->dwNrOfTrustedRootCAInList++;

				SW2FreeMemory((PVOID*)&pbCertificate);
			}

			wsprintf( pwcTemp2, TEXT( "Certificate.%ld" ), i );

			i++;

			SW2FreeMemory((PVOID*)&pbData);
		}

		RegCloseKey( hKeyLM );
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::SW2_ReadCertificates: returning %ld, found %ld certificates" ), 
		dwReturnCode, pProfileData->dwNrOfTrustedRootCAInList );

	return dwReturnCode;
}

//
// Name: SW2_WriteCertificates
// Description: Writes the trusted Root CA List to the registry
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
SW2_WriteCertificates( IN WCHAR * pwcProfileId, IN SW2_PROFILE_DATA ProfileData )
{
	HKEY	hKeyLM;
	PBYTE	pbCertificate;
	WCHAR	pwcTemp[MAX_PATH*2];
	DWORD	i;
	DWORD	dwDisposition = 0;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteCertificates" ) );

	wsprintf( pwcTemp, 
			TEXT( "%s\\%s\\RootCACert" ), 
			SW2_METHOD_PROFILE_LOCATION,
			pwcProfileId );
				
	if( ( dwReturnCode = SW2_CreateSecureKey( HKEY_LOCAL_MACHINE,
									pwcTemp,
									&hKeyLM,
									&dwDisposition ) ) == NO_ERROR )
	{
		//
		// Remove previous certificates if any
		//
		i = 0;

		memset( pwcTemp, 0, sizeof( pwcTemp ) );

		wsprintf( pwcTemp, TEXT( "Certificate.0" ) );

		while( RegDeleteValue( hKeyLM,
								pwcTemp ) == ERROR_SUCCESS )
		{
			i++;

			wsprintf( pwcTemp, TEXT( "Certificate.%ld" ), i );
		}

		for( i=0; i < ProfileData.dwNrOfTrustedRootCAInList; i++ )
		{
			if( ( dwReturnCode = SW2_XorData( ( PBYTE ) ProfileData.pbTrustedRootCAList[i], 
							sizeof( ProfileData.pbTrustedRootCAList[i] ), 
							(PBYTE)SW2_XOR, 
							( DWORD ) strlen( SW2_XOR ),
							&pbCertificate ) ) == NO_ERROR )
			{
				memset( pwcTemp, 0, sizeof( pwcTemp ) );

				wsprintf( pwcTemp, TEXT( "Certificate.%ld" ), i );

				if( RegSetValueEx( hKeyLM,
									pwcTemp,
									0,
									REG_BINARY,
									pbCertificate,
									20 ) != ERROR_SUCCESS )
				{
					dwReturnCode = ERROR_CANTOPEN;
				}

				SW2FreeMemory((PVOID*)&pbCertificate);
			}
		}
							
		RegCloseKey( hKeyLM );
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteCertificates: returning: %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_WriteUserProfile
// Description: Writes the user part of the profile to the registry 
//				using the pwcProfileID. If hTokenImpersonateUser is 
//				defined and valid use it to write the profile 
//				information of the logged on user 
// Author: Tom Rixom
// Created: 31 Januari 2007
//
DWORD
SW2_WriteUserProfile(	IN WCHAR *pwcProfileID,
						IN HANDLE hTokenImpersonateUser,
						IN SW2_PROFILE_DATA ProfileData )
{
	HKEY				hKeyCU;
	HANDLE				hToken = NULL;
	WCHAR				pwcTemp[MAX_PATH*2];
	DWORD				dwDisposition;
	PBYTE				pbUserPassword;
	DWORD				i = 0;
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteUserProfile" ) );

	//
	// If we are running on an extension library then do not store any information at all
	//
	if (g_ResContext)
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteUserProfile::extension library found, NOT storing information" ) );

		return NO_ERROR;
	}

	//
	// If the EAPHOSTXML is being used then we do not save the user credentials
	//
	if (wcscmp(pwcProfileID, L"EAPHOSTXML")==0)
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteUserProfile::EAPHOSTXML profile found, user credentials are ignored" ) );

		return NO_ERROR;
	}

#ifndef _WIN32_WCE

	//
	// Check if we have a user token so we can read out Sid
	//
	if( hTokenImpersonateUser )
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, 
			TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteUserProfile::using provided impersonate token" ) );

		hToken = hTokenImpersonateUser;
	}
	else
	{
		if( !OpenThreadToken( GetCurrentThread(),
								TOKEN_QUERY,
								TRUE,
								&hToken ) )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteUserProfile: FAILED to read user thread token: %ld" ), 
				GetLastError() );

			hToken = NULL;

			//
			// Try by process
			//
			if( !OpenProcessToken( GetCurrentThread(),
									TOKEN_QUERY,
									&hToken ) )
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, 
					TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteUserProfile: FAILED to read user process token: %ld" ), 
					GetLastError() );

				hToken = NULL;
			}
		}
	}

	if( hToken )
	{
		PBYTE		pbData;
		DWORD		cbData;
		PTOKEN_USER	pTokenUser;
		WCHAR		pwcSid[UNLEN];
		DWORD		cwcSid;

		cbData = 0;
					
		GetTokenInformation( hTokenImpersonateUser, 
								TokenUser,
								NULL,
								0,
								&cbData );

		if ((dwReturnCode = SW2AllocateMemory(cbData, (PVOID*) &pbData)) == NO_ERROR)
		{
			if( GetTokenInformation( hTokenImpersonateUser, 
									TokenUser,
									pbData,
									cbData,
									&cbData ) )
			{
				cwcSid = sizeof( pwcSid );

				pTokenUser = ( PTOKEN_USER ) pbData;

				if( SW2_GetTextualSid( pTokenUser->User.Sid,
									pwcSid,
									&cwcSid ) )
				{
					memset( pwcTemp, 0, sizeof( pwcTemp ) );

					wsprintf( pwcTemp, 
								TEXT( "%s\\%s\\%s\\Credentials" ), 
								pwcSid,
								SW2_METHOD_PROFILE_LOCATION,
								pwcProfileID );

					dwReturnCode = RegCreateKeyEx(	HKEY_USERS, 
											pwcTemp, 
											0, 
											NULL, 
											0, 
											KEY_READ | KEY_WRITE, 
											NULL,
											&hKeyCU, 
											&dwDisposition );
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
						TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteUserProfile: SW2_GetTextualSid FAILED: %ld" ), 
						GetLastError() );		
					dwReturnCode = ERROR_CANTOPEN;
				}
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteUserProfile: GetTokenInformation FAILED: %ld" ), 
					GetLastError() );		
				dwReturnCode = ERROR_CANTOPEN;
			}

			SW2FreeMemory((PVOID*)&pbData);
		}
		else
			dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
	}
	else
	{
		wsprintf( pwcTemp, 
				TEXT( "%s\\%s\\Credentials" ), 
				SW2_METHOD_PROFILE_LOCATION,
				pwcProfileID );

		dwReturnCode = RegCreateKeyEx(	HKEY_CURRENT_USER, 
								pwcTemp, 
								0, 
								NULL, 
								0, 
								KEY_READ | KEY_WRITE, 
								NULL,
								&hKeyCU, 
								&dwDisposition );
	}

	if( dwReturnCode == NO_ERROR)
	{
#else
	wsprintf( pwcTemp, 
			TEXT( "%s\\%s\\Credentials" ), 
			SW2_METHOD_PROFILE_LOCATION,
			pwcProfileID );

	if( ( dwReturnCode = RegCreateKeyEx(	HKEY_CURRENT_USER, 
									pwcTemp, 
									0, 
									NULL, 
									0, 
									KEY_READ | KEY_WRITE, 
									NULL,
									&hKeyCU, 
									&dwDisposition ) ) == ERROR_SUCCESS )
	{
#endif // _WIN32_WCE
		//
		// PromptUser
		//
		RegSetValueEx( hKeyCU,
						L"PromptUser",
						0,
						REG_BINARY,
						( PBYTE ) &ProfileData.bPromptUser,
						1 );

		SW2Trace( SW2_TRACE_LEVEL_INFO, 
			TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteUserProfile: PromptUser: %ld" ),
			ProfileData.bPromptUser );

		//
		// Username
		//
		dwReturnCode = RegSetValueEx( hKeyCU,
							L"UserName",
							0,
							REG_EXPAND_SZ,
							( PBYTE ) ProfileData.pwcUserName,
							sizeof( ProfileData.pwcUserName ) );

		SW2Trace( SW2_TRACE_LEVEL_INFO, 
			TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteUserProfile: ProfileData.pwcUserName: %s" ), 
			ProfileData.pwcUserName );

		if( dwReturnCode == NO_ERROR )
		{
			//
			// UserPassword
			//
			if( ( dwReturnCode = SW2_XorData( ( PBYTE ) ProfileData.pwcUserPassword, 
								sizeof( ProfileData.pwcUserPassword ), 
								(PBYTE)SW2_XOR, 
								( DWORD ) strlen( SW2_XOR ),
								&pbUserPassword ) ) == NO_ERROR )
			{
				if( RegSetValueEx( hKeyCU,
									L"UserPassword",
									0,
									REG_BINARY,
									pbUserPassword,
									sizeof( ProfileData.pwcUserPassword ) ) != ERROR_SUCCESS )
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, 
						TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteUserProfile: failed to set UserPassword" ) );

					dwReturnCode = ERROR_CANTOPEN;
				}

				SW2FreeMemory((PVOID*)&pbUserPassword);
			}
		}

		if( dwReturnCode == NO_ERROR )
		{
			//
			// Domain
			//
			dwReturnCode = RegSetValueEx( hKeyCU,
								L"UserDomain",
								0,
								REG_EXPAND_SZ,
								( PBYTE ) ProfileData.pwcUserDomain,
								sizeof( ProfileData.pwcUserDomain ) );				
		}

		RegCloseKey( hKeyCU );
	}
#ifdef _WIN32_WCE
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteUserProfile: RegCreateKeyEx Failed: %ld" ), 
			dwReturnCode );
	}
#endif // _WIN32_WCE	

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteUserProfile: returning: %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_WriteComputerProfile
// Description: Writes a profile to the registry using the pwcProfileID
//				If hTokenImpersonateUser is defined and valid use it
//				to write the profile information of the logged on user 
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
SW2_WriteComputerProfile( IN WCHAR *pwcProfileID,
						  IN HANDLE hTokenImpersonateUser,
						  IN SW2_PROFILE_DATA ProfileData )
{
	HKEY				hKeyLM;
	HANDLE				hToken = NULL;
	WCHAR				pwcTemp[MAX_PATH*2];
	DWORD				dwDisposition;
#ifndef _WIN32_WCE
	PBYTE				pbCompPassword;
#endif // _WIN32_WCE
	DWORD				i = 0;
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteComputerProfile" ) );

	//
	// If we are running on an extension library then do not store any information at all
	//
	if (g_ResContext)
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteComputerProfile::extension library found, NOT storing information" ) );

		return NO_ERROR;
	}

	wsprintf( pwcTemp, 
				TEXT( "%s\\%s" ), 
				SW2_METHOD_PROFILE_LOCATION,
				pwcProfileID );

	if( SW2_CreateSecureKey( HKEY_LOCAL_MACHINE,
							pwcTemp,
							&hKeyLM,
							&dwDisposition ) == ERROR_SUCCESS )
	{
		//
		// Version
		//
		if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
									L"Version", 
									0,
									REG_BINARY,
									(PBYTE)&ProfileData.iVersion,
									sizeof(ProfileData.iVersion) ) ) != NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set Version" ) );
		}

		if( dwReturnCode == NO_ERROR )
		{
			//
			// AlloweCachePW
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"AllowCachePW", 
										0,
										REG_BINARY,
										(PBYTE)&ProfileData.bAllowCachePW,
										1 ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set AllowCachePW" ) );
			}
		}

#ifndef _WIN32_WCE
		if( dwReturnCode == NO_ERROR )
		{
			//
			// AltUsernameStr
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"AltUsernameStr", 
										0,
										REG_BINARY,
										(PBYTE)ProfileData.pwcAltUsernameStr,
										sizeof(ProfileData.pwcAltUsernameStr) ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set AltUsernameStr" ) );
			}
		}

		if( dwReturnCode == NO_ERROR )
		{
			//
			// AltPasswordStr
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"AltPasswordStr", 
										0,
										REG_BINARY,
										(PBYTE)ProfileData.pwcAltPasswordStr,
										sizeof(ProfileData.pwcAltPasswordStr) ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set AltPasswordStr" ) );
			}
		}

		if (dwReturnCode == NO_ERROR)
		{
			//
			// AltRePasswordStr
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"AltRePasswordStr", 
										0,
										REG_BINARY,
										(PBYTE)ProfileData.pwcAltRePasswordStr,
										sizeof(ProfileData.pwcAltRePasswordStr) ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set AltRePasswordStr" ) );
			}
		}

		if (dwReturnCode == NO_ERROR)
		{
			//
			// AltDomainStr
			//
			if ((dwReturnCode = RegSetValueEx( hKeyLM, 
										L"AltDomainStr", 
										0,
										REG_BINARY,
										(PBYTE)ProfileData.pwcAltDomainStr,
										sizeof(ProfileData.pwcAltDomainStr) ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set AltDomainStr" ) );
			}
		}

		if (dwReturnCode == NO_ERROR)
		{
			//
			// AltCredsTitle
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"AltCredsTitle", 
										0,
										REG_BINARY,
										(PBYTE)ProfileData.pwcAltCredsTitle,
										sizeof(ProfileData.pwcAltCredsTitle) ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set AltCredsTitle" ) );
			}
		}
#endif // _WIN32_WCE

		if( dwReturnCode == NO_ERROR )
		{
			//
			// InnerAuth
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"InnerAuth", 
										0,
										REG_BINARY,
										(PBYTE)ProfileData.pwcInnerAuth,
										sizeof(ProfileData.pwcInnerAuth) ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set InnerAuth" ) );
			}
		}

		if( dwReturnCode == NO_ERROR )
		{
			//
			// UseAlternateIdentity
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"UseAlternateOuterIdentity", 
										0,
										REG_BINARY,
										(PBYTE)&ProfileData.bUseAlternateIdentity,
										1 ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set UseAlternateIdentity" ) );
			}
		}

		if( dwReturnCode == NO_ERROR )
		{
			//
			// UseAnonymousIdentity
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"UseAnonymousOuterIdentity", 
										0,
										REG_BINARY,
										(PBYTE)&ProfileData.bUseAnonymousIdentity,
										1 ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set UseAnonymousIdentity" ) );
			}
		}

		if( dwReturnCode == NO_ERROR )
		{
			//
			// AlternateIdentity
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"AlternateOuterIdentity", 
										0,
										REG_BINARY,
										(PBYTE)ProfileData.pwcAlternateIdentity,
										sizeof( ProfileData.pwcAlternateIdentity) ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set AlternateIdentity" ) );
			}
		}

		if( dwReturnCode == NO_ERROR )
		{
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"VerifyServerCertificate", 
										0,
										REG_BINARY,
										(PBYTE)&ProfileData.bVerifyServerCertificate,
										1 ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set VerifyServerCertificate" ) );
			}
		}

		if( dwReturnCode == NO_ERROR )
		{
			//
			// VerifyServerName
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"VerifyServerName", 
										0,
										REG_BINARY,
										(PBYTE)&ProfileData.bVerifyServerName,
										1 ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set VerifyServerName" ) );
			}
		}

		if( dwReturnCode == NO_ERROR )
		{
			//
			// ServerCertificateLocal
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"ServerCertificateLocal", 
										0,
										REG_BINARY,
										(PBYTE)&ProfileData.bServerCertificateLocal,
										1 ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set ServerCertificateLocal" ) );
			}
		}

		if( dwReturnCode == NO_ERROR )
		{
			//
			// ServerName
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"ServerName", 
										0,
										REG_BINARY,
										(PBYTE)ProfileData.pwcServerName,
										sizeof(ProfileData.pwcServerName) ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set ServerName" ) );
			}
		}

#ifndef _WIN32_WCE

		if( dwReturnCode == NO_ERROR )
		{
			//
			// UseAlternateComputerCred
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"UseAlternateComputerCred", 
										0,
										REG_BINARY,
										(PBYTE)&ProfileData.bUseAlternateComputerCred,
										1 ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set UseAlternateComputerCred" ) );
			}
		}

		if( dwReturnCode == NO_ERROR )
		{
			//
			// UseCredentialsForComputer
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"UseUserCredentialsForComputer", 
										0,
										REG_BINARY,
										(PBYTE)&ProfileData.bUseUserCredentialsForComputer,
										1 ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set UseUserCredentialsForComputer" ) );
			}
		}
#endif // _WIN32_WCE

		if( dwReturnCode == NO_ERROR )
		{
			//
			// bPromptUser
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"PromptUser", 
										0,
										REG_BINARY,
										(PBYTE)&ProfileData.bPromptUser,
										1 ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set PromptUser" ) );
			}
		}

		if( dwReturnCode == NO_ERROR )
		{
			//
			// UseSessionResumption
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"UseSessionResumption", 
										0,
										REG_BINARY,
										(PBYTE)&ProfileData.bUseSessionResumption,
										1 ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set UseSessionResumption" ) );
			}
		}

#ifndef _WIN32_WCE

		if( dwReturnCode == NO_ERROR )
		{
			//
			// RenewIP
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"RenewIP", 
										0,
										REG_BINARY,
										(PBYTE)&ProfileData.bRenewIP,
										1 ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set RenewIP" ) );
			}
		}

#endif // _WIN32_WCE

		if( dwReturnCode == NO_ERROR )
		{
			//
			// CheckForMicrosoftExtension
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"CheckForMicrosoftExtension", 
										0,
										REG_BINARY,
										(PBYTE)&ProfileData.bVerifyMSExtension,
										1 ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set VerifyMSExtension" ) );
			}
		}

		if( dwReturnCode == NO_ERROR )
		{
			//
			// UseEmptyOuterIdentity
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"UseEmptyOuterIdentity", 
										0,
										REG_BINARY,
										(PBYTE)&ProfileData.bUseEmptyIdentity,
										sizeof( ProfileData.bUseEmptyIdentity) ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set UseEmptyOuterIdentity" ) );
			}
		}

		if( dwReturnCode == NO_ERROR )
		{
			//
			// AllowNewConnection
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"AllowNewConnections", 
										0,
										REG_BINARY,
										(PBYTE)&ProfileData.bAllowNewConnection,
										1 ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set AllowNewConnection" ) );
			}
		}

#ifndef _WIN32_WCE
		if( dwReturnCode == NO_ERROR )
		{
			//
			// AllowNotifications
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"AllowNotifications", 
										0,
										REG_BINARY,
										(PBYTE)&ProfileData.bAllowNotifications,
										1 ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set AllowNotifications" ) );
			}
		}
#endif // _WIN32_WCE

		if( dwReturnCode == NO_ERROR )
		{
			//
			// CurrentInnerEapMethod
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"CurrentInnerEapMethod", 
										0,
										REG_BINARY,
										(PBYTE)&ProfileData.dwCurrentInnerEapMethod,
										sizeof(ProfileData.dwCurrentInnerEapMethod) ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set CurrentInnerEapMethod" ) );
			}
		}

		if( dwReturnCode == NO_ERROR )
		{
			//
			// CurrentProfileId
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"CurrentProfileId", 
										0,
										REG_BINARY,
										(PBYTE)ProfileData.pwcCurrentProfileId,
										sizeof(ProfileData.pwcCurrentProfileId) ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set CurrentProfileId" ) );
			}
		}

		//
		// Currently the profile description is only used during 
		// installation on non Windows CE, to save space we ignore
		// this on Windows CE
		//
		// Windows CE only support registry keys up to 4096 bytes, so we need to save space
		//
		// 
#ifndef _WIN32_WCE
		if( dwReturnCode == NO_ERROR )
		{
			//
			// ProfileDescription
			//
			if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
										L"ProfileDescription", 
										0,
										REG_BINARY,
										(PBYTE)ProfileData.pwcProfileDescription,
										sizeof(ProfileData.pwcProfileDescription) ) ) != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set ProfileDescription" ) );
			}
		}
#endif _WIN32_WCE

		RegCloseKey( hKeyLM );

		dwReturnCode = SW2_WriteCertificates( pwcProfileID,
										ProfileData );

#ifndef _WIN32_WCE

		//
		// If the EAPHOSTXML is being used then we do not save the user credentials
		//
		if (wcscmp(pwcProfileID, L"EAPHOSTXML")!=0)
		{
			wsprintf( pwcTemp, 
						TEXT( "%s\\%s\\Credentials" ), 
						SW2_METHOD_PROFILE_LOCATION,
						pwcProfileID );

			//
			// Write the computer credentials
			//
			if( SW2_CreateAdminKey( HKEY_LOCAL_MACHINE,
											pwcTemp,
											&hKeyLM,
											&dwDisposition ) == NO_ERROR )
			{
				if( dwReturnCode == NO_ERROR )
				{
					//
					// Copy user info to computer info if required
					//
					if( ProfileData.bUseUserCredentialsForComputer && 
						!ProfileData.bUseAlternateComputerCred )
					{
						memset( ProfileData.pwcCompName, 0, sizeof( ProfileData.pwcCompName ) );
						memcpy( ProfileData.pwcCompName, ProfileData.pwcUserName, sizeof( ProfileData.pwcCompName ) );
						memset( ProfileData.pwcCompPassword, 0, sizeof( ProfileData.pwcCompPassword ) );
						memcpy( ProfileData.pwcCompPassword, ProfileData.pwcUserPassword, sizeof( ProfileData.pwcCompPassword ) );
						memset( ProfileData.pwcCompDomain, 0, sizeof( ProfileData.pwcCompDomain ) );
						memcpy( ProfileData.pwcCompDomain, ProfileData.pwcUserDomain, sizeof( ProfileData.pwcCompDomain ) );
					}
				
					//
					// CompName
					//
					if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
												L"CompName", 
												0,
												REG_BINARY,
												(PBYTE)ProfileData.pwcCompName,
												sizeof(ProfileData.pwcCompName) ) ) != NO_ERROR )
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set CompName" ) );
					}

					if( dwReturnCode == NO_ERROR )
					{

						//
						// ComputerPassword
						//
						if( ( dwReturnCode = SW2_XorData( ( PBYTE ) ProfileData.pwcCompPassword, 
											sizeof( ProfileData.pwcCompPassword ), 
											(PBYTE)SW2_XOR, 
											( DWORD ) strlen( SW2_XOR ),
											&pbCompPassword ) ) == NO_ERROR )
						{
							if( RegSetValueEx( hKeyLM,
												L"CompPassword",
												0,
												REG_BINARY,
												pbCompPassword,
												sizeof( ProfileData.pwcCompPassword ) ) != ERROR_SUCCESS )
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, 
									TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set ComputerPassword" ) );

								dwReturnCode = ERROR_CANTOPEN;
							}

							SW2FreeMemory((PVOID*)&pbCompPassword);
						}
					}

					if( dwReturnCode == NO_ERROR )
					{
						//
						// CompName
						//
						if( ( dwReturnCode = RegSetValueEx( hKeyLM, 
													L"CompDomain", 
													0,
													REG_BINARY,
													(PBYTE)ProfileData.pwcCompDomain,
													sizeof(ProfileData.pwcCompDomain) ) ) != NO_ERROR )
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, 
								TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteComputerProfile: failed to set CompDomain" ) );
						}
					}
				}

				RegCloseKey( hKeyLM );
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteUserProfile::EAPHOSTXML profile found, computer credentials are ignored" ) );
		}
#endif // _WIN32_WCE

	}
	else
		dwReturnCode = ERROR_CANTOPEN;

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteComputerProfile: returning: %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_ReadInnerEapMethod
// Description: Read the inner EAP information out of the registry
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
SW2_ReadInnerEapMethod( IN DWORD dwEapType, 
						IN WCHAR *pwcCurrentProfileId, 
						OUT PSW2_INNER_EAP_CONFIG_DATA pInnerEapConfigData )
{
	HKEY		hKey;
	HKEY		hKeyConfig;
	DWORD		dwType;
	PBYTE		pbConfigData;
	DWORD		cbConfigData;
	WCHAR		pwcTemp[MAX_PATH];
	WCHAR		*pwcFriendlyName;
	DWORD		cwcFriendlyName;
	WCHAR		*pwcConfigUiPath;
	DWORD		cwcConfigUiPath;
	WCHAR		*pwcIdentityPath;
	DWORD		cwcIdentityPath;
	WCHAR		*pwcInteractiveUIPath;
	DWORD		cwcInteractiveUIPath;
	WCHAR		*pwcPath;
	DWORD		cwcPath;
	DWORD		dwReturnCode;
	DWORD		dwErr = ERROR_SUCCESS;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_ReadInnerEapMethod( %ld )" ), dwEapType );

	memset( pInnerEapConfigData, 0, sizeof( SW2_INNER_EAP_CONFIG_DATA ) );

	pInnerEapConfigData->dwEapType = dwEapType;

	wsprintf( pwcTemp, L"%s\\%ld", EAP_EAP_METHOD_LOCATION, dwEapType );

	if( RegOpenKeyEx( HKEY_LOCAL_MACHINE,
						pwcTemp,
						0,
						KEY_QUERY_VALUE,
						&hKey ) == ERROR_SUCCESS )
	{
		dwType = 0;

		//
		// Read friendly name
		//
		if( ( dwReturnCode = SW2_RegGetValue( hKey, 
										L"FriendlyName", 
										( PBYTE * ) &pwcFriendlyName, 
										&cwcFriendlyName ) ) == NO_ERROR )
		{
			if( ( wcslen( pwcFriendlyName ) > 0 ) && 
				( wcslen( pwcFriendlyName ) + ( 1 * sizeof( WCHAR ) ) < UNLEN ) )
			{
#ifdef _WIN32_WCE
				memcpy( pInnerEapConfigData->pwcEapFriendlyName, 
						pwcFriendlyName, cwcFriendlyName );
#else
				if( ExpandEnvironmentStrings( pwcFriendlyName, 
												pInnerEapConfigData->pwcEapFriendlyName,
												UNLEN ) > 0 )
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, 
						TEXT( "SW2_TRACE_LEVEL_INFO::SW2_ReadInnerEapMethod: Friendly Name: %s" ), 
						pInnerEapConfigData->pwcEapFriendlyName );
				}
				else
				{
					dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
				}
#endif // _WIN32_WCE
			}
			else
			{
				dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
			}

			SW2FreeMemory((PVOID*)&pwcFriendlyName);
		}

		//
		// Read ConfigUiPath
		//
		if( dwReturnCode == NO_ERROR )
		{
			if( ( dwReturnCode = SW2_RegGetValue( hKey, 
										L"ConfigUiPath", 
										( PBYTE * ) &pwcConfigUiPath, 
										&cwcConfigUiPath ) ) == NO_ERROR )
			{
				if( ( wcslen( pwcConfigUiPath ) > 0 ) && 
					( wcslen( pwcConfigUiPath ) + ( 1 * sizeof( WCHAR ) ) < UNLEN ) )
				{
#ifdef _WIN32_WCE
					memcpy( pInnerEapConfigData->pwcEapConfigUiPath, pwcConfigUiPath, cwcConfigUiPath );
#else

					if( ExpandEnvironmentStrings( pwcConfigUiPath,
													pInnerEapConfigData->pwcEapConfigUiPath, UNLEN ) > 0 )
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, 
							TEXT( "SW2_TRACE_LEVEL_INFO::SW2_ReadInnerEapMethod: ConfigUiPath: %s" ), 
							pInnerEapConfigData->pwcEapConfigUiPath );
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_ReadInnerEapMethod: ExpandEnvironmentStrings Failed: %ld" ), 
							GetLastError() );

						dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
					}
#endif // _WIN32_WCE
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_ReadInnerEapMethod: ConfigUiPath value too large" ) );

					dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
				}

				SW2FreeMemory((PVOID*)&pwcConfigUiPath);
			}
			else
			{
				//
				// If this failed it just means we cannot configure the
				// EAP method
				//
				SW2Trace( SW2_TRACE_LEVEL_WARNING, 
						TEXT( "SW2_TRACE_LEVEL_WARNING::SW2_ReadInnerEapMethod: ConfigUiPath not defined, cannot configure EAP method" ) );

				dwReturnCode = NO_ERROR;

				memset( pInnerEapConfigData->pwcEapConfigUiPath, 0, UNLEN );
			}
		}

		//
		// Read IdentityPath
		//
		if( dwReturnCode == NO_ERROR )
		{
			if( ( dwReturnCode = SW2_RegGetValue( hKey, 
											L"IdentityPath", 
											( PBYTE * ) &pwcIdentityPath, 
											&cwcIdentityPath ) ) == NO_ERROR )
			{
				if( ( wcslen( pwcIdentityPath ) > 0 ) && 
					( wcslen( pwcIdentityPath ) + ( 1 * sizeof( WCHAR ) ) < UNLEN ) )
				{
#ifdef _WIN32_WCE
					memcpy( pInnerEapConfigData->pwcEapIdentityPath, pwcIdentityPath, cwcIdentityPath );
#else

					if( ExpandEnvironmentStrings( pwcIdentityPath, 
													pInnerEapConfigData->pwcEapIdentityPath, 
													UNLEN ) > 0 )
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, 
							TEXT( "SW2_TRACE_LEVEL_INFO::SW2_ReadInnerEapMethod: IdentityPath: %s" ), 
							pInnerEapConfigData->pwcEapIdentityPath );
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_ReadInnerEapMethod: ExpandEnvironmentStrings Failed: %ld" ), 
							GetLastError() );

						dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
					}
#endif // _WIN32_WCE
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_ReadInnerEapMethod: IdentityPath value too large" ) );

					dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
				}

				SW2FreeMemory((PVOID*)&pwcIdentityPath);
			}
			else
			{
				//
				// If this failed it just means we cannot use this function with the
				// EAP method
				//
				SW2Trace( SW2_TRACE_LEVEL_WARNING, 
						TEXT( "SW2_TRACE_LEVEL_WARNING::SW2_ReadInnerEapMethod: IdentityPath not defined, EAP method not used for identity" ) );

				dwReturnCode = NO_ERROR;

				memset( pInnerEapConfigData->pwcEapIdentityPath, 0, UNLEN );
			}
		}

		//
		// Read InteractiveUIPath
		//
		if( dwReturnCode == NO_ERROR )
		{
			if( ( dwReturnCode = SW2_RegGetValue( hKey, 
											L"InteractiveUIPath", 
											( PBYTE * ) &pwcInteractiveUIPath, 
											&cwcInteractiveUIPath ) ) == NO_ERROR )
			{
				if( ( wcslen( pwcInteractiveUIPath ) > 0 ) && 
					( wcslen( pwcInteractiveUIPath ) + ( 1 * sizeof( WCHAR ) ) < UNLEN ) )
				{
#ifdef _WIN32_WCE
					memcpy( pInnerEapConfigData->pwcEapInteractiveUIPath, 
							pwcInteractiveUIPath, 
							cwcInteractiveUIPath );
#else

					if( ExpandEnvironmentStrings( pwcInteractiveUIPath, 
													pInnerEapConfigData->pwcEapInteractiveUIPath, 
UNLEN ) > 0 )
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, 
							TEXT( "SW2_TRACE_LEVEL_INFO::SW2_ReadInnerEapMethod: InteractiveUIPath: %s" ), pInnerEapConfigData->pwcEapInteractiveUIPath );
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_ReadInnerEapMethod: ExpandEnvironmentStrings Failed: %ld" ), 
							GetLastError() );

						dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
					}
#endif // _WIN32_WCE
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_ReadInnerEapMethod: InteractiveUIPath value too large" ) );

					dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
				}

				SW2FreeMemory((PVOID*)&pwcInteractiveUIPath);
			}
			else
			{
				//
				// If this failed it just means we cannot use this function with the
				// EAP method
				//
				SW2Trace( SW2_TRACE_LEVEL_WARNING, 
						TEXT( "SW2_TRACE_LEVEL_WARNING::SW2_ReadInnerEapMethod: InteractiveUIPath not defined, EAP method not used for interactive UI" ) );

				dwReturnCode = NO_ERROR;

				memset( pInnerEapConfigData->pwcEapIdentityPath, 0, UNLEN );
			}
		}

		//
		// Read Path
		//
		if( dwReturnCode == NO_ERROR )
		{
			if( ( dwReturnCode = SW2_RegGetValue( hKey, 
										L"Path", 
										( PBYTE * ) 
										&pwcPath, 
										&cwcPath ) ) == NO_ERROR )
			{
				if( ( wcslen( pwcPath ) > 0 ) && 
					( wcslen( pwcPath ) + ( 1 * sizeof( WCHAR ) ) < UNLEN ) )
				{
#ifdef _WIN32_WCE
					memcpy( pInnerEapConfigData->pwcEapPath, pwcPath, cwcPath );
#else
					if( ExpandEnvironmentStrings( pwcPath, 
													pInnerEapConfigData->pwcEapPath, 
													UNLEN ) > 0 )
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, 
							TEXT( "SW2_TRACE_LEVEL_INFO::SW2_ReadInnerEapMethod: Path: %s" ), pInnerEapConfigData->pwcEapPath );
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_ReadInnerEapMethod: ExpandEnvironmentStrings Failed: %ld" ), 
							GetLastError() );

						dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
					}
#endif // _WIN32_WCE
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_ReadInnerEapMethod: Path value too large" ) );

					dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
				}

				SW2FreeMemory((PVOID*)&pwcPath);
			}
		}

		if( dwReturnCode == NO_ERROR )
		{
			pInnerEapConfigData->dwInvokeUsernameDlg = 0;

			if( SW2_RegGetDWORDValue( hKey, 
									L"InvokeUsernameDialog", 
									&pInnerEapConfigData->dwInvokeUsernameDlg ) != NO_ERROR )
				pInnerEapConfigData->dwInvokeUsernameDlg = 0;

			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::SW2_ReadInnerEapMethod: dwInvokeUsernameDlg: %ld" ), 
				pInnerEapConfigData->dwInvokeUsernameDlg );

			if( SW2_RegGetDWORDValue( hKey, 
									L"InvokePasswordDialog", 
									&pInnerEapConfigData->dwInvokePasswordDlg ) != NO_ERROR )
				pInnerEapConfigData->dwInvokePasswordDlg = 0;

			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::SW2_ReadInnerEapMethod: dwInvokePasswordDlg: %ld" ), 
				pInnerEapConfigData->dwInvokePasswordDlg );
		}

		//
		// Read configuration data
		//
		wsprintf( pwcTemp, 
					TEXT( "%s\\%s\\%ld" ),
					SW2_METHOD_PROFILE_LOCATION, 
					pwcCurrentProfileId,
					dwEapType );
		//
		// Open Registry entry for this inner EAP module and try to read config
		//
		if( dwReturnCode == NO_ERROR )
		{
			if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
							pwcTemp,
							0,
							KEY_READ,
							&hKeyConfig) == ERROR_SUCCESS)
			{
				//
				// Load previous config or else create new config
				//
				if( ( dwReturnCode = SW2_RegGetValue( hKeyConfig, 
											L"ConfigData", 
											&pbConfigData,
											&cbConfigData ) ) == NO_ERROR )
				{
					if( cbConfigData <= EAP_MAX_INNER_CONNECTION_DATA)
					{
						pInnerEapConfigData->cbConnectionData = cbConfigData;

						memcpy( pInnerEapConfigData->pbConnectionData,
								pbConfigData,
								pInnerEapConfigData->cbConnectionData );
					}
					else
						dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

					SW2FreeMemory((PVOID*)&pbConfigData);

					cbConfigData = 0;
				}

				if( dwReturnCode != NO_ERROR )
				{
					//
					// Couldn't read config so default back to empty config
					// reset error
					//
					dwReturnCode = NO_ERROR;

					memset( pInnerEapConfigData->pbConnectionData, 
							0,
							sizeof( pInnerEapConfigData->pbConnectionData ) );

					pInnerEapConfigData->cbConnectionData = 0;
				}

				RegCloseKey( hKeyConfig );
			}
			else
			{
				//
				// Create new empty config
				//
				memset( pInnerEapConfigData->pbConnectionData, 
						0,
						sizeof( pInnerEapConfigData->pbConnectionData ) );

				pInnerEapConfigData->cbConnectionData = 0;
			}
		}

		RegCloseKey( hKey );
	}
	else
		dwReturnCode = ERROR_CANTOPEN;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_ReadInnerEapMethod: returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_WriteInnerEapMethod
// Description: Write the inner EAP information to the registry
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
SW2_WriteInnerEapMethod( IN DWORD dwEapType, 
						IN WCHAR *pwcCurrentProfileId,
						IN PBYTE pbConnectionData,
						IN DWORD cbConnectionData)
{
	HKEY		hKey;
	WCHAR		pwcTemp[1024];
	DWORD		dwReturnCode;
	DWORD		dwDisposition;
	DWORD		dwErr = ERROR_SUCCESS;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteInnerEapMethod( %ld )" ), dwEapType );

	if (g_ResContext)
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteInnerEapMethod::extension library found, NOT storing information" ) );

		return NO_ERROR;
	}

	//
	// Write configuration data
	//
	wsprintf( pwcTemp, 
				TEXT( "%s\\%s\\%ld" ), 
				SW2_METHOD_PROFILE_LOCATION, 
				pwcCurrentProfileId,
				dwEapType );

	//
	// Open Registry entry for this inner EAP module
	//
	if( SW2_CreateSecureKey( HKEY_LOCAL_MACHINE,
							pwcTemp,
							&hKey,
							&dwDisposition ) == ERROR_SUCCESS )
	{
		//
		// Save previous config if any else create new config
		//
		if( RegSetValueEx( hKey,
							L"ConfigData",
							0,
							REG_BINARY,
							pbConnectionData,
							cbConnectionData ) != ERROR_SUCCESS )
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_WriteInnerEapMethod: could not write ConfigData" ) );

			dwReturnCode = ERROR_CANTOPEN;
		}

		RegCloseKey( hKey );
	}
	else
		dwReturnCode = ERROR_CANTOPEN;

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::SW2_WriteInnerEapMethod: returning %ld" ), dwReturnCode );

	return dwReturnCode;
}