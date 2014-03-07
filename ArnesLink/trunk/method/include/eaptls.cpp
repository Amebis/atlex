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
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "msxml6.lib")

//
// Initialize the module
//
DWORD SW2EapMethodInitialize()
{
	BOOL	bInvokeUI;
	DWORD	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInitialize()");
	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInitialize()::running on %ld (g_dwMajorVersion) - %ld (g_dwMinorVersion)", g_dwMajorVersion, g_dwMinorVersion);

	SW2_HandleError(dwReturnCode, 
					SW2_EAP_FUNCTION_Initialize, 
					SW2_TLS_STATE_None,
					&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInitialize()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

//
// De-Initialize the module
//
DWORD SW2EapMethodDeInitialize()
{
#ifndef _WIN32_WCE
	DWORD	dwFree;
#endif // _WIN32_WCE
	BOOL	bInvokeUI;
	DWORD	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodDeInitialize()");

#ifndef _WIN32_WCE
	// free up any memory that is flying about
	if ((dwFree = ( DWORD) HeapCompact( g_localHeap, 0 ))>0)
		SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodDeInitialize()::compacted %ld memory", dwFree);
	else
		SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodDeInitialize()::failed to compact memory (%ld)", 
		GetLastError());
#endif // _WIN32_WCE

	SW2_HandleError(dwReturnCode, 
		SW2_EAP_FUNCTION_DeInitialize, 
		SW2_TLS_STATE_None,
		&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodDeInitialize()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

//
// Handle outer identity according to configuration
//
DWORD SW2HandleOuterIdentity(IN PSW2_PROFILE_DATA	pProfileData,
							 IN PSW2_USER_DATA		pUserData,
							 OUT PWCHAR				*pwcOuterIdentity)
{
	WCHAR	pwcUsername[UNLEN];
	PWCHAR	pwcDomain;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2HandleOuterIdentity" ) );

	*pwcOuterIdentity = NULL;

	if( ( pwcDomain = wcsstr( pUserData->pwcUsername, L"@" ) ) )
	{
		memset( pwcUsername, 0, UNLEN * sizeof( WCHAR ) );

		wcsncpy( pwcUsername, 
			pUserData->pwcUsername, 
			wcslen( pUserData->pwcUsername ) - wcslen( pwcDomain ) );

		if (wcslen(pwcDomain)>0)
		{
			//
			// strip domain from pwcUsername and copy it to pwcDomain
			//
			pwcDomain++;

			//
			// Clear the domain first before copying the data, 
			// BUG-Fix 05 October 2005, Tom Rixom
			//
			memset( pUserData->pwcDomain, 0, sizeof( pUserData->pwcDomain ) );

			memcpy( pUserData->pwcDomain, pwcDomain, ( wcslen( pwcDomain ) * sizeof( WCHAR ) ) );
		}

		memset( pUserData->pwcUsername, 0, UNLEN * sizeof( WCHAR ) );

		wcscpy( pUserData->pwcUsername, pwcUsername );
	}

	if (pProfileData->bUseAlternateIdentity)
	{
		if (pProfileData->bUseAnonymousIdentity)
		{
			if (pProfileData->bUseEmptyIdentity)
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2HandleOuterIdentity::using empty alternate outer identity" ) );

				//
				// Outer authentication will be "@domain" or ""
				// conforms with RFC 4282 in which the username part of the identity is stripped completely
				//
				if (wcslen(pUserData->pwcDomain) > 0)
				{
					if ((dwReturnCode = SW2AllocateMemory(
						(1 + (DWORD)wcslen(pUserData->pwcDomain) + 1) * sizeof(WCHAR), 
						(PVOID*) pwcOuterIdentity)) == NO_ERROR)
					{
#ifndef _WIN32_WCE
						swprintf_s( *pwcOuterIdentity, 1 + wcslen( pUserData->pwcDomain ) + 1, L"@%s", pUserData->pwcDomain );
#else
						swprintf( *pwcOuterIdentity, L"@%s", pUserData->pwcDomain );
#endif // _WIN32_WCE
					}
				}
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2HandleOuterIdentity::using anonymous alternate outer identity"));

				if (wcslen(pUserData->pwcDomain) > 0)
				{
					if ((dwReturnCode = SW2AllocateMemory(
						( (DWORD)wcslen( L"anonymous" ) + 1 + (DWORD)wcslen(pUserData->pwcDomain) + 1) * sizeof(WCHAR), 
						(PVOID*) pwcOuterIdentity)) == NO_ERROR)
					{
#ifndef _WIN32_WCE
						swprintf_s( *pwcOuterIdentity, 
							wcslen( L"anonymous" ) + 1 + wcslen( pUserData->pwcDomain ) + 1, 
							L"anonymous@%s", pUserData->pwcDomain );
#else
						swprintf( *pwcOuterIdentity, L"anonymous@%s", pUserData->pwcDomain );
#endif // _WIN32_WCE
					}
				}
				else
				{
					if ((dwReturnCode = SW2AllocateMemory(
						( (DWORD)wcslen( L"anonymous" ) + 1) * sizeof(WCHAR), (PVOID*) pwcOuterIdentity)) == NO_ERROR)
					{
#ifndef _WIN32_WCE
						swprintf_s( *pwcOuterIdentity, 
							wcslen( L"anonymous" ) + 1, 
							L"anonymous", pUserData->pwcDomain );
#else
						swprintf( *pwcOuterIdentity, L"anonymous" );
#endif // _WIN32_WCE
					}
				}
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2HandleOuterIdentity::using specified alternate outer identity" ) );

			//
			// Outer authentication will alternate username
			//
			if ((dwReturnCode = SW2AllocateMemory(
						((DWORD)wcslen(pProfileData->pwcAlternateIdentity) + 1) * sizeof(WCHAR), 
						(PVOID*) pwcOuterIdentity)) == NO_ERROR)
			{
				wcscpy_s( *pwcOuterIdentity, 
							(DWORD)wcslen( pProfileData->pwcAlternateIdentity) + 1, 
							pProfileData->pwcAlternateIdentity );
			}
		}
	}
	else
	{
		//
		// Outer authentication will be user@domain
		//
		if ((dwReturnCode = SW2AllocateMemory(
						((DWORD)wcslen( pUserData->pwcUsername ) + 1 + (DWORD)wcslen( pUserData->pwcDomain ) + 1) * sizeof(WCHAR), 
						(PVOID*) pwcOuterIdentity)) == NO_ERROR)
		{
			wcscpy( *pwcOuterIdentity, pUserData->pwcUsername );

			if( wcslen( pUserData->pwcDomain ) > 0 )
			{
				wcscat( *pwcOuterIdentity, L"@" );
				wcscat( *pwcOuterIdentity, pUserData->pwcDomain );
			}
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2HandleOuterIdentity::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}


DWORD SW2EapMethodGetUserIdentity(IN DWORD				dwFlags,
								  IN PSW2_PROFILE_DATA	pProfileData, 								 
								  IN PSW2_USER_DATA		pUserData,
								  OUT BOOL				*pfInvokeUI)
{
	WCHAR	pwcUsername[UNLEN];
	WCHAR	*pwcIdentity = NULL;
	WCHAR	*pwcTemp;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetUserIdentity" ) );

	if (dwFlags & RAS_EAP_FLAG_MACHINE_AUTH)
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetUserIdentity::Authenticating as computer" ) );	

#ifndef _WIN32_WCE

		//
		// Authenticating as machine
		//
		if( ( pProfileData->bUseAlternateComputerCred ||
			pProfileData->bUseUserCredentialsForComputer ) &&
			( wcslen( pProfileData->pwcCompName ) > 0 ) &&
			( wcslen( pProfileData->pwcCompPassword ) > 0 ) )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetUserIdentity::using computer credentials" ) );

			//
			// Can copy the password as we should have been able to read it
			//
			memcpy( pUserData->pwcUsername, 
					pProfileData->pwcCompName, 
					sizeof( pUserData->pwcUsername ) );
			memcpy( pUserData->pwcPassword, 
					pProfileData->pwcCompPassword, 
					sizeof( pUserData->pwcPassword ) );
			memcpy( pUserData->pwcDomain, 
					pProfileData->pwcCompDomain, 
					sizeof( pUserData->pwcDomain ) );
		}
		else
#endif // _WIN32_WCE
			dwReturnCode = ERROR_NO_SUCH_USER;
	}
	else
	{
		if (pProfileData->bPromptUser)
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetUserIdentity::requesting user interface" ) );

			*pfInvokeUI = TRUE;

			return dwReturnCode;
		}
		else if(wcslen(pProfileData->pwcUserName ) > 0) //overwrite user data with config data
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetUserIdentity::using user credentials" ) );

			memcpy( pUserData->pwcUsername, 
					pProfileData->pwcUserName, 
					sizeof( pUserData->pwcUsername ) );

			memcpy( pUserData->pwcDomain, 
					pProfileData->pwcUserDomain, 
					sizeof( pUserData->pwcDomain ) );

			memcpy( pUserData->pwcPassword, 
					pProfileData->pwcUserPassword, 
					sizeof( pUserData->pwcPassword ) );
		}
		else if (wcslen(pUserData->pwcUsername)>0) // use user data provided by MS
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetUserIdentity::using user data provided by MS" ) );
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodGetUserIdentity::could not determine user credentials" ) );

			dwReturnCode = ERROR_NO_SUCH_USER;
		}

		if (dwReturnCode == NO_ERROR)
		{
			//
			// It is possible to put the domain name in the following form:
			// tom@tom.com
			//
			if ((pwcTemp = wcsstr(pUserData->pwcUsername, L"@")))
			{
				memset(pwcUsername, 0, UNLEN * sizeof(WCHAR));

				wcsncpy( pwcUsername, pUserData->pwcUsername, wcslen( pUserData->pwcUsername ) - wcslen( pwcTemp ) );

				//
				// strip domain from pwcUsername and copy it to pwcDomain
				//
				pwcTemp++;

				memset( pUserData->pwcDomain, 0, sizeof( pUserData->pwcDomain ) );

				memcpy( pUserData->pwcDomain, pwcTemp, ( wcslen( pwcTemp ) * sizeof( WCHAR ) ) );

				memset( pUserData->pwcUsername, 0, UNLEN * sizeof( WCHAR ) );

				wcscpy( pUserData->pwcUsername, pwcUsername );
			}

			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetUserIdentity::inner username: %s" ), pUserData->pwcUsername );
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetUserIdentity::inner domain: %s" ), pUserData->pwcDomain );
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetUserIdentity::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

DWORD SW2EapMethodGetEAPHOSTIdentity(IN DWORD				dwFlags,
									 IN PSW2_PROFILE_DATA	pProfileData,
									 IN PSW2_USER_DATA		pUserData,
									 OUT BOOL				*pfInvokeUI)
{
#ifndef SW2_EAP_HOST
	return ERROR_NOT_SUPPORTED;
#else
	PBYTE						pbInnerEapUserDataOut = NULL;
	DWORD						dwInnerEapUserDataOut = 0;
	WCHAR						*pwcIdentity;
	DWORD						dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::RasEapGetEAPHOSTIdentity" ) );

	memset( pUserData, 0, sizeof( SW2_USER_DATA ) );

	pUserData->PrevAuthResult = PREV_AUTH_RESULT_pending;

	if( ( dwReturnCode = EapHostPeerInitialize() ) == NO_ERROR )
	{
		DWORD						dwFlags = 0;
		EAP_METHOD_TYPE				eapMethodType;
		HANDLE						hTokenImpersonateUser = NULL;
		size_t						threadId = 0;
		EAP_SESSIONID				eapSessionId = 0;
		EAP_ERROR					*pEapError = NULL;
		EapPacket					*pEapSendPacket;
		DWORD						dwSizeOfEapSendPacket;
		EapPacket					eapReceivePacket;
		EapHostPeerResponseAction	eapHostPeerResponseAction;
		PCHAR						pcIdentity;

		eapMethodType.eapType.type = 6;
		eapMethodType.eapType.dwVendorId = 0;
		eapMethodType.eapType.dwVendorType = 0;
		eapMethodType.dwAuthorId = 311;

		if( ( dwReturnCode = EapHostPeerBeginSession( 
						dwFlags,					//Flags
						eapMethodType,				//EAP_METHOD_TYPE
						NULL,						//EapAttributes
						hTokenImpersonateUser,		//HANDLE
						0,							//Connection Data Size
						NULL,						//Connection Data
						0,							//User Data Size
						NULL,	 					//User Data
						1400,						//Max Packet
						NULL,						//ConnectionId
						NULL,					 	//Notification Call Back Handler
						NULL,						//Context Data (Thread Identifier)
						&eapSessionId,   			// Session Id
						&pEapError ) ) == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::RasEapGetEAPHOSTIdentity::pInnerEapHostPeerBeginSession succeeded, eapSessionId: %ld" ),
				eapSessionId );

			//
			// Fill the elments of the Identity Request Packet.
			//
			eapReceivePacket.Code = EapCodeRequest;
			eapReceivePacket.Id = 0;
			SW2_HostToWireFormat16( 5, ( PBYTE ) &( eapReceivePacket.Length ) );
			eapReceivePacket.Data[0] = 0x01; //Identity Request Type

			if( ( dwReturnCode = EapHostPeerProcessReceivedPacket(
				eapSessionId,					//Session Id	
				5,								//Length of the Packet
				(PBYTE) &eapReceivePacket,				//Packet
				&eapHostPeerResponseAction,		//EapHostPeerResponseAction
				&pEapError
				) ) == NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::RasEapGetEAPHOSTIdentity::EapHostPeerProcessReceivedPacket succeeded: %ld" ), 
					eapHostPeerResponseAction );

				switch( eapHostPeerResponseAction )
				{
					case EapHostPeerResponseSend:
						
						dwSizeOfEapSendPacket = 0;

						//
						// Send identity packet to retrieve inner eap identity
						//
						if( ( dwReturnCode = EapHostPeerGetSendPacket(
										eapSessionId, 
										&dwSizeOfEapSendPacket,
										( PBYTE * ) &pEapSendPacket,
										&pEapError ) ) == NO_ERROR )
						{
							SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::RasEapGetEAPHOSTIdentity::EapHostPeerGetSendPacket succeeded, sending packet(%ld):" ), dwSizeOfEapSendPacket );
							SW2Dump( SW2_TRACE_LEVEL_INFO,  ( PBYTE ) pEapSendPacket, dwSizeOfEapSendPacket );

							//
							// Extract identity
							//
							!!if( ( pcIdentity = ( CHAR* ) malloc( dwSizeOfEapSendPacket - 5 + 1 ) ) )
							{
								//
								// Copy to string
								//
								memset( pcIdentity, 0, dwSizeOfEapSendPacket - 5 + 1 );

								memcpy_s( pcIdentity, dwSizeOfEapSendPacket - 5 + 1, &pEapSendPacket->Data[1], dwSizeOfEapSendPacket - 5 );

								//
								// Convert to wide char string
								//
								if( ( pwcIdentity = ( WCHAR* ) malloc( ( dwSizeOfEapSendPacket - 5 + 1 ) * sizeof( WCHAR ) ) ) )
								{
									memset( pwcIdentity, 0, dwSizeOfEapSendPacket - 5 + 1 );

									if( MultiByteToWideChar( CP_ACP, 0, pcIdentity, -1, pwcIdentity, dwSizeOfEapSendPacket - 5 + 1 ) > 0 )
									{
										SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::RasEapGetEAPHOSTIdentity::EapHostPeerGetSendPacket:: pwcIdentity: %s" ), pwcIdentity );
									}
									else
										dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

									if( dwReturnCode != NO_ERROR )
										SW2FreeMemory((PVOID*)&pwcIdentity);
								}
								else
									dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

								SW2FreeMemory((PVOID*)&pcIdentity);
							}
							else
								dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::RasEapGetEAPHOSTIdentity::EapHostPeerGetSendPacket failed: %ld" ), dwReturnCode );

							if( pEapError )
								EapHostPeerFreeEapError( pEapError );
						}

						if( dwReturnCode == NO_ERROR )
						{
							if( pwcIdentity )
							{
								if( wcslen( pwcIdentity ) )
								{
									//
									// Copy the inner Identity
									//
									if( wcslen( pwcIdentity ) <= ( UNLEN * sizeof( WCHAR ) ) )
									{
										wcscpy_s( pUserData->InnerEapUserData.pwcIdentity, 
											sizeof( pUserData->InnerEapUserData.pwcIdentity ),
											pwcIdentity );

										//
										// Check if we have an @ in the inner identity which will be followed by the domain
										//
										if( ( pwcDomain = wcsstr( pUserData->InnerEapUserData.pwcIdentity, L"@" ) ) )
										{
											if (wcslen(pwcDomain)>1)
											{
												pwcDomain = pwcDomain + 1;

												memset( pUserData->pwcUsername, 0, sizeof( pUserData->pwcUsername ) );

												//
												// Copy username
												//
												wcsncpy_s( pUserData->pwcUsername, 
													sizeof( pUserData->pwcUsername ), 
													pUserData->InnerEapUserData.pwcIdentity,
													wcslen( pwcDomain ) - 1 );

												memset( pUserData->pwcDomain, 0, sizeof( pUserData->pwcDomain ) );

												//
												// Copy domainname
												//
												wcsncpy_s( pUserData->pwcDomain, 
													sizeof( pUserData->pwcDomain ), 
													pwcDomain,
													wcslen( pwcDomain ) );
											}
										}
										else
										{
											wcscpy_s( pUserData->pwcUsername, sizeof( pUserData->pwcUsername ),
												pUserData->InnerEapUserData.pwcIdentity );
										}
									}
									else
									{
										SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::RasEapGetEAPHOSTIdentity::pwcInnerEapIdentityOut is too large" ) );

										dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
									}
								}
							}
							else
							{
								dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
							}
						}

					break;

					default:

						dwReturnCode = ERROR_NOT_SUPPORTED;

					break;
				}
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::RasEapGetEAPHOSTIdentity::EapHostPeerProcessReceivedPacket failed: %ld" ), dwReturnCode );

				if( pEapError )
					EapHostPeerFreeEapError( pEapError );
			}

			EapHostPeerEndSession(eapSessionId, &pEapError);
		}
		else
		{
			if( pEapError )
				EapHostPeerFreeEapError( pEapError );
		}

		EapHostPeerUninitialize();
	}
	else
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::RasEapGetEAPHOSTIdentity::pInnerEapHostPeerInitialize failed: %ld" ), dwReturnCode );

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::RasEapGetEAPHOSTIdentity::returning %ld" ), dwReturnCode );

	return dwReturnCode;
#endif // SW2_EAP_HOST
}

DWORD SW2EapMethodGetEAPIdentity(IN HWND				hWndParent,
								 IN DWORD				dwFlags,
								 IN PSW2_PROFILE_DATA	pProfileData, 														 
								 IN PSW2_USER_DATA		pUserData)
{
//	PWCHAR						pwcDomain;
	HINSTANCE					hEapInstance;
	PBYTE						pbInnerEapUserDataOut = NULL;
	DWORD						dwInnerEapUserDataOut = 0;
	SW2_INNER_EAP_CONFIG_DATA	InnerEapConfigData;
	PINNEREAPGETIDENTITY		pInnerEapGetIdentity;
	PINNEREAPFREEMEMORY			pInnerEapFreeMemory;
	WCHAR						*pwcInnerEapIdentityOut;
	BOOL						fInvokeUI = FALSE;
	DWORD						dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetEAPIdentity" ) );

	//
	// First let's check in the registry if the inner eap requires
	// handles the username password itself.
	//
	if ((dwReturnCode = SW2_ReadInnerEapMethod(pProfileData->dwCurrentInnerEapMethod, 
										pProfileData->pwcCurrentProfileId,
										&InnerEapConfigData)) == NO_ERROR)
	{
#ifndef _WIN32_WCE
		//
		// Check to see if we received any information from the WLAN API
		//
		if (pProfileData->cbInnerEapConnectionData > 0)
		{
			memset(InnerEapConfigData.pbConnectionData, 0, sizeof(InnerEapConfigData.pbConnectionData));

			memcpy_s(InnerEapConfigData.pbConnectionData, sizeof(InnerEapConfigData.pbConnectionData),
				pProfileData->pbInnerEapConnectionData,
				pProfileData->cbInnerEapConnectionData);
			InnerEapConfigData.cbConnectionData = pProfileData->cbInnerEapConnectionData;
		}
#endif // _WIN32_WCE

		if (hWndParent&&
			InnerEapConfigData.dwInvokeUsernameDlg == 1&&
			InnerEapConfigData.dwInvokePasswordDlg == 1)
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
				TEXT( "SW2_TRACE_LEVEL_DEBUG::SW2EapMethodGetEAPIdentity:: using our own dialog for inner RASEAP method" ));

			//
			// Called in interactive mode and EAP method does not support interaction
			// Use our own dialog
			//
			if ((dwReturnCode = SW2EapMethodInvokeUserIdentityUI(hWndParent, pProfileData, pUserData)) == NO_ERROR)
			{
				//
				// Because we used our own dialog box we need to determine if we stick the domain name onto the end
				//
				if( !wcsstr(pUserData->pwcUsername, L"@") && wcslen( pUserData->pwcDomain ) > 0 )
				{
					wcscpy( pUserData->InnerEapUserData.pwcIdentity, pUserData->pwcUsername );

					//
					// If we have enough space then copy the domain onto the end
					//
					if ( ( wcslen( pUserData->pwcUsername ) + 1 + 
													wcslen( pUserData->pwcDomain ) + 1 ) <= 
													(sizeof(pUserData->InnerEapUserData.pwcIdentity)/sizeof(WCHAR)))
					{
						wcscat( pUserData->InnerEapUserData.pwcIdentity, L"@" );
						wcscat( pUserData->InnerEapUserData.pwcIdentity, pUserData->pwcDomain );
					}
				}
				else
				{
					wcscpy( pUserData->InnerEapUserData.pwcIdentity, pUserData->pwcUsername );
				}

				wcscpy( pUserData->InnerEapUserData.pwcPassword, pUserData->pwcPassword);
			}
		}
		else if (!hWndParent&&
				(!pProfileData->bPromptUser ||
				(InnerEapConfigData.dwInvokeUsernameDlg == 1&&
				 InnerEapConfigData.dwInvokePasswordDlg == 1)))
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
				TEXT( "SW2_TRACE_LEVEL_DEBUG::SW2EapMethodGetEAPIdentity:: going to try use pre-configured username/password for inner RASEAP" ));

			//
			// Called in non-interactive mode and we have a pre-configured username/password
			//
			if ((dwReturnCode = SW2EapMethodGetUserIdentity(dwFlags,
														pProfileData, 
														pUserData,
														&fInvokeUI)) == NO_ERROR)
			{
				//
				// Check if we requested a user interface, if so then return the error ERROR_INTERACTIVE_MODE as
				// we should simulate how a RASEAP method works
				//
				if (fInvokeUI)
				{
					dwReturnCode = ERROR_INTERACTIVE_MODE;
				}
				else
				{
					//
					// Because we used our own credentials we need to determine if we stick the domain name onto the end
					//
					if( !wcsstr(pUserData->pwcUsername, L"@") && wcslen( pUserData->pwcDomain ) > 0 )
					{
						wcscpy( pUserData->InnerEapUserData.pwcIdentity, pUserData->pwcUsername );

						//
						// If we have enough space then copy the domain onto the end
						//
						if ( ( wcslen( pUserData->pwcUsername ) + 1 + 
														wcslen( pUserData->pwcDomain ) + 1 ) <= 
														(sizeof(pUserData->InnerEapUserData.pwcIdentity)/sizeof(WCHAR)))
						{
							wcscat( pUserData->InnerEapUserData.pwcIdentity, L"@" );
							wcscat( pUserData->InnerEapUserData.pwcIdentity, pUserData->pwcDomain );
						}
					}
					else
					{
						wcscpy( pUserData->InnerEapUserData.pwcIdentity, pUserData->pwcUsername );
					}

					wcscpy( pUserData->InnerEapUserData.pwcPassword, pUserData->pwcPassword);
				}
			}
		}
		else		
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
				TEXT( "SW2_TRACE_LEVEL_DEBUG::SW2EapMethodGetEAPIdentity:: pwcEapIdentityPath: %s" ), 
				InnerEapConfigData.pwcEapIdentityPath );

			//
			// Connect to EAP DLL
			//
			if( ( hEapInstance = LoadLibrary( InnerEapConfigData.pwcEapIdentityPath ) ) )
			{
#ifndef _WIN32_WCE
				if( ( pInnerEapGetIdentity = ( PINNEREAPGETIDENTITY ) 
									GetProcAddress( hEapInstance, "RasEapGetIdentity" ) ) )
#else
				if( ( pInnerEapGetIdentity = ( PINNEREAPGETIDENTITY ) 
									GetProcAddress( hEapInstance, L"RasEapGetIdentity" ) ) )
#endif // _WIN32_WCE
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
						TEXT( "SW2_TRACE_LEVEL_DEBUG::SW2EapMethodGetEAPIdentity:: cbConnectionData: %ld" ), 
						InnerEapConfigData.cbConnectionData );

					if(	( dwReturnCode = pInnerEapGetIdentity( InnerEapConfigData.dwEapType,
														hWndParent,
														dwFlags,
														NULL,
														NULL,
														InnerEapConfigData.pbConnectionData,
														InnerEapConfigData.cbConnectionData,
														pUserData->InnerEapUserData.pbUserData,
														pUserData->InnerEapUserData.cbUserData,
														&pbInnerEapUserDataOut,
														&dwInnerEapUserDataOut,
														&pwcInnerEapIdentityOut ) ) == NO_ERROR )
					{
#ifndef _WIN32_WCE
						if( ( pInnerEapFreeMemory = ( PINNEREAPFREEMEMORY ) 
									GetProcAddress( hEapInstance, "RasEapFreeMemory" ) ) )
#else
						if( ( pInnerEapFreeMemory = ( PINNEREAPFREEMEMORY )
									GetProcAddress( hEapInstance, L"RasEapFreeMemory" ) ) )
#endif // _WIN32_WCE
						{
							//
							// Copy the inner user data if any and then free it
							//
							if (pbInnerEapUserDataOut)
							{
								if (dwInnerEapUserDataOut > 0 &&
									dwInnerEapUserDataOut <= EAP_MAX_INNER_USER_DATA)
								{
									memset(&(pUserData->InnerEapUserData), 0, sizeof(pUserData->InnerEapUserData));

									pUserData->InnerEapUserData.cbUserData = dwInnerEapUserDataOut;

									memcpy( pUserData->InnerEapUserData.pbUserData, 
											pbInnerEapUserDataOut, 
											pUserData->InnerEapUserData.cbUserData );

									pInnerEapFreeMemory(pbInnerEapUserDataOut);
								}
							}

							if (pwcInnerEapIdentityOut)
							{
								if (wcslen(pwcInnerEapIdentityOut) > 0 &&
									wcslen( pwcInnerEapIdentityOut ) <= ( UNLEN * sizeof( WCHAR ) ))
								{
									wcscpy( pUserData->InnerEapUserData.pwcIdentity, 
											pwcInnerEapIdentityOut );

									SW2Trace( SW2_TRACE_LEVEL_INFO, 
										TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetEAPIdentity:: pwcInnerIdentityOut: %s" ), 
										pUserData->InnerEapUserData.pwcIdentity );
								}

								//
								// copy inner user identity to userdata
								//
								memset(pUserData->pwcUsername, 0, sizeof(pUserData->pwcUsername));

								wcscpy_s(pUserData->pwcUsername, 
									sizeof( pUserData->pwcUsername ),
									pUserData->InnerEapUserData.pwcIdentity);

								pInnerEapFreeMemory(( PBYTE ) pwcInnerEapIdentityOut);
							}
						}
						else
						{
							dwReturnCode = ERROR_DLL_INIT_FAILED;
						}
					}
					else
					{
						if (dwReturnCode == ERROR_INTERACTIVE_MODE)
							SW2Trace( SW2_TRACE_LEVEL_WARNING, 
								TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodGetEAPIdentity::pInnerEapGetIdentity requested interface in NON_INTERACTIVE_MODE" ), 
								dwReturnCode );
						else
							SW2Trace( SW2_TRACE_LEVEL_ERROR, 
								TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodGetEAPIdentity::pInnerEapGetIdentity FAILED: %ld" ), 
								dwReturnCode );
					}
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
						TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodGetEAPIdentity:: GetProcAddress FAILED" ) );

					dwReturnCode = ERROR_DLL_INIT_FAILED;
				}

				FreeLibrary( hEapInstance );
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodGetEAPIdentity:: LoadLibrary FAILED: %ld" ), GetLastError() );

				dwReturnCode = ERROR_DLL_INIT_FAILED;
			}
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetEAPIdentity::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Retrieve Identity without user interaction, return *pfInvokeUI = TRUE if
// User Interface is required
//
DWORD SW2EapMethodGetIdentity(IN DWORD		dwFlags,
							  IN DWORD		dwSizeOfConnectionData,
							  IN const BYTE	*pbConnectionData,
							  IN DWORD		dwSizeOfUserData,
							  IN const BYTE	*pbUserData,								
							  IN HANDLE		hTokenImpersonateUser,
							  OUT BOOL		*pfInvokeUI,
							  OUT DWORD		*pdwSizeOfUserDataOut,
							  OUT PBYTE		*ppbUserDataOut,
							  OUT PWCHAR	*ppwcIdentity)
{
	BOOL				bInvokeUI;
	SW2_CONFIG_DATA		configData;
	SW2_PROFILE_DATA	profileData;
	PWCHAR				pwcIdentity = NULL;
	DWORD				cwcIdentity;
	PWCHAR				pwcPassword = NULL;
	DWORD				cwcPassword;
	PSW2_USER_DATA		pUserData;
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	*ppwcIdentity = NULL;
	*ppbUserDataOut = NULL;
	*pdwSizeOfUserDataOut = 0;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity::dwFlags: %x" ), dwFlags );

	*pfInvokeUI = FALSE;

	if ((dwReturnCode = SW2AllocateMemory(sizeof(SW2_USER_DATA), (PVOID*) &pUserData)) == NO_ERROR)
	{
		if (dwSizeOfUserData == sizeof(SW2_USER_DATA))
		{
			//
			// Old user data available, copy it and overwrite it with information
			// retrieved from the configuration
			//
			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity::found previous userdata"));

			memcpy_s(pUserData, sizeof(SW2_USER_DATA), pbUserData, sizeof(SW2_USER_DATA));
		}

		memset(&configData, 0, sizeof(SW2_CONFIG_DATA));

		if (pbConnectionData && (dwSizeOfConnectionData == sizeof(SW2_CONFIG_DATA)))
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity::found previous config data (SW2 Profile)"));

			memcpy(&configData, pbConnectionData, sizeof(SW2_CONFIG_DATA));

			dwReturnCode = SW2_ReadProfile(configData.pwcProfileId,
											hTokenImpersonateUser,
											&profileData);
		}
#ifndef _WIN32_WCE
		else if(pbConnectionData && (dwSizeOfConnectionData == sizeof(SW2_PROFILE_DATA)))
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity::found previous config data (XML Profile)"));

			memcpy(&profileData, pbConnectionData, sizeof(SW2_PROFILE_DATA)); 
		}
#endif // _WIN32_WCE
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity::no previous user or config data available, using DEFAULT profile data"));

			wcscpy(configData.pwcProfileId, L"DEFAULT");

			dwReturnCode = SW2_ReadProfile(configData.pwcProfileId,
											hTokenImpersonateUser,
											&profileData);
		}

		if (dwReturnCode == NO_ERROR)
		{
			if (wcscmp(profileData.pwcInnerAuth, L"PAP") == 0)
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, 
					TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity::authenticating using PAP" ) );

				//
				// If we have a generic resource available, use this except if
				// a username was pre-configured in the XML
				//
				if (g_ResContext && wcslen(profileData.pwcUserName) < 1 )
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, 
						TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity::using extension library" ) );

					//
					// call external interface to get User Identity (non interactive)
					//
					if ((dwReturnCode = g_ResContext->pSW2GetCredentials(g_ResContext->pContext,
																		&pwcIdentity,
																		&pwcPassword,
																		pfInvokeUI,
																		&pUserData->bSaveUserCredentials))==NO_ERROR)
					{
						if (!*pfInvokeUI)
						{
							if (pwcIdentity != NULL|| pwcPassword != NULL)
							{
								//
								// Copy Identity over to User Data struct
								//
								cwcIdentity = (DWORD) wcslen(pwcIdentity)+1;

								SW2Trace( SW2_TRACE_LEVEL_INFO, 
									L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity()::extension library returned identity: %s", 
									pwcIdentity);

								if (cwcIdentity > 0)
								{
									if (cwcIdentity <= (sizeof(pUserData->pwcUsername)/sizeof(WCHAR)))
										wcscpy_s(pUserData->pwcUsername, 
												sizeof(pUserData->pwcUsername)/sizeof(WCHAR), 
												pwcIdentity);
									else
									{
										SW2Trace( SW2_TRACE_LEVEL_ERROR, 
											TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodGetIdentity::identity too large (%ld)"), 
											cwcIdentity);

										dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
									}
								}
							

								cwcPassword = (DWORD) wcslen(pwcPassword)+1;

								if (dwReturnCode = NO_ERROR)
								{
									if (cwcPassword > 0)
									{
										if (cwcPassword <= (sizeof(pUserData->pwcPassword)/sizeof(WCHAR)))
											wcscpy_s(pUserData->pwcPassword, 
													sizeof(pUserData->pwcPassword)/sizeof(WCHAR), 
													pwcPassword);
										else
										{
											SW2Trace( SW2_TRACE_LEVEL_ERROR, 
												TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodGetIdentity::password too large") );

											dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
										}
									}
								}
							}
							else
							{
								dwReturnCode = ERROR_INVALID_DATA;

								SW2Trace( SW2_TRACE_LEVEL_ERROR, 
									L"SW2_TRACE_LEVEL_ERROR::information returned from extension library is invalid");

							}
						}
						else
							SW2Trace( SW2_TRACE_LEVEL_INFO, 
							L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity()::extension library requested interactive UI");


						//
						// Call external interface to free memory allocated for Identity
						//
						g_ResContext->pSW2FreeCredentials(pwcIdentity, pwcPassword);

						pwcIdentity = NULL;
					}
					else
					{
						// translate error codes to windows based error codes
						dwReturnCode = SW2ConvertExternalErrorCode(dwReturnCode);
					}
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, 
						TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity::using builtin resource" ) );

					dwReturnCode = SW2EapMethodGetUserIdentity(
						dwFlags,
						&profileData, 
						pUserData,
						pfInvokeUI);
				}
			}
			else 
			{
				if (wcscmp(profileData.pwcInnerAuth, L"EAP") == 0)
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, 
						TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity::using inner EAP for identity" ) );
					
					//
					// In RasEap the following calls handles both the GetIdentity and the InvokeUI functionality
					// now present in EapHost, to mimic a GetIdentity set the flags to RAS_EAP_FLAG_NON_INTERACTIVE. 
					//
					dwReturnCode = SW2EapMethodGetEAPIdentity(
						NULL,
						dwFlags|RAS_EAP_FLAG_NON_INTERACTIVE,
						&profileData,
						pUserData);

					//
					// If the method requires an interaction with the user, it SHOULD return ERROR_INTERACTIVE_MODE
					//
					if (dwReturnCode == ERROR_INTERACTIVE_MODE)
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, 
							TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity::inner eap requires interactive ui" ) );

						dwReturnCode = NO_ERROR;

						*pfInvokeUI = TRUE;
					}

				}
				else if(  wcscmp( profileData.pwcInnerAuth, L"EAPHOST" ) == 0 )
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, 
						TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity::using inner EAPHOST for identity" ) );

					dwReturnCode = SW2EapMethodGetEAPHOSTIdentity(
						dwFlags,
						&profileData,
						pUserData,
						pfInvokeUI);
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
						TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodGetIdentity::invalid authentication type: %s" ), profileData.pwcInnerAuth );

					dwReturnCode = ERROR_NOT_SUPPORTED;
				}
			}

			if (dwReturnCode == NO_ERROR &&
				*pfInvokeUI == FALSE)
			{
				dwReturnCode = SW2HandleOuterIdentity(&profileData, pUserData, &pwcIdentity);
			
				if( dwReturnCode == NO_ERROR )
				{
					if (pwcIdentity)
						SW2Trace( SW2_TRACE_LEVEL_INFO, 
							TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity::outer identity: %s" ), 
							pwcIdentity );
					else
						SW2Trace( SW2_TRACE_LEVEL_INFO, 
							TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity::outer identity: empty" ) );

					*ppwcIdentity = pwcIdentity;
					*ppbUserDataOut = ( PBYTE ) pUserData;
					*pdwSizeOfUserDataOut = sizeof( SW2_USER_DATA );
				}
				else
				{
					//
					// Something went wrong so clean up allocated memory
					// also inform windows that user data can be cleared
					// to prevent loop
					//
					*ppbUserDataOut = NULL;
					*pdwSizeOfUserDataOut = 0;
				}
			}
		}

		if (dwReturnCode != NO_ERROR ||
			*pfInvokeUI == TRUE)
			SW2FreeMemory((PVOID*)&pUserData);
	}

	SW2_HandleError(dwReturnCode, 
		SW2_EAP_FUNCTION_GetIdentity, 
		SW2_TLS_STATE_None,
		&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetIdentity::Returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Show Identity User interface (Balloon)
//
DWORD SW2EapMethodInvokeUserIdentityUI(IN HWND					hWndParent,
									   IN IN PSW2_PROFILE_DATA	pProfileData, 
									   IN PSW2_USER_DATA		pUserData)
{
	PWCHAR			pwcIdentity = NULL;
	DWORD		cwcIdentity;
	PWCHAR		pwcPassword = NULL;
	DWORD		cwcPassword;
	DWORD		dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeUserIdentityUI"));

	if (g_ResContext)
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeUserIdentityUI::using extension library" ) );

		//
		// call external interface to get User Identity (non interactive)
		//
		if ((dwReturnCode = g_ResContext->pSW2InvokeCredentialsUI(g_ResContext->pContext,
															hWndParent,
															&pwcIdentity,
															&pwcPassword,
															&pUserData->bSaveUserCredentials))==NO_ERROR)
		{
			if (pwcIdentity!=NULL)
			{
				cwcIdentity = (DWORD) wcslen(pwcIdentity)+1;

				if (cwcIdentity > 0)
				{
					if (cwcIdentity <= (sizeof(pUserData->pwcUsername)/sizeof(WCHAR)))
						wcscpy_s(pUserData->pwcUsername, 
								sizeof(pUserData->pwcUsername)/sizeof(WCHAR), 
								pwcIdentity);
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodInvokeIdentityUI::username provided by extension library too large (%ld)" ), 
							cwcIdentity );

						dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
					}
				}

				cwcPassword = (DWORD) wcslen(pwcPassword)+1;
			}

			if (pwcPassword!=NULL&&
				dwReturnCode == NO_ERROR)
			{
				if (cwcPassword > 0)
				{
					if (cwcPassword <= (sizeof(pUserData->pwcPassword)/sizeof(WCHAR)))
						wcscpy_s(pUserData->pwcPassword, 
								sizeof(pUserData->pwcPassword)/sizeof(WCHAR), 
								pwcPassword);
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodInvokeIdentityUI::password provided by extension library too large" ) );

						dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
					}
				}
			}

			//
			// Call external interface to free memory allocated for Identity
			//
			g_ResContext->pSW2FreeCredentials(pwcIdentity, pwcPassword);
			pwcIdentity = NULL;
			pwcPassword = NULL;
		}
		else
		{
			dwReturnCode = SW2ConvertExternalErrorCode(dwReturnCode);
		}
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeUserIdentityUI::using builtin resource" ) );
		//
		// Copy any information we already have
		//
		memcpy(pUserData->pwcUsername, 
			pProfileData->pwcUserName, 
			sizeof(pUserData->pwcUsername));

		memcpy(pUserData->pwcDomain, 
			pProfileData->pwcUserDomain, 
			sizeof(pUserData->pwcDomain));

		//
		// Show username dialog
		//
		//
		// CUSTOM DIALOG
		// Contributed by Wyman Miles (Cornell University)
		//
		// we're going to have to copy some values from
		// pProfileData to their equivalents in pUserData 
		// to make this work with a minimum of headache
		//
#ifndef _WIN32_WCE
		pUserData->bAllowCachePW = pProfileData->bAllowCachePW;
		memcpy(pUserData->pwcAltCredsTitle,
				pProfileData->pwcAltCredsTitle,
				sizeof( pUserData->pwcAltCredsTitle ) );
		memcpy(pUserData->pwcAltPasswordStr,
				pProfileData->pwcAltPasswordStr,
				sizeof( pUserData->pwcAltPasswordStr ) );
		memcpy(pUserData->pwcAltUsernameStr,
				pProfileData->pwcAltUsernameStr,
				sizeof( pUserData->pwcAltUsernameStr ) );
		memcpy(pUserData->pwcAltDomainStr,
				pProfileData->pwcAltDomainStr,
				sizeof( pUserData->pwcAltDomainStr ) );
		memcpy(pUserData->pwcProfileDescription,
				pProfileData->pwcProfileDescription,
				sizeof( pUserData->pwcProfileDescription ) );
#endif // _WIN32_WCE

		//
		// handle to parent in Vista "looses" focus
		//
		if (!DialogBoxParam(g_hResource,
							MAKEINTRESOURCE(IDD_CRED_DLG),
							GetForegroundWindow(),
							CredentialsDlgProc,
							(LPARAM) pUserData))
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT("SW2_TRACE_LEVEL_ERROR::SW2EapMethodInvokeUserIdentityUI::user cancelled") );

			dwReturnCode = ERROR_CANCELLED;
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeUserIdentityUI::returning %ld"), dwReturnCode);

	return dwReturnCode;
}

DWORD SW2EapMethodInvokeIdentityUI(IN HWND			hWndParent,
								   IN DWORD			dwFlags,
								   IN DWORD			dwSizeOfConnectionData,
								   IN const BYTE	*pbConnectionData,										
								   IN DWORD			dwSizeOfUserDataIn,
								   IN const BYTE	*pbUserDataIn,
								   OUT DWORD		*pdwSizeOfUserDataOut,
								   OUT PBYTE		*ppbUserDataOut,
								   OUT PWCHAR		*ppwcIdentity)
{
	PWCHAR				pwcIdentity = NULL;
	BOOL				bInvokeUI;
	SW2_CONFIG_DATA		configData;
	SW2_PROFILE_DATA	profileData;
	PSW2_USER_DATA		pUserData;
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeIdentityUI()");

	memset( &configData, 0, sizeof( SW2_CONFIG_DATA ) );

	if ((dwReturnCode = SW2AllocateMemory(sizeof(SW2_USER_DATA), (PVOID*) &pUserData)) == NO_ERROR)
	{
		if (dwSizeOfUserDataIn == sizeof(SW2_USER_DATA))
		{
			//
			// Old user data available, copy it and overwrite it with information
			// retrieved from the configuration
			//
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeIdentityUI::copying old userdata" ) );

			memcpy_s(pUserData, sizeof(SW2_USER_DATA), pUserData, sizeof( SW2_USER_DATA ) );
		}

		if (pbConnectionData && (dwSizeOfConnectionData == sizeof(SW2_CONFIG_DATA)))
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeIdentityUI::using provided configuration (SW2 Profile)" ) );

			memcpy( &configData, pbConnectionData, sizeof( SW2_CONFIG_DATA ) );

			dwReturnCode = SW2_ReadProfile(configData.pwcProfileId,
											NULL,
											&profileData );
		}
#ifndef _WIN32_WCE
		else if (pbConnectionData && (dwSizeOfConnectionData == sizeof(SW2_PROFILE_DATA)))
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeIdentityUI::using provided configuration (XML Profile)" ) );

			memcpy(&profileData, pbConnectionData, sizeof(SW2_PROFILE_DATA));
		}
#endif // _WIN32_WCE
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeIdentityUI::using default profile)" ) );

			wcscpy( configData.pwcProfileId, L"DEFAULT" );

			dwReturnCode = SW2_ReadProfile(configData.pwcProfileId,
											NULL,
											&profileData );
		}

		if( dwReturnCode == NO_ERROR)
		{
			if (wcscmp(profileData.pwcInnerAuth, L"PAP") == 0)
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeIdentityUI::using builtin identity" ) );

				dwReturnCode = SW2EapMethodInvokeUserIdentityUI(hWndParent, 
																&profileData, 
																pUserData);
			}
			else if (wcscmp(profileData.pwcInnerAuth, L"EAP") == 0)
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeIdentityUI::using inner EAP identity" ) );

				dwReturnCode = SW2EapMethodGetEAPIdentity(hWndParent, 
															dwFlags, 
															&profileData, 
															pUserData);
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodInvokeIdentityUI::invalid inner authentication type %s" ), 
					profileData.pwcInnerAuth );

				dwReturnCode = ERROR_NOT_SUPPORTED;
			}

			if (dwReturnCode == NO_ERROR)
			{
				dwReturnCode = SW2HandleOuterIdentity(&profileData, pUserData, &pwcIdentity);

				SW2Trace( SW2_TRACE_LEVEL_INFO, 
					TEXT("SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeIdentityUI::username: %s"), pUserData->pwcUsername);
				SW2Trace( SW2_TRACE_LEVEL_INFO, 
					TEXT("SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeIdentityUI::domain: %s"), pUserData->pwcDomain);

				if( dwReturnCode == NO_ERROR )
				{
					if (pwcIdentity)
						SW2Trace( SW2_TRACE_LEVEL_INFO, 
						TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeIdentityUI::outer identity: %s" ), pwcIdentity );
					else
						SW2Trace( SW2_TRACE_LEVEL_INFO, 
						TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeIdentityUI::outer identity: empty" ) );

					*ppwcIdentity = pwcIdentity;
					*ppbUserDataOut = ( PBYTE ) pUserData;
					*pdwSizeOfUserDataOut = sizeof( SW2_USER_DATA );
				}
				else
				{
					//
					// Something went wrong so clean up allocated memory
					// also inform windows that user data can be cleared
					// to prevent loop
					//
					*ppbUserDataOut = NULL;
					*pdwSizeOfUserDataOut = 0;
				}
			}
		}
			
		if (dwReturnCode != NO_ERROR )
			SW2FreeMemory((PVOID*)&pUserData);
	}

	SW2_HandleError(dwReturnCode, 
		SW2_EAP_FUNCTION_InvokeIdentityUI, 
		SW2_TLS_STATE_None,
		&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		L"SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeIdentityUI()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

//
// Identity has been determined, begin an authentication session
//
DWORD SW2EapMethodBegin(IN DWORD	dwFlags,
						IN HANDLE	hTokenImpersonateUser,
						IN DWORD	dwSizeOfConnectionData,
						IN PBYTE	pbConnectionData,
						IN DWORD	dwSizeOfUserData,
						IN PBYTE	pbUserData,
						IN PWCHAR	pwcUsername,
						IN PWCHAR	pwcPassword,
						OUT	PVOID	*ppWorkBuffer)
{
	BOOL				bInvokeUI;
	PSW2_SESSION_DATA	pSessionData;
	SW2_CONFIG_DATA		configData;
	PINNEREAPGETINFO	pInnerEapGetInfo;
	PPP_EAP_INFO		eapInfo;
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodBegin" ) );

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
		TEXT( "SW2_TRACE_LEVEL_DEBUG::SW2EapMethodBegin::dwFlags: %x" ), dwFlags );

	*ppWorkBuffer = NULL;

	if ((dwReturnCode = SW2AllocateMemory(sizeof(SW2_SESSION_DATA), (PVOID*) &pSessionData)) == NO_ERROR)
	{
		//
		// Initialise pSessionData
		//
		memset( pSessionData, 0, sizeof( SW2_SESSION_DATA ) );

		//
		// Initialize TLS session
		//
		TLSInit(&(pSessionData->TLSSession));

		pSessionData->hTokenImpersonateUser = hTokenImpersonateUser;

		//
		// Did we receive user and connection data
		// and is it the correct size?
		//
		if (!pbUserData)
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodBegin::invalid user data" ) );

			dwReturnCode = ERROR_NO_SUCH_USER;
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodBegin::using user data provided by own DLL" ) );

			if ((dwSizeOfUserData == sizeof(SW2_USER_DATA)))
			{
				//
				// Save user and connection stuff
				//
				memset( &(pSessionData->UserData), 0, sizeof( SW2_USER_DATA ) );

				memcpy( &(pSessionData->UserData), pbUserData, dwSizeOfUserData );
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodBegin::invalid user data" ) );

				dwReturnCode = ERROR_NO_SUCH_USER;
			}
		}

		if (dwReturnCode == NO_ERROR)
		{
			if (pbConnectionData && 
				(dwSizeOfConnectionData == sizeof(SW2_CONFIG_DATA)))
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, 
					TEXT("SW2_TRACE_LEVEL_INFO::SW2EapMethodBegin::using connection data provided by user interface (SW2 Profile)"));

				memset(&configData, 0, sizeof(SW2_CONFIG_DATA));

				memcpy(&configData, pbConnectionData, sizeof(SW2_CONFIG_DATA));

				memcpy(pSessionData->pwcCurrentProfileId, 
					configData.pwcProfileId, 
					sizeof(pSessionData->pwcCurrentProfileId));

				dwReturnCode = SW2_ReadProfile(configData.pwcProfileId,
												pSessionData->hTokenImpersonateUser,
												&(pSessionData->ProfileData));
			}
#ifndef _WIN32_WCE
			else if (pbConnectionData && (dwSizeOfConnectionData == sizeof(SW2_PROFILE_DATA)))
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, 
					TEXT("SW2_TRACE_LEVEL_INFO::SW2EapMethodBegin::using connection data provided by user interface (XML Profile)"));

				wcscpy_s(pSessionData->pwcCurrentProfileId, 
					sizeof(pSessionData->pwcCurrentProfileId), 
					L"EAPHOSTXML");

				memcpy(&(pSessionData->ProfileData), 
					pbConnectionData, 
					sizeof(SW2_PROFILE_DATA));			

				SW2_WriteUserProfile( pSessionData->pwcCurrentProfileId, 
									pSessionData->hTokenImpersonateUser,
									pSessionData->ProfileData );

				SW2_WriteComputerProfile( pSessionData->pwcCurrentProfileId, 
									pSessionData->hTokenImpersonateUser,
									pSessionData->ProfileData );

				dwReturnCode = SW2_WriteInnerEapMethod(pSessionData->ProfileData.dwCurrentInnerEapMethod, 
														pSessionData->pwcCurrentProfileId,
														 pSessionData->ProfileData.pbInnerEapConnectionData,
														 pSessionData->ProfileData.cbInnerEapConnectionData);
			}
#endif // _WIN32_WCE
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, 
					TEXT("SW2_TRACE_LEVEL_INFO::SW2EapMethodBegin::using default profile)"));

				memset(&configData, 0, sizeof(SW2_CONFIG_DATA));

				wcscpy(configData.pwcProfileId, L"DEFAULT");

				memcpy(pSessionData->pwcCurrentProfileId, 
					configData.pwcProfileId, 
					sizeof( pSessionData->pwcCurrentProfileId ) );

				dwReturnCode = SW2_ReadProfile(configData.pwcProfileId,
												pSessionData->hTokenImpersonateUser,
												&(pSessionData->ProfileData));
			}

			if (dwReturnCode==NO_ERROR)
			{
				//
				// Enable session resumption? (Only if previous authentication was success)
				//
				if( !pSessionData->ProfileData.bUseSessionResumption || 
					pSessionData->UserData.prevEapReason != SW2_EAP_REASON_Success )
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodBegin::not resuming session" ) );

					memset( pSessionData->UserData.pbTLSSessionID, 0, sizeof( pSessionData->UserData.pbTLSSessionID ) );

					pSessionData->UserData.cbTLSSessionID = 0;

					memset( pSessionData->UserData.pbMS, 0, TLS_MS_SIZE );
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodBegin::resuming session" ) );

					pSessionData->TLSSession.cbTLSSessionID = pSessionData->UserData.cbTLSSessionID;

					memset(pSessionData->TLSSession.pbTLSSessionID, 0, sizeof(pSessionData->TLSSession.pbTLSSessionID));

					memcpy_s(pSessionData->TLSSession.pbTLSSessionID,
							sizeof(pSessionData->TLSSession.pbTLSSessionID), 
							pSessionData->UserData.pbTLSSessionID,
							pSessionData->UserData.cbTLSSessionID);

					memcpy_s(&pSessionData->TLSSession.tTLSSessionID,
							sizeof(time_t),
							&pSessionData->UserData.tTLSSessionID,
							sizeof(time_t));

					memcpy_s(pSessionData->TLSSession.pbMS,
							TLS_MS_SIZE, 
							pSessionData->UserData.pbMS,
							TLS_MS_SIZE);
				}

				if( dwReturnCode == NO_ERROR )
				{				
					//
					// If we are using EAP then load in the current EAP config
					//
					if (wcscmp( pSessionData->ProfileData.pwcInnerAuth, L"EAP") == 0)
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodBegin::initializing Inner RASEAP Method" ) );

						//
						// Read in config data for current EAP method 
						//
						if ((dwReturnCode = SW2AllocateMemory(sizeof(SW2_INNER_EAP_CONFIG_DATA), 
							(PVOID*) &(pSessionData->InnerSessionData.pInnerEapConfigData))) == NO_ERROR)
						{
							if( ( dwReturnCode = SW2_ReadInnerEapMethod( pSessionData->ProfileData.dwCurrentInnerEapMethod,
																	pSessionData->pwcCurrentProfileId,
																	pSessionData->InnerSessionData.pInnerEapConfigData ) ) == NO_ERROR )
							{
								SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodBegin::connecting to method %ld" ), pSessionData->ProfileData.dwCurrentInnerEapMethod );

#ifndef _WIN32_WCE
								//
								// Check to see if we received any information from the WLAN API
								//
								if (pSessionData->ProfileData.cbInnerEapConnectionData > 0)
								{
									memset(pSessionData->InnerSessionData.pInnerEapConfigData->pbConnectionData, 
										0, sizeof(pSessionData->InnerSessionData.pInnerEapConfigData->pbConnectionData));

									memcpy_s(pSessionData->InnerSessionData.pInnerEapConfigData->pbConnectionData, 
										sizeof(pSessionData->InnerSessionData.pInnerEapConfigData->pbConnectionData),
										pSessionData->ProfileData.pbInnerEapConnectionData,
										pSessionData->ProfileData.cbInnerEapConnectionData);
									pSessionData->InnerSessionData.pInnerEapConfigData->cbConnectionData = pSessionData->ProfileData.cbInnerEapConnectionData;
								}
#endif // _WIN32_WCE
								//
								// Connect to EAP DLL
								//
								if( ( pSessionData->InnerSessionData.hInnerEapInstance = 
									LoadLibrary( pSessionData->InnerSessionData.pInnerEapConfigData->pwcEapPath ) ) )
								{
#ifndef _WIN32_WCE
									if( ( pInnerEapGetInfo = ( PINNEREAPGETINFO ) 
										GetProcAddress( pSessionData->InnerSessionData.hInnerEapInstance, "RasEapGetInfo" ) ) )
#else
									if( ( pInnerEapGetInfo = ( PINNEREAPGETINFO ) 
										GetProcAddress( pSessionData->InnerSessionData.hInnerEapInstance, L"RasEapGetInfo" ) ) )
#endif
									{
										eapInfo.dwSizeInBytes = sizeof( eapInfo );

										if( ( dwReturnCode = pInnerEapGetInfo( 
											pSessionData->InnerSessionData.pInnerEapConfigData->dwEapType, 
											&eapInfo ) ) == NO_ERROR )
										{
											pSessionData->InnerSessionData.pInnerEapInitialize = eapInfo.RasEapInitialize;
											pSessionData->InnerSessionData.pInnerEapBegin = eapInfo.RasEapBegin;
											pSessionData->InnerSessionData.pInnerEapEnd = eapInfo.RasEapEnd;
											pSessionData->InnerSessionData.pInnerEapMakeMessage = eapInfo.RasEapMakeMessage;

											if( pSessionData->InnerSessionData.pInnerEapInitialize )
											{
												if( ( dwReturnCode = pSessionData->InnerSessionData.pInnerEapInitialize( TRUE ) ) != NO_ERROR )
												{
													SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodBegin::Inner EAP function RasEapInitialize FAILED: %ld" ), dwReturnCode );
												}
											}

											if( dwReturnCode == NO_ERROR )
											{
												memset( &( pSessionData->InnerSessionData.InnerEapInput ), 0, sizeof( pSessionData->InnerSessionData.InnerEapInput ) );

												pSessionData->InnerSessionData.InnerEapInput.dwSizeInBytes = sizeof( pSessionData->InnerSessionData.InnerEapInput );

												pSessionData->InnerSessionData.InnerEapInput.bInitialId = 0;

												pSessionData->InnerSessionData.InnerEapInput.dwAuthResultCode = 0;

												pSessionData->InnerSessionData.InnerEapInput.pConnectionData = pSessionData->InnerSessionData.pInnerEapConfigData->pbConnectionData;
												pSessionData->InnerSessionData.InnerEapInput.dwSizeOfConnectionData = pSessionData->InnerSessionData.pInnerEapConfigData->cbConnectionData;

												pSessionData->InnerSessionData.InnerEapInput.dwSizeOfDataFromInteractiveUI = 0;
												pSessionData->InnerSessionData.InnerEapInput.pDataFromInteractiveUI = NULL;

												pSessionData->InnerSessionData.InnerEapInput.dwSizeOfUserData = pSessionData->UserData.InnerEapUserData.cbUserData;

												pSessionData->InnerSessionData.InnerEapInput.pUserData = pSessionData->UserData.InnerEapUserData.pbUserData;

												pSessionData->InnerSessionData.InnerEapInput.fAuthenticationComplete = FALSE;

												pSessionData->InnerSessionData.InnerEapInput.fAuthenticator = FALSE;

												pSessionData->InnerSessionData.InnerEapInput.fDataReceivedFromInteractiveUI = FALSE;

												pSessionData->InnerSessionData.InnerEapInput.fSuccessPacketReceived = FALSE;

												pSessionData->InnerSessionData.InnerEapInput.hReserved = 0;

												pSessionData->InnerSessionData.InnerEapInput.hTokenImpersonateUser = hTokenImpersonateUser;
												
												// FIXME:
												//pSessionData->InnerSessionData.InnerEapInput.pUserAttributes = pInput->pUserAttributes;
												
												pSessionData->InnerSessionData.InnerEapInput.pwszIdentity = 
													pSessionData->UserData.InnerEapUserData.pwcIdentity;

												pSessionData->InnerSessionData.InnerEapInput.pwszPassword = 
													pSessionData->UserData.InnerEapUserData.pwcPassword;
												
												if (dwReturnCode == NO_ERROR)
												{
													pSessionData->InnerSessionData.InnerEapInput.fFlags = 
														pSessionData->InnerSessionData.InnerEapInput.fFlags | RAS_EAP_FLAG_LOGON;

													if( ( dwReturnCode = pSessionData->InnerSessionData.pInnerEapBegin( 
														(PVOID*) &( pSessionData->InnerSessionData.pbInnerEapSessionData ), 
														&( pSessionData->InnerSessionData.InnerEapInput ) ) ) == NO_ERROR )
													{
														pSessionData->InnerSessionData.InnerEapState = SW2_INNER_EAP_STATE_Start;
													}
													else
														SW2Trace( SW2_TRACE_LEVEL_ERROR, 
															TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodBegin::Inner EAP function SW2EapMethodBegin failed: %ld" ), dwReturnCode );
												}
											}
										}
									}
									else
									{
										SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodBegin::pInnerEapGetInfo failed: %ld" ), GetLastError() );

										dwReturnCode = ERROR_DLL_INIT_FAILED;
									}

									if( dwReturnCode != NO_ERROR )
										FreeLibrary( pSessionData->InnerSessionData.hInnerEapInstance  );
								}
								else
								{
									SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodBegin::LoadLibrary failed: %ld" ), GetLastError() );

									dwReturnCode = ERROR_DLL_INIT_FAILED;
								}
							}

							if( dwReturnCode != NO_ERROR )
								SW2FreeMemory((PVOID*)&(pSessionData->InnerSessionData.pInnerEapConfigData));
						}
						else
							dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
					}
					else if( wcscmp( pSessionData->ProfileData.pwcInnerAuth, L"EAPHOST" ) == 0 )
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodBegin::initializing Inner EapHost Method" ) );

#ifndef SW2_EAP_HOST
						dwReturnCode = ERROR_NOT_SUPPORTED;
#else
						!!if( ( pSessionData->InnerSessionData.pInnerEapConfigData = 
							( PSW2_INNER_EAP_CONFIG_DATA ) malloc( sizeof( SW2_INNER_EAP_CONFIG_DATA ) ) ) )
						{
							//
							// FIXME: Read EAPHost configuration
							//
							pSessionData->InnerSessionData.pInnerEapConfigData->eapMethodType.eapType.type = 6;
							pSessionData->InnerSessionData.pInnerEapConfigData->eapMethodType.eapType.dwVendorId = 0;
							pSessionData->InnerSessionData.pInnerEapConfigData->eapMethodType.eapType.dwVendorType = 0;
							pSessionData->InnerSessionData.pInnerEapConfigData->eapMethodType.dwAuthorId = 311;

							if( ( dwReturnCode = EapHostPeerInitialize() ) == NO_ERROR )
							{
								DWORD						dwFlags = 0;
								HANDLE						hTokenImpersonateUser = NULL;
								EAP_ERROR					*pEapError = NULL;

								pSessionData->InnerSessionData.eapSessionId = 0;

								if( ( dwReturnCode = EapHostPeerBeginSession( 
									dwFlags,					//Flags
									pSessionData->InnerSessionData.pInnerEapConfigData->eapMethodType,//EAP_METHOD_TYPE
									NULL,						//EapAttributes
									hTokenImpersonateUser,		//HANDLE
									0,							//Connection Data Size
									NULL,						//Connection Data
									0,							//User Data Size
									NULL,	 					//User Data
									1400,						//Max Packet
									NULL,						//ConnectionId
									NULL,					 	//Notification Call Back Handler
									NULL,						//Context Data (Thread Identifier)
									&pSessionData->InnerSessionData.eapSessionId,// Session Id
									&pEapError ) ) != NO_ERROR )
								{
									if( pEapError )
										EapHostPeerFreeEapError( pEapError );
								}

								if( dwReturnCode != NO_ERROR)
								{
									//
									// Something went wrong, de-initialize EapHost
									//
									EapHostPeerUninitialize();
								}
							}

							if( dwReturnCode != NO_ERROR )
								SW2FreeMemory((PVOID*)&pSessionData->InnerSessionData.pInnerEapConfigData);
						}
						else
							dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
#endif // SW2_EAP_HOST
					}
				}
			}
		}

		if (dwReturnCode == NO_ERROR)
		{
			*ppWorkBuffer = pSessionData;
		}
	}
	else
        dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

	SW2_HandleError(dwReturnCode, 
		SW2_EAP_FUNCTION_Begin, 
		SW2_TLS_STATE_None,
		&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodBegin::returning %ld" ), dwReturnCode );

    return dwReturnCode;
}

//
// Authentication has finished (either succesfull or not), End authentication session (Cleanup)
//
DWORD SW2EapMethodEnd(IN PVOID pWorkBuffer)
{
	BOOL				bInvokeUI;
	PSW2_SESSION_DATA	pSessionData;
#ifdef SW2_EAP_HOST
	EAP_ERROR					*pEapError = NULL;
#endif // SW2_EAP_HOST
#ifndef _WIN32_WCE
	HANDLE				hThread;
	DWORD				dwThreadID;
#endif // _WIN32_WCE
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodEnd" ) );

	if( pWorkBuffer )
		 pSessionData = ( PSW2_SESSION_DATA ) pWorkBuffer;
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodEnd::Windows gave me a NULL pointer" ) );

		return dwReturnCode;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodEnd::cleaning TLS data" ) );

	//
	// Cleanup TLS Session
	//
	TLSCleanup(&(pSessionData->TLSSession));

	//
	// Cleanup Inner Data
	//
	if( wcscmp( pSessionData->ProfileData.pwcInnerAuth, L"EAP" ) == 0 )
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodEnd::cleaning inner RASEAP data" ) );

		if( ( dwReturnCode = pSessionData->InnerSessionData.pInnerEapEnd( pSessionData->InnerSessionData.pbInnerEapSessionData ) ) == NO_ERROR )
		{
			if( pSessionData->InnerSessionData.pInnerEapInitialize )
				pSessionData->InnerSessionData.pInnerEapInitialize( FALSE );

			FreeLibrary( pSessionData->InnerSessionData.hInnerEapInstance );
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodEnd::pInnerEapEnd FAILED: %ld" ), dwReturnCode );
		}

		if( pSessionData->InnerSessionData.pInnerEapConfigData )
			SW2FreeMemory((PVOID*)&(pSessionData->InnerSessionData.pInnerEapConfigData));
	}
	else if( wcscmp( pSessionData->ProfileData.pwcInnerAuth, L"EAPHOST" ) == 0 )
	{
#ifndef SW2_EAP_HOST
		dwReturnCode = ERROR_NOT_SUPPORTED;
#else
		SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodEnd::cleaning inner EAPHOST data" ) );

		if( ( dwReturnCode = EapHostPeerEndSession(pSessionData->InnerSessionData.eapSessionId, &pEapError) ) == NO_ERROR )
		{
			EapHostPeerUninitialize();
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodEnd::EapHostPeerEndSession Failed" ) );

			if( pEapError )
				EapHostPeerFreeEapError( pEapError );
		}

		if( pSessionData->InnerSessionData.pInnerEapConfigData )
			SW2FreeMemory((PVOID*)&pSessionData->InnerSessionData.pInnerEapConfigData);
#endif // SW2_EAP_HOST
	}


#ifndef _WIN32_WCE

	//
	// DHCP Fix
	//
	if( pSessionData->ProfileData.bRenewIP &&
		pSessionData->UserData.prevEapReason == SW2_EAP_REASON_Success )
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodEnd::DHCP Fix: %s" ) , pSessionData->UserData.pwcEntry );

		dwThreadID = 0;

		if( hThread = CreateThread( NULL,
									0,
									SW2_RenewIP,
									pSessionData->UserData.pwcEntry,
									0,
									&dwThreadID ) )
		{
			//
			// Allow thread to copy entry name
			//
			Sleep( 500 );

			CloseHandle( hThread );
		}
	}

#endif // _WIN32_WCE

	//
	// free UserAttributes
	//
	if( pSessionData->pUserAttributes )
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodEnd::cleaning inner attributes" ) );

		if( pSessionData->pUserAttributes[0].Value )
			SW2FreeMemory((PVOID*)&(pSessionData->pUserAttributes[0].Value));

		if( pSessionData->pUserAttributes[1].Value )
			SW2FreeMemory((PVOID*)&(pSessionData->pUserAttributes[1].Value));

		SW2FreeMemory((PVOID*)&(pSessionData->pUserAttributes));
	}

	//
	// Free data from interactiveUI
	//
	if( pSessionData->pbDataFromInteractiveUI )
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodEnd::cleaning data from interactive UI" ) );

		SW2FreeMemory((PVOID*)&(pSessionData->pbDataFromInteractiveUI));
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodEnd::cleaning session data" ) );

	SW2FreeMemory((PVOID*)&pSessionData);

	SW2_HandleError(dwReturnCode, 
		SW2_EAP_FUNCTION_End, 
		SW2_TLS_STATE_None,
		&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodEnd::returning: %ld" ), dwReturnCode );

    return dwReturnCode;
}

DWORD SW2EapMethodFreeMemory(PVOID *ppMemory)
{
	BOOL	bInvokeUI;
	DWORD	dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodFreeMemory" ) );

	dwReturnCode = NO_ERROR;

	dwReturnCode = SW2FreeMemory(ppMemory);

	SW2_HandleError(dwReturnCode, 
		SW2_EAP_FUNCTION_FreeMemory, 
		SW2_TLS_STATE_None,
		&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodFreeMemory:: Returning" ) );

    return dwReturnCode;
}

//
// Before the Interactive UI is called, this function is called in which the
// context data for the Interactive UI is returned
//
DWORD SW2EapMethodGetUIContext(IN PVOID pWorkBuffer,
							   IN DWORD *pdwSizeOfUIContextData,
							   IN PBYTE	*ppbUIContextData)
{
	BOOL				bInvokeUI;
	PSW2_SESSION_DATA	pSessionData;
	DWORD				dwSizeOfSessionData;
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetUIContext()");

	pSessionData = (PSW2_SESSION_DATA) pWorkBuffer;
	dwSizeOfSessionData = sizeof( SW2_SESSION_DATA );

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
		L"SW2_TRACE_LEVEL_DEBUG::SW2EapMethodGetUIContext()::dwSizeOfSessionData: %ld",
		dwSizeOfSessionData);

	*pdwSizeOfUIContextData = dwSizeOfSessionData;
    *ppbUIContextData = (PBYTE) pSessionData;

	SW2_HandleError(dwReturnCode, 
		SW2_EAP_FUNCTION_GetUIContext, 
		SW2_TLS_STATE_None,
		&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetUIContext()::returning %ld", dwReturnCode);

	return dwReturnCode;
}

//
// After the Interactive UI is called, this function is called in which the
// context data for the Interactive UI is provided
//
DWORD SW2EapMethodSetUIContext(IN PVOID pWorkBuffer,
							   IN DWORD dwSizeOfUIContextData,
							   IN PBYTE	pbUIContextData)
{
	BOOL				bInvokeUI;
	PSW2_SESSION_DATA	pSessionData;
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodSetUIContext()");

	pSessionData = (PSW2_SESSION_DATA) pWorkBuffer;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"SW2_TRACE_LEVEL_DEBUG::SW2EapMethodSetUIContext()::dwSizeOfUIContextData: %ld", dwSizeOfUIContextData);

	//
	// Sanity check
	//
	if (pbUIContextData &&
		dwSizeOfUIContextData > 0)
	{
		pSessionData->dwSizeOfDataFromInteractiveUI = dwSizeOfUIContextData;

		if ((dwReturnCode = 
			SW2AllocateMemory(dwSizeOfUIContextData, 
								(PVOID*)&pSessionData->pbDataFromInteractiveUI))==NO_ERROR)
		{
			memcpy_s(pSessionData->pbDataFromInteractiveUI, 
				dwSizeOfUIContextData, 
				pbUIContextData, 
				dwSizeOfUIContextData);
		}
	}
	else
	{
		// NULL response
		pSessionData->dwSizeOfDataFromInteractiveUI = 0;
	}

	SW2_HandleError(dwReturnCode, 
		SW2_EAP_FUNCTION_InvokeInteractiveUI, 
		SW2_TLS_STATE_None,
		&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodSetUIContext()::returning %ld", dwReturnCode);

	return dwReturnCode;
}

//
// Show Configuration User interface
//
DWORD  SW2EapMethodInvokeConfigUI(IN HWND		hWndParent,
								  IN DWORD		dwFlags,
								  IN DWORD		dwSizeOfConnectionDataIn,
								  IN PBYTE		pbConnectionDataIn,
								  OUT DWORD		*pdwSizeOfConnectionDataOut,
								  OUT PBYTE		*ppbConnectionDataOut)
{
	BOOL				bInvokeUI;
	PSW2_CONFIG_DATA	pConfigData;
	SW2_PROFILE_DATA	ProfileData;
#ifndef _WIN32_WCE
	HKEY				hKey;
	WCHAR				*pwcTemp;
	DWORD				cwcTemp;
	SHELLEXECUTEINFO	se;
	WCHAR				pwcParameters[1024];
#endif
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeConfigUI" ));

	*ppbConnectionDataOut = NULL;
	*pdwSizeOfConnectionDataOut = 0;

	if (pbConnectionDataIn && (sizeof( SW2_PROFILE_DATA ) == dwSizeOfConnectionDataIn))
	{
		//
		// Configuration based on XML (EapHost)
		//
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeConfigUI:: using XML profile" ) );

		if ((dwReturnCode = SW2AllocateMemory(sizeof(SW2_PROFILE_DATA), (PVOID*) ppbConnectionDataOut )) == NO_ERROR)
		{
			memset(&ProfileData, 0, sizeof(ProfileData));

			memcpy( &ProfileData, pbConnectionDataIn, sizeof(ProfileData));

			//
			// only show dialog if no external resource is available
			//
			if (!g_ResContext)
			{
				if (!DialogBoxParam( g_hResource,
									MAKEINTRESOURCE(IDD_PROFILE_DLG),
									hWndParent,
									&ProfileDlgProc,
									( LPARAM ) &ProfileData ) )
					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::ConfigProfileDlgProc::failed to create dialog(ProfileDlgProc): %d" ), GetLastError() );
			}

			*pdwSizeOfConnectionDataOut = sizeof(ProfileData);
			memcpy(*ppbConnectionDataOut, &ProfileData, sizeof(ProfileData));
		}
	}
	else
	{
		if ((dwReturnCode = SW2AllocateMemory(sizeof(SW2_CONFIG_DATA), (PVOID*) &pConfigData)) == NO_ERROR)
		{
			if( pbConnectionDataIn && ( sizeof( SW2_CONFIG_DATA ) == dwSizeOfConnectionDataIn ) )
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeConfigUI:: using SecureW2 profile" ) );

				memcpy( pConfigData, pbConnectionDataIn, dwSizeOfConnectionDataIn );
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeConfigUI:: received invalid configuration data" ) );

				dwReturnCode= ERROR_INVALID_DATA;
			}

			if( dwReturnCode != NO_ERROR ||
				wcslen(pConfigData->pwcProfileId) <= 0 )
			{
				dwReturnCode = NO_ERROR;
			
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeConfigUI:: using default profile" ) );

#ifndef _WIN32_WCE
				swprintf_s( pConfigData->pwcProfileId, 
							sizeof(pConfigData->pwcProfileId)/sizeof(WCHAR), 
							TEXT( "DEFAULT" ) );
#else
				swprintf( pConfigData->pwcProfileId, 
							TEXT( "DEFAULT" ) );
#endif
			}

			if( dwReturnCode == NO_ERROR )
			{
#ifndef _WIN32_WCE
				if( SW2_IsAdmin() )
				{
					//
					// Only Admins can access profile configuration
					//
					swprintf_s( pwcParameters, 
								sizeof(pwcParameters)/sizeof(WCHAR), 
								TEXT( "profile \"%s\"" ),
								pConfigData->pwcProfileId );
		 
					ZeroMemory( &se, sizeof(se) );

					se.cbSize = sizeof( se );
					se.hwnd = hWndParent;
					se.fMask = SEE_MASK_NOCLOSEPROCESS;
					se.lpDirectory = NULL;
					//se.lpVerb = L"runas";
					if (EAPTYPE == EAP_TYPE_PEAP)
						se.lpFile = L"sw2_peap_manager.exe";
					else
						se.lpFile = L"sw2_ttls_manager.exe";
					se.lpParameters = pwcParameters;
					se.nShow = SW_SHOWNORMAL;

					if( ShellExecuteEx( &se ) )
					{
						WaitForSingleObject( se.hProcess, INFINITE );
						CloseHandle( se.hProcess );
					}
					else
					{
						dwReturnCode = GetLastError();

						SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodInvokeConfigUI:: creating process failed: %ld" ), dwReturnCode );
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
							cwcTemp = sizeof( pConfigData->pwcProfileId );

							if( ( dwReturnCode = SW2_RegGetValue( hKey, 
														L"SelectedProfile", 
														( PBYTE *) &pwcTemp, 
														&cwcTemp ) ) == NO_ERROR )
							{
								if( wcscmp( pwcTemp, L"none" ) == 0 )
								{
									// VISTA works slightly different, Windows 2K XP return ERROR_CANCELLED
									// VISTA returns ok, but simply does not change the configuration (also logical...)
									*ppbConnectionDataOut = ( PBYTE ) pConfigData;
									*pdwSizeOfConnectionDataOut = sizeof( SW2_CONFIG_DATA );
								}
								else
								{
									wcscpy_s( pConfigData->pwcProfileId, 
												sizeof( pConfigData->pwcProfileId )/sizeof( WCHAR ),
												pwcTemp );

									*ppbConnectionDataOut = ( PBYTE ) pConfigData;
									*pdwSizeOfConnectionDataOut = sizeof( SW2_CONFIG_DATA );
								}

								SW2FreeMemory((PVOID*)&pwcTemp);
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodInvokeConfigUI::could not find registry value SelectedProfile: %ld" ), dwReturnCode );
							}

							RegCloseKey( hKey );
						}							
					}
				}
				else
				{
					//
					// Normal users see only the user config
					//
#endif // _WIN32_WCE
					if (DialogBoxParam(g_hResource,
									MAKEINTRESOURCE(IDD_CONFIG_DLG),
									hWndParent,
									ConfigDlgProc,
									(LPARAM) pConfigData))
					{
						*ppbConnectionDataOut = ( PBYTE ) pConfigData;
						*pdwSizeOfConnectionDataOut = sizeof( SW2_CONFIG_DATA );
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodInvokeConfigUI::User cancelled" ) );

						dwReturnCode = ERROR_CANCELLED;
					}
#ifndef _WIN32_WCE
				}
#endif // _WIN32_WCE

			}

			if( dwReturnCode != NO_ERROR )
				SW2FreeMemory((PVOID*)&pConfigData);
		}
	}

	SW2_HandleError(dwReturnCode, 
		SW2_EAP_FUNCTION_InvokeConfigUI, 
		SW2_TLS_STATE_None,
		&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeConfigUI::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Show Interactive User interface (Balloon)
//
DWORD SW2EapMethodInvokeInteractiveUI(IN HWND		hwndParent,
									  IN DWORD		dwSizeofUIContextData,
									  IN PBYTE		pbUIContextData,
									  OUT DWORD		*pdwSizeOfDataFromInteractiveUI,
									  OUT PBYTE		*ppbDataFromInteractiveUI)
{
	BOOL							bInvokeUI;
	PSW2_SESSION_DATA 				pSessionData;
	SW2_INNER_EAP_CONFIG_DATA		InnerEapConfigData;
	PINNEREAPINVOKEINTERACTIVEUI	pInnerEapInvokeInteractiveUI;
	PINNEREAPFREEMEMORY				pInnerEapFreeMemory;
	PBYTE							pbInnerEapDataFromInteractiveUI;
	DWORD							dwInnerEapSizeOfDataFromInteractiveUI;
	HINSTANCE						hEapInstance;
#ifdef SW2_EAP_HOST
	EAP_ERROR						*pEapError = NULL;
#endif // SW2_EAP_HOST
	PBYTE							pbReturn;
	WCHAR							*pwcReturn;
	DWORD							dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeInteractiveUI"));

	dwReturnCode = NO_ERROR;

	*ppbDataFromInteractiveUI = NULL;
	*pdwSizeOfDataFromInteractiveUI = 0;

	if (!pbUIContextData)
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodInvokeInteractiveUI::Invalid pointer to Context Data" ) );
		
		return ERROR_INVALID_DATA;
	}
	else
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeInteractiveUI::dwSizeofUIContextData: %ld" ), dwSizeofUIContextData );

	pSessionData = (PSW2_SESSION_DATA) pbUIContextData;

	if( pSessionData->bInteractiveUIType == UI_TYPE_VERIFY_CERT )
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeInteractiveUI()::UI_TYPE_VERIFY_CERT" ) );

		//
		// Show server trust dialog
		//
		if( DialogBoxParam( g_hResource,
							MAKEINTRESOURCE( IDD_SERVER_TRUST_DLG ),
							hwndParent,
							TLSServerTrustDlgProc,
							( LPARAM ) pSessionData ) )
		{
			//
			// User managed to install certificates
			//
			if ((dwReturnCode = SW2AllocateMemory(((DWORD)wcslen( L"ERROR_OK" ) + 1 ) * sizeof( WCHAR ), 
				(PVOID*) &pwcReturn)) == NO_ERROR)
			{
				wcscpy( pwcReturn, L"ERROR_OK" );

				*ppbDataFromInteractiveUI = ( PBYTE ) pwcReturn;
													
				*pdwSizeOfDataFromInteractiveUI = ( DWORD ) ( wcslen( pwcReturn ) + 1 ) * sizeof( WCHAR );
			}
		}
		else
		{
			//
			// User cancelled
			//
			if ((dwReturnCode = SW2AllocateMemory(((DWORD)wcslen( L"ERROR_CANCELLED" ) + 1 ) * sizeof( WCHAR ), 
				(PVOID*) &pwcReturn)) == NO_ERROR)
			{
				wcscpy( pwcReturn, L"ERROR_CANCELLED" );

				*ppbDataFromInteractiveUI = ( PBYTE ) pwcReturn;
													
				*pdwSizeOfDataFromInteractiveUI = ( DWORD ) ( wcslen( pwcReturn ) + 1 ) * sizeof( WCHAR );
			}
		}
	}
	else if( pSessionData->bInteractiveUIType == UI_TYPE_INNER_EAP )
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeInteractiveUI()::UI_TYPE_INNER_EAP" ) );

		if( ( dwReturnCode = SW2_ReadInnerEapMethod( pSessionData->ProfileData.dwCurrentInnerEapMethod, 
												pSessionData->ProfileData.pwcCurrentProfileId,
												&InnerEapConfigData ) ) == NO_ERROR )
		{
			//
			// Connect to EAP DLL
			//
			if( ( hEapInstance = 
				LoadLibrary( InnerEapConfigData.pwcEapInteractiveUIPath ) ) )
			{
#ifndef _WIN32_WCE
				if( ( pInnerEapInvokeInteractiveUI = ( PINNEREAPINVOKEINTERACTIVEUI ) 
					GetProcAddress( hEapInstance, "RasEapInvokeInteractiveUI" ) ) )
#else
				if( ( pInnerEapInvokeInteractiveUI = ( PINNEREAPINVOKEINTERACTIVEUI ) 
					GetProcAddress( hEapInstance, L"RasEapInvokeInteractiveUI" ) ) )
#endif // _WIN32_WCE
				{
					if(	( dwReturnCode = pInnerEapInvokeInteractiveUI( InnerEapConfigData.dwEapType,
																hwndParent,
																pSessionData->pbInnerUIContextData,
																pSessionData->cbInnerUIContextData,
																&pbInnerEapDataFromInteractiveUI,
																&dwInnerEapSizeOfDataFromInteractiveUI ) ) == NO_ERROR )
					{
#ifndef _WIN32_WCE
						if( ( pInnerEapFreeMemory = ( PINNEREAPFREEMEMORY ) 
							GetProcAddress( hEapInstance, "RasEapFreeMemory" ) ) )
#else
						if( ( pInnerEapFreeMemory = ( PINNEREAPFREEMEMORY ) 
							GetProcAddress( hEapInstance, L"RasEapFreeMemory" ) ) )
#endif // _WIN32_WCE
						{
							if ((dwReturnCode = SW2AllocateMemory(dwInnerEapSizeOfDataFromInteractiveUI, (PVOID*) &pbReturn)) == NO_ERROR)
							{
								memcpy( pbReturn, 
										pbInnerEapDataFromInteractiveUI, 
										dwInnerEapSizeOfDataFromInteractiveUI );

								*ppbDataFromInteractiveUI = pbReturn;
														
								*pdwSizeOfDataFromInteractiveUI = dwInnerEapSizeOfDataFromInteractiveUI;

								pInnerEapFreeMemory( ( PBYTE ) pbInnerEapDataFromInteractiveUI );
							}
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, 
								TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodInvokeInteractiveUI::GetProcAddress FAILED: %ld" ), GetLastError() );

							dwReturnCode = ERROR_DLL_INIT_FAILED;
						}
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodInvokeInteractiveUI::pInnerInvokeInteractiveUI FAILED: %ld" ), 
							dwReturnCode );
					}
				}
				else
				{

					SW2Trace( SW2_TRACE_LEVEL_INFO, 
						TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeInteractiveUI:: GetProcAddress FAILED: %ld" ), GetLastError() );

					dwReturnCode = ERROR_DLL_INIT_FAILED;
				}

				FreeLibrary( hEapInstance );
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, 
					TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeInteractiveUI:: LoadLibrary FAILED: %ld" ), GetLastError() );

				dwReturnCode = ERROR_DLL_INIT_FAILED;
			}
		}
	}
	else if ( pSessionData->bInteractiveUIType == UI_TYPE_INNER_EAPHOST )
	{
#ifndef SW2_EAP_HOST
		dwReturnCode = ERROR_NOT_SUPPORTED;
#else
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeInteractiveUI::UI_TYPE_INNER_EAPHOST") );
/*
		if( ( dwReturnCode = EapHostPeerInvokeInteractiveUI( hwndParent,
			pSessionData->cbInnerUIContextData,
			pSessionData->pbInnerUIContextData,
			&dwInnerEapSizeOfDataFromInteractiveUI,
			&pbInnerEapDataFromInteractiveUI,
			&pEapError ) ) == NO_ERROR )
		{
			!!if( ( *ppDataFromInteractiveUI = ( PBYTE ) malloc( dwInnerEapSizeOfDataFromInteractiveUI ) ) )
			{
				memcpy( *ppDataFromInteractiveUI, 
						pbInnerEapDataFromInteractiveUI, 
						dwInnerEapSizeOfDataFromInteractiveUI );
										
				*lpdwSizeOfDataFromInteractiveUI = dwInnerEapSizeOfDataFromInteractiveUI;
			}
			else
			{
				dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		else
		{
			if( pEapError )
				EapHostPeerFreeEapError( pEapError );
		}
*/
#endif // SW2_EAP_HOST
	}
	else if( pSessionData->bInteractiveUIType == UI_TYPE_ERROR )
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeInteractiveUI::UI_TYPE_ERROR") );

		SW2_HandleInteractiveError(	hwndParent,
									pSessionData->dwLastSW2Error, 
									pSessionData->LastEapFunction, 
									pSessionData->TLSSession.LastTLSState );

		//
		// fill return data to inform SecureW2 to continue
		//
		if ((dwReturnCode = SW2AllocateMemory(((DWORD)wcslen( L"ERROR_OK" ) + 1) * sizeof(WCHAR), (PVOID*) &pwcReturn)) == NO_ERROR)
		{
			wcscpy( pwcReturn, L"ERROR_OK" );

			*ppbDataFromInteractiveUI = ( PBYTE ) pwcReturn;
												
			*pdwSizeOfDataFromInteractiveUI = ( DWORD ) ( wcslen( pwcReturn ) + 1 ) * sizeof( WCHAR );
		}
		else
		{
			dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
		}
	}
	else if( pSessionData->bInteractiveUIType == UI_TYPE_CREDENTIALS )
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, 
			TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeInteractiveUI::UI_TYPE_CREDENTIALS" ) );

		//
		// Not implemented yet
		//
		dwReturnCode = ERROR_NOT_SUPPORTED;
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodInvokeInteractiveUI(), unknown pSessionData->bInteractiveUIType %x" ), 
			pSessionData->bInteractiveUIType );

		dwReturnCode = ERROR_CANCELLED;
	}

	SW2_HandleError(dwReturnCode, 
		SW2_EAP_FUNCTION_InvokeInteractiveUI, 
		SW2_TLS_STATE_None,
		&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodInvokeInteractiveUI(), returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Process an EAP packet
//
DWORD SW2EapMethodProcess(IN PVOID				pWorkBuffer,
						  IN PSW2EAPPACKET		pReceivePacket,
						  OUT DWORD				cbSendPacket,
						  OUT PSW2EAPPACKET		pSendPacket,
						  OUT SW2EAPOUTPUT		*pEapOutput)
{
	PSW2_SESSION_DATA	pSessionData;
	DWORD				dwEAPPacketLength;
	DWORD				dwType = 0;
	PCCERT_CONTEXT		pCertContext;
	WCHAR				*pwcTemp;
	int					i=0;
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess" ));

	if (!pWorkBuffer)
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodProcess::ERROR::pWorkBuf is NULL" ) );

		dwReturnCode = ERROR_INVALID_DATA;
	}
	else
	{
		pSessionData = ( PSW2_SESSION_DATA ) pWorkBuffer;

		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::Method version: %ld" ), pSessionData->bCurrentMethodVersion );

		//
		// Reset output
		//
		memset(pEapOutput, 0, sizeof(SW2EAPOUTPUT));

		//
		// copy Notification option from configuration
		//
#ifndef _WIN32_WCE
		pEapOutput->bAllowNotifications = pSessionData->ProfileData.bAllowNotifications;
#endif // _WIN32_WCE

		//
		// Copy the packet ID for later use
		//
		if (pReceivePacket)
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, TEXT( "SW2_TRACE_LEVEL_DEBUG::SW2EapMethodProcess::Received packet ID: %ld" ), pReceivePacket->Id );
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, TEXT( "SW2_TRACE_LEVEL_DEBUG::SW2EapMethodProcess::Received packet(%ld)" ), SW2_WireToHostFormat16( pReceivePacket->Length ) );
			SW2Dump( SW2_TRACE_LEVEL_DEBUG,  ( PBYTE ) pReceivePacket, SW2_WireToHostFormat16( pReceivePacket->Length ) );

			pSendPacket->Id = pReceivePacket->Id;
			pSessionData->bPacketId = pReceivePacket->Id;

			//
			// check for unexpected start packet during communication
			//
			if (pSessionData->TLSSession.TLSState != SW2_TLS_STATE_Start &&
				SW2_WireToHostFormat16( pReceivePacket->Length ) == 5 &&
				pReceivePacket->Data[1] & TLS_REQUEST_START )
			{
				SW2Trace( SW2_TRACE_LEVEL_WARNING, TEXT("SW2_TRACE_LEVEL_WARNING::SW2EapMethodProcess::received unexpected EAPTTLS_REQUEST_START"));

				//
				// reset TLS session data
				//
				TLSInit(&(pSessionData->TLSSession));

				if( pSessionData->pUserAttributes )
				{
					if( pSessionData->pUserAttributes[0].Value )
						SW2FreeMemory((PVOID*)&(pSessionData->pUserAttributes[0].Value));

					if( pSessionData->pUserAttributes[1].Value )
						SW2FreeMemory((PVOID*)&(pSessionData->pUserAttributes[1].Value));

					SW2FreeMemory((PVOID*)&pSessionData->pUserAttributes);
				}
			}
		}

		switch (pSessionData->TLSSession.TLSState)
		{
			case SW2_TLS_STATE_Start:

				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::SW2_TLS_STATE_Start" ) );

				if( pReceivePacket )
				{
					switch( pReceivePacket->Code )
					{
						case EAPCODE_Request:

							if( pReceivePacket->Data[1] & TLS_REQUEST_START )
							{
								SW2Trace( SW2_TRACE_LEVEL_INFO, 
									TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::received EAPTTLS_REQUEST_START") );

								pSessionData->bCurrentMethodVersion = pReceivePacket->Data[1] & EAP_METHOD_VERSION;

								SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::using method version %ld"), 
									pSessionData->bCurrentMethodVersion );

								dwReturnCode = TLSBuildResponsePacket(&(pSessionData->TLSSession), 
																		pSessionData->bPacketId, 
																		pSendPacket, 
																		cbSendPacket, 
																		pEapOutput,
																		EAPTYPE,
																		pSessionData->bCurrentMethodVersion);
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_WARNING, 
									TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodProcess::SW2_SW2_TLS_STATE_Start::unexpected packet") );

								dwReturnCode = ERROR_PPP_INVALID_PACKET;
							}

						break;

						case EAPCODE_Response:

							SW2Trace( SW2_TRACE_LEVEL_WARNING, 
								TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodProcess::AUTH_STATE_Client_Hello::Response Packet->" ) );

							dwReturnCode = ERROR_PPP_INVALID_PACKET;

						break;

						case EAPCODE_Success:

							SW2Trace( SW2_TRACE_LEVEL_WARNING, 
								TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodProcess::SW2_SW2_TLS_STATE_Start::Success Packet->" ) );

							dwReturnCode = ERROR_PPP_INVALID_PACKET;

						break;

						case EAPCODE_Failure:

							SW2Trace( SW2_TRACE_LEVEL_ERROR, 
								TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodProcess::SW2_SW2_TLS_STATE_Start::Failure Packet->" ) );

							dwReturnCode = ERROR_AUTH_INTERNAL;

						break;

						default:

							SW2Trace( SW2_TRACE_LEVEL_WARNING, 
								TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::SW2_SW2_TLS_STATE_Start::WARNING:unexpected packet") );

							dwReturnCode = ERROR_PPP_INVALID_PACKET;

						break;
					}
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_WARNING, 
						TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodProcess::SW2_SW2_TLS_STATE_Start::pReceivePacket == NULL" ) );
				}

			break;

			case SW2_TLS_STATE_Server_Hello:

				SW2Trace( SW2_TRACE_LEVEL_INFO, 
					TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::SW2_TLS_STATE_Server_Hello" ) );

				if( pReceivePacket )
				{
					switch( pReceivePacket->Code )
					{
						case EAPCODE_Request:

							dwEAPPacketLength = SW2_WireToHostFormat16(&(pReceivePacket->Length[0]));

							//
							// This function will read all the information in the fragged messages
							//
							dwReturnCode = TLSReadMessage(&(pSessionData->TLSSession),
													pSessionData->bPacketId,
													pReceivePacket, 
													pSendPacket, 
													cbSendPacket, 
													pEapOutput, 
													&pSessionData->bNewMethodVersion,
													dwEAPPacketLength,
													EAPTYPE,
													pSessionData->bCurrentMethodVersion);
						
							//
							// Sanity check, version must stay the same
							//
							if( pSessionData->bNewMethodVersion != pSessionData->bCurrentMethodVersion )
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, 
									TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodProcess::SW2_TLS_STATE_Server_Hello::server requested method version: %ld, we want %ld" ), pSessionData->bNewMethodVersion, pSessionData->bCurrentMethodVersion );

								dwReturnCode = ERROR_PPP_INVALID_PACKET;
							}
							else if( ( pEapOutput->eapAction != SW2EAPACTION_Send) && dwReturnCode == NO_ERROR )
							{
								if( ( dwReturnCode = TLSParseServerPacket(pSessionData) ) == NO_ERROR )
								{
									if( pSessionData->TLSSession.bServerFinished && 
										pSessionData->TLSSession.bCipherSpec && 
										pSessionData->ProfileData.bUseSessionResumption )
									{
										//
										// Found a change cipher spec and a finished message which means we are allowed to resume a session
										// if we want to resume as well then everything is ok else fail...
										//
										//
										// Set appropiate state
										//
										pSessionData->TLSSession.TLSState = SW2_TLS_STATE_Resume_Session;

										dwReturnCode = TLSBuildResponsePacket( &(pSessionData->TLSSession), 
																				pSessionData->bPacketId,
																				pSendPacket, 
																				cbSendPacket, 
																				pEapOutput,
																				EAPTYPE,
																				pSessionData->bCurrentMethodVersion);
									}
									else
									{
										//
										// Continue with TLS handshake
										//
										//
										// Check if we have a certificate
										//
										if( pSessionData->TLSSession.pbCertificate[0] )
										{
											//
											// Should we verify the TTLS server certificate?
											//
											if( pSessionData->ProfileData.bVerifyServerCertificate )
											{
												if (dwReturnCode == NO_ERROR)
												{
													//
													// Verify server certificate
													//
													if( ( pCertContext = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
																										pSessionData->TLSSession.pbCertificate[0], 
																										pSessionData->TLSSession.cbCertificate[0] ) ) )
													{
														//
														// If required verify MS Extensions
														//
														if( pSessionData->ProfileData.bVerifyMSExtension )
															dwReturnCode = SW2_CertCheckEnhkeyUsage( pCertContext );

														//
														// If required check server namespace
														//
														if( dwReturnCode == NO_ERROR &&
															pSessionData->ProfileData.bVerifyServerName)
																dwReturnCode = SW2_CertVerifyServerName(pSessionData, pCertContext);

														if (dwReturnCode == NO_ERROR)
														{
															//
															// Verify chain
															//
															if( ( dwReturnCode = SW2_VerifyCertificateChain( pSessionData, pCertContext ) ) == NO_ERROR )
															{
																//
																// If required verify if certificate is installed locally
																//
																if( pSessionData->ProfileData.bServerCertificateLocal && dwReturnCode == NO_ERROR )
																	dwReturnCode = SW2_VerifyCertificateInStore( pCertContext );
															}

															//
															// Only show dialog if option bAllowNewConnection is specified
															// and no extension library is being used
															//
															if (dwReturnCode != NO_ERROR &&
																pSessionData->ProfileData.bAllowNewConnection&&
																!g_ResContext)
															{
																SW2Trace( SW2_TRACE_LEVEL_WARNING, 
																	TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodProcess()::could not verify certificate chain, showing unknown server dialog" ));

																//
																// Could not validate chain show dialog to allow user 
																// to install missing certificates
																//
																//
																// If we are already showing a dialog then
																// cancel this request
																//
																if( FindWindow( WC_DIALOG, L"SecureW2 Unknown Server" ) )
																{
																	SW2Trace( SW2_TRACE_LEVEL_WARNING, TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodProcess::Unknown Server Dialog already shown" ) );

																	dwReturnCode = PENDING;
																}
																else
																{
																	pEapOutput->eapAction = SW2EAPACTION_InvokeUI;

																	pSessionData->bInteractiveUIType = UI_TYPE_VERIFY_CERT;

																	pSessionData->TLSSession.TLSState = SW2_TLS_STATE_Verify_Cert_UI;

																	pSessionData->bVerifyMSExtension = pSessionData->ProfileData.bVerifyMSExtension;

																	pSessionData->bServerCertificateLocal = pSessionData->ProfileData.bServerCertificateLocal;

																	dwReturnCode = NO_ERROR;
																}									
															}
														}

														CertFreeCertificateContext( pCertContext );
													}
												}											
											}

											//
											// If did not encounter an error and we do not need to show the InteractiveUI
											// then continue with next response
											//
											if( dwReturnCode == NO_ERROR && pEapOutput->eapAction != SW2EAPACTION_InvokeUI )
											{
												dwReturnCode = TLSBuildResponsePacket( &(pSessionData->TLSSession), 
																						pSessionData->bPacketId,
																						pSendPacket, 
																						cbSendPacket, 
																						pEapOutput,
																						EAPTYPE,
																						pSessionData->bCurrentMethodVersion);
											}
										}
										else
										{
											//
											// Could not find a certificate, fail
											//
											dwReturnCode = ERROR_AUTH_INTERNAL;
										}
									}
								}

								TLSResetReceiveMsg(&(pSessionData->TLSSession));
							}
							else if( dwReturnCode != NO_ERROR )
							{
								TLSResetReceiveMsg(&(pSessionData->TLSSession));
							}


						break;

						case EAPCODE_Response:

							SW2Trace( SW2_TRACE_LEVEL_WARNING, 
								TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodProcess::AUTH_STATE_Client_Hello::Response Packet->" ) );

							dwReturnCode = ERROR_PPP_INVALID_PACKET;

						break;

						case EAPCODE_Success:

							SW2Trace( SW2_TRACE_LEVEL_WARNING, 
								TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodProcess::AUTH_STATE_Client_Hello::Success Packet->" ) );

							dwReturnCode = ERROR_PPP_INVALID_PACKET;

						break;

						case EAPCODE_Failure:

							SW2Trace( SW2_TRACE_LEVEL_ERROR, 
								TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodProcess::AUTH_STATE_Client_Hello::Failure Packet->" ) );

							dwReturnCode = ERROR_AUTH_INTERNAL;

						break;

						default:

							SW2Trace( SW2_TRACE_LEVEL_WARNING, 
								TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodProcess::AUTH_STATE_Client_Hello::WARNING:unexpected packet") );

							dwReturnCode = ERROR_PPP_INVALID_PACKET;

						break;
					}
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_WARNING, TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodProcess::TLS_STATE_Client_Hello::WARNING: pReceivePacket == NULL" ) );
				}

			break;

			case  SW2_TLS_STATE_Verify_Cert_UI:

				SW2Trace( SW2_TRACE_LEVEL_INFO, 
					TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::SW2_TLS_STATE_Verify_Cert_UI" ) );

				if (pSessionData->pbDataFromInteractiveUI &&
					pSessionData->dwSizeOfDataFromInteractiveUI > 0)
				{
					pwcTemp = (PWCHAR) pSessionData->pbDataFromInteractiveUI;

					if (wcscmp(pwcTemp, L"ERROR_OK") == 0)
					{
						//
						// Everything is OK, re-read profile configuration
						//
						dwReturnCode = SW2_ReadProfile(pSessionData->pwcCurrentProfileId, 
														pSessionData->hTokenImpersonateUser, 
														&(pSessionData->ProfileData));
					}
					else
						dwReturnCode = ERROR_CANCELLED;

					if (dwReturnCode == NO_ERROR)
						dwReturnCode = TLSBuildResponsePacket(&(pSessionData->TLSSession), 
																pSessionData->bPacketId,
																pSendPacket, 
																cbSendPacket, 
																pEapOutput,
																EAPTYPE,
																pSessionData->bCurrentMethodVersion);
					//
					// Clear any information from interactiveUI
					//
					SW2FreeMemory((PVOID*)&pSessionData->pbDataFromInteractiveUI);
					pSessionData->dwSizeOfDataFromInteractiveUI = 0;
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, 
						TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::SW2_TLS_STATE_Verify_Cert_UI::User has not exited from VerifyCertificate dialog yet" ) );

					dwReturnCode = PENDING;
				}

			break;

			case SW2_TLS_STATE_Change_Cipher_Spec:

				SW2Trace( SW2_TRACE_LEVEL_INFO, 
					TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::SW2_TLS_STATE_Change_Cipher_Spec" ) );

				if( pReceivePacket )
				{
					switch( pReceivePacket->Code )
					{
						case EAPCODE_Request:

							dwEAPPacketLength = SW2_WireToHostFormat16( &( pReceivePacket->Length[0] ) );

							//
							// This function will read all the information in the fragged messages
							//
							dwReturnCode = TLSReadMessage( &(pSessionData->TLSSession),
													pSessionData->bPacketId,
													pReceivePacket, 
													pSendPacket, 
													cbSendPacket, 
													pEapOutput, 
													&pSessionData->bNewMethodVersion,
													dwEAPPacketLength,
													EAPTYPE,
													pSessionData->bCurrentMethodVersion);
						
							//
							// Sanity check, version must stay the same
							//
							if( pSessionData->bNewMethodVersion != pSessionData->bCurrentMethodVersion )
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, 
									TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodProcess::SW2_TLS_STATE_Inner_Authentication::Invalid TLS version (TTLS)" ) );

								dwReturnCode = ERROR_PPP_INVALID_PACKET;
							}
							else if( ( pEapOutput->eapAction != SW2EAPACTION_Send ) && dwReturnCode == NO_ERROR )
							{
								if( ( dwReturnCode = TLSParseServerPacket( pSessionData ) ) == NO_ERROR )
								{
									if( pSessionData->TLSSession.bCipherSpec && pSessionData->TLSSession.bServerFinished )
									{
										//
										// This means the tunnel was setup succesfully
										// start inner authentication
										//
										if( ( dwReturnCode = TLSInitTLSResponsePacket( pSessionData->bPacketId, 
																					pSendPacket, 
																					cbSendPacket,
																					EAPTYPE,
																					pSessionData->bCurrentMethodVersion ) ) == NO_ERROR )
											dwReturnCode = AuthHandleInnerAuthentication( pSessionData, 
																							pSendPacket, 
																							cbSendPacket, 
																							pEapOutput );
									}
									else
									{
										SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::SW2_TLS_STATE_Change_Cipher_Spec::ERROR::either no change cipher spec was found or the server did not send a finished packet" ) );

										dwReturnCode = ERROR_PPP_INVALID_PACKET;
									}
								}

								TLSResetReceiveMsg(&(pSessionData->TLSSession));
							}
							else if( dwReturnCode != NO_ERROR )
							{
								TLSResetReceiveMsg(&(pSessionData->TLSSession));
							}


						break;

						case EAPCODE_Response:

							SW2Trace( SW2_TRACE_LEVEL_WARNING, 
								TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodProcess::SW2_TLS_STATE_Change_Cipher_Spec::Response Packet->" ) );

							dwReturnCode = ERROR_PPP_INVALID_PACKET;

						break;

						case EAPCODE_Success:

							SW2Trace( SW2_TRACE_LEVEL_WARNING, 
								TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodProcess::SW2_TLS_STATE_Change_Cipher_Spec::Success Packet->" ) );

							dwReturnCode = ERROR_PPP_INVALID_PACKET;

						break;

						case EAPCODE_Failure:

							SW2Trace( SW2_TRACE_LEVEL_ERROR, 
								TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodProcess::SW2_TLS_STATE_Change_Cipher_Spec::Failure Packet->" ) );

							dwReturnCode = ERROR_AUTH_INTERNAL;

						break;

						default:

							SW2Trace( SW2_TRACE_LEVEL_WARNING, 
								TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodProcess::SW2_TLS_STATE_Change_Cipher_Spec::WARNING:unexpected packet") );
							
							dwReturnCode = ERROR_PPP_INVALID_PACKET;

						break;
					}
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_WARNING, TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodProcess::SW2_TLS_STATE_Change_Cipher_Spec::WARNING: pReceivePacket == NULL" ) );
				}

			break;

			case SW2_TLS_STATE_Resume_Session_Ack:

				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::SW2_TLS_STATE_Resume_Session_Ack" ) );

				//
				// If we are ready for session resumption then allow inner EAP to handle the data else
				// continue as normal
				//

				if( pReceivePacket )
				{
					switch( pReceivePacket->Code )
					{
						case EAPCODE_Request:

							dwEAPPacketLength = SW2_WireToHostFormat16(  &( pReceivePacket->Length[0] ) );

							if( pSessionData->ProfileData.bUseSessionResumption && 
								pSessionData->TLSSession.bCipherSpec && pSessionData->TLSSession.bServerFinished && 
								pSessionData->TLSSession.bSentFinished )
							{
								//
								// This will allow PEAP to handle EAP extensions
								//
								pSessionData->InnerSessionData.InnerEapState = SW2_INNER_EAP_STATE_MakeMessage;
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, 
									TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodProcess::SW2_TLS_STATE_Resume_Session_Ack::ERROR::either no change cipher spec was found or the server did not send a finished packet" ) );

								dwReturnCode = ERROR_PPP_INVALID_PACKET;
							}
					}
				}

			case SW2_TLS_STATE_Inner_Authentication:

				if( pReceivePacket )
				{
					switch( pReceivePacket->Code )
					{
						case EAPCODE_Request:
						case EAPCODE_Success:
						case EAPCODE_Failure:

							SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::SW2_TLS_STATE_Inner_Authentication::Request Packet->" ) );


							dwEAPPacketLength = SW2_WireToHostFormat16(  &( pReceivePacket->Length[0] ) );

							//
							// This function will read all the information in the fragged messages
							//
							dwReturnCode = TLSReadMessage( &(pSessionData->TLSSession),
													pSessionData->bPacketId,
													pReceivePacket, 
													pSendPacket, 
													cbSendPacket, 
													pEapOutput, 
													&pSessionData->bNewMethodVersion,
													dwEAPPacketLength,
													EAPTYPE,
													pSessionData->bCurrentMethodVersion);
						
							//
							// Sanity check, version must stay the same
							//
							if( pSessionData->bNewMethodVersion != pSessionData->bCurrentMethodVersion )
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, 
									TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodProcess::SW2_TLS_STATE_Inner_Authentication::Invalid Method version" ) );

								dwReturnCode = ERROR_PPP_INVALID_PACKET;
							}
							else if( ( pEapOutput->eapAction != SW2EAPACTION_Send) && dwReturnCode == NO_ERROR )
							{
								if( ( dwReturnCode = TLSParseServerPacket( pSessionData ) ) == NO_ERROR )
								{
									if( ( dwReturnCode = TLSInitTLSResponsePacket( pSessionData->bPacketId, 
																					pSendPacket, 
																					cbSendPacket,
																					EAPTYPE,
																					pSessionData->bCurrentMethodVersion ) ) == NO_ERROR )
										dwReturnCode = AuthHandleInnerAuthentication( pSessionData, 
																						pSendPacket, 
																						cbSendPacket, 
																						pEapOutput );
								}

								TLSResetReceiveMsg(&(pSessionData->TLSSession));
							}
							else if( dwReturnCode != NO_ERROR )
							{
								TLSResetReceiveMsg(&(pSessionData->TLSSession));
							}

						break;

						case EAPCODE_Response:

							SW2Trace( SW2_TRACE_LEVEL_WARNING, 
								TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodProcess::SW2_TLS_STATE_Inner_Authentication::Response Packet->" ) );

							dwReturnCode = ERROR_PPP_INVALID_PACKET;

						break;

						default:

							SW2Trace( SW2_TRACE_LEVEL_WARNING, 
								TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodProcess::SW2_TLS_STATE_Change_Cipher_Spec::WARNING:unexpected packet") );

							dwReturnCode = ERROR_PPP_INVALID_PACKET;

						break;
					}
				}
				else
				{
					//
					// Could be that the interactive userinterface was invoked
					//
					if( ( dwReturnCode = TLSInitTLSResponsePacket( pSessionData->bPacketId, 
																pSendPacket, 
																cbSendPacket,
																EAPTYPE,
																pSessionData->bCurrentMethodVersion ) ) == NO_ERROR )
					{
						dwReturnCode = AuthHandleInnerAuthentication( pSessionData, 
																		pSendPacket, 
																		cbSendPacket, 
																		pEapOutput );

						TLSResetReceiveMsg(&(pSessionData->TLSSession));
					}
				}

			break;

			case SW2_TLS_STATE_Error:

				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::SW2_TLS_STATE_Error" ) );

				if (pSessionData->pbDataFromInteractiveUI &&
					pSessionData->dwSizeOfDataFromInteractiveUI > 0)
				{
					//
					// Clear any information from interactiveUI
					//
					SW2FreeMemory((PVOID*)&pSessionData->pbDataFromInteractiveUI);
					pSessionData->dwSizeOfDataFromInteractiveUI = 0;

					dwReturnCode = pSessionData->dwLastSW2Error;

					pEapOutput->eapAction = SW2EAPACTION_None;
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_WARNING, 
						TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::SW2_TLS_STATE_Error::User has not exited from error dialog yet" ) );

					dwReturnCode = PENDING;

					pEapOutput->eapAction = SW2EAPACTION_None;
				}

			break;

			case SW2_TLS_STATE_Finished:

				// do nothing
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::SW2_TLS_STATE_Finished" ) );

				dwReturnCode = NO_ERROR;

				pEapOutput->eapAction = SW2EAPACTION_Done;

			break;

			default:

				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2EapMethodProcess::Unknown State" ) );

				dwReturnCode = ERROR_PPP_INVALID_PACKET;

			break;
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, TEXT( "SW2_TRACE_LEVEL_DEBUG::SW2EapMethodProcess::Send packet ID: %ld" ), pSendPacket->Id );
	SW2Trace( SW2_TRACE_LEVEL_DEBUG, TEXT( "SW2_TRACE_LEVEL_DEBUG::SW2EapMethodProcess::Sending packet(%ld)" ), SW2_WireToHostFormat16( pSendPacket->Length ) );
	SW2Dump( SW2_TRACE_LEVEL_DEBUG,  ( PBYTE ) pSendPacket, SW2_WireToHostFormat16( pSendPacket->Length ) );

	//
	// Handle error
	//	
	if( dwReturnCode != NO_ERROR &&
		dwReturnCode != PENDING )
	{
		BOOL bInvokeUI = TRUE;
		
		if (g_ResContext)
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::handling error via extension library" ) );

			//
			// use external interface to handle error
			// bInvokeUI will be set to TRUE if interaction is required
			//
			SW2_HandleError(dwReturnCode,
							SW2_EAP_FUNCTION_Process, 
							pSessionData->TLSSession.TLSState,
							&bInvokeUI);
		}

		if (bInvokeUI)
		{
			// 
			// Show error 
			// except of course if this has already been shown or
			// we received an error packet in which case we are not allowed to show an error...
			//
			if ( pSessionData->TLSSession.TLSState != SW2_TLS_STATE_Error &&
				pReceivePacket &&
				pReceivePacket->Code != SW2EAPCODE_Failure )
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::handling error via interactive UI" ) );

				pEapOutput->eapAction = SW2EAPACTION_InvokeUI;

				pSessionData->bInteractiveUIType = UI_TYPE_ERROR;

				pSessionData->dwLastSW2Error = dwReturnCode;

				pSessionData->LastEapFunction = SW2_EAP_FUNCTION_Process;

				pSessionData->TLSSession.LastTLSState = pSessionData->TLSSession.TLSState;

				pSessionData->TLSSession.TLSState = SW2_TLS_STATE_Error;

				dwReturnCode = NO_ERROR;
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::handling error normally (via Windows)" ) );

				//
				// Handle ERROR
				// If authentication failed, return no action to start reauthentication
				// immediatly
				//
				if( dwReturnCode == ERROR_PPP_INVALID_PACKET 
					|| dwReturnCode == PENDING)
					pEapOutput->eapAction = SW2EAPACTION_None;
				else if( dwReturnCode != NO_ERROR )
				{
					pEapOutput->eapAction = SW2EAPACTION_None;

				}
			}
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodProcess::returning: %ld" ), dwReturnCode );

	return dwReturnCode;
}


DWORD
SW2_GenerateKeyMaterial(IN HCRYPTPROV	hCSP,
						 IN BYTE		bEapType,
						IN DWORD		bCurrentMethodVersion,
						IN PBYTE		pbRandomClient,
						IN PBYTE		pbRandomServer,
						IN PBYTE		pbMS,
						IN PBYTE		pbKeyMaterial,
						IN DWORD		cbKeyMaterial)
{
	BYTE		pbClientServerRandom[TLS_RANDOM_SIZE*2];
	CHAR		pcLabel[UNLEN];
	DWORD		ccLabel;
	DWORD		dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_GenerateKeyMaterial" ) );

	dwReturnCode = NO_ERROR;

	if (hCSP)
	{
		//
		// Define label according to TTLS version
		//
		if (bEapType == EAP_TYPE_PEAP)
		{
			if( bCurrentMethodVersion == EAP_PEAP_V0 )
			{
				memset( pcLabel, 0, sizeof( pcLabel ) );

				strcpy_s(pcLabel, sizeof(pcLabel), 
						EAP_KEYING_MATERIAL_LABEL_PEAP_V0 );
			}
			else if( bCurrentMethodVersion == EAP_PEAP_V1 )
			{
				memset( pcLabel, 0, sizeof( pcLabel ) );

				strcpy_s(pcLabel, sizeof(pcLabel),
						EAP_KEYING_MATERIAL_LABEL_PEAP_V1 );									
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_GenerateKeyMaterial::Invalid method version" ) );

				dwReturnCode = ERROR_AUTH_INTERNAL;
			}
		}
		else if (bEapType == EAP_TYPE_TTLS)
		{
			if( bCurrentMethodVersion == EAP_TTLS_V0 )
			{
				memset( pcLabel, 0, sizeof( pcLabel ) );

				strcpy_s(pcLabel, sizeof(pcLabel),
						EAP_KEYING_MATERIAL_LABEL_TTLS_V0 );
			}
			else if( bCurrentMethodVersion == EAP_TTLS_V1 )
			{
				memset( pcLabel, 0, sizeof( pcLabel ) );

				strcpy_s(pcLabel, sizeof(pcLabel),
						EAP_KEYING_MATERIAL_LABEL_TTLS_V1 );		
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_GenerateKeyMaterial::Invalid method version" ) );

				dwReturnCode = ERROR_AUTH_INTERNAL;
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_GenerateKeyMaterial::Invalid EAPID" ) );

			dwReturnCode = ERROR_AUTH_INTERNAL;
		}

		if (dwReturnCode == NO_ERROR)
		{
			ccLabel = (DWORD) strlen(pcLabel);

			memset( pbClientServerRandom, 0, TLS_RANDOM_SIZE * 2 );
			memcpy( pbClientServerRandom, pbRandomClient, TLS_RANDOM_SIZE );
			memcpy( &( pbClientServerRandom[TLS_RANDOM_SIZE] ), pbRandomServer, TLS_RANDOM_SIZE );

			dwReturnCode = TLS_PRF( hCSP, 
									pbMS, 
									TLS_MS_SIZE, 
									(PBYTE)pcLabel, 
									ccLabel, 
									pbClientServerRandom, 
									TLS_RANDOM_SIZE * 2, 
									pbKeyMaterial, 
									cbKeyMaterial );
		}
	}
	
	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_GenerateKeyMaterial::return: %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_MakeMPPEKey
// Description: Creates the MPPE Keys needed for line encryption
// Author: Tom Rixom
//
DWORD	SW2_MakeMPPEKey(IN PBYTE					pbKeyMaterial,
						IN DWORD					cbKeyMaterial,
						IN OUT SW2EAPATTRIBUTE 		**ppUserAttributes )
{
	PBYTE				pb;
	DWORD				dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_MakeMPPEKey" ) );

	dwReturnCode = NO_ERROR;

	//
	// Copy the Read and Write keys into the radus attributes
	//
	//
	// Create the MPPE Struct:
	if ((dwReturnCode = SW2AllocateMemory(
		sizeof( SW2EAPATTRIBUTE ) * 3, 
		(PVOID*)ppUserAttributes))==NO_ERROR)
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_MakeMPPEKey::allocated %ld bytes for attributes" ),
			sizeof( SW2EAPATTRIBUTE ) * 3);

		//
		//
		// Bytes needed:
		//      4: Vendor-Id
		//      1: Vendor-Type
		//      1: Vendor-Length
		//      2: Salt
		//      1: Key-Length
		//     32: Key
		//     15: Padding
		//     -----------------
		//     56: Total
		//


		//
		// Copy MS-MPPE-Send-Key
		//
		if ((dwReturnCode = SW2AllocateMemory(
			56, 
			(PVOID*)&((*ppUserAttributes )[0].Value)))==NO_ERROR)
		{
			pb = (PBYTE)( *ppUserAttributes )[0].Value;

			SW2_HostToWireFormat32( 311, pb);	// Vendor-Id
			pb[4] = 16;							// Vendor-Type (MS-MPPE-Send-Key)
			pb[5] = 56 - 4;						// Vendor-Length (all except Vendor-Id)
			// pByte[6-7] is the zero-filled salt field
			pb[8] = 32;							// Key-Length

			memcpy(pb + 9, pbKeyMaterial, 32);

			// pByte[41-55] is the Padding (zero octets)

			( *ppUserAttributes )[0].dwLength = 56;
			( *ppUserAttributes )[0].aaType  = SW2EAPATTRIBUTE_VendorSpecific;

			//
			// Copy MS-MPPE-Recv-Key
			//
			if ((dwReturnCode = SW2AllocateMemory(
				56, 
				(PVOID*)&((*ppUserAttributes )[1].Value)))==NO_ERROR)
			{
				pb = (PBYTE)( *ppUserAttributes )[1].Value;

				SW2_HostToWireFormat32(311, pb); // Vendor-Id
				pb[4] = 17;                  // Vendor-Type (MS-MPPE-Recv-Key)
				pb[5] = 56 - 4;              // Vendor-Length (all except Vendor-Id)
				// pByte[6-7] is the zero-filled salt field
				pb[8] = 32;                  // Key-Length

				memcpy( pb + 9, pbKeyMaterial+32, 32);

				// pByte[41-55] is the Padding (zero octets)

				( *ppUserAttributes )[1].dwLength = 56;
				( *ppUserAttributes )[1].aaType  = SW2EAPATTRIBUTE_VendorSpecific;

				//
				// For Termination
				//
				( *ppUserAttributes )[2].aaType  = SW2EAPATTRIBUTE_Minimum;
				( *ppUserAttributes )[2].dwLength = 0;
				( *ppUserAttributes )[2].Value    = NULL;
			}

			if( dwReturnCode != NO_ERROR )
				SW2FreeMemory((PVOID*)&( *ppUserAttributes )[0].Value );
		}

		if( dwReturnCode != NO_ERROR )
			SW2FreeMemory((PVOID*)ppUserAttributes );
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_MakeMPPEKey::returning error: %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Return the authentication result. In this function the user data and/or
// configuration data is also returned to the upper layer to be stored
//
DWORD SW2EapMethodGetResult(IN PVOID				pWorkBuffer,
							IN SW2_EAP_REASON		eapReason,
							OUT	BOOL				*pfResult,
							OUT BOOL				*pfSaveUserData,
							OUT	DWORD				*pdwSizeofUserData,
							OUT PBYTE				*ppbUserData,
							OUT BOOL				*pfSaveConnectionData,
							OUT	DWORD				*pdwSizeofConnectionData,
							OUT PBYTE				*ppbConnectionData,
							OUT	DWORD				*pdwNumberOfAttributes,
							OUT PSW2EAPATTRIBUTE	*pAttributes)
{
	BOOL				bInvokeUI;
	PSW2_SESSION_DATA	pSessionData;
	PSW2_USER_DATA		pUserData;
	PSW2_PROFILE_DATA	pProfileData;
	BYTE				pSendPacket[1500];
	DWORD				dwSizeOfSendPacket;
	SW2EAPOUTPUT		EapOutput;
	DWORD				dwReturnCode;
	DWORD				dwSizeOfUserData;
	DWORD				dwSizeOfProfileData;
	BYTE				pbKeyMaterial[TLS_RANDOM_SIZE*2];
	DWORD				cbKeyMaterial = sizeof( pbKeyMaterial );

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetResult()");

	pSessionData = (PSW2_SESSION_DATA) pWorkBuffer;

	*pfResult = FALSE;

	*pfSaveUserData = FALSE;
	*pdwSizeofUserData = 0;
	*ppbUserData = NULL;
	*pfSaveConnectionData = FALSE;
	*pdwSizeofConnectionData = 0;
	*ppbConnectionData = NULL;
	*pdwNumberOfAttributes = 0;
	*pAttributes = NULL;

	//
	// Update the authentication state
	//
	pSessionData->UserData.prevEapReason = eapReason;

	//
	// When using inner EAP inform the inner method of the result (except if this is a session resume or the access/reject was already handled)
	//
	if ((wcscmp( pSessionData->ProfileData.pwcInnerAuth, L"EAP") == 0) &&
		pSessionData->TLSSession.TLSState != SW2_TLS_STATE_Resume_Session_Ack &&
		!pSessionData->InnerSessionData.bHandledInnerAccessReject)
	{
		//
		// For RASEAP construct a EAP Success or Failure packet 
		//
		SW2Trace( SW2_TRACE_LEVEL_INFO, 
			TEXT( "SW2_TRACE_LEVEL_INFO::calling inner eap" ));

		dwSizeOfSendPacket = sizeof(pSendPacket);

		if (eapReason == SW2_EAP_REASON_Success)
		{
			dwReturnCode = TLSInitTLSAcceptPacket(pSessionData->bPacketId, 
												(PSW2EAPPACKET)pSessionData->TLSSession.pbInnerEapMessage, 
												sizeof(pSessionData->TLSSession.pbInnerEapMessage));
		}
		else
		{
			dwReturnCode = TLSInitTLSRejectPacket(pSessionData->bPacketId, 
													(PSW2EAPPACKET)pSessionData->TLSSession.pbInnerEapMessage, 
													sizeof(pSessionData->TLSSession.pbInnerEapMessage));
		}

		if (dwReturnCode == NO_ERROR)
		{
			dwReturnCode = AuthHandleInnerAuthentication( pSessionData, 
														(PSW2EAPPACKET)pSendPacket, 
														dwSizeOfSendPacket, 
														&EapOutput );
		}
	}
	else
	{
		//TODO: For EapHost call GetResult on inner eap method
	}

	if (dwReturnCode == NO_ERROR)
	{
		if (eapReason==SW2_EAP_REASON_Success)
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetResult::authentication SUCCESS" ) );

			if( pSessionData->TLSSession.TLSState == SW2_TLS_STATE_Resume_Session_Ack ||
				pSessionData->TLSSession.TLSState == SW2_TLS_STATE_Inner_Authentication)
			{
				if ((dwReturnCode = SW2_GenerateKeyMaterial(pSessionData->TLSSession.hCSP,
														EAPTYPE,
														pSessionData->bCurrentMethodVersion,
														pSessionData->TLSSession.pbRandomClient,
														pSessionData->TLSSession.pbRandomServer,
														pSessionData->TLSSession.pbMS,
														pbKeyMaterial,
														cbKeyMaterial))==NO_ERROR)
				{
					if( ( dwReturnCode = SW2_MakeMPPEKey( pbKeyMaterial, 
														cbKeyMaterial,
														pAttributes ) ) == NO_ERROR )
					{
						*pdwNumberOfAttributes = 3;
						*pfResult = TRUE;
					}
				}

				//
				// Save user credentials for single logon?
				//
				if (pSessionData->UserData.bSaveUserCredentials)
				{
					memcpy( pSessionData->ProfileData.pwcUserName,
							pSessionData->UserData.pwcUsername,
							sizeof( pSessionData->ProfileData.pwcUserName ) );

					memcpy( pSessionData->ProfileData.pwcUserPassword,
							pSessionData->UserData.pwcPassword,
							sizeof( pSessionData->ProfileData.pwcUserPassword ) );

					memcpy( pSessionData->ProfileData.pwcUserDomain,
							pSessionData->UserData.pwcDomain,
							sizeof( pSessionData->ProfileData.pwcUserDomain ) );

					pSessionData->ProfileData.bPromptUser = FALSE;
				}

				//
				// Save TLS session data for TLS session resumption?
				//
				if (pSessionData->ProfileData.bUseSessionResumption)
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
						TEXT( "SW2_TRACE_LEVEL_DEBUG::SW2EapMethodGetResult::saving TLS session" ) );

					pSessionData->UserData.cbTLSSessionID = pSessionData->TLSSession.cbTLSSessionID;

					memset(pSessionData->UserData.pbTLSSessionID, 0, sizeof(pSessionData->UserData.pbTLSSessionID));

					memcpy_s(pSessionData->UserData.pbTLSSessionID,
							sizeof(pSessionData->UserData.pbTLSSessionID), 
							pSessionData->TLSSession.pbTLSSessionID,
							pSessionData->UserData.cbTLSSessionID);

					memcpy_s(&pSessionData->UserData.tTLSSessionID,
							sizeof(time_t),
							&pSessionData->TLSSession.tTLSSessionID,
							sizeof(time_t));

					memcpy_s(pSessionData->UserData.pbMS,
							TLS_MS_SIZE, 
							pSessionData->TLSSession.pbMS,
							TLS_MS_SIZE);
				}

				SW2_WriteUserProfile( pSessionData->pwcCurrentProfileId, 
									pSessionData->hTokenImpersonateUser,
									pSessionData->ProfileData );

				SW2_WriteComputerProfile( pSessionData->pwcCurrentProfileId, 
										pSessionData->hTokenImpersonateUser,
											pSessionData->ProfileData );

				//
				// Save user data
				//
				dwSizeOfUserData = sizeof(SW2_USER_DATA);

				SW2Trace( SW2_TRACE_LEVEL_INFO, 
					TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetResult::allocating %ld bytes for user data" ),
					dwSizeOfUserData );

				if ((SW2AllocateMemory(dwSizeOfUserData, (PVOID*) &pUserData))==NO_ERROR)
				{
					memcpy(pUserData, &(pSessionData->UserData), dwSizeOfUserData);

					if (!pUserData->InnerEapUserData.fSaveUserData)
						memset(&(pUserData->InnerEapUserData), 0, sizeof(pUserData->InnerEapUserData));

					*pfSaveUserData = TRUE;
					*pdwSizeofUserData = dwSizeOfUserData;
					*ppbUserData = (PBYTE) pUserData;
				}

				//
				// Save inner EAP connection data
				//
				if (pSessionData->InnerSessionData.pInnerEapConfigData &&
					pSessionData->InnerSessionData.pInnerEapConfigData->fSaveConnectionData)
				{
					dwReturnCode = SW2_WriteInnerEapMethod(pSessionData->ProfileData.dwCurrentInnerEapMethod, 
															pSessionData->pwcCurrentProfileId,
															pSessionData->InnerSessionData.pInnerEapConfigData->pbConnectionData,
															pSessionData->InnerSessionData.pInnerEapConfigData->cbConnectionData);
				}

				pSessionData->TLSSession.TLSState = SW2_TLS_STATE_Finished;
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_WARNING, 
					TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodGetResult::invalid authentication state %ld" ),
					pSessionData->TLSSession.TLSState );
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetResult::authentication FAILED" ) );

			SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
				TEXT( "SW2_TRACE_LEVEL_DEBUG::SW2EapMethodGetResult::pSessionData->TLSSession.LastTLSState: %ld" ),
				pSessionData->TLSSession.LastTLSState);

			SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
				TEXT( "SW2_TRACE_LEVEL_DEBUG::SW2EapMethodGetResult::pSessionData->TLSSession.TLSState: %ld" ), 
				pSessionData->TLSSession.TLSState);

			//
			// If we failed after the TLS was setup, in the inner authentication, 
			// bPromptUser to query for password next time (if we are using the SW2 interface ofc)
			//
			if ((pSessionData->TLSSession.LastTLSState == SW2_TLS_STATE_Inner_Authentication||
				pSessionData->TLSSession.TLSState == SW2_TLS_STATE_Inner_Authentication))
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, 
					TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetResult::inner authentication failed, will prompt user for password" ) );

				pSessionData->ProfileData.bPromptUser = TRUE;

				SW2_WriteUserProfile( pSessionData->pwcCurrentProfileId, 
										pSessionData->hTokenImpersonateUser,
										pSessionData->ProfileData );
			}
		}

		if (wcscmp(pSessionData->pwcCurrentProfileId, L"EAPHOSTXML") == 0)
		{
			dwSizeOfProfileData = sizeof(SW2_PROFILE_DATA);

			SW2Trace( SW2_TRACE_LEVEL_INFO, 
					TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetResult::allocating %ld bytes for connection data" ),
					dwSizeOfProfileData );

			if ((SW2AllocateMemory(dwSizeOfProfileData, (PVOID*) &pProfileData))==NO_ERROR)
			{
				memcpy(pProfileData, &(pSessionData->ProfileData), dwSizeOfProfileData);

#ifndef _WIN32_WCE
				if (pSessionData->InnerSessionData.pInnerEapConfigData &&
					pSessionData->InnerSessionData.pInnerEapConfigData->fSaveConnectionData)
				{
					if (pSessionData->InnerSessionData.pInnerEapConfigData->cbConnectionData <= sizeof(pProfileData->pbInnerEapConnectionData))
					{
						memset(pProfileData->pbInnerEapConnectionData, 0, sizeof(pProfileData->pbInnerEapConnectionData));
						
						pProfileData->cbInnerEapConnectionData = pSessionData->InnerSessionData.pInnerEapConfigData->cbConnectionData;
						
						memcpy(pProfileData->pbInnerEapConnectionData, 
							pSessionData->InnerSessionData.pInnerEapConfigData->pbConnectionData, 
							pSessionData->InnerSessionData.pInnerEapConfigData->cbConnectionData);
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_WARNING, 
							L"SW2_TRACE_LEVEL_WARNING::SW2EapMethodGetResult()::not enough memory to store inner connection data in XML profile");
					}
				}

#endif //_WIN32_WCE

				*pfSaveConnectionData = TRUE;
				*pdwSizeofConnectionData = dwSizeOfProfileData;
				*ppbConnectionData = (PBYTE) pProfileData;

			}
		}
	}


	// inform extension library of success/failure
	if (g_ResContext)
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, 
			TEXT( "SW2_TRACE_LEVEL_INFO::SW2EapMethodGetResult::handling result via extension library" ) );


		if (!*pfResult && eapReason == SW2_EAP_REASON_Success)
		{
			// we did recieve a ACCESS-ACCEPT, but we failed on the client side
			g_ResContext->pSW2HandleResult(g_ResContext->pContext,
											SW2_EAP_REASON_Failure);
		}
		else
		{
			g_ResContext->pSW2HandleResult(g_ResContext->pContext,
											eapReason);
		}
	}

	SW2_HandleError(dwReturnCode, 
		SW2_EAP_FUNCTION_GetResult, 
		pSessionData->TLSSession.TLSState,
		&bInvokeUI);

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodGetResult()::returning %ld", dwReturnCode);

	return dwReturnCode;
}

#ifndef _WIN32_WCE
//
// Convert an XML structure to a byte blob, this blob is uses in
// the API function calls during authentication
//
DWORD SW2EapMethodConfigXml2Blob(IN DWORD				dwFlags,
								 IN IXMLDOMDocument2	*pXMLConfigDoc,
								 OUT PBYTE				*ppbConfigOut,
								 OUT DWORD				*pdwSizeOfConfigOut)
{
	HRESULT						hr;
	IXMLDOMNodeList				*pDOMList = NULL;
	IXMLDOMNode					*pDOMNode = NULL;
	IXMLDOMNode					*pEAPConfigDOMNode = NULL;
	long						lListLength;
	PSW2_CONFIG_DATA			pConfigData;
	PSW2_PROFILE_DATA			pProfileData;
	CHAR						pcTemp[256];
	PBYTE						pbTemp;
	DWORD						cbTemp = 0;
	PWCHAR						pwcElementValue;
	DWORD						dwSizeOfConfigData;
	DWORD						i;
    DWORD						dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodConfigXml2Blob()::flags: %x", dwFlags);

	if ((dwReturnCode = SW2_GetXmlElementValue(pXMLConfigDoc, L"Profile", &pwcElementValue))==NO_ERROR)
	{   
		if ((dwReturnCode = SW2AllocateMemory(sizeof(SW2_CONFIG_DATA), (PVOID*)&pConfigData))==NO_ERROR)
		{
			if (((wcslen(pwcElementValue)+1)*sizeof(WCHAR))<=sizeof(pConfigData->pwcProfileId))
			{
				wcscpy_s(pConfigData->pwcProfileId, sizeof(pConfigData->pwcProfileId), pwcElementValue);
			}
			else
			{
				wcscpy_s(pConfigData->pwcProfileId, sizeof(pConfigData->pwcProfileId), L"DEFAULT");
			}

			dwSizeOfConfigData = sizeof(SW2_CONFIG_DATA);

			*ppbConfigOut = (PBYTE) pConfigData;
			*pdwSizeOfConfigOut = dwSizeOfConfigData;
		}

		SysFreeString(pwcElementValue);
	}
	else if ((dwReturnCode = SW2_GetXmlElementValue(pXMLConfigDoc, L"Configuration", &pwcElementValue))==NO_ERROR)
	{   
		SysFreeString(pwcElementValue);

		if ((dwReturnCode = SW2AllocateMemory(sizeof(SW2_PROFILE_DATA), (PVOID*)&pProfileData))==NO_ERROR)
		{
			SW2_InitDefaultProfile(pProfileData, EAPTYPE);

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"UseAlternateOuterIdentity", &pwcElementValue))==NO_ERROR)			
			{ 
				pProfileData->bUseAlternateIdentity = FALSE;

				if (wcscmp(pwcElementValue, L"true")==0 ||
					wcscmp(pwcElementValue, L"TRUE")==0)
					pProfileData->bUseAlternateIdentity = TRUE;

				SysFreeString(pwcElementValue);
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"UseAnonymousOuterIdentity", &pwcElementValue))==NO_ERROR)			
			{ 
				pProfileData->bUseAnonymousIdentity = FALSE;

				if (wcscmp(pwcElementValue, L"true")==0 ||
					wcscmp(pwcElementValue, L"TRUE")==0)
					pProfileData->bUseAnonymousIdentity = TRUE;

				SysFreeString(pwcElementValue);
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"AlternateOuterIdentity", &pwcElementValue))==NO_ERROR)			
			{ 
				if (((wcslen(pwcElementValue)+1)*sizeof(WCHAR))<=sizeof(pProfileData->pwcAlternateIdentity))
				{
					wcscpy_s(pProfileData->pwcAlternateIdentity, sizeof(pProfileData->pwcAlternateIdentity), 
						pwcElementValue);
				}

				SysFreeString(pwcElementValue);
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"UseSessionResumption", &pwcElementValue))==NO_ERROR)			
			{ 
				pProfileData->bUseSessionResumption = FALSE;

				if (wcscmp(pwcElementValue, L"true")==0 ||
					wcscmp(pwcElementValue, L"TRUE")==0)
					pProfileData->bUseSessionResumption= TRUE;

				SysFreeString(pwcElementValue);
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"VerifyServerCertificate", &pwcElementValue))==NO_ERROR)			
			{ 
				pProfileData->bVerifyServerCertificate = FALSE;

				if (wcscmp(pwcElementValue, L"true")==0 ||
					wcscmp(pwcElementValue, L"TRUE")==0)
					pProfileData->bVerifyServerCertificate = TRUE;

				SysFreeString(pwcElementValue);
			}

			pProfileData->bVerifyServerName = FALSE;
			
			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"ServerName", &pwcElementValue))==NO_ERROR)			
			{ 
				if (((wcslen(pwcElementValue)+1)*sizeof(WCHAR))<=sizeof(pProfileData->pwcServerName))
				{
					wcscpy_s(pProfileData->pwcServerName, sizeof(pProfileData->pwcServerName), pwcElementValue);
				}

				pProfileData->bVerifyServerName = TRUE;

				SysFreeString(pwcElementValue);
			}

			pProfileData->dwNrOfTrustedRootCAInList = 0;

			//
			// Retrieve XML list
			//
			if ((SW2_GetXmlElementList(pXMLConfigDoc, L"Certificate", &pDOMList))==NO_ERROR)			
			{ 
				if (pDOMList != NULL)
				{
					//
					// Retrieve length of list
					//
					if (SUCCEEDED(hr = pDOMList->get_length(&lListLength)))
					{
						//
						// Loop through list and retrieve text value of each node
						//
						for (i=0; (i<(DWORD)lListLength)&&(i<SW2_MAX_CA); i++)
						{
							if (SUCCEEDED(hr = pDOMList->get_item(i, &pDOMNode)))
							{
								// 
								// Get the content of the node as BSTR, to free string call SysFreeString(pbstrElementValue);
								//
								if (SUCCEEDED(hr = pDOMNode->get_text((BSTR*)&pwcElementValue)))
								{
									if ((WideCharToMultiByte(CP_ACP, 
																0, 
																pwcElementValue, -1, 
																pcTemp, sizeof(pcTemp), 
																NULL, NULL)) > 0)
									{
										if (SW2_HexToByte(pcTemp, &cbTemp, &pbTemp) == NO_ERROR)
										{
											if (cbTemp <= sizeof(pProfileData->pbTrustedRootCAList[i]))
											{
												memcpy_s(pProfileData->pbTrustedRootCAList[i],
													sizeof(pProfileData->pbTrustedRootCAList[i]),
													pbTemp,
													cbTemp);

												pProfileData->dwNrOfTrustedRootCAInList++;
											}

											SW2FreeMemory((PVOID*)&pbTemp);
										}
									}

									SysFreeString((BSTR)pwcElementValue);
								}
								else
								{
									dwReturnCode = HRESULT_CODE(hr);

									SW2Trace( SW2_TRACE_LEVEL_ERROR, 
										L"SW2_TRACE_LEVEL_ERROR::SW2EapMethodConfigXml2Blob()::get_text failed for Element = Certificate, error: %ld", 
										dwReturnCode);
								}
							}
						}
					}

					pDOMList->Release();
					pDOMList = NULL;
				}
				else
				{
					dwReturnCode = ERROR_NO_DATA;

					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
						L"SW2_TRACE_LEVEL_ERROR::SW2EapMethodConfigXml2Blob()::no information available for Element = Certificate");
				}
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"AuthenticationMethod", &pwcElementValue))==NO_ERROR)			
			{ 
				if (((wcslen(pwcElementValue)+1)*sizeof(WCHAR))<=sizeof(pProfileData->pwcInnerAuth))
				{
					wcscpy_s(pProfileData->pwcInnerAuth, sizeof(pProfileData->pwcInnerAuth), pwcElementValue);
				}

				SysFreeString(pwcElementValue);
			}

			if (wcscmp(pProfileData->pwcInnerAuth, L"EAP")==0)
			{
				//
				// Retrieve inner EAP configuration
				//
				if (SW2_GetXmlElementValue(pXMLConfigDoc, 
					L"EapConfig//securew2:EapHostConfig//securew2:EapMethod//securew2:Type", &pwcElementValue)== NO_ERROR)
				{
					pProfileData->dwCurrentInnerEapMethod = _wtol(pwcElementValue);
					SysFreeString(pwcElementValue);

					if (SW2_GetXmlElementValue(pXMLConfigDoc, 
						L"EapConfig//securew2:EapHostConfig//securew2:ConfigBlob", 
						&pwcElementValue)== NO_ERROR)
					{
						if ((WideCharToMultiByte(CP_ACP, 
												0, 
												pwcElementValue, -1, 
												pcTemp, sizeof(pcTemp), 
												NULL, NULL)) > 0)
					
						{
							if (SW2_HexToByte(pcTemp, &cbTemp, &pbTemp) == NO_ERROR)
							{
								if (cbTemp <= sizeof(pProfileData->pbInnerEapConnectionData))
								{
									memcpy_s(pProfileData->pbInnerEapConnectionData,
										sizeof(pProfileData->pbInnerEapConnectionData),
										pbTemp,
										cbTemp);

									pProfileData->cbInnerEapConnectionData = cbTemp;
								}

								SW2FreeMemory((PVOID*)&pbTemp);
							}
						}

						SysFreeString(pwcElementValue);
					}
				}
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"PromptUser", &pwcElementValue))==NO_ERROR)			
			{ 
				pProfileData->bPromptUser = FALSE;

				if (wcscmp(pwcElementValue, L"true")==0 ||
					wcscmp(pwcElementValue, L"TRUE")==0)
					pProfileData->bPromptUser = TRUE;

				SysFreeString(pwcElementValue);
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"UserName", &pwcElementValue))==NO_ERROR)			
			{ 
				if (((wcslen(pwcElementValue)+1)*sizeof(WCHAR))<=sizeof(pProfileData->pwcUserName))
				{
					wcscpy_s(pProfileData->pwcUserName, sizeof(pProfileData->pwcUserName), pwcElementValue);
				}

				SysFreeString(pwcElementValue);
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"UserPassword", &pwcElementValue))==NO_ERROR)			
			{ 
				if (((wcslen(pwcElementValue)+1)*sizeof(WCHAR))<=sizeof(pProfileData->pwcUserPassword))
				{
					wcscpy_s(pProfileData->pwcUserPassword, sizeof(pProfileData->pwcUserPassword), pwcElementValue);
				}

				SysFreeString(pwcElementValue);
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"UserDomain", &pwcElementValue))==NO_ERROR)			
			{ 
				if (((wcslen(pwcElementValue)+1)*sizeof(WCHAR))<=sizeof(pProfileData->pwcUserDomain))
				{
					wcscpy_s(pProfileData->pwcUserDomain, sizeof(pProfileData->pwcUserDomain), pwcElementValue);
				}

				SysFreeString(pwcElementValue);
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"UseUserCredentialsForComputer", &pwcElementValue))==NO_ERROR)			
			{ 
				pProfileData->bUseUserCredentialsForComputer = FALSE;

				if (wcscmp(pwcElementValue, L"true")==0 ||
					wcscmp(pwcElementValue, L"TRUE")==0)
					pProfileData->bUseUserCredentialsForComputer = TRUE;

				SysFreeString(pwcElementValue);
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"UseAlternateComputerCredentials", &pwcElementValue))==NO_ERROR)			
			{ 
				pProfileData->bUseAlternateComputerCred = FALSE;

				if (wcscmp(pwcElementValue, L"true")==0 ||
					wcscmp(pwcElementValue, L"TRUE")==0)
					pProfileData->bUseAlternateComputerCred = TRUE;

				SysFreeString(pwcElementValue);
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"ComputerName", &pwcElementValue))==NO_ERROR)			
			{ 
				if (((wcslen(pwcElementValue)+1)*sizeof(WCHAR))<=sizeof(pProfileData->pwcCompName))
				{
					wcscpy_s(pProfileData->pwcCompName, sizeof(pProfileData->pwcCompName), pwcElementValue);
				}

				SysFreeString(pwcElementValue);
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"ComputerPassword", &pwcElementValue))==NO_ERROR)			
			{ 
				if (((wcslen(pwcElementValue)+1)*sizeof(WCHAR))<=sizeof(pProfileData->pwcCompPassword))
				{
					wcscpy_s(pProfileData->pwcCompPassword, sizeof(pProfileData->pwcCompPassword), pwcElementValue);
				}

				SysFreeString(pwcElementValue);
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"ComputerDomain", &pwcElementValue))==NO_ERROR)			
			{ 
				if (((wcslen(pwcElementValue)+1)*sizeof(WCHAR))<=sizeof(pProfileData->pwcCompDomain))
				{
					wcscpy_s(pProfileData->pwcCompDomain, sizeof(pProfileData->pwcCompDomain), pwcElementValue);
				}

				SysFreeString(pwcElementValue);
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"ServerCertificateOnLocalComputer", &pwcElementValue))==NO_ERROR)			
			{ 
				pProfileData->bServerCertificateLocal = FALSE;

				if (wcscmp(pwcElementValue, L"true")==0 ||
					wcscmp(pwcElementValue, L"TRUE")==0)
					pProfileData->bServerCertificateLocal = TRUE;

				SysFreeString(pwcElementValue);
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"CheckForMicrosoftExtension", &pwcElementValue))==NO_ERROR)			
			{ 
				pProfileData->bVerifyMSExtension = FALSE;

				if (wcscmp(pwcElementValue, L"true")==0 ||
					wcscmp(pwcElementValue, L"TRUE")==0)
					pProfileData->bVerifyMSExtension = TRUE;

				SysFreeString(pwcElementValue);
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"AllowNewConnections", &pwcElementValue))==NO_ERROR)			
			{ 
				pProfileData->bAllowNewConnection = FALSE;

				if (wcscmp(pwcElementValue, L"true")==0 ||
					wcscmp(pwcElementValue, L"TRUE")==0)
					pProfileData->bAllowNewConnection = TRUE;

				SysFreeString(pwcElementValue);
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"UseEmptyOuterIdentity", &pwcElementValue))==NO_ERROR)			
			{ 
				pProfileData->bUseEmptyIdentity = FALSE;

				if (wcscmp(pwcElementValue, L"true")==0 ||
					wcscmp(pwcElementValue, L"TRUE")==0)
					pProfileData->bUseEmptyIdentity = TRUE;

				SysFreeString(pwcElementValue);
			}

			if ((SW2_GetXmlElementValue(pXMLConfigDoc, L"AllowNotifications", &pwcElementValue))==NO_ERROR)			
			{ 
				pProfileData->bAllowNotifications = FALSE;

				if (wcscmp(pwcElementValue, L"true")==0 ||
					wcscmp(pwcElementValue, L"TRUE")==0)
					pProfileData->bAllowNotifications = TRUE;

				SysFreeString(pwcElementValue);
			}

			if (pProfileData->bUseUserCredentialsForComputer && 
				!pProfileData->bUseAlternateComputerCred)
			{
				memset(pProfileData->pwcCompName, 0, sizeof(pProfileData->pwcCompName) );
				memcpy(pProfileData->pwcCompName, pProfileData->pwcUserName, sizeof(pProfileData->pwcCompName ) );
				memset(pProfileData->pwcCompPassword, 0, sizeof(pProfileData->pwcCompPassword ) );
				memcpy(pProfileData->pwcCompPassword, pProfileData->pwcUserPassword, sizeof(pProfileData->pwcCompPassword ) );
				memset(pProfileData->pwcCompDomain, 0, sizeof(pProfileData->pwcCompDomain ) );
				memcpy(pProfileData->pwcCompDomain, pProfileData->pwcUserDomain, sizeof(pProfileData->pwcCompDomain ) );
			}

			dwSizeOfConfigData = sizeof(SW2_PROFILE_DATA);

			*ppbConfigOut = (PBYTE) pProfileData;
			*pdwSizeOfConfigOut = dwSizeOfConfigData;
		}

		if (dwReturnCode != NO_ERROR)
			SW2FreeMemory((PVOID*)&pConfigData);
	}

	//
	// Something went wrong, return no data, this will be handled by TTLS client by using DEFAULT connection
	//
	if (dwReturnCode != NO_ERROR)
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2EapMethodConfigXml2Blob()::an error occured (%ld), returning empty blob", dwReturnCode);

		dwReturnCode = NO_ERROR;

		*ppbConfigOut = NULL;
		*pdwSizeOfConfigOut = 0;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodConfigXml2Blob()::returning: %ld", dwReturnCode);

    return dwReturnCode;
}

//
// Convert a configuration blob to an XML structure
//
DWORD SW2EapMethodConfigBlob2Xml(IN DWORD				dwFlags,
								 IN const BYTE			*pbConfig,
								 IN DWORD				dwSizeOfConfig,
								 OUT IXMLDOMDocument2	**ppXMLConfigDoc)
{
	PSW2_CONFIG_DATA	pConfigData;
	PSW2_PROFILE_DATA	pProfileData;
	SW2_GTC_CONFIG_DATA	gtcConfigData;
	IXMLDOMNode			*pTTLSDOMNode;
	IXMLDOMNode			*pConfigurationDOMNode;
	IXMLDOMNode			*pSectionDOMNode;
	IXMLDOMNode			*pSubSectionDOMNode;
	IXMLDOMNode			*pSubSubSectionDOMNode;
	CComVariant			varNodeType;
	VARIANT				var;
	HRESULT				hr;
	DWORD				dwReturnCode = NO_ERROR;
	VARIANT_BOOL		fSuccess;
	IXMLDOMDocument2	*pXmlDoc = NULL;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapmethodConfigBlob2Xml()");

	if (SUCCEEDED((hr = CoCreateInstance(CLSID_DOMDocument60,
								  NULL,
								  CLSCTX_INPROC_SERVER,
								  IID_IXMLDOMDocument2,
								  reinterpret_cast<void**>(&pXmlDoc)
								  ))))
	{
		if (SUCCEEDED((hr = pXmlDoc->put_async(VARIANT_FALSE))))
		{
			VARIANT_BOOL isSuccess = VARIANT_FALSE;

			if ((var.bstrVal = 
				SysAllocString(L"xmlns:securew2=\"http://schemas.securew2.com/eapconfig/eap-ttls/v0\"")))
			{
				var.vt = VT_BSTR;

				if (SUCCEEDED(hr = pXmlDoc->setProperty((BSTR)L"SelectionNamespaces", var)))
				{
					//
					// Load default configuration
					//
					if (SUCCEEDED(
						(hr = pXmlDoc->loadXML(L"<Config xmlns=\"http://www.microsoft.com/provisioning/EapHostConfig\"><eap-ttls xmlns=\"http://schemas.securew2.com/eapconfig/eap-ttls/v0\"></eap-ttls></Config>", &isSuccess))))
					{
						if (isSuccess)
						{
							//
							// Select eap-ttls node
							//
							if (SUCCEEDED(hr = pXmlDoc->selectSingleNode((BSTR)L"//securew2:eap-ttls", &pTTLSDOMNode)))
							{
								if (!pTTLSDOMNode)
									dwReturnCode = ERROR_NO_DATA;
							}
							else
							{
								dwReturnCode = HRESULT_CODE(hr);

								SW2Trace( SW2_TRACE_LEVEL_ERROR, 
									L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::failed to selectSingleNode: %ld", 
									dwReturnCode);
							}
						}
						else
							dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
					}
					else
					{
						dwReturnCode = HRESULT_CODE(hr);

						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::failed to loadXML: %ld", 
							dwReturnCode);
					}
				}
				else
				{
					dwReturnCode = HRESULT_CODE(hr);

					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
						L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::failed to setProperty(SelectionNamespaces): %ld", 
						dwReturnCode);
				}

				SysFreeString(var.bstrVal);
			}
			else
				dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
		}
		else
		{
			dwReturnCode = HRESULT_CODE(hr);		
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::put_async failed::error: %ld", dwReturnCode);
		}

		//
		// Fill XML according to data provided in blob
		//
		if (dwReturnCode == NO_ERROR)
		{
			dwReturnCode = ERROR_INVALID_DATA;

			if (pbConfig && dwSizeOfConfig == sizeof(SW2_CONFIG_DATA))
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapmethodConfigBlob2Xml()::using normal profile data (SW2 Profile)");

				pConfigData = (PSW2_CONFIG_DATA) pbConfig;

				dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
													pTTLSDOMNode,
													L"Profile",
													pConfigData->pwcProfileId);

			}
			else if (pbConfig && dwSizeOfConfig == sizeof(SW2_PROFILE_DATA))
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, 
					L"SW2_TRACE_LEVEL_INFO::SW2EapmethodConfigBlob2Xml()::using configuration data provided by wlan interface (XML Profile)");

				pProfileData = (PSW2_PROFILE_DATA) pbConfig;

				if ((dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
															pTTLSDOMNode,
															L"Configuration",
															NULL))==NO_ERROR)
				{
					if (SUCCEEDED(hr = pXmlDoc->selectSingleNode((BSTR)L"//securew2:Configuration", &pConfigurationDOMNode)))
					{
						if (!pConfigurationDOMNode)
							dwReturnCode = ERROR_NO_DATA;
					}
					else
					{
						dwReturnCode = HRESULT_CODE(hr);

						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::failed to selectSingleNode: %ld", 
							dwReturnCode);
					}
				}

				if (dwReturnCode == NO_ERROR )
				{
					// connection
					if ((dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
															pConfigurationDOMNode,
															L"Connection",
															NULL))==NO_ERROR)
					{
						if (SUCCEEDED(hr = pXmlDoc->selectSingleNode((BSTR)L"//securew2:Connection", &pSectionDOMNode)))
						{
							if (!pSectionDOMNode)
								dwReturnCode = ERROR_NO_DATA;
						}
						else
						{
							dwReturnCode = HRESULT_CODE(hr);

							SW2Trace( SW2_TRACE_LEVEL_ERROR, 
								L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::failed to selectSingleNode: %ld", 
								dwReturnCode);
						}
					}

					if (dwReturnCode == NO_ERROR)
					{
						dwReturnCode = SW2_PutXmlElementBOOL(pXmlDoc,
															pSectionDOMNode,
															L"UseAlternateOuterIdentity",
															pProfileData->bUseAlternateIdentity);
						if (dwReturnCode==NO_ERROR)
						{
							dwReturnCode = SW2_PutXmlElementBOOL(pXmlDoc,
																pSectionDOMNode,
																L"UseAnonymousOuterIdentity",
																pProfileData->bUseAnonymousIdentity);
						}

						if (dwReturnCode==NO_ERROR)
						{
							if (wcslen(pProfileData->pwcAlternateIdentity)>0)
							{
								dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
																	pSectionDOMNode,
																	L"AlternateOuterIdentity",
																	pProfileData->pwcAlternateIdentity);
							}
						}

						if (dwReturnCode==NO_ERROR)
						{
							dwReturnCode = SW2_PutXmlElementBOOL(pXmlDoc,
																pSectionDOMNode,
																L"UseSessionResumption",
																pProfileData->bUseSessionResumption);
						}	

						pSectionDOMNode->Release();
						pSectionDOMNode = NULL;
					}
				
					if (dwReturnCode == NO_ERROR)
					{
						// certificates
						if ((dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
																pConfigurationDOMNode,
																L"ServerValidation",
																NULL))==NO_ERROR)
						{
							if (SUCCEEDED(hr = pXmlDoc->selectSingleNode((BSTR)L"//securew2:ServerValidation", &pSectionDOMNode)))
							{
								if (!pSectionDOMNode)
									dwReturnCode = ERROR_NO_DATA;
							}
							else
							{
								dwReturnCode = HRESULT_CODE(hr);

								SW2Trace( SW2_TRACE_LEVEL_ERROR, 
									L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::failed to selectSingleNode: %ld", 
									dwReturnCode);
							}
						}

						if (dwReturnCode == NO_ERROR)
						{
							dwReturnCode = SW2_PutXmlElementBOOL(pXmlDoc,
																pSectionDOMNode,
																L"VerifyServerCertificate",
																pProfileData->bVerifyServerCertificate);

							if (dwReturnCode==NO_ERROR)
							{
								if (wcslen(pProfileData->pwcServerName)>0)
								{
									dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
																		pSectionDOMNode,
																		L"ServerName",
																		pProfileData->pwcServerName);
								}
							}

							if (dwReturnCode==NO_ERROR)
							{
								if ((dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
																pSectionDOMNode,
																L"TrustedRootCA",
																NULL))==NO_ERROR)
								{
									if (SUCCEEDED(hr = pXmlDoc->selectSingleNode((BSTR)L"//securew2:TrustedRootCA", &pSubSectionDOMNode)))
									{
										if (!pSubSectionDOMNode)
											dwReturnCode = ERROR_NO_DATA;
									}
									else
									{
										dwReturnCode = HRESULT_CODE(hr);

										SW2Trace( SW2_TRACE_LEVEL_ERROR, 
											L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::failed to selectSingleNode: %ld", 
											dwReturnCode);
									}
								}

								if (dwReturnCode==NO_ERROR)
								{
									DWORD i;

									for(i=0; i< pProfileData->dwNrOfTrustedRootCAInList&&dwReturnCode==NO_ERROR;i++)
									{
										dwReturnCode = SW2_PutXmlElementHex(pXmlDoc,
																			pSubSectionDOMNode,
																			L"Certificate",
																			sizeof(pProfileData->pbTrustedRootCAList[i]),
																			pProfileData->pbTrustedRootCAList[i]);
									}

									pSubSectionDOMNode->Release();
									pSubSectionDOMNode = NULL;
								}
							}

							pSectionDOMNode->Release();
							pSectionDOMNode = NULL;
						}
					}

					if (dwReturnCode == NO_ERROR)
					{
						// authentication
						if ((dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
																pConfigurationDOMNode,
																L"Authentication",
																NULL))==NO_ERROR)
						{
							if (SUCCEEDED(hr = pXmlDoc->selectSingleNode((BSTR)L"//securew2:Authentication", &pSectionDOMNode)))
							{
								if (!pSectionDOMNode)
								{
									SW2Trace( SW2_TRACE_LEVEL_ERROR, 
										L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::pSectionDOMNode invalid");

									dwReturnCode = ERROR_NO_DATA;
								}
							}
							else
							{
								dwReturnCode = HRESULT_CODE(hr);

								SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::failed to selectSingleNode: %ld", 
									dwReturnCode);
							}
						}

						if (dwReturnCode == NO_ERROR)
						{
							dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
																pSectionDOMNode,
																L"AuthenticationMethod",
																pProfileData->pwcInnerAuth);

							if (dwReturnCode==NO_ERROR&&
								wcscmp(pProfileData->pwcInnerAuth, L"EAP")==0)
							{
								//
								// Write EAP information
								//
								if ((dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
																pSectionDOMNode,
																L"EapConfig",
																NULL))==NO_ERROR)
								{
									if (SUCCEEDED(hr = pXmlDoc->selectSingleNode((BSTR)L"//securew2:EapConfig", &pSubSectionDOMNode)))
									{
										if (!pSubSectionDOMNode)
										{
											SW2Trace( SW2_TRACE_LEVEL_ERROR, 
												L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::pSectionDOMNode invalid");

											dwReturnCode = ERROR_NO_DATA;
										}
									}
									else
									{
										dwReturnCode = HRESULT_CODE(hr);

										SW2Trace( SW2_TRACE_LEVEL_ERROR, 
											L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::failed to selectSingleNode: %ld", 
											dwReturnCode);
									}

									if (dwReturnCode==NO_ERROR)
									{
										if ((dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
																	pSubSectionDOMNode,
																	L"EapHostConfig",
																	NULL))==NO_ERROR)
										{
											pSubSectionDOMNode->Release();
											pSubSectionDOMNode = NULL;

											if (SUCCEEDED(hr = pXmlDoc->selectSingleNode(
												(BSTR)L"//securew2:EapConfig//securew2:EapHostConfig", 
												&pSubSectionDOMNode)))
											{
												if (!pSubSectionDOMNode)
												{
													SW2Trace( SW2_TRACE_LEVEL_ERROR, 
														L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::pSectionDOMNode invalid");

													dwReturnCode = ERROR_NO_DATA;
												}
											}
											else
											{
												dwReturnCode = HRESULT_CODE(hr);

												SW2Trace( SW2_TRACE_LEVEL_ERROR, 
													L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::failed to selectSingleNode: %ld", 
													dwReturnCode);
											}

										}
										else
										{
											pSubSectionDOMNode->Release();
											pSubSectionDOMNode = NULL;
										}
									}

									if (dwReturnCode==NO_ERROR)
									{
										if ((dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
																	pSubSectionDOMNode,
																	L"EapMethod",
																	NULL))==NO_ERROR)
										{
											if (SUCCEEDED(hr = pXmlDoc->selectSingleNode(
												(BSTR)L"//securew2:EapConfig//securew2:EapHostConfig//securew2:EapMethod", 
												&pSubSubSectionDOMNode)))
											{
												if (!pSubSubSectionDOMNode)
												{
													SW2Trace( SW2_TRACE_LEVEL_ERROR, 
														L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::pSectionDOMNode invalid");

													dwReturnCode = ERROR_NO_DATA;
												}
											}
											else
											{
												dwReturnCode = HRESULT_CODE(hr);

												SW2Trace( SW2_TRACE_LEVEL_ERROR, 
													L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::failed to selectSingleNode: %ld", 
													dwReturnCode);
											}

										}
									}
								}

								if (dwReturnCode == NO_ERROR)
								{
									dwReturnCode = SW2_PutXmlElementDWORD(pXmlDoc,
											pSubSubSectionDOMNode,
											L"Type",
											pProfileData->dwCurrentInnerEapMethod);

									dwReturnCode = SW2_PutXmlElementDWORD(pXmlDoc,
											pSubSubSectionDOMNode,
											L"VendorId",
											0);

									dwReturnCode = SW2_PutXmlElementDWORD(pXmlDoc,
											pSubSubSectionDOMNode,
											L"VendorType",
											0);

									dwReturnCode = SW2_PutXmlElementDWORD(pXmlDoc,
											pSubSubSectionDOMNode,
											L"AuthorId",
											AUTHOR_ID);

									pSubSubSectionDOMNode->Release();
									pSubSubSectionDOMNode = NULL;
								}

								if (dwReturnCode==NO_ERROR)
								{
									//
									// Currently  storing the config as XML for GTC is supported
									// other methods are stored using ConfigBlob
									//
									if ((pProfileData->dwCurrentInnerEapMethod == 6) &&
										(pProfileData->cbInnerEapConnectionData == sizeof(gtcConfigData)))
									{
										if ((dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
																	pSubSectionDOMNode,
																	L"Config",
																	NULL))==NO_ERROR)
										{
											if (SUCCEEDED(hr = pXmlDoc->selectSingleNode(
												(BSTR)L"//securew2:EapConfig//securew2:EapHostConfig//securew2:Config", 
												&pSubSubSectionDOMNode)))
											{
												if (!pSubSubSectionDOMNode)
												{
													SW2Trace( SW2_TRACE_LEVEL_ERROR, 
														L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::pSectionDOMNode invalid");

													dwReturnCode = ERROR_NO_DATA;
												}
											}
											else
											{
												dwReturnCode = HRESULT_CODE(hr);

												SW2Trace( SW2_TRACE_LEVEL_ERROR, 
													L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::failed to selectSingleNode: %ld", 
													dwReturnCode);
											}

										}

										pSubSectionDOMNode->Release();
										pSubSectionDOMNode = NULL;

										if (dwReturnCode==NO_ERROR)
										{
											memcpy_s(&gtcConfigData, sizeof(gtcConfigData),
												pProfileData->pbInnerEapConnectionData,
												sizeof(gtcConfigData));

											dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
												pSubSubSectionDOMNode,
												L"Identity",
												gtcConfigData.pwcIdentity);
										}
									}
									else
									{
										dwReturnCode = SW2_PutXmlElementHex(pXmlDoc,
												pSubSectionDOMNode,
												L"ConfigBlob",
												pProfileData->cbInnerEapConnectionData,
												pProfileData->pbInnerEapConnectionData);
									}

									if (pSubSubSectionDOMNode)
									{
										pSubSubSectionDOMNode->Release();
										pSubSubSectionDOMNode = NULL;
									}
								}
							}

							pSectionDOMNode->Release();
							pSectionDOMNode = NULL;
						}
					}

					if (dwReturnCode == NO_ERROR)
					{
						// useraccount
						if ((dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
																pConfigurationDOMNode,
																L"UserAccount",
																NULL))==NO_ERROR)
						{
							if (SUCCEEDED(hr = pXmlDoc->selectSingleNode((BSTR)L"//securew2:UserAccount", &pSectionDOMNode)))
							{
								if (!pSectionDOMNode)
								{
									SW2Trace( SW2_TRACE_LEVEL_ERROR, 
										L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::pSectionDOMNode invalid");

									dwReturnCode = ERROR_NO_DATA;
								}
							}
							else
							{
								dwReturnCode = HRESULT_CODE(hr);

								SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::failed to selectSingleNode: %ld", 
									dwReturnCode);
							}
						}

						if (dwReturnCode == NO_ERROR)
						{
							dwReturnCode = SW2_PutXmlElementBOOL(pXmlDoc,
																pSectionDOMNode,
																L"PromptUser",
																pProfileData->bPromptUser);

							if (dwReturnCode==NO_ERROR)
							{
								if (wcslen(pProfileData->pwcUserName)>0)
								{
									dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
																		pSectionDOMNode,
																		L"UserName",
																		pProfileData->pwcUserName);
								}
							}

							if (dwReturnCode==NO_ERROR)
							{
								if (wcslen(pProfileData->pwcUserDomain)>0)
								{
									dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
																		pSectionDOMNode,
																		L"UserDomain",
																		pProfileData->pwcUserDomain);
								}
							}

							if (dwReturnCode==NO_ERROR)
							{
								if (wcslen(pProfileData->pwcUserPassword)>0)
								{
									dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
																		pSectionDOMNode,
																		L"UserPassword",
																		pProfileData->pwcUserPassword);
								}
							}

							if (dwReturnCode==NO_ERROR)
							{
								dwReturnCode = SW2_PutXmlElementBOOL(pXmlDoc,
																pSectionDOMNode,
																L"UseUserCredentialsForComputer",
																pProfileData->bUseUserCredentialsForComputer);
							}

							pSectionDOMNode->Release();
							pSectionDOMNode = NULL;
						}
					}

					if (dwReturnCode == NO_ERROR)
					{
						// advanced
						if ((dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
																pConfigurationDOMNode,
																L"Advanced",
																NULL))==NO_ERROR)
						{
							if (SUCCEEDED(hr = pXmlDoc->selectSingleNode((BSTR)L"//securew2:Advanced", &pSectionDOMNode)))
							{
								if (!pSectionDOMNode)
								{
									SW2Trace( SW2_TRACE_LEVEL_ERROR, 
										L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::pSectionDOMNode invalid");

									dwReturnCode = ERROR_NO_DATA;
								}
							}
							else
							{
								dwReturnCode = HRESULT_CODE(hr);

								SW2Trace( SW2_TRACE_LEVEL_ERROR, 
									L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::failed to selectSingleNode: %ld", 
									dwReturnCode);
							}
						}

						if (dwReturnCode == NO_ERROR)
						{

							dwReturnCode = SW2_PutXmlElementBOOL(pXmlDoc,
																pSectionDOMNode,
																L"UseAlternateComputerCredentials",
																pProfileData->bUseAlternateComputerCred);

							if (dwReturnCode==NO_ERROR)
							{
								if (wcslen(pProfileData->pwcCompName)>0)
								{
									dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
																		pSectionDOMNode,
																		L"ComputerName",
																		pProfileData->pwcCompName);
								}
							}

							if (dwReturnCode==NO_ERROR)
							{
								if (wcslen(pProfileData->pwcCompDomain)>0)
								{
									dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
																		pSectionDOMNode,
																		L"ComputerDomain",
																		pProfileData->pwcCompDomain);
								}
							}

							if (dwReturnCode==NO_ERROR)
							{
								if (wcslen(pProfileData->pwcCompPassword)>0)
								{
									dwReturnCode = SW2_PutXmlElementString(pXmlDoc,
																		pSectionDOMNode,
																		L"ComputerPassword",
																		pProfileData->pwcCompPassword);
								}
							}

							if (dwReturnCode==NO_ERROR)
							{
								dwReturnCode = SW2_PutXmlElementBOOL(pXmlDoc,
																pSectionDOMNode,
																L"ServerCertificateOnLocalComputer",
																pProfileData->bServerCertificateLocal);
							}

							if (dwReturnCode==NO_ERROR)
							{
								dwReturnCode = SW2_PutXmlElementBOOL(pXmlDoc,
																pSectionDOMNode,
																L"CheckForMicrosoftExtension",
																pProfileData->bVerifyMSExtension);
							}

							if (dwReturnCode==NO_ERROR)
							{
								dwReturnCode = SW2_PutXmlElementBOOL(pXmlDoc,
																pSectionDOMNode,
																L"AllowNewConnections",
																pProfileData->bAllowNewConnection);
							}

							if (dwReturnCode==NO_ERROR)
							{
								dwReturnCode = SW2_PutXmlElementBOOL(pXmlDoc,
																pSectionDOMNode,
																L"UseEmptyOuterIdentity",
																pProfileData->bUseEmptyIdentity);
							}

							pSectionDOMNode->Release();
							pSectionDOMNode = NULL;
						}
					}

					pConfigurationDOMNode->Release();
					pConfigurationDOMNode = NULL;
				}
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::provided data is invalid");

				dwReturnCode = ERROR_INVALID_DATA;
			}

			if (dwReturnCode != NO_ERROR)
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapmethodConfigBlob2Xml()::invalid data, using default profile");

				dwReturnCode = HRESULT_CODE(hr = pXmlDoc->loadXML((BSTR)L"<Profile>DEFAULT</Profile>", &fSuccess));
			}

			pTTLSDOMNode->Release();
			pTTLSDOMNode = NULL;
		}

		if (dwReturnCode == NO_ERROR)
		{
			//
			// Set the output parameters.
			// 
			*ppXMLConfigDoc = pXmlDoc;

			pXmlDoc = NULL;
		}
		
		if(pXmlDoc)
			pXmlDoc->Release();
	}
	else	
	{
		dwReturnCode = HRESULT_CODE(hr);
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2EapmethodConfigBlob2Xml()::Unable to CoCreate XMLDOMDocument2::error: %ld", dwReturnCode);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapmethodConfigBlob2Xml()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

DWORD SW2EapMethodCredentialsXml2Blob(IN DWORD					dwFlags,
										IN IXMLDOMDocument2*	pXMLCredentialsDoc,
										IN 	const BYTE*			pbConfigIn,
										IN DWORD				dwSizeOfConfigIn,
										OUT	BYTE				** ppbCredentialsOut,
										OUT DWORD*				pdwSizeOfCredentialsOut)
{
	PSW2_USER_DATA				pUserData;
	PWCHAR						pwcElementValue;
    DWORD						dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		L"SW2_TRACE_LEVEL_INFO::SW2EapMethodCredentialsXml2Blob()");

	dwReturnCode = NO_ERROR;

	*ppbCredentialsOut = NULL;
	*pdwSizeOfCredentialsOut = 0;

	if ((dwReturnCode = SW2AllocateMemory(sizeof(SW2_USER_DATA), (PVOID*)&pUserData))==NO_ERROR)
	{		
		if ((SW2_GetXmlElementValue(pXMLCredentialsDoc, L"UserName", &pwcElementValue))==NO_ERROR)			
		{ 
			if (((wcslen(pwcElementValue)+1)*sizeof(WCHAR))<=sizeof(pUserData->pwcUsername))
			{
				wcscpy_s(pUserData->pwcUsername, sizeof(pUserData->pwcUsername), pwcElementValue);
			}

			SysFreeString(pwcElementValue);
		}

		if ((SW2_GetXmlElementValue(pXMLCredentialsDoc, L"UserPassword", &pwcElementValue))==NO_ERROR)			
		{ 
			if (((wcslen(pwcElementValue)+1)*sizeof(WCHAR))<=sizeof(pUserData->pwcPassword))
			{
				wcscpy_s(pUserData->pwcPassword, sizeof(pUserData->pwcPassword), pwcElementValue);
			}

			SysFreeString(pwcElementValue);
		}

		if ((SW2_GetXmlElementValue(pXMLCredentialsDoc, L"UserDomain", &pwcElementValue))==NO_ERROR)			
		{ 
			if (((wcslen(pwcElementValue)+1)*sizeof(WCHAR))<=sizeof(pUserData->pwcDomain))
			{
				wcscpy_s(pUserData->pwcDomain, sizeof(pUserData->pwcDomain), pwcElementValue);
			}

			SysFreeString(pwcElementValue);
		}
	
		*ppbCredentialsOut = (PBYTE) pUserData;
		*pdwSizeOfCredentialsOut = sizeof(SW2_USER_DATA);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodCredentialsXml2Blob()::returning: %ld", dwReturnCode);

    return dwReturnCode;
}

DWORD	
SW2EapMethodQueryCredentialInputFields(IN  HANDLE							hUserToken,
									   IN  DWORD							dwFlags,
									   IN  DWORD							dwSizeofConnectionData,
									   IN  PBYTE							pbConnectionData,
									   OUT	EAP_CONFIG_INPUT_FIELD_ARRAY	*pEapConfigInputFieldArray)
{
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodQueryCredentialInputFields");
/*
	if ((dwReturnCode = SW2AllocateMemory(
		2* sizeof(EAP_CONFIG_INPUT_FIELD_DATA), 
		(PVOID*) &pEapConfigInputFieldArray->pFields)) ==NO_ERROR )
	{
		*pEapConfigInputFieldArray->pFields[0].dwSize =  sizeof(EAP_CONFIG_INPUT_FIELD_DATA);

		*pEapConfigInputFieldArray->pFields[0].dwFlagProps = 0;
		*pEapConfigInputFieldArray->pFields[0].dwMaxDataLength = 1;
		*pEapConfigInputFieldArray->pFields[0].dwMinDataLength = UNLEN + 1;
		*pEapConfigInputFieldArray->pFields[0].pwszData = L"";
		if ( ( *pEapConfigInputFieldArray->pFields[0].pwszLabel = L"User name"; 
		*pEapConfigInputFieldArray->pFields[0].Type = EapConfigInputUsername;


		/// The credential input fields needed for this method to authenticate users.
static EAP_CONFIG_INPUT_FIELD_DATA defaultCredentialInputFields[] =
{
    {
        CRED_FIELD_SIZE,                       ///< Size of this structure.
        ,                ///< This element's field type.
        EAP_CONFIG_INPUT_FIELD_PROPS_DEFAULT,  ///< Desired EAP_CONFIG_FLAG values.
        L"User name:",                         ///< Label/name for this field.
        L"",                                   ///< Data entered by the user for this field. (When passing this list of fields back to the caller, leave this value blank.)
        1,                                     ///< Minimum length (in bytes) for valid user data.
        UNLEN + 1                              ///< Maximum length (in bytes) for valid user data.
    },

    {
        CRED_FIELD_SIZE,                       ///< Size of this structure.
        EapConfigInputPassword,                ///< This element's field type.
        EAP_CONFIG_INPUT_FIELD_PROPS_DEFAULT,  ///< Desired EAP_CONFIG_FLAG values.
        L"Password:",                          ///< Label/name for this field.
        L"",                                   ///< Data entered by the user for this field. (When passing this list of fields back to the caller, leave this value blank.)
        0,                                     ///< Minimum length (in bytes) for valid user data.
        PWLEN + 1                              ///< Maximum length (in bytes) for valid user data.
    },
};

/// A credential fields array, used when passing the credential fields from
/// this Eap Peer Method <--> EapHost <--> the Eap Supplicant <--> WinLogon.
static const EAP_CONFIG_INPUT_FIELD_ARRAY defaultCredentialInputArray =
{
    1,                            ///< Version
    2,                            ///< Number of fields in the array buffer
    defaultCredentialInputFields  ///< Pointer to the array of input fields needed.
};
*/
	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodQueryCredentialInputFields()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

DWORD	
SW2EapMethodQueryUserBlobFromCredentialInputFields(IN  HANDLE								hUserToken,
												   IN  DWORD								dwFlags,
												   IN  DWORD								dwEapConnDataSize,
												   IN  PBYTE								pbEapConnData,
												   IN  CONST EAP_CONFIG_INPUT_FIELD_ARRAY	*pEapConfigInputFieldArray,
												   OUT DWORD								*pdwUserBlobSize,
												   OUT PBYTE								*ppbUserBlob)
{
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodQueryUserBlobFromCredentialInputFields");
	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2EapMethodQueryUserBlobFromCredentialInputFields()::returning: %ld", dwReturnCode);

	return dwReturnCode;
}

#endif // _WIN32_WCE

#ifndef _WIN32_WCE
//
// Renew the IP adresses off all the currently active
// adapters, this is not normally a function for a EAP
// module but the DHCP on a Windows 2000 Machine does not
// work well with 802.1X
//
DWORD
WINAPI
SW2_RenewIP( LPVOID lpvoid )
{
	PIP_ADAPTER_INFO	pAdaptersInfo;
	PIP_ADAPTER_INFO	p;
	DWORD				dwAdaptersInfoSize;
	WCHAR				pwcEntry[UNLEN];
	CHAR				pcDescription[UNLEN];
	PIP_INTERFACE_INFO	pInterfaceInfo;
	DWORD				dwInterfaceInfoSize;
	int					i;
	WCHAR				pwcGUID[UNLEN];
	WCHAR				pwcKey[UNLEN];
	DWORD				cwcKey;
	PBYTE				pbName;
	DWORD				cbName;
	WCHAR				*pwcName;
	FILETIME 			ftLastWriteTime;
	HKEY				hKey1;
	HKEY				hKey2;
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	if( !lpvoid )
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_RenewIP::!lpvoid" ) );

		return ERROR_NO_DATA;
	}

	wcscpy( pwcEntry, ( WCHAR * ) lpvoid );

	//
	// Allow Ras to cleanup and initialize connection
	//
	Sleep( 2000 );

	//
	// Translate the friendly name to a GUID
	//
	if( ( dwReturnCode =  RegOpenKeyEx( HKEY_LOCAL_MACHINE,
								TEXT( "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}" ),
								0,
								KEY_READ,
								&hKey1 ) ) == NO_ERROR )
	{
		for (i = 0; dwReturnCode == NO_ERROR; i++) 
		{ 
			cwcKey = sizeof( pwcKey );

			if( ( dwReturnCode = RegEnumKeyEx( hKey1, 
										i, 
										pwcKey, 
										&cwcKey, 
										NULL, 
										NULL, 
										NULL, 
										&ftLastWriteTime ) ) == NO_ERROR )
			{
				//
				// Copy keyname which contains the GUID for later use
				//
				wcscpy( pwcGUID, pwcKey );

				wcscat( pwcKey, L"\\Connection" );

				if( RegOpenKeyEx( hKey1,
								pwcKey,
								0,
								KEY_QUERY_VALUE,
								&hKey2 ) == NO_ERROR )
				{
					//
					// Read time stamp
					//
					if( ( dwReturnCode = SW2_RegGetValue( hKey2, L"Name", &pbName, &cbName ) ) == NO_ERROR )
					{
						pwcName = ( WCHAR * ) pbName;

						if( wcscmp( pwcName, pwcEntry ) == 0 )
						{
							break;
						}

						SW2FreeMemory((PVOID*)&pbName);
					}

					RegCloseKey( hKey2 );
				}
			}
		}

		RegCloseKey( hKey1 );
	}

	if( dwReturnCode != NO_ERROR )
	{
		//
		// Couldn't find GUID by searching by entry name
		// so try searching for guid using the friendly name (Description)
		//
		if( ( WideCharToMultiByte( CP_ACP, 0, pwcEntry, -1, pcDescription, sizeof( pcDescription ), NULL, NULL ) ) > 0 )
		{
			dwAdaptersInfoSize = 0;

			dwReturnCode = GetAdaptersInfo( NULL, &dwAdaptersInfoSize );

			if( dwReturnCode == ERROR_BUFFER_OVERFLOW )
			{
				if ((dwReturnCode = SW2AllocateMemory(dwAdaptersInfoSize, 
																	(PVOID*) &pAdaptersInfo)) == NO_ERROR)
				{
					if( ( dwReturnCode = GetAdaptersInfo( pAdaptersInfo, &dwAdaptersInfoSize ) ) == NO_ERROR )
					{
						p = pAdaptersInfo;

						//
						// loop through the adapters till we find a corresponding friendly name
						//
						while( p )
						{
							if( strcmp( p->Description, pcDescription  ) == 0 )
							{
								//
								// Found equal, now copy GUID
								//
								if( ( DWORD ) strlen( p->AdapterName ) <= UNLEN )
								{
									MultiByteToWideChar( CP_ACP, 0, p->AdapterName, -1, pwcGUID, sizeof( pwcGUID ) );
								}

								break;
							}

							p = p->Next;
						}
					}

					SW2FreeMemory((PVOID*)&pAdaptersInfo);
				}
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_RenewIP::failed to convert characters to multibyte" ) );

			dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
		}
	}

	if( dwReturnCode == NO_ERROR )
	{
		dwInterfaceInfoSize = 0;
			
		dwReturnCode = GetInterfaceInfo( NULL, &dwInterfaceInfoSize );

		if( dwReturnCode == ERROR_INSUFFICIENT_BUFFER )
		{
			if ((dwReturnCode = SW2AllocateMemory(dwInterfaceInfoSize, 
				(PVOID*) &pInterfaceInfo)) == NO_ERROR)
			{
				if( ( dwReturnCode = GetInterfaceInfo( pInterfaceInfo, &dwInterfaceInfoSize ) ) == NO_ERROR )
				{
					for( i=0; i < pInterfaceInfo->NumAdapters; i++ )
					{
						//
						// Compare the GUIDs and if they match renew the adapter
						//
						if( wcsstr( pInterfaceInfo->Adapter[i].Name, pwcGUID ) )
						{
							if( ( dwReturnCode = IpReleaseAddress( &pInterfaceInfo->Adapter[i] ) ) == NO_ERROR )
							{
								IpRenewAddress( &pInterfaceInfo->Adapter[i] );
							}

							break;
						}
					}
				}

				SW2FreeMemory((PVOID*)&pInterfaceInfo);
			}
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_RenewIP:: returning: %ld" ), dwReturnCode );

	return dwReturnCode;
}
#endif // _WIN32_CE
