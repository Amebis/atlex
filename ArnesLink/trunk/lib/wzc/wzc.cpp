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
#pragma comment(lib, "Version.lib")

DWORD
WZCInit( IN PSW2_WZC_LIB_CONTEXT *ppWZCContext )
{
	PSW2_WZC_LIB_CONTEXT pWZCContext;
#ifndef SW2_WZC_LIB_VISTA
	VS_FIXEDFILEINFO*	pvsFileInfo;
	DWORD				dwvsFileInfoSize;
	PBYTE				pbVersion;
	DWORD				dwHandle = 0;
	DWORD				cbVersion;
#endif // SW2_WZC_LIB_VISTA
	DWORD				dwRet;

	dwRet = NO_ERROR;	

	if ((dwRet = SW2AllocateMemory( sizeof( SW2_WZC_LIB_CONTEXT), (PVOID*) ppWZCContext)) == NO_ERROR)
	{
		memset( *ppWZCContext, 0, sizeof( SW2_WZC_LIB_CONTEXT ) );

		pWZCContext = *ppWZCContext;
#ifdef SW2_WZC_LIB_VISTA
		pWZCContext->dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_VISTA;
#else
		//
		// See if zero config API present in system
		//
		if ((pWZCContext->hWZCDll = LoadLibrary( L"wzcsapi.dll")))
		{
			//
			// Check file version
			//
			cbVersion = GetFileVersionInfoSize( L"wzcsapi.dll", &dwHandle );

			if ((pbVersion = ( PBYTE ) malloc( cbVersion)))
			{
				if (GetFileVersionInfo( L"wzcsapi.dll",
										0,
										cbVersion,
										pbVersion ) )
				{
					dwvsFileInfoSize = 0;

					if (VerQueryValue( pbVersion, L"\\", ( LPVOID*) &pvsFileInfo, (PUINT) &dwvsFileInfoSize ) )
					{
						if (pvsFileInfo->dwProductVersionLS == 143857554 )
						{
							pWZCContext->dwWZCSDllVersion = WZCS_DLL_VERSION_5_0_6034;
						}
						else if (pvsFileInfo->dwProductVersionLS == 143858124 )
						{
							pWZCContext->dwWZCSDllVersion = WZCS_DLL_VERSION_5_0_6604;
						}
						else if (pvsFileInfo->dwProductVersionLS == 170393600 )
						{
							pWZCContext->dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600;
						}
						else if (pvsFileInfo->dwProductVersionLS == 170394706 )
						{
							pWZCContext->dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600_1106;
						}
						else if (pvsFileInfo->dwProductVersionLS == 170394781 )
						{
							pWZCContext->dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600_1181;
						}
						else if (pvsFileInfo->dwProductVersionLS == 170394876 )
						{
							pWZCContext->dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600_1276; // Windows XP SP1 + WPA Rollup
						}				
						else if (pvsFileInfo->dwProductVersionLS >= 170395780 )
						{
							pWZCContext->dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600_2149;
						}
						else
						{
							dwRet = ERROR_NOT_SUPPORTED;
						}
					}
					else
						dwRet = ERROR_NOT_SUPPORTED;
				}
				else
				{
					dwRet = ERROR_NOT_SUPPORTED;
				}

				free( pbVersion );
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}

			if (dwRet == NO_ERROR )
			{
				pWZCContext->pfnWZCEnumInterfaces = ( PFN_WZCEnumInterfaces ) GetProcAddress( pWZCContext->hWZCDll, "WZCEnumInterfaces" );

#ifdef SW2_WZC_LIB_XP_SP2
				pWZCContext->pfnWZCQueryInterface	= ( PFN_WZCQueryInterface ) GetProcAddress( pWZCContext->hWZCDll, "WZCQueryInterface" );
				pWZCContext->pfnWZCSetInterface		= ( PFN_WZCQueryInterface ) GetProcAddress( pWZCContext->hWZCDll, "WZCSetInterface" );
				pWZCContext->pfnWZCRefreshInterface	= ( PFN_WZCQueryInterface ) GetProcAddress( pWZCContext->hWZCDll, "WZCRefreshInterface" );
#endif

#ifdef SW2_WZC_LIB_XP_SP1
				if (pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
				{
					pWZCContext->pfnWZCQueryInterface_1106		= ( PFN_WZCQueryInterface_1106 ) GetProcAddress( pWZCContext->hWZCDll, "WZCQueryInterface" );
					pWZCContext->pfnWZCSetInterface_1106		= ( PFN_WZCSetInterface_1106 ) GetProcAddress( pWZCContext->hWZCDll, "WZCSetInterface" );
					pWZCContext->pfnWZCRefreshInterface_1106	= ( PFN_WZCRefreshInterface_1106 ) GetProcAddress( pWZCContext->hWZCDll, "WZCRefreshInterface" );
				}
				else
				{
					pWZCContext->pfnWZCQueryInterface_1181		= ( PFN_WZCQueryInterface_1181 ) GetProcAddress( pWZCContext->hWZCDll, "WZCQueryInterface" );
					pWZCContext->pfnWZCSetInterface_1181		= ( PFN_WZCSetInterface_1181 ) GetProcAddress( pWZCContext->hWZCDll, "WZCSetInterface" );
					pWZCContext->pfnWZCRefreshInterface_1181	= ( PFN_WZCRefreshInterface_1181 ) GetProcAddress( pWZCContext->hWZCDll, "WZCRefreshInterface" );
				}
#endif

#ifdef SW2_WZC_LIB_2K_XP_SP0
				pWZCContext->pfnWZCQueryInterface	= ( PFN_WZCQueryInterface ) GetProcAddress( pWZCContext->hWZCDll, "WZCQueryInterface" );
				pWZCContext->pfnWZCSetInterface		= ( PFN_WZCSetInterface ) GetProcAddress( pWZCContext->hWZCDll, "WZCSetInterface" );
				pWZCContext->pfnWZCRefreshInterface	= ( PFN_WZCRefreshInterface ) GetProcAddress( pWZCContext->hWZCDll, "WZCRefreshInterface" );
#endif


				pWZCContext->pfnWZCEapolReAuthenticate	= ( PFN_WZCEapolReAuthenticate ) GetProcAddress( pWZCContext->hWZCDll, "WZCEapolReAuthenticate" );

				pWZCContext->pfnWZCEapolGetInterfaceParams = ( PFN_WZCEapolGetInterfaceParams ) GetProcAddress( pWZCContext->hWZCDll, "WZCEapolGetInterfaceParams" );
				pWZCContext->pfnWZCEapolSetInterfaceParams = ( PFN_WZCEapolSetInterfaceParams ) GetProcAddress( pWZCContext->hWZCDll, "WZCEapolSetInterfaceParams" );
				pWZCContext->pfnWZCEapolSetCustomAuthData = ( PFN_WZCEapolSetCustomAuthData ) GetProcAddress( pWZCContext->hWZCDll, "WZCEapolSetCustomAuthData" );
				pWZCContext->pfnWZCEapolGetCustomAuthData = ( PFN_WZCEapolGetCustomAuthData ) GetProcAddress( pWZCContext->hWZCDll, "WZCEapolGetCustomAuthData" );

				pWZCContext->pfnWZCGetEapUserInfo = ( PFN_WZCGetEapUserInfo ) GetProcAddress( pWZCContext->hWZCDll, "WZCGetEapUserInfo" );

#ifndef SW2_WZC_LIB_2K_XP_SP0
				pWZCContext->pfnWZCQueryContext = ( PFN_WZCQueryContext ) GetProcAddress( pWZCContext->hWZCDll, "WZCQueryContext" );

				pWZCContext->pfnWZCEapolQueryState = ( PFN_WZCEapolQueryState ) GetProcAddress( pWZCContext->hWZCDll, "WZCEapolQueryState" );
#endif

				//
				// Connected to procs?
				//

#ifdef SW2_WZC_LIB_XP_SP2
				if ((pWZCContext->pfnWZCEnumInterfaces == NULL )			||
					( pWZCContext->pfnWZCQueryInterface == NULL )		||
					( pWZCContext->pfnWZCSetInterface == NULL )		||
					( pWZCContext->pfnWZCRefreshInterface == NULL )	||
					( pWZCContext->pfnWZCEapolReAuthenticate == NULL )		||
					( pWZCContext->pfnWZCEapolGetInterfaceParams == NULL )	||
					( pWZCContext->pfnWZCEapolSetInterfaceParams == NULL )	||
					( pWZCContext->pfnWZCEapolSetCustomAuthData == NULL )	||
					( pWZCContext->pfnWZCEapolGetCustomAuthData == NULL )	||
					( pWZCContext->pfnWZCGetEapUserInfo == NULL )			||
					( pWZCContext->pfnWZCQueryContext == NULL )				||
					( pWZCContext->pfnWZCEapolQueryState == NULL ) )
				{
					dwRet = ERROR_NOT_SUPPORTED;
				}
#endif

#ifdef SW2_WZC_LIB_XP_SP1
				//
				// Connected to procs?
				//
				if (pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
				{
					if ((pWZCContext->pfnWZCEnumInterfaces == NULL )			||
						( pWZCContext->pfnWZCQueryInterface_1106 == NULL )		||
						( pWZCContext->pfnWZCSetInterface_1106 == NULL )		||
						( pWZCContext->pfnWZCRefreshInterface_1106 == NULL )	||
						( pWZCContext->pfnWZCEapolReAuthenticate == NULL )		||
						( pWZCContext->pfnWZCEapolGetInterfaceParams == NULL )	||
						( pWZCContext->pfnWZCEapolSetInterfaceParams == NULL )	||
						( pWZCContext->pfnWZCEapolSetCustomAuthData == NULL )	||
						( pWZCContext->pfnWZCEapolGetCustomAuthData == NULL )	||
						( pWZCContext->pfnWZCGetEapUserInfo == NULL )			||
						( pWZCContext->pfnWZCQueryContext == NULL )				||
						( pWZCContext->pfnWZCEapolQueryState == NULL ) )
					{
						dwRet = ERROR_NOT_SUPPORTED;
					}
				}
				else
				{
					if ((pWZCContext->pfnWZCEnumInterfaces == NULL )			||
						( pWZCContext->pfnWZCQueryInterface_1181 == NULL )		||
						( pWZCContext->pfnWZCSetInterface_1181 == NULL )		||
						( pWZCContext->pfnWZCRefreshInterface_1181 == NULL )	||
						( pWZCContext->pfnWZCEapolReAuthenticate == NULL )		||
						( pWZCContext->pfnWZCEapolGetInterfaceParams == NULL )	||
						( pWZCContext->pfnWZCEapolSetInterfaceParams == NULL )	||
						( pWZCContext->pfnWZCEapolSetCustomAuthData == NULL )	||
						( pWZCContext->pfnWZCEapolGetCustomAuthData == NULL )	||
						( pWZCContext->pfnWZCGetEapUserInfo == NULL )			||
						( pWZCContext->pfnWZCQueryContext == NULL )				||
						( pWZCContext->pfnWZCEapolQueryState == NULL ) )
					{
						dwRet = ERROR_NOT_SUPPORTED;
					}
				}
#endif

#ifdef SW2_WZC_LIB_2K_XP_SP0
				if ((pWZCContext->pfnWZCEnumInterfaces == NULL )			||
					( pWZCContext->pfnWZCQueryInterface == NULL )			||
					( pWZCContext->pfnWZCSetInterface == NULL )				||
					( pWZCContext->pfnWZCRefreshInterface == NULL )			||
					( pWZCContext->pfnWZCEapolGetInterfaceParams == NULL )	||
					( pWZCContext->pfnWZCEapolSetInterfaceParams == NULL )	||
					( pWZCContext->pfnWZCEapolSetCustomAuthData == NULL )	||
					( pWZCContext->pfnWZCEapolGetCustomAuthData == NULL )	||
					( pWZCContext->pfnWZCGetEapUserInfo == NULL ) )
				{
					dwRet = ERROR_NOT_SUPPORTED;
				}
#endif
			}

			if (dwRet != NO_ERROR )
				FreeLibrary( pWZCContext->hWZCDll );
		}
		else
		{
			dwRet = ERROR_NOT_SUPPORTED;
		}

#endif // SW2_WZC_LIB_VISTA

		if (dwRet != NO_ERROR )
			SW2FreeMemory((PVOID*)ppWZCContext);
    }
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCInit::dwWZCSDllVersion", pWZCContext->dwWZCSDllVersion );

	return dwRet;
}

//
// Builds an initial WZC_WLAN_CONFIG item
// The SSID and InfrastructureMode are used to distinct between WZC_WLAN_CONFIG items
//
DWORD
WZCInitConfig(	IN PSW2_WZC_LIB_CONTEXT	pWZCContext, 
				IN WZC_WLAN_CONFIG		*pWZCCfgNew, 
				IN WCHAR				*pwcSSID,
				IN DWORD				dwInfrastructureMode )
{
	PCHAR	pcSSID;
	DWORD	ccSSID;
	DWORD	dwRet;

	dwRet = NO_ERROR;

	ccSSID = ( DWORD ) wcslen( pwcSSID ) + 1;

	if ((pcSSID = ( PCHAR ) malloc( ccSSID)))
	{
		if (WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID, NULL, NULL ) > 0 )
		{
			memset( pWZCCfgNew, 0, sizeof( WZC_WLAN_CONFIG ) );

			pWZCCfgNew->AuthenticationMode = Ndis802_11AuthModeOpen;

			pWZCCfgNew->Length = sizeof( WZC_WLAN_CONFIG );
/*
			pWZCCfgNew->Configuration.ATIMWindow = 0;
			pWZCCfgNew->Configuration.BeaconPeriod = 0;
			pWZCCfgNew->Configuration.DSConfig = 0;
			pWZCCfgNew->Configuration.FHConfig = 0;
			pWZCCfgNew->Configuration.Length = 0;
			pWZCCfgNew->dwCtlFlags = WZCCTL_WEPK_XFORMAT | WZCCTL_WEPK_PRESENT;
*/
			pWZCCfgNew->InfrastructureMode = (NDIS_802_11_NETWORK_INFRASTRUCTURE) dwInfrastructureMode;
/*
			pWZCCfgNew->KeyIndex
			pWZCCfgNew->KeyLength
			pWZCCfgNew->KeyMaterial
			pWZCCfgNew->MacAddress
			pWZCCfgNew->NetworkTypeInUse = Ndis802_11DS;
*/
			if (pWZCContext->dwWZCSDllVersion >= WZCS_DLL_VERSION_5_1_2600_1181 )
				pWZCCfgNew->Privacy = 0; // Encryption is not OFF ;)
			else
				pWZCCfgNew->Privacy = 1; // Encryption ON
/*
			pWZCCfgNew->rdUserData
			pWZCCfgNew->Reserved
			pWZCCfgNew->Rssi
*/
			strcpy_s( (CHAR*) pWZCCfgNew->Ssid.Ssid, sizeof(pWZCCfgNew->Ssid.Ssid), pcSSID );
			pWZCCfgNew->Ssid.SsidLength = ( ULONG ) strlen( pcSSID );
/*
			pWZCCfgNew->SupportedRates
*/
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pcSSID );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

#ifdef SW2_WZC_LIB_XP_SP1
DWORD
WZCSetZeroConfState_1106( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN BOOL bOn )
{
	INTF_ENTRY_1106			Intf;
	DWORD					dwOIDFlags;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if ((dwRet = pWZCContext->pfnWZCQueryInterface_1106( NULL,
														INTF_ALL_FLAGS,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
		if (bOn )
			Intf.dwCtlFlags |= INTFCTL_ENABLED;
		else
			Intf.dwCtlFlags &= ~INTFCTL_ENABLED;

		dwRet = pWZCContext->pfnWZCSetInterface_1106( NULL,
														INTF_ALL_FLAGS,
														&Intf,
														&dwOIDFlags );
	}

	return dwRet;
}

DWORD
WZCSetZeroConfState_1181( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN BOOL bOn )
{
	INTF_ENTRY_1181			Intf;
	DWORD					dwOIDFlags;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if ((dwRet = pWZCContext->pfnWZCQueryInterface_1181( NULL,
														INTF_ALL_FLAGS,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
		if (bOn )
			Intf.dwCtlFlags |= INTFCTL_ENABLED;
		else
			Intf.dwCtlFlags &= ~INTFCTL_ENABLED;

		dwRet = pWZCContext->pfnWZCSetInterface_1181( NULL,
														INTF_ALL_FLAGS,
														&Intf,
														&dwOIDFlags );
	}

	return dwRet;
}
#endif

DWORD
WZCSetZeroConfState( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN BOOL bOn )
{
	DWORD dwRet = NO_ERROR;

#ifdef SW2_WZC_LIB_XP_SP2

	dwRet = ERROR_NOT_SUPPORTED;

#endif

#ifdef SW2_WZC_LIB_XP_SP1

	if (pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCSetZeroConfState_1106( pWZCContext, pwcGUID, bOn );
	}
	else
	{
		dwRet = WZCSetZeroConfState_1181( pWZCContext, pwcGUID, bOn );
	}
#endif

	return dwRet;
}

#ifdef SW2_WZC_LIB_XP_SP1
DWORD
WZCSetMediaState_1106( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN BOOL bOn )
{
	INTF_ENTRY_1106			Intf;
	DWORD					dwOIDFlags;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if (bOn )
		Intf.ulMediaState = 1;
	else
		Intf.ulMediaState = 0;

	//
	// First query interface for existing configs
	//
	dwRet = pWZCContext->pfnWZCSetInterface_1106( NULL,
													INTF_NDISMEDIA,
													&Intf,
													&dwOIDFlags );

	return dwRet;
}

DWORD
WZCSetMediaState_1181( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN BOOL bOn )
{
	INTF_ENTRY_1181			Intf;
	DWORD					dwOIDFlags;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if (bOn )
		Intf.ulMediaState = 1;
	else
		Intf.ulMediaState = 0;

	//
	// First query interface for existing configs
	//
	dwRet = pWZCContext->pfnWZCSetInterface_1181( NULL,
													INTF_NDISMEDIA,
													&Intf,
													&dwOIDFlags );

	return dwRet;
}
#endif // SW2_WZC_LIB_XP_SP1

DWORD
WZCSetMediaState( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN BOOL bOn )
{
	DWORD dwRet = NO_ERROR;

#ifdef SW2_WZC_LIB_XP_SP2
	INTF_ENTRY			Intf;
	DWORD				dwOIDFlags;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if (bOn )
		Intf.ulMediaState = 1;
	else
		Intf.ulMediaState = 0;

	//
	// First query interface for existing configs
	//
	dwRet = pWZCContext->pfnWZCSetInterface( NULL,
											INTF_NDISMEDIA,
											&Intf,
											&dwOIDFlags );

#endif

#ifdef SW2_WZC_LIB_XP_SP1

	if (pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCSetMediaState_1106( pWZCContext, pwcGUID, bOn );
	}
	else
	{
		dwRet = WZCSetMediaState_1181( pWZCContext, pwcGUID, bOn );
	}
#endif

	return dwRet;
}

#ifdef SW2_WZC_LIB_XP_SP1
DWORD
WZCGetMediaState_1106( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID )
{
	INTF_ENTRY_1106			Intf;
	DWORD					dwOIDFlags;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if ((dwRet = pWZCContext->pfnWZCQueryInterface_1106( NULL,
															INTF_NDISMEDIA,
															&Intf,
															&dwOIDFlags ) ) == NO_ERROR )
	{
		if (Intf.ulMediaState == 0 )
			dwRet = ERROR_MEDIA_OFFLINE;
	}

	return dwRet;
}

DWORD
WZCGetMediaState_1181( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID )
{
	INTF_ENTRY_1181			Intf;
	DWORD					dwOIDFlags;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if ((dwRet = pWZCContext->pfnWZCQueryInterface_1181( NULL,
															INTF_NDISMEDIA,
															&Intf,
															&dwOIDFlags ) ) == NO_ERROR )
	{
		if (Intf.ulMediaState == 0 )
			dwRet = ERROR_MEDIA_OFFLINE;
	}

	return dwRet;
}
#endif // SW2_WZC_LIB_XP_SP1

DWORD
WZCGetMediaState( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID )
{
	DWORD dwRet = NO_ERROR;

#ifdef SW2_WZC_LIB_XP_SP2
	INTF_ENTRY	Intf;
	DWORD		dwOIDFlags;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if ((dwRet = pWZCContext->pfnWZCQueryInterface( NULL,
													INTF_NDISMEDIA,
													&Intf,
													&dwOIDFlags ) ) == NO_ERROR )
	{
		if (Intf.ulMediaState == 0 )
			dwRet = ERROR_MEDIA_OFFLINE;
	}

#endif

#ifdef SW2_WZC_LIB_XP_SP1
	
	if (pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCGetMediaState_1106( pWZCContext, pwcGUID );
	}
	else
	{
		dwRet = WZCGetMediaState_1181( pWZCContext, pwcGUID );
	}
#endif // SW2_WZC_LIB_XP_SP1

	return dwRet;
}

#ifdef SW2_WZC_LIB_XP_SP1
//
// Retrieves WZC_WLAN_CONFIG item of current SSID belonging to the adapter pwcGUID
//
DWORD
WZCGetCurrentConfig_1106( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT WZC_WLAN_CONFIG *pWZCCfg )
{
	BOOL					bFoundCfg;
	INTF_ENTRY_1106			Intf;
	DWORD					dwOIDFlags;
	PWZC_802_11_CONFIG_LIST	pWZCCfgList;
	WZC_WLAN_CONFIG			WZCCfg;
	PCHAR					pcSSID;
	DWORD					i;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	//
	// First query interface for existing configs
	//
	if ((dwRet = pWZCContext->pfnWZCQueryInterface_1106( NULL,
														INTF_ALL,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
		//
		// Connected to SSID?
		//
		if (Intf.rdSSID.dwDataLen > 0 )
		{
			if ((pcSSID = ( PCHAR ) malloc( Intf.rdSSID.dwDataLen + 1)))
			{
				memset( pcSSID, 0, Intf.rdSSID.dwDataLen + 1 );

				memcpy( pcSSID, Intf.rdSSID.pData, Intf.rdSSID.dwDataLen );

//				printf( "Connected to SSID: %s", pcSSID );

				if (Intf.rdBSSIDList.dwDataLen > 0 )
				{
//					printf( "Intf.rdBSSIDList.dwDataLen: %ld", Intf.rdBSSIDList.dwDataLen );
				
					if ((pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdBSSIDList.dwDataLen)))
					{
						memcpy( pWZCCfgList, Intf.rdBSSIDList.pData, Intf.rdBSSIDList.dwDataLen );

//						printf( "pWZCCfgList->NumberOfItems: %ld", pWZCCfgList->NumberOfItems );

						bFoundCfg = FALSE;

						//
						// Add existing items
						//
						for( i=0; i < pWZCCfgList->NumberOfItems; i++ )
						{
							WZCCfg = pWZCCfgList->Config[i];

							if ((strcmp((PCHAR)WZCCfg.Ssid.Ssid, pcSSID ) == 0 ) &&
								( WZCCfg.InfrastructureMode == Intf.nInfraMode ) )
							{
								memcpy( pWZCCfg, &WZCCfg, sizeof( WZCCfg ) );
								
								bFoundCfg = TRUE;

								i = pWZCCfgList->NumberOfItems;
							}
						}

						if (!bFoundCfg )
							dwRet = ERROR_NO_DATA;

						free( pWZCCfgList );
					}
					else
					{
						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}
				}

				free( pcSSID );
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}

	return dwRet;
}

DWORD
WZCGetCurrentConfig_1181( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT WZC_WLAN_CONFIG *pWZCCfg )
{
	BOOL					bFoundCfg;
	INTF_ENTRY_1181			Intf;
	DWORD					dwOIDFlags;
	PWZC_802_11_CONFIG_LIST	pWZCCfgList;
	WZC_WLAN_CONFIG			WZCCfg;
	PCHAR					pcSSID;
//	CHAR					pcTemp[1024];
	DWORD					i;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	//
	// First query interface for existing configs
	//
	if ((dwRet = pWZCContext->pfnWZCQueryInterface_1181( NULL,
														INTF_ALL,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
/*
		printf( "Intf.dwCapabilities: %ld", Intf.dwCapabilities );
		printf( "Intf.dwCtlFlags: %ld", Intf.dwCtlFlags );
		printf( "Intf.nAuthMode: %ld", Intf.nAuthMode );
		printf( "Intf.nInfraMode: %ld", Intf.nInfraMode );
		printf( "Intf.nWepStatus: %ld", Intf.nWepStatus );
		printf( "Intf.rdBSSID.dwDataLen: %ld", Intf.rdBSSID.dwDataLen );

		memset( pcTemp, 0, sizeof( pcTemp ) );
		memcpy( pcTemp, Intf.rdBSSID.pData, Intf.rdBSSID.dwDataLen );

		printf( "rdBSSID: %s", pcTemp );

		printf( "Intf.rdBSSIDList.dwDataLen: %ld", Intf.rdBSSIDList.dwDataLen );
		printf( "Intf.rdCtrlData.dwDataLen: %ld", Intf.rdCtrlData.dwDataLen );
		printf( "Intf.rdSSID.dwDataLen: %ld", Intf.rdSSID.dwDataLen );

		memset( pcTemp, 0, sizeof( pcTemp ) );
		memcpy( pcTemp, Intf.rdSSID.pData, Intf.rdSSID.dwDataLen );

		printf( "rdSSID: %s", pcTemp );

		printf( "Intf.rdStSSIDList: %ld", Intf.rdStSSIDList.dwDataLen );
		printf( "Intf.ulMediaState: %ld", Intf.ulMediaState );
		printf( "Intf.ulMediaType: %ld", Intf.ulMediaType );
		printf( "Intf.ulPhysicalMediaType: %ld", Intf.ulPhysicalMediaType );
		printf( "Intf.wszDescr: %ws", Intf.wszDescr );
		printf( "Intf.wszGuid: %ws", Intf.wszGuid);
*/
		//
		// Connected to SSID?
		//
		if (Intf.rdSSID.dwDataLen > 0 )
		{
			if ((pcSSID = ( PCHAR ) malloc( Intf.rdSSID.dwDataLen + 1)))
			{
				memset( pcSSID, 0, Intf.rdSSID.dwDataLen + 1 );

				memcpy( pcSSID, Intf.rdSSID.pData, Intf.rdSSID.dwDataLen );

//				printf( "Connected to SSID: %s", pcSSID );

				if (Intf.rdBSSIDList.dwDataLen > 0 )
				{
//					printf( "Intf.rdBSSIDList.dwDataLen: %ld", Intf.rdBSSIDList.dwDataLen );
				

					if ((pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdBSSIDList.dwDataLen)))
					{
						memcpy( pWZCCfgList, Intf.rdBSSIDList.pData, Intf.rdBSSIDList.dwDataLen );

//						printf( "pWZCCfgList->NumberOfItems: %ld", pWZCCfgList->NumberOfItems );

						bFoundCfg = FALSE;

						//
						// Add existing items
						//
						for( i=0; i < pWZCCfgList->NumberOfItems; i++ )
						{
							WZCCfg = pWZCCfgList->Config[i];
/*
							printf( "WZCCfgList[%ld]", i );

							printf( "WZCCfg.AuthenticationMode: %ld", WZCCfg.AuthenticationMode );
							printf( "WZCCfg.Configuration.ATIMWindow: %ld", WZCCfg.Configuration.ATIMWindow );
							printf( "WZCCfg.Configuration.BeaconPeriod: %ld", WZCCfg.Configuration.BeaconPeriod );
							printf( "WZCCfg.Configuration.DSConfig: %ld", WZCCfg.Configuration.DSConfig );
							printf( "WZCCfg.Configuration.FHConfig: %ld", WZCCfg.Configuration.FHConfig );
							printf( "WZCCfg.Configuration.Length: %ld", WZCCfg.Configuration.Length );
							printf( "WZCCfg.dwCtlFlags: %ld", WZCCfg.dwCtlFlags );
							printf( "WZCCfg.InfrastructureMode: %ld", WZCCfg.InfrastructureMode );
							printf( "WZCCfg.KeyIndex: %ld", WZCCfg.KeyIndex );
							printf( "WZCCfg.KeyLength: %ld", WZCCfg.KeyLength );
							printf( "WZCCfg.KeyMaterial: %s", A_ByteToHex( WZCCfg.KeyMaterial, 32 ) );
							printf( "WZCCfg.Length: %ld", WZCCfg.Length );
							printf( "WZCCfg.MacAddress: %s", A_ByteToHex( WZCCfg.MacAddress, 6 ) );
							printf( "WZCCfg.NetworkTypeInUse: %ld", WZCCfg.NetworkTypeInUse );
							printf( "WZCCfg.Privacy: %ld", WZCCfg.Privacy );
							printf( "WZCCfg.rdUserData: %s", A_ByteToHex( WZCCfg.rdUserData.pData, WZCCfg.rdUserData.dwDataLen ) );
							printf( "WZCCfg.Reserved: %s", A_ByteToHex( WZCCfg.Reserved, 2 ) );
							printf( "WZCCfg.Rssi: %ld", WZCCfg.Rssi );
							printf( "WZCCfg.Ssid.Ssid: %s", WZCCfg.Ssid.Ssid );
							printf( "WZCCfg.Ssid.length: %ld", WZCCfg.Ssid.SsidLength );
							printf( "WZCCfg.SupportedRates: %s", A_ByteToHex( WZCCfg.SupportedRates, 8 ) );
*/
							if ((strcmp((PCHAR)WZCCfg.Ssid.Ssid, pcSSID) == 0) &&
								( WZCCfg.InfrastructureMode == Intf.nInfraMode ) )
							{
								memcpy( pWZCCfg, &WZCCfg, sizeof( WZCCfg ) );
								
								bFoundCfg = TRUE;

								i = pWZCCfgList->NumberOfItems;
							}
						}

						if (!bFoundCfg )
							dwRet = ERROR_NO_DATA;

						free( pWZCCfgList );
					}
					else
					{
						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}
				}

				free( pcSSID );
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}

	return dwRet;
}
#endif // SW2_WZC_LIB_XP_SP1

//
// Retrieves WZC_WLAN_CONFIG item of current SSID belonging to the adapter pwcGUID
//
DWORD
WZCGetCurrentConfig( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT WZC_WLAN_CONFIG *pWZCCfg )
{
	DWORD dwRet;

#ifdef SW2_WZC_LIB_XP_SP1
	dwRet = NO_ERROR;

	if (pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCGetCurrentConfig_1106( pWZCContext, pwcGUID, pWZCCfg );
	}
	else
	{
		dwRet = WZCGetCurrentConfig_1181( pWZCContext, pwcGUID, pWZCCfg );
	}
#else
	BOOL					bFoundCfg;
	INTF_ENTRY				Intf;
	DWORD					dwOIDFlags;
	PWZC_802_11_CONFIG_LIST	pWZCCfgList;
	WZC_WLAN_CONFIG			WZCCfg;
	PCHAR					pcSSID;
	DWORD					i;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCurrentConfig");

	//
	// First query interface for existing configs
	//
	if ((dwRet = pWZCContext->pfnWZCQueryInterface( NULL,
													INTF_ALL,
													&Intf,
													&dwOIDFlags ) ) == NO_ERROR )
	{
		//
		// Connected to SSID?
		//
		if (Intf.rdSSID.dwDataLen > 0 )
		{
			if ((pcSSID = ( PCHAR ) malloc( Intf.rdSSID.dwDataLen + 1)))
			{
				memset( pcSSID, 0, Intf.rdSSID.dwDataLen + 1 );

				memcpy( pcSSID, Intf.rdSSID.pData, Intf.rdSSID.dwDataLen );

				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"Connected to SSID: %s", pcSSID );

				if (Intf.rdBSSIDList.dwDataLen > 0 )
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"Intf.rdBSSIDList.dwDataLen: %ld", Intf.rdBSSIDList.dwDataLen );

					if ((pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdBSSIDList.dwDataLen)))
					{
						memcpy( pWZCCfgList, Intf.rdBSSIDList.pData, Intf.rdBSSIDList.dwDataLen );

						SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"pWZCCfgList->NumberOfItems: %ld", pWZCCfgList->NumberOfItems );

						bFoundCfg = FALSE;

						//
						// Add existing items
						//
						for( i=0; i < pWZCCfgList->NumberOfItems; i++ )
						{
							WZCCfg = pWZCCfgList->Config[i];

							if ((strcmp( (CHAR*) WZCCfg.Ssid.Ssid, pcSSID ) == 0 ) &&
								( WZCCfg.InfrastructureMode == Intf.nInfraMode ) )
							{
								memcpy( pWZCCfg, &WZCCfg, sizeof( WZCCfg ) );
								
								bFoundCfg = TRUE;

								i = pWZCCfgList->NumberOfItems;
							}
						}

						if (!bFoundCfg )
							dwRet = ERROR_NO_DATA;

						free( pWZCCfgList );
					}
					else
					{
						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}
				}

				free( pcSSID );
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}
#endif

	return dwRet;
}

#ifdef SW2_WZC_LIB_XP_SP2
DWORD
WZCGetPrefSSIDList_SP2( IN PSW2_WZC_LIB_CONTEXT pWZCContext, 
						IN WCHAR *pwcGUID, 
						OUT PSW2_WZC_CONFIG_LIST_ITEM *ppWZCConfigListItem )
{
	PSW2_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem = NULL;
	WCHAR						pwcRegEntry[MAX_PATH];
	WZC_WLAN_CONFIG				WZCCfg;
	HKEY						hKey1;
	DWORD						dwRegValue;
	DWORD						cbSizeOfWZCCfg;
	WCHAR						pwcWZCEntryName[1024];
	DWORD						j;
	BOOL						bFirstTime;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetPrefSSIDList_SP2");

	if (wcslen(pwcGUID) > 0 &&
		wcslen(pwcGUID) < MAX_PATH - ( wcslen( L"SOFTWARE\\Microsoft\\WZCSVC\\Parameters\\Interfaces\\" ) + 1 ) )
	{
		wsprintf( pwcRegEntry, L"SOFTWARE\\Microsoft\\WZCSVC\\Parameters\\Interfaces\\%s", pwcGUID );

		if (RegOpenKeyEx( HKEY_LOCAL_MACHINE,
						pwcRegEntry,
						0,
						KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WRITE,
						&hKey1 ) == ERROR_SUCCESS )
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetPrefSSIDList_SP2::Opened guid key: %s", pwcGUID );

			//
			// Count number of entries
			// are found
			//
			j = 0;
			memset( pwcWZCEntryName, 0, sizeof( pwcWZCEntryName ) );
			wsprintf( pwcWZCEntryName, L"static#%.4ld", j );
			
			cbSizeOfWZCCfg = sizeof( WZCCfg );

			memset( &WZCCfg, 0, sizeof( WZCCfg ) );

			bFirstTime = TRUE;

			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetPrefSSIDList_SP2::querying value %s", pwcWZCEntryName);

			while( ( (RegQueryValueEx( hKey1,
									pwcWZCEntryName,
									NULL,
									&dwRegValue,
									( PBYTE ) &WZCCfg,
									&cbSizeOfWZCCfg) == ERROR_SUCCESS ) &&
									( dwRet == NO_ERROR)))
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetPrefSSIDList_SP2::querying succesfull");

				if (cbSizeOfWZCCfg <= sizeof( WZCCfg ) )
				{
					if (bFirstTime )
					{
						SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetPrefSSIDList_SP2::first time");

						SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetPrefSSIDList_SP2::creating WZCConfigItem");

						if ((*ppWZCConfigListItem = WZCConfigItemCreate( pWZCContext, 
																			WZCCfg,
																			SW2_WZC_LIB_CONFIG_PREF ) ) == NULL )
						{
							SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetPrefSSIDList_SP2::creating WZCConfigItem");

							dwRet = ERROR_NOT_ENOUGH_MEMORY;
						}

						bFirstTime = FALSE;
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetPrefSSIDList_SP2::next time");

						SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetPrefSSIDList_SP2::creating WZCConfigItem");

						dwRet = WZCConfigItemAppend( *ppWZCConfigListItem, 
											WZCConfigItemCreate( pWZCContext, 
																WZCCfg, 
																SW2_WZC_LIB_CONFIG_PREF ), TRUE );
					}
				}

				j++;
				memset( pwcWZCEntryName, 0, sizeof( pwcWZCEntryName ) );
				wsprintf( pwcWZCEntryName, L"static#%.4ld", j );

				memset( &WZCCfg, 0, sizeof( WZCCfg ) );
			}

			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetPrefSSIDList_SP2::closing registry key");

			if (dwRet != NO_ERROR)
				WZCConfigItemDeleteList( &pWZCConfigListItem );

			RegCloseKey( hKey1 );
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetPrefSSIDList_SP2::returning %ld");

	return dwRet;
}
#endif // SW2_WZC_LIB_XP_SP2

#ifdef SW2_WZC_LIB_XP_SP1
DWORD
WZCGetPrefSSIDList_1106( IN PSW2_WZC_LIB_CONTEXT pWZCContext, 
						 IN WCHAR *pwcGUID, 
						 OUT PSW2_WZC_CONFIG_LIST_ITEM *ppWZCConfigListItem )
{
	INTF_ENTRY_1106				Intf;
	PSW2_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						i;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if ((dwRet = pWZCContext->pfnWZCQueryInterface_1106( NULL,
														INTF_PREFLIST,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
		//
		// Retrieve Preferred List
		//
		if (Intf.rdStSSIDList.dwDataLen > 0 )
		{	
			if ((pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdStSSIDList.dwDataLen)))
			{
				memcpy( pWZCCfgList, Intf.rdStSSIDList.pData, Intf.rdStSSIDList.dwDataLen );

				if ((*ppWZCConfigListItem = WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[0], SW2_WZC_LIB_CONFIG_PREF)))
				{
					pWZCConfigListItem = *ppWZCConfigListItem;

					for( i=1; i < pWZCCfgList->NumberOfItems; i++ )
					{
						if ((dwRet = WZCConfigItemAppend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[i], SW2_WZC_LIB_CONFIG_PREF ), TRUE ) ) == NO_ERROR )
						{
							pWZCConfigListItem = pWZCConfigListItem->pNext;
						}
						else
							break;
					}
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}

				free( pWZCCfgList );
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}

	return dwRet;
}

DWORD
WZCGetPrefSSIDList_1181( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT PSW2_WZC_CONFIG_LIST_ITEM *ppWZCConfigListItem )
{
	INTF_ENTRY_1181				Intf;
	PSW2_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						i;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetPrefSSIDList_1181");

	if ((dwRet = pWZCContext->pfnWZCQueryInterface_1181( NULL,
														INTF_PREFLIST,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"pfnWZCQueryInterface_1181");

		//
		// Retrieve Preferred List
		//
		if (Intf.rdStSSIDList.dwDataLen > 0 )
		{
			if ((pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdStSSIDList.dwDataLen)))
			{
				memcpy( pWZCCfgList, Intf.rdStSSIDList.pData, Intf.rdStSSIDList.dwDataLen );

				if ((*ppWZCConfigListItem = WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[0], SW2_WZC_LIB_CONFIG_PREF)))
				{
					pWZCConfigListItem = *ppWZCConfigListItem;

					for( i=1; i < pWZCCfgList->NumberOfItems; i++ )
					{
						if ((dwRet = WZCConfigItemAppend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[i], SW2_WZC_LIB_CONFIG_PREF ), TRUE ) ) == NO_ERROR )
						{
							pWZCConfigListItem = pWZCConfigListItem->pNext;
						}
						else
							break;
					}
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}

				free( pWZCCfgList );
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetPrefSSIDList_1181::returning: %ld", dwRet );

	return dwRet;
}
#endif // SW2_WZC_LIB_XP_SP1

DWORD
WZCGetPrefSSIDList( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT PSW2_WZC_CONFIG_LIST_ITEM *ppWZCConfigListItem )
{
	DWORD	dwRet;

#ifdef SW2_WZC_LIB_XP_SP2
	dwRet = WZCGetPrefSSIDList_SP2( pWZCContext, pwcGUID, ppWZCConfigListItem );
#endif // SW2_WZC_LIB_XP_SP2

#ifdef SW2_WZC_LIB_XP_SP1
	dwRet = NO_ERROR;

	if (pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCGetPrefSSIDList_1106( pWZCContext, pwcGUID, ppWZCConfigListItem );
	}
	else
	{
		dwRet = WZCGetPrefSSIDList_1181( pWZCContext, pwcGUID, ppWZCConfigListItem );
	}
#endif

#ifdef SW2_WZC_LIB_2K_XP_SP0
	INTF_ENTRY					Intf;
	PSW2_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;
	DWORD						dwOIDFlags;
	CHAR						pcSSID[MAX_SSID_LEN];
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						i;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if ((dwRet = pWZCContext->pfnWZCQueryInterface( NULL,
													INTF_ALL,
													&Intf,
													&dwOIDFlags ) ) == NO_ERROR )
	{
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetPrefSSIDList::Intf.rdStSSIDList(%ld)", Intf.rdStSSIDList.dwDataLen );
		SW2Dump( Intf.rdStSSIDList.pData, Intf.rdStSSIDList.dwDataLen );

		//
		// Retrieve Preferred List
		//
		if (Intf.rdStSSIDList.dwDataLen > 0 )
		{
			if ((pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdStSSIDList.dwDataLen)))
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetPrefSSIDList::malloced pWZCCfgList");

				memcpy( pWZCCfgList, Intf.rdStSSIDList.pData, Intf.rdStSSIDList.dwDataLen );

				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetPrefSSIDList::pWZCCfgList->NumberOfItems: %ld", pWZCCfgList->NumberOfItems );

				if ((*ppWZCConfigListItem = WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[0], SW2_WZC_LIB_CONFIG_PREF ) )  )
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetPrefSSIDList::WZCConfigItemCreate::successfull");

					pWZCConfigListItem = *ppWZCConfigListItem;

					for( i=1; i < pWZCCfgList->NumberOfItems; i++ )
					{
						memset( pcSSID, 0, sizeof( pcSSID ) );

						memcpy( pcSSID, pWZCCfgList->Config->Ssid.Ssid, pWZCCfgList->Config->Ssid.SsidLength );

						if ((dwRet = WZCConfigItemAppend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[i], SW2_WZC_LIB_CONFIG_PREF ), TRUE ) ) == NO_ERROR )
						{
							pWZCConfigListItem = pWZCConfigListItem->pNext;
						}
						else
							break;
					}
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}

				free( pWZCCfgList );
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}
#endif // SW2_WZC_LIB_2K_XP_SP0

	return dwRet;
}

#ifdef SW2_WZC_LIB_XP_SP2
DWORD
WZCSetPrefSSIDList_SP2( IN PSW2_WZC_LIB_CONTEXT pWZCContext, 
						IN WCHAR *pwcGUID, 
						OUT PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigListItem )
{
	PSW2_WZC_CONFIG_LIST_ITEM	pWZCConfigListCurrentItem;
	WCHAR						pwcRegEntry[MAX_PATH];
	WZC_WLAN_CONFIG				WZCCfg;
	HKEY						hKey1;
	WCHAR						pwcWZCEntryName[1024];
	DWORD						j;
	BOOL						bFirstTime;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	if (pWZCConfigListItem == NULL )
		return ERROR_NO_DATA;

	if ((dwRet = SW2_StopSVC(L"WZCSVC") ) == NO_ERROR ) 
	{
		if (wcslen(pwcGUID) > 0 &&
			wcslen(pwcGUID) < MAX_PATH - ( wcslen( L"SOFTWARE\\Microsoft\\WZCSVC\\Parameters\\Interfaces\\" ) + 1 ) )
		{
			wsprintf( pwcRegEntry, L"SOFTWARE\\Microsoft\\WZCSVC\\Parameters\\Interfaces\\%s", pwcGUID );

			if (RegOpenKeyEx( HKEY_LOCAL_MACHINE,
							pwcRegEntry,
							0,
							KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WRITE,
							&hKey1 ) == ERROR_SUCCESS )
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCSetPrefSSIDList_SP2::Opened guid key: %s", pwcGUID );

				//
				// Count number of entries
				// are found
				//
				j = 0;
				memset( pwcWZCEntryName, 0, sizeof( pwcWZCEntryName ) );
				wsprintf( pwcWZCEntryName, L"static#%.4ld", j );

				memset( &WZCCfg, 0, sizeof( WZCCfg ) );

				bFirstTime = TRUE;

				//
				// Remove original keys
				// TODO: save old values if anything goes wrong
				//
				while( ( dwRet = RegDeleteValue( hKey1,
										pwcWZCEntryName ) ) == NO_ERROR )
				{
					j++;
					memset( pwcWZCEntryName, 0, sizeof( pwcWZCEntryName ) );
					wsprintf( pwcWZCEntryName, L"static#%.4ld", j );
				}

				if (dwRet == ERROR_FILE_NOT_FOUND )
					dwRet = NO_ERROR;

				//
				// Reset counter and add entries
				//
				j  = 0;
				
				memset( pwcWZCEntryName, 0, sizeof( pwcWZCEntryName ) );
				wsprintf( pwcWZCEntryName, L"static#%.4ld", j );

				pWZCConfigListCurrentItem = pWZCConfigListItem;

				while( pWZCConfigListCurrentItem != NULL &&
						( dwRet == NO_ERROR ) )
				{
					dwRet = RegSetValueEx( hKey1,
											pwcWZCEntryName,
											0,
											REG_BINARY,
											( PBYTE ) &( pWZCConfigListCurrentItem->WZCConfig ),
											sizeof( pWZCConfigListCurrentItem->WZCConfig ) );

					j++;
					memset( pwcWZCEntryName, 0, sizeof( pwcWZCEntryName ) );
					wsprintf( pwcWZCEntryName, L"static#%.4ld", j );

					pWZCConfigListCurrentItem = pWZCConfigListCurrentItem->pNext;
				}

				RegCloseKey( hKey1 );
			}
		}

		SW2_StartSVC(L"WZCSVC", FALSE );
	}

	return dwRet;
}
#endif // SW2_WZC_LIB_XP_SP2

#ifdef SW2_WZC_LIB_XP_SP1
DWORD
WZCSetPrefSSIDList_1106( IN PSW2_WZC_LIB_CONTEXT pWZCContext, 
							IN WCHAR *pwcGUID, 
							IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigListItem )
{
	INTF_ENTRY_1106				Intf;
	PSW2_WZC_CONFIG_LIST_ITEM	p;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	p = pWZCConfigListItem;

	Intf.rdStSSIDList.pData = NULL;
	Intf.rdStSSIDList.dwDataLen = 0;

	if (p )
	{
		Intf.rdStSSIDList.dwDataLen = sizeof( WZC_802_11_CONFIG_LIST );

		while( p->pNext )
		{
			Intf.rdStSSIDList.dwDataLen = Intf.rdStSSIDList.dwDataLen + sizeof( WZC_WLAN_CONFIG );

			p = p->pNext;
		}

		p = pWZCConfigListItem;

		if ((pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdStSSIDList.dwDataLen)))
		{
			pWZCCfgList->Config[0] = p->WZCConfig;

			pWZCCfgList->NumberOfItems = 1;

			while( p->pNext )
			{
				pWZCCfgList->Config[pWZCCfgList->NumberOfItems] = p->pNext->WZCConfig;

				pWZCCfgList->NumberOfItems++;

				p = p->pNext;
			}


			pWZCCfgList->Index = pWZCCfgList->NumberOfItems;

			if ((Intf.rdStSSIDList.pData = ( PBYTE ) malloc( Intf.rdStSSIDList.dwDataLen)))
			{
				memcpy( Intf.rdStSSIDList.pData, pWZCCfgList, Intf.rdStSSIDList.dwDataLen );
			}
			else
				dwRet = ERROR_NOT_ENOUGH_MEMORY;

			free( pWZCCfgList );
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}
	}

	if (dwRet == NO_ERROR )
	{
		dwRet = pWZCContext->pfnWZCSetInterface_1106( NULL,
													INTF_PREFLIST,
													&Intf,
													&dwOIDFlags );

		if (Intf.rdStSSIDList.pData )
			free( Intf.rdStSSIDList.pData );
	}

	return dwRet;
}

DWORD
WZCSetPrefSSIDList_1181( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigListItem )
{
	INTF_ENTRY_1181				Intf;
	PSW2_WZC_CONFIG_LIST_ITEM	p;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	p = pWZCConfigListItem;

	Intf.rdStSSIDList.pData = NULL;
	Intf.rdStSSIDList.dwDataLen = 0;

	if (p )
	{
		Intf.rdStSSIDList.dwDataLen = sizeof( WZC_802_11_CONFIG_LIST );

		while( p->pNext )
		{
			Intf.rdStSSIDList.dwDataLen = Intf.rdStSSIDList.dwDataLen + sizeof( WZC_WLAN_CONFIG );

			p = p->pNext;
		}

		p = pWZCConfigListItem;

		if ((pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdStSSIDList.dwDataLen)))
		{
			pWZCCfgList->Config[0] = p->WZCConfig;

			pWZCCfgList->NumberOfItems = 1;

			while( p->pNext )
			{
				pWZCCfgList->Config[pWZCCfgList->NumberOfItems] = p->pNext->WZCConfig;

				pWZCCfgList->NumberOfItems++;

				p = p->pNext;
			}


			pWZCCfgList->Index = pWZCCfgList->NumberOfItems;

			if ((Intf.rdStSSIDList.pData = ( PBYTE ) malloc( Intf.rdStSSIDList.dwDataLen)))
			{
				memcpy( Intf.rdStSSIDList.pData, pWZCCfgList, Intf.rdStSSIDList.dwDataLen );
			}
			else
				dwRet = ERROR_NOT_ENOUGH_MEMORY;

			free( pWZCCfgList );
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}
	}

	if (dwRet == NO_ERROR )
	{
		dwRet = pWZCContext->pfnWZCSetInterface_1181( NULL,
													INTF_PREFLIST,
													&Intf,
													&dwOIDFlags );

		if (Intf.rdStSSIDList.pData )
			free( Intf.rdStSSIDList.pData );
	}

	return dwRet;
}
#endif // SW2_WZC_LIB_XP_SP1

DWORD
WZCSetPrefSSIDList( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigListItem )
{
	DWORD	dwRet;

#ifdef SW2_WZC_LIB_XP_SP2
	dwRet = WZCSetPrefSSIDList_SP2( pWZCContext, pwcGUID, pWZCConfigListItem );
#endif // SW2_WZC_LIB_XP_SP2

#ifdef SW2_WZC_LIB_XP_SP1
	dwRet = NO_ERROR;

	if (pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCSetPrefSSIDList_1106( pWZCContext, pwcGUID, pWZCConfigListItem );
	}
	else
	{
		dwRet = WZCSetPrefSSIDList_1181( pWZCContext, pwcGUID, pWZCConfigListItem );
	}
#endif // SW2_WZC_LIB_XP_SP1

#ifdef SW2_WZC_LIB_2K_XP_SP0
	INTF_ENTRY					Intf;
	PSW2_WZC_CONFIG_LIST_ITEM	p;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	p = pWZCConfigListItem;

	Intf.rdStSSIDList.pData = NULL;
	Intf.rdStSSIDList.dwDataLen = 0;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCSetPrefSSIDList: %s", pwcGUID );

	if (p )
	{
		Intf.rdStSSIDList.dwDataLen = sizeof( WZC_802_11_CONFIG_LIST );

		while( p->pNext )
		{
			Intf.rdStSSIDList.dwDataLen = Intf.rdStSSIDList.dwDataLen + sizeof( WZC_WLAN_CONFIG );

			p = p->pNext;
		}

		p = pWZCConfigListItem;

		if ((pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdStSSIDList.dwDataLen)))
		{
			pWZCCfgList->Config[0] = p->WZCConfig;

			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCSetPrefSSIDList::WZCCfg[0](%ld)", sizeof( WZC_WLAN_CONFIG ) );
			SW2Dump( ( PBYTE ) &( pWZCCfgList->Config[0] ), sizeof( WZC_WLAN_CONFIG ) );

			pWZCCfgList->NumberOfItems = 1;

			while( p->pNext )
			{
				pWZCCfgList->Config[pWZCCfgList->NumberOfItems] = p->pNext->WZCConfig;

				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCSetPrefSSIDList::WZCCfg[%ld](%ld)", pWZCCfgList->NumberOfItems, sizeof( WZC_WLAN_CONFIG ) );
				SW2Dump( ( PBYTE ) &( pWZCCfgList->Config[pWZCCfgList->NumberOfItems] ), sizeof( WZC_WLAN_CONFIG ) );

				pWZCCfgList->NumberOfItems++;

				p = p->pNext;
			}


			pWZCCfgList->Index = pWZCCfgList->NumberOfItems;

			if ((Intf.rdStSSIDList.pData = ( PBYTE ) malloc( Intf.rdStSSIDList.dwDataLen)))
			{
				memcpy( Intf.rdStSSIDList.pData, pWZCCfgList, Intf.rdStSSIDList.dwDataLen );
			}
			else
				dwRet = ERROR_NOT_ENOUGH_MEMORY;

			free( pWZCCfgList );
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}
	}

	if (dwRet == NO_ERROR )
	{
		dwRet = pWZCContext->pfnWZCSetInterface( NULL,
												INTF_PREFLIST,
												&Intf,
												&dwOIDFlags );

		if (Intf.rdStSSIDList.pData )
			free( Intf.rdStSSIDList.pData );
	}
#endif // SW2_WZC_LIB_2K_XP_SP0

	return dwRet;
}

#ifdef SW2_WZC_LIB_XP_SP1
DWORD
WZCGetBSSIDList_1106( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT PSW2_WZC_CONFIG_LIST_ITEM *ppWZCConfigListItem )
{
	INTF_ENTRY_1106				Intf;
	PSW2_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						i;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if ((dwRet = pWZCContext->pfnWZCQueryInterface_1106( NULL,
														INTF_BSSIDLIST,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
		if (Intf.rdBSSIDList.dwDataLen > 0 )
		{	
			if ((pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdBSSIDList.dwDataLen)))
			{
				memcpy( pWZCCfgList, Intf.rdBSSIDList.pData, Intf.rdBSSIDList.dwDataLen );

				if ((*ppWZCConfigListItem = WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[0], SW2_WZC_LIB_CONFIG_BSSID)))
				{
					pWZCConfigListItem = *ppWZCConfigListItem;

					for( i=1; i < pWZCCfgList->NumberOfItems; i++ )
					{
						WZCConfigItemAppend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[i], SW2_WZC_LIB_CONFIG_BSSID ), TRUE );
						pWZCConfigListItem = pWZCConfigListItem->pNext;
					}
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}

				free( pWZCCfgList );
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}

	return dwRet;
}

DWORD
WZCGetBSSIDList_1181( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT PSW2_WZC_CONFIG_LIST_ITEM *ppWZCConfigListItem )
{
	INTF_ENTRY_1181				Intf;
	PSW2_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						i;
	DWORD						dwRet;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetBSSIDList_1181: %ws", pwcGUID );

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if ((dwRet = pWZCContext->pfnWZCQueryInterface_1181( NULL,
														INTF_BSSIDLIST,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetBSSIDList_1181::pfnWZCQueryInterface_1181");

		//
		// Retrieve Preferred List
		//
		if (Intf.rdBSSIDList.dwDataLen > 0 )
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetBSSIDList_1181::Intf.rdBSSIDList.dwDataLen %ld", Intf.rdBSSIDList.dwDataLen );

			if ((pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdBSSIDList.dwDataLen)))
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetBSSIDList_1181::malloced");

				memcpy( pWZCCfgList, Intf.rdBSSIDList.pData, Intf.rdBSSIDList.dwDataLen );

				if ((*ppWZCConfigListItem = WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[0], SW2_WZC_LIB_CONFIG_BSSID)))
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetBSSIDList_1181::WZCConfigItemCreate");

					pWZCConfigListItem = *ppWZCConfigListItem;

					for( i=1; i < pWZCCfgList->NumberOfItems; i++ )
					{
						SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetBSSIDList_1181::appending item %ld", i );

						if ((WZCConfigItemAppend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[i], SW2_WZC_LIB_CONFIG_BSSID ), TRUE ) ) == NO_ERROR )
						{
							SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetBSSIDList_1181::appended");

							pWZCConfigListItem = pWZCConfigListItem->pNext;
						}
						else
							break;
					}
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}

				free( pWZCCfgList );
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetBSSIDList_1181::returning");

	return dwRet;
}
#endif // SW2_WZC_LIB_XP_SP1

DWORD
WZCGetBSSIDList( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT PSW2_WZC_CONFIG_LIST_ITEM *ppWZCConfigListItem )
{
	DWORD	dwRet = NO_ERROR;

#ifdef SW2_WZC_LIB_XP_SP2
	INTF_ENTRY					Intf;
	PSW2_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						i;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetBSSIDList_1181: %ws", pwcGUID );

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if ((dwRet = pWZCContext->pfnWZCQueryInterface( NULL,
													INTF_BSSIDLIST,
													&Intf,
													&dwOIDFlags ) ) == NO_ERROR )
	{
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetBSSIDList::pfnWZCQueryInterface");

		//
		// Retrieve Preferred List
		//
		if (Intf.rdBSSIDList.dwDataLen > 0 )
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetBSSIDList::Intf.rdBSSIDList.dwDataLen %ld", Intf.rdBSSIDList.dwDataLen );

			if ((pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdBSSIDList.dwDataLen)))
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetBSSIDList::malloced");

				memcpy( pWZCCfgList, Intf.rdBSSIDList.pData, Intf.rdBSSIDList.dwDataLen );

				if ((*ppWZCConfigListItem = WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[0], SW2_WZC_LIB_CONFIG_BSSID)))
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetBSSIDList::WZCConfigItemCreate");

					pWZCConfigListItem = *ppWZCConfigListItem;

					for( i=1; i < pWZCCfgList->NumberOfItems; i++ )
					{
						SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetBSSIDList::appending item %ld", i );

						if ((WZCConfigItemAppend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[i], SW2_WZC_LIB_CONFIG_BSSID ), TRUE ) ) == NO_ERROR )
						{
							SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetBSSIDList::appended");

							pWZCConfigListItem = pWZCConfigListItem->pNext;
						}
						else
							break;
					}
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}

				free( pWZCCfgList );
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}
#endif

#ifdef SW2_WZC_LIB_XP_SP1

	if (pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCGetBSSIDList_1106( pWZCContext, pwcGUID, ppWZCConfigListItem );
	}
	else
	{
		dwRet = WZCGetBSSIDList_1181( pWZCContext, pwcGUID, ppWZCConfigListItem );
	}
#endif // SW2_WZC_LIB_XP_SP1

	return dwRet;
}

#ifdef SW2_WZC_LIB_XP_SP1
DWORD
WZCSetBSSIDList_1106( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigListItem )
{
	INTF_ENTRY_1106				Intf;
	PSW2_WZC_CONFIG_LIST_ITEM	p;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	if (!pWZCConfigListItem  )
		return ERROR_NO_DATA;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	p = pWZCConfigListItem;

	Intf.rdBSSIDList.dwDataLen = sizeof( WZC_802_11_CONFIG_LIST );

	while( p->pNext )
	{
		Intf.rdBSSIDList.dwDataLen = Intf.rdBSSIDList.dwDataLen + sizeof( WZC_WLAN_CONFIG );

		p = p->pNext;
	}

//	printf( "Intf.rdBSSIDList.dwDataLen: %ld", Intf.rdBSSIDList.dwDataLen );

	p = pWZCConfigListItem;

	if ((pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdBSSIDList.dwDataLen)))
	{
		pWZCCfgList->Config[0] = p->WZCConfig;

		pWZCCfgList->NumberOfItems = 1;

		while( p->pNext )
		{
			pWZCCfgList->Config[pWZCCfgList->NumberOfItems] = p->pNext->WZCConfig;

			pWZCCfgList->NumberOfItems++;

			p = p->pNext;
		}

		pWZCCfgList->Index = pWZCCfgList->NumberOfItems;

//		printf( "pWZCCfgList->Index: %ld", pWZCCfgList->Index );
//		printf( "pWZCCfgList->NumberOfItems: %ld", pWZCCfgList->NumberOfItems );

		if ((Intf.rdBSSIDList.pData = ( PBYTE ) malloc( Intf.rdBSSIDList.dwDataLen)))
		{
			memcpy( Intf.rdBSSIDList.pData, pWZCCfgList, Intf.rdBSSIDList.dwDataLen );

			dwRet = pWZCContext->pfnWZCSetInterface_1106( NULL,
														INTF_BSSIDLIST,
														&Intf,
														&dwOIDFlags );

			free( Intf.rdBSSIDList.pData );
		}

		free( pWZCCfgList );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

DWORD
WZCSetBSSIDList_1181( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigListItem )
{
	INTF_ENTRY_1181				Intf;
	PSW2_WZC_CONFIG_LIST_ITEM	p;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	if (!pWZCConfigListItem  )
		return ERROR_NO_DATA;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	p = pWZCConfigListItem;

	Intf.rdBSSIDList.dwDataLen = sizeof( WZC_802_11_CONFIG_LIST );

	while( p->pNext )
	{
		Intf.rdBSSIDList.dwDataLen = Intf.rdBSSIDList.dwDataLen + sizeof( WZC_WLAN_CONFIG );

		p = p->pNext;
	}

	p = pWZCConfigListItem;

	if ((pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdBSSIDList.dwDataLen)))
	{
		pWZCCfgList->Config[0] = p->WZCConfig;

		pWZCCfgList->NumberOfItems = 1;

		while( p->pNext )
		{
			pWZCCfgList->Config[pWZCCfgList->NumberOfItems] = p->pNext->WZCConfig;

			pWZCCfgList->NumberOfItems++;

			p = p->pNext;
		}

		pWZCCfgList->Index = pWZCCfgList->NumberOfItems;

		printf( "pWZCCfgList->Index: %ld", pWZCCfgList->Index );
		printf( "pWZCCfgList->NumberOfItems: %ld", pWZCCfgList->NumberOfItems );

		if ((Intf.rdBSSIDList.pData = ( PBYTE ) malloc( Intf.rdBSSIDList.dwDataLen)))
		{
			memcpy( Intf.rdBSSIDList.pData, pWZCCfgList, Intf.rdBSSIDList.dwDataLen );

			dwRet = pWZCContext->pfnWZCSetInterface_1181( NULL,
														INTF_BSSIDLIST,
														&Intf,
														&dwOIDFlags );

			free( Intf.rdBSSIDList.pData );
		}

		free( pWZCCfgList );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}
#endif // SW2_WZC_LIB_XP_SP1

DWORD
WZCSetBSSIDList( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigListItem )
{
	DWORD	dwRet = NO_ERROR;

#ifdef SW2_WZC_LIB_XP_SP2
	INTF_ENTRY					Intf;
	PSW2_WZC_CONFIG_LIST_ITEM	p;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;

	dwRet = NO_ERROR;

	if (!pWZCConfigListItem  )
		return ERROR_NO_DATA;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	p = pWZCConfigListItem;

	Intf.rdBSSIDList.dwDataLen = sizeof( WZC_802_11_CONFIG_LIST );

	while( p->pNext )
	{
		Intf.rdBSSIDList.dwDataLen = Intf.rdBSSIDList.dwDataLen + sizeof( WZC_WLAN_CONFIG );

		p = p->pNext;
	}

	p = pWZCConfigListItem;

	if ((pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdBSSIDList.dwDataLen)))
	{
		pWZCCfgList->Config[0] = p->WZCConfig;

		pWZCCfgList->NumberOfItems = 1;

		while( p->pNext )
		{
			pWZCCfgList->Config[pWZCCfgList->NumberOfItems] = p->pNext->WZCConfig;

			pWZCCfgList->NumberOfItems++;

			p = p->pNext;
		}

		pWZCCfgList->Index = pWZCCfgList->NumberOfItems;

		printf( "pWZCCfgList->Index: %ld", pWZCCfgList->Index );
		printf( "pWZCCfgList->NumberOfItems: %ld", pWZCCfgList->NumberOfItems );

		if ((Intf.rdBSSIDList.pData = ( PBYTE ) malloc( Intf.rdBSSIDList.dwDataLen)))
		{
			memcpy( Intf.rdBSSIDList.pData, pWZCCfgList, Intf.rdBSSIDList.dwDataLen );

			dwRet = pWZCContext->pfnWZCSetInterface( NULL,
													INTF_BSSIDLIST,
													&Intf,
													&dwOIDFlags );

			free( Intf.rdBSSIDList.pData );
		}

		free( pWZCCfgList );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}
#endif

#ifdef SW2_WZC_LIB_XP_SP1

	if (pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCSetBSSIDList_1106( pWZCContext, pwcGUID, pWZCConfigListItem );
	}
	else
	{
		dwRet = WZCSetBSSIDList_1181( pWZCContext, pwcGUID, pWZCConfigListItem );
	}
#endif // SW2_WZC_LIB_XP_SP1

	return dwRet;
}

DWORD
WZCGetCompleteSSIDList( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, PSW2_WZC_CONFIG_LIST_ITEM	*ppWZCConfigListItem )
{
	PSW2_WZC_CONFIG_LIST_ITEM	pWZCPrefConfigListItem;
	PSW2_WZC_CONFIG_LIST_ITEM	pWZCBConfigListItem;
	PSW2_WZC_CONFIG_LIST_ITEM	p1, p2, p3;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList");

	//
	// First retrieve BSSID List
	//
	if ((dwRet = WZCGetBSSIDList( pWZCContext, pwcGUID, &pWZCBConfigListItem ) ) == NO_ERROR )
	{
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList::WZCGetBSSIDList");

		p1 = pWZCBConfigListItem;

		if ((*ppWZCConfigListItem = WZCConfigItemCreate( pWZCContext, p1->WZCConfig, p1->dwFlags)))
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList::BSSID:WZCConfigItemCreate");

			p2 = *ppWZCConfigListItem;

			while( p1->pNext )
			{
				if ((dwRet = WZCConfigItemAppend( p2, WZCConfigItemCreate( pWZCContext, p1->pNext->WZCConfig, p1->pNext->dwFlags ), TRUE ) ) != NO_ERROR )
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList::BSSID:appendWZCConfigItemCreate: failed: %ld", dwRet );

					break;
				}

				p2 = p2->pNext;
				p1 = p1->pNext;
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList::BSSID:WZCConfigItemCreate failed");

			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		if (dwRet != NO_ERROR )
		{
			while( pWZCBConfigListItem->pNext )
				WZCConfigItemDelete( &pWZCBConfigListItem->pNext );

			WZCConfigItemDelete( &pWZCBConfigListItem );
		}
	}

	if (dwRet == NO_ERROR )
	{
		//
		// Reset list back to last item
		//
		p2 = *ppWZCConfigListItem;

		while( p2->pNext )
			p2 = p2->pNext;

		//
		// Retrieve Preferred SSID List
		//
		if ((dwRet = WZCGetPrefSSIDList( pWZCContext, pwcGUID, &pWZCPrefConfigListItem ) ) == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList::BSSID:WZCGetPrefSSIDList");

			p1 = pWZCPrefConfigListItem;

			while( p1 )
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList::BSSID:PREF:checking list for item(%ld): %s", p1->WZCConfig.Ssid.SsidLength, p1->WZCConfig.Ssid.Ssid );

				//
				// Check if we have already found this SSID in the list
				//
				if ((dwRet = WZCConfigItemGet( *ppWZCConfigListItem, (PCHAR) p1->WZCConfig.Ssid.Ssid, &p3 ) ) == NO_ERROR )
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList::BSSID:PREF:found item in list");

					//
					// Found item in the list so just OR the flags
					//
					p3->dwFlags |= p1->dwFlags;
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList::BSSID:PREF:going to append");

					if ((dwRet = WZCConfigItemAppend( p2, WZCConfigItemCreate( pWZCContext, p1->WZCConfig, p1->dwFlags ), TRUE ) ) != NO_ERROR )
					{
						SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList::BSSID:PREF:WZCConfigItemAppend failed: %ld", dwRet );

						break;
					}

					//
					// Added an item so reset the list to the last item
					//
					p2 = p2->pNext;
				}

				p1 = p1->pNext;
			}

			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList::BSSID:PREF:deleting PREF");

			while( pWZCPrefConfigListItem->pNext )
				WZCConfigItemDelete( &pWZCPrefConfigListItem->pNext );

			WZCConfigItemDelete( &pWZCPrefConfigListItem );
		}
		else
		{
			//
			// Did not retrieve pref SSID list, but did succeed in getting a BSSID list
			// so set dwRet to NO_ERROR to continue with just a BSSID
			//
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList::BSSID:PREF:WZCGetPrefSSIDList failed: %ld", dwRet );

			dwRet = NO_ERROR;
		}

		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList::BSSID:deleting BSSID");

		while( pWZCBConfigListItem->pNext )
			WZCConfigItemDelete( &pWZCBConfigListItem->pNext );

		WZCConfigItemDelete( &pWZCBConfigListItem );
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList::WZCGetBSSIDList failed: %ld", dwRet );

		//
		// Could not find a BSSID list, so just add PREF (If Any)
		//
		if ((dwRet = WZCGetPrefSSIDList( pWZCContext, pwcGUID, &pWZCPrefConfigListItem ) ) == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList::WZCGetPrefSSIDList");

			p1 = pWZCPrefConfigListItem;

			if ((*ppWZCConfigListItem = WZCConfigItemCreate( pWZCContext, p1->WZCConfig, p1->dwFlags)))
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList::PREF:WZCConfigItemCreate");

				p2 = *ppWZCConfigListItem;

				while( p1->pNext )
				{
					if ((dwRet = WZCConfigItemAppend( p2, WZCConfigItemCreate( pWZCContext, p1->pNext->WZCConfig, p1->pNext->dwFlags ), TRUE ) ) != NO_ERROR )
					{
						SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList::PREF:WZCConfigItemAppend failed: %ld", dwRet );

						break;
					}

					p2 = p2->pNext;
					p1 = p1->pNext;
				}
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}

			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList::PREF:deleting PREF");
		
			while( pWZCPrefConfigListItem->pNext )
				WZCConfigItemDelete( &pWZCPrefConfigListItem->pNext );

			WZCConfigItemDelete( &pWZCPrefConfigListItem );
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCompleteSSIDList::returning");

	return dwRet;
}

DWORD
WZCGetEapUserData( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN DWORD dwEapTypeId, IN OUT PBYTE pbUserInfo, IN OUT DWORD cbUserInfo )
{
	WCHAR	*pwcSSID;
	PCHAR	pcSSID;
	DWORD	ccSSID;
	DWORD	dwRet;

	dwRet = NO_ERROR;

	if ((dwRet = WZCGetCurrentSSID( pWZCContext, pwcGUID, &pwcSSID ) ) == NO_ERROR )
	{
		ccSSID = ( DWORD ) wcslen( pwcSSID );

		if ((pcSSID = ( PCHAR ) malloc( ccSSID + 1)))
		{
			if (WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID + 1, NULL, NULL ) > 0 )
			{
				dwRet = pWZCContext->pfnWZCGetEapUserInfo( pwcGUID,
															dwEapTypeId,
															ccSSID,
															(PBYTE) pcSSID,
															pbUserInfo,
															&cbUserInfo );
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}

			free( pcSSID );
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pwcSSID );
	}	
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

#ifdef SW2_WZC_LIB_XP_SP1
DWORD
WZCGetCurrentSSID_1106( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT WCHAR ** ppwcSSID )
{
	INTF_ENTRY_1106			Intf;
	DWORD					dwOIDFlags;
	PCHAR					pcSSID;
	DWORD					ccSSID;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	//
	// Refresh INTF_SSID
	//
	if ((dwRet = pWZCContext->pfnWZCRefreshInterface_1106( NULL,
															INTF_SSID | INTF_WEPSTATUS,
															&Intf,
															&dwOIDFlags ) ) == NO_ERROR )
	{
		if ((dwRet = pWZCContext->pfnWZCQueryInterface_1106( NULL,
															INTF_SSID,
															&Intf,
															&dwOIDFlags ) ) == NO_ERROR )
		{
			//
			// Connected to SSID?
			//
			if (Intf.rdSSID.dwDataLen > 0 )
			{
				if ((pcSSID = ( PCHAR ) malloc( Intf.rdSSID.dwDataLen + 1)))
				{
					memset( pcSSID, 0, Intf.rdSSID.dwDataLen + 1 );

					memcpy( pcSSID, Intf.rdSSID.pData, Intf.rdSSID.dwDataLen );

					ccSSID = ( DWORD ) strlen( pcSSID ) + 1;

					if ((*ppwcSSID = ( WCHAR* ) malloc( ccSSID * sizeof( WCHAR))) )
					{
						memset( *ppwcSSID, 0, ccSSID );

						if (MultiByteToWideChar( CP_ACP, 0, pcSSID, -1, *ppwcSSID, ccSSID ) == 0 )
							dwRet = ERROR_NOT_ENOUGH_MEMORY;

						if (dwRet != NO_ERROR )
							free( *ppwcSSID );
					}

					free( pcSSID );
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}
			}
			else
			{
				dwRet = ERROR_NO_DATA;
			}
		}
	}

	return dwRet;
}

DWORD
WZCGetCurrentSSID_1181( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT WCHAR ** ppwcSSID )
{
	INTF_ENTRY_1181			Intf;
	DWORD					dwOIDFlags;
	PCHAR					pcSSID;
	DWORD					ccSSID;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	//
	// Refresh INTF_SSID
	//
	if ((dwRet = pWZCContext->pfnWZCRefreshInterface_1181( NULL,
															INTF_SSID | INTF_WEPSTATUS,
															&Intf,
															&dwOIDFlags ) ) == NO_ERROR )
	{
		if ((dwRet = pWZCContext->pfnWZCQueryInterface_1181( NULL,
																INTF_SSID,
																&Intf,
																&dwOIDFlags ) ) == NO_ERROR )
		{
			//
			// Connected to SSID?
			//
			if (Intf.rdSSID.dwDataLen > 0 )
			{
				if ((pcSSID = ( PCHAR ) malloc( Intf.rdSSID.dwDataLen + 1)))
				{
					memset( pcSSID, 0, Intf.rdSSID.dwDataLen + 1 );

					memcpy( pcSSID, Intf.rdSSID.pData, Intf.rdSSID.dwDataLen );

					ccSSID = ( DWORD ) strlen( pcSSID ) + 1;

					if ((*ppwcSSID = ( WCHAR* ) malloc( ccSSID * sizeof( WCHAR))) )
					{
						memset( *ppwcSSID, 0, ccSSID );

						if (MultiByteToWideChar( CP_ACP, 0, pcSSID, -1, *ppwcSSID, ccSSID ) == 0 )
							dwRet = ERROR_NOT_ENOUGH_MEMORY;

						if (dwRet != NO_ERROR )
							free( *ppwcSSID );
					}

					free( pcSSID );
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}
			}
		}
	}

	return dwRet;
}
#endif // SW2_WZC_LIB_XP_SP1

//
// Searches for the INTF_ENTRY beloning to the GUID and retrieves the current SSID
// The calling function is responsible for freeing ppwcSSID using free();
//
DWORD
WZCGetCurrentSSID( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT WCHAR ** ppwcSSID )
{
	DWORD	dwRet = NO_ERROR;

#ifdef SW2_WZC_LIB_XP_SP1
	if (pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCGetCurrentSSID_1106( pWZCContext, pwcGUID, ppwcSSID );
	}
	else
	{
		dwRet = WZCGetCurrentSSID_1181( pWZCContext, pwcGUID, ppwcSSID );
	}
#else

	INTF_ENTRY			Intf;
	DWORD				dwOIDFlags;
	PCHAR				pcSSID;
	DWORD				ccSSID;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCurrentSSID");

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCGetCurrentSSID::refreshing interface");

	//
	// Refresh INTF_SSID
	//
	if ((dwRet = pWZCContext->pfnWZCRefreshInterface( NULL,
														INTF_SSID | INTF_WEPSTATUS,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"pfnWZCRefreshInterface:successfull");

		if ((dwRet = pWZCContext->pfnWZCQueryInterface( NULL,
														INTF_SSID,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"pfnWZCQueryInterface:successfull");

			//
			// Connected to SSID?
			//
			if (Intf.rdSSID.dwDataLen > 0 )
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"Intf.rdSSID.dwDataLen: %ld", Intf.rdSSID.dwDataLen );

				if ((pcSSID = ( PCHAR ) malloc( Intf.rdSSID.dwDataLen + 1)))
				{
					memset( pcSSID, 0, Intf.rdSSID.dwDataLen + 1 );

					memcpy( pcSSID, Intf.rdSSID.pData, Intf.rdSSID.dwDataLen );

					ccSSID = ( DWORD ) strlen( pcSSID ) + 1;

					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"pcSSID(%ld): %s", ccSSID, pcSSID );

					if ((*ppwcSSID = ( WCHAR* ) malloc( ccSSID * sizeof( WCHAR))) )
					{
						memset( *ppwcSSID, 0, ccSSID );

						if (MultiByteToWideChar( CP_ACP, 0, pcSSID, -1, *ppwcSSID, ccSSID ) == 0 )
							dwRet = ERROR_NOT_ENOUGH_MEMORY;

						if (dwRet != NO_ERROR )
							free( *ppwcSSID );
					}

					free( pcSSID );
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}
			}
			else
			{
				dwRet = ERROR_NO_DATA;
			}
		}
	}
#endif //  SW2_WZC_LIB_2K_XP_SP0

	return dwRet;
}

#ifdef SW2_WZC_LIB_XP_SP1
DWORD
WZCSetCurrentSSID_1106( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WCHAR * pwcSSID )
{
	INTF_ENTRY_1106			Intf;
	DWORD					dwOIDFlags;
	PCHAR					pcSSID;
	DWORD					ccSSID;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	ccSSID = ( DWORD ) wcslen( pwcSSID );

	if ((pcSSID = ( PCHAR ) malloc( ccSSID + 1)))
	{
		if (WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID + 1, NULL, NULL ) > 0 )
		{
			if ((Intf.rdSSID.pData = ( PBYTE ) malloc( ccSSID + 1)))
			{
				printf( "SSID: %s", pcSSID );

				memset( Intf.rdSSID.pData, 0, ccSSID + 1 );

				memcpy( Intf.rdSSID.pData, pcSSID, ccSSID );
				Intf.rdSSID.dwDataLen = ccSSID;

				dwRet = pWZCContext->pfnWZCSetInterface_1106( NULL,
															INTF_SSID,
															&Intf,
															&dwOIDFlags );

				free( Intf.rdSSID.pData );
			}
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pcSSID );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

DWORD
WZCSetCurrentSSID_1181( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WCHAR * pwcSSID )
{
	INTF_ENTRY_1181			Intf;
	DWORD					dwOIDFlags;
	PCHAR					pcSSID;
	DWORD					ccSSID;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	ccSSID = ( DWORD ) wcslen( pwcSSID );

	if ((pcSSID = ( PCHAR ) malloc( ccSSID + 1)))
	{
		if (WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID + 1, NULL, NULL ) > 0 )
		{
			if ((Intf.rdSSID.pData = ( PBYTE ) malloc( ccSSID + 1)))
			{
				memset( Intf.rdSSID.pData, 0, ccSSID + 1 );

				memcpy( Intf.rdSSID.pData, pcSSID, ccSSID );
				Intf.rdSSID.dwDataLen = ccSSID;

				dwRet = pWZCContext->pfnWZCSetInterface_1181( NULL,
															INTF_SSID,
															&Intf,
															&dwOIDFlags );

				free( Intf.rdSSID.pData );
			}
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pcSSID );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}
#endif // SW2_WZC_LIB_XP_SP1

//
// Searches for the INTF_ENTRY beloning to the GUID and sets the current SSID
// The calling function is responsible for freeing ppwcSSID using free();
//
DWORD
WZCSetCurrentSSID( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WCHAR * pwcSSID )
{
	DWORD	dwRet;

#ifdef SW2_WZC_LIB_XP_SP1
	dwRet = NO_ERROR;

	if (pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCSetCurrentSSID_1106( pWZCContext, pwcGUID, pwcSSID );
	}
	else
	{
		dwRet = WZCSetCurrentSSID_1181( pWZCContext, pwcGUID, pwcSSID );
	}
#else
	INTF_ENTRY				Intf;
	DWORD					dwOIDFlags;
	PCHAR					pcSSID;
	DWORD					ccSSID;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	ccSSID = ( DWORD ) wcslen( pwcSSID );

	if ((pcSSID = ( PCHAR ) malloc( ccSSID + 1)))
	{
		if (WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID + 1, NULL, NULL ) > 0 )
		{
			if ((Intf.rdSSID.pData = ( PBYTE ) malloc( ccSSID + 1)))
			{
				printf( "SSID: %s", pcSSID );

				memset( Intf.rdSSID.pData, 0, ccSSID + 1 );

				memcpy( Intf.rdSSID.pData, pcSSID, ccSSID );
				Intf.rdSSID.dwDataLen = ccSSID;

				Intf.nInfraMode = Ndis802_11Infrastructure;

				dwRet = pWZCContext->pfnWZCSetInterface( NULL,
														INTF_SSID | INTF_INFRAMODE,
														&Intf,
														&dwOIDFlags );

				free( Intf.rdSSID.pData );
			}
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pcSSID );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

#endif // SW2_WZC_LIB_XP_SP1

	return dwRet;
}

#ifdef SW2_WZC_LIB_XP_SP1
DWORD
WZCRefreshList_1106( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID )
{
	INTF_ENTRY_1106			Intf;
	DWORD					dwOIDFlags;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	//
	// Refresh INTF_SSID
	//
	dwRet = pWZCContext->pfnWZCRefreshInterface_1106( NULL,
													INTF_LIST_SCAN,
													&Intf,
													&dwOIDFlags );

	return dwRet;
}

DWORD
WZCRefreshList_1181( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID )
{
	INTF_ENTRY_1181			Intf;
	DWORD					dwOIDFlags;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	//
	// Refresh INTF_SSID
	//
	dwRet = pWZCContext->pfnWZCRefreshInterface_1181( NULL,
													INTF_LIST_SCAN,
													&Intf,
													&dwOIDFlags );

	return dwRet;
}
#endif // SW2_WZC_LIB_XP_SP1

DWORD
WZCRefreshList( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID )
{
	DWORD	dwRet;

	dwRet = NO_ERROR;

#ifdef SW2_WZC_LIB_XP_SP1

	if (pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCRefreshList_1106( pWZCContext, pwcGUID );
	}
	else
	{
		dwRet = WZCRefreshList_1181( pWZCContext, pwcGUID );
	}
#endif // SW2_WZC_LIB_XP_SP1

	return dwRet;
}

DWORD
WZCGetConfigEapData(	IN PSW2_WZC_LIB_CONTEXT pWZCContext,
						IN WCHAR *pwcGUID, 
						IN WCHAR *pwcSSID, 
						IN DWORD dwEapType, 
						OUT PBYTE *ppbConfigData, 
						OUT DWORD *pcbConfigData )
{
//	EAPOL_INTF_PARAMS		IntfParams;
	PCHAR					pcSSID;
	DWORD					ccSSID;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	ccSSID = ( DWORD ) wcslen( pwcSSID );

	if ((pcSSID = ( PCHAR ) malloc( ccSSID + 1)))
	{
		memset( pcSSID, 0, ccSSID );

		if (WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID + 1, NULL, NULL ) > 0 )
		{
			*pcbConfigData = 0;

			dwRet = pWZCContext->pfnWZCEapolGetCustomAuthData ( NULL,
																pwcGUID,
																dwEapType,															
																( DWORD ) ccSSID,
																( PBYTE ) pcSSID,
																( PBYTE ) NULL,
																pcbConfigData );

			if (dwRet == ERROR_BUFFER_TOO_SMALL )
			{
				if (*pcbConfigData == 0 )
				{
					//
					// no eap data available
					//
					*ppbConfigData = NULL;
				}
				else
				{
					if ((*ppbConfigData = ( PBYTE ) malloc( *pcbConfigData)))
					{
						if (dwRet = pWZCContext->pfnWZCEapolGetCustomAuthData ( NULL,
																			pwcGUID,
																			dwEapType,															
																			( DWORD ) ccSSID,
																			( PBYTE ) pcSSID,
																			( PBYTE ) *ppbConfigData,
																			pcbConfigData ) != NO_ERROR )
						{
							free( *ppbConfigData );
							*ppbConfigData = NULL;
							*pcbConfigData = 0;
						}
					}
					else
					{
						*pcbConfigData = 0;

						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}
				}
			}
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pcSSID );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

#ifdef SW2_WZC_LIB_XP_SP2
//
// This function will enable 802.1X, set the EAP Type and the EAP Data for 
// the pwcGUID SP2 style
//
DWORD
WZCSetConfigEapDataSP2(	IN PSW2_WZC_LIB_CONTEXT pWZCContext,
						IN WCHAR *pwcGUID, 
						IN WCHAR *pwcSSID, 
						IN DWORD dwEapType, 
						IN DWORD dw8021XFlags, 
						IN PBYTE pbConfigData, 
						IN DWORD cbConfigData )
{
	HKEY					hKey1;
	HKEY					hKey2;
	CHAR					pcSSID[UNLEN];
	DWORD					ccSSID;
	CHAR					pcRegSSID[32];
	BYTE					pb8021X[] = {
										0x5,0x0,0x0,0x0,
										0x0,0x0,0x0,0x0,
										0x0,0x0,0x0,0xc0, //
										0x0,0x0,0x0,0x0,// AUTH SELECTION: 0x15=SecureW2,0xd=standard smartcard stuff
										};
	BYTE					pbUnknown1[] = 	{ 
									0x0D,0x0,0x0,0x0,// End of SSID?
									0x28,0x0,0x0,0x0,
									0x0,0x0,0x0,0x0,
									0x28,0x0,0x0,0x0,
									0x5,0x0,0x0,0x0,
									0x0,0x0,0x0,0x0,
									0x0,0x0,0x0,0x0,
									0x0,0x0,0x0,0x0,
									0x0,0x0,0x0,0x0,
									0x0,0x0,0x0,0x0,
									0x0,0x0,0x0,0x0,
									0x0,0x0,0x0,0x0,
									0x0,0x0,0x0,0x0,
									0x15,0x0,0x0,0x0 };
	PBYTE					pbNewReg;
	DWORD					cbNewReg;
	DWORD					cbOldReg;
	ULONG					ulStatus = 0;
	HRESULT					hrInit = S_OK;
	HRESULT					hr = S_OK;
	DWORD					dwLen = 0;
	WCHAR					pwcEapEntryName[UNLEN];
	DWORD					cwcEapEntryName;
	BYTE					pbEapEntryValue[1024];
	DWORD					cbEapEntryValue;
	DWORD					dwEapEntryType;
	PWCHAR					pwcTemp;
	int						j;
	DWORD					dwSSIDLength;
	CHAR					pcSSIDValue[32];
	DWORD					dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"SW2_TRACE_LEVEL_DEBUG::WZCSetConfigEapDataSP2");

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"SW2_TRACE_LEVEL_DEBUG::WZCSetConfigEapDataSP2:: cbConfigData: %ld", cbConfigData );

	if (dwReturnCode == NO_ERROR)
	{
		memset( pcRegSSID, 0, sizeof( pcRegSSID ) );

		if ((WideCharToMultiByte( CP_ACP, 
									0, 
									pwcSSID, 
									-1, 
									pcSSID, 
									sizeof( pcSSID ), 
									NULL, 
									NULL ) ) > 0 )
		{
			memcpy( pcRegSSID, pcSSID, strlen( pcSSID ) );

			ccSSID = ( DWORD ) strlen( pcSSID );

			if ((dwReturnCode = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
										L"SOFTWARE\\Microsoft\\EAPOL\\Parameters\\Interfaces",
										0,
										KEY_ALL_ACCESS,
										&hKey1 ) ) == ERROR_SUCCESS )
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"SW2_TRACE_LEVEL_DEBUG::WZCSetConfigEapDataSP2::opened Interfaces entry");

				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"SW2_TRACE_LEVEL_DEBUG::WZCSetConfigEapDataSP2::opening GUID:%s", pwcGUID );

				if ((dwReturnCode = RegOpenKeyEx( hKey1,
								pwcGUID,
								0,
								KEY_QUERY_VALUE | KEY_SET_VALUE,
								&hKey2 ) ) == ERROR_SUCCESS )
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"SW2_TRACE_LEVEL_DEBUG::WZCSetConfigEapDataSP2::opened guid key: %s", pwcGUID );

					//
					// Loop through Eap Entry till we find an
					// entry with the same SSID or no more entries 
					// are found
					//
					j = 0;

					memset( pwcEapEntryName, 0, sizeof( pwcEapEntryName ) );
					memset( pbEapEntryValue, 0, sizeof( pbEapEntryValue ) );

					cbEapEntryValue = sizeof( pbEapEntryValue );
					cwcEapEntryName = sizeof( pwcEapEntryName );

					while( RegEnumValue( hKey2,
										 j,
										 pwcEapEntryName,
										 &cwcEapEntryName,
										 NULL,
										 &dwEapEntryType,
										 pbEapEntryValue,
										 &cbEapEntryValue ) == ERROR_SUCCESS )
					{
						SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"SW2_TRACE_LEVEL_DEBUG::WZCSetConfigEapDataSP2::opened eap entry: %s, value: %ld", 
									pwcEapEntryName, cbEapEntryValue );
						
						//
						// Sanity check, should only contain EAP data
						//
						if (cbEapEntryValue > 16 )
						{
							//
							// Retrieve SSID Length
							//
							memcpy( &dwSSIDLength, &( pbEapEntryValue[16] ), sizeof( dwSSIDLength ) );

							SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"SW2_TRACE_LEVEL_DEBUG::WZCSetConfigEapDataSP2::retrieved dwSSIDLength: %ld", dwSSIDLength );

							memset( pcSSIDValue, 0, sizeof( pcSSIDValue ) );

							if (dwSSIDLength == ccSSID )
							{
								memcpy( pcSSIDValue, &( pbEapEntryValue[16 + sizeof( dwSSIDLength )] ), dwSSIDLength );

								if (strcmp( pcSSIDValue, pcRegSSID ) == 0 )
								{
									// found correct SSID
									SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"SW2_TRACE_LEVEL_DEBUG::WZCSetConfigEapDataSP2::SSID Value Match");

									break;
								}
								else
								{
									SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"SW2_TRACE_LEVEL_DEBUG::WZCSetConfigEapDataSP2::SSID Value Mismatch");
								}
							}
							else
								SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"SW2_TRACE_LEVEL_DEBUG::WZCSetConfigEapDataSP2::SSID Length MisMatch");
						}

						j++;
						memset( pwcEapEntryName, 0, sizeof( pwcEapEntryName ) );
						memset( pbEapEntryValue, 0, sizeof( pbEapEntryValue ) );
						cbEapEntryValue = sizeof( pbEapEntryValue );
						cwcEapEntryName = sizeof( pwcEapEntryName );
					} // while

					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"SW2_TRACE_LEVEL_DEBUG::WZCSetConfigEapDataSP2::setting entry %s", pwcEapEntryName );

					cbOldReg = 0;

					// length = 802.1X + SSIDLength + SSID + Unknown1
					cbNewReg = sizeof( pb8021X ) +
							sizeof( DWORD ) + 
							sizeof( pcRegSSID ) + 
							sizeof( pbUnknown1 ) +
							sizeof( DWORD ) +
							cbConfigData +
							sizeof( DWORD );

					if ((dwReturnCode = SW2AllocateMemory( cbNewReg, (PVOID*) &pbNewReg))==NO_ERROR)
					{
						memset( pbNewReg, 0, cbNewReg );

						//
						// Copy 802.1X information
						//

						//
						// Copy 802.1X Flags
						//
						pb8021X[8] = (BYTE) ((DWORD)(dw8021XFlags) >> 24);
						pb8021X[9] = (BYTE) ((DWORD)(dw8021XFlags) >> 16);
						pb8021X[10] = (BYTE) ((DWORD)(dw8021XFlags) >>  8);
						pb8021X[11] = (BYTE) (dw8021XFlags);

						SW2_ByteToHex(sizeof(DWORD), &(pb8021X[8]), &pwcTemp);

						SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"dw8021XFlags: %x, pb8021X[8]: %s", 
							dw8021XFlags, pwcTemp );

						SW2FreeMemory((PVOID*)&pwcTemp);

						//
						// Copy 802.1X EAP Type
						//
						memcpy( &(pb8021X[12]), &(dwEapType), sizeof( dwEapType ) );

						memcpy( pbNewReg, 
								pb8021X, 
								sizeof( pb8021X ) );

						//
						// Copy SSID length
						//
						memcpy( pbNewReg + 
								sizeof( pb8021X ),
								&ccSSID, 
								sizeof( ccSSID ) );

						//
						// Copy SSID
						//
						memcpy( pbNewReg + 
								sizeof( pb8021X ) + 
								sizeof( ccSSID ),
								pcRegSSID, 
								sizeof( pcRegSSID ) );

						//
						// Copy Unknown
						//
						memcpy( pbNewReg + 
								sizeof( pb8021X ) + 
								sizeof( ccSSID ) + 
								sizeof( pcRegSSID ),
								pbUnknown1, 
								sizeof( pbUnknown1 ) );

						memcpy( pbNewReg + 
								sizeof( pb8021X ) + 
								sizeof( ccSSID ) + 
								sizeof( pcRegSSID ) +
								sizeof( pbUnknown1 ),
								&cbConfigData, 
								sizeof( cbConfigData ) );

						memcpy( pbNewReg + 
								sizeof( pb8021X ) + 
								sizeof( ccSSID ) + 
								sizeof( pcRegSSID ) +
								sizeof( pbUnknown1 ) +
								sizeof( cbConfigData ), 
								pbConfigData, 
								cbConfigData);
				
						//
						// Write entry
						//
						if (RegSetValueEx( hKey2,
										pwcEapEntryName,
										0,
										REG_BINARY,
										pbNewReg,
										cbNewReg ) != ERROR_SUCCESS )
						{
							SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
								L"SW2_TRACE_LEVEL_DEBUG::WZCSetConfigEapDataSP2::Failed to set value: %ld", 
								GetLastError() );
						}

						SW2FreeMemory((PVOID*)&pbNewReg );
					}
					else 
						dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
	
					RegCloseKey(hKey2);
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
						L"SW2_TRACE_LEVEL_DEBUG::WZCSetConfigEapDataSP2::failed to open guid key: %ld", 
						dwReturnCode );

					dwReturnCode = ERROR_OPEN_FAILED;
				}

				RegCloseKey(hKey1);
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
					L"SW2_TRACE_LEVEL_DEBUG::WZCSetConfigEapDataSP2::failed to open interfaces key: %ld", 
					dwReturnCode );

				dwReturnCode = ERROR_OPEN_FAILED;
			}
		}
		else
			dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwReturnCode;
}
#endif //SW2_WZC_LIB_XP_SP2

//
// This function will enable 802.1X, set the EAP Type and the EAP Data for the pwcGUID
//
DWORD
WZCSetConfigEapData(	IN PSW2_WZC_LIB_CONTEXT pWZCContext,
						IN WCHAR *pwcGUID, 
						IN WCHAR *pwcSSID, 
						IN DWORD dwEapType, 
						IN DWORD dwFlags,
						IN PBYTE pbConfigData, 
						IN DWORD cbConfigData )
{
	DWORD					dwRet;
#ifdef SW2_WZC_LIB_XP_SP2
	dwRet = WZCSetConfigEapDataSP2( pWZCContext,
									pwcGUID, 
									pwcSSID, 
									dwEapType, 
									dwFlags,
									pbConfigData, 
									cbConfigData );
#else
	EAPOL_INTF_PARAMS		IntfParams;
	PCHAR					pcSSID;
	DWORD					ccSSID;

	dwRet = NO_ERROR;

	ccSSID = ( DWORD ) wcslen( pwcSSID );

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCSetConfigEapData");

	if ((pcSSID = ( PCHAR ) malloc( ccSSID + 1)))
	{
		memset( pcSSID, 0, ccSSID );

		if (WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID + 1, NULL, NULL ) > 0 )
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCSetConfigEapData::pwcSSID: %s", pwcSSID );

			memset( &IntfParams, 0, sizeof( EAPOL_INTF_PARAMS ) );

			memcpy( &IntfParams.bSSID, pcSSID, ccSSID );
			IntfParams.dwSizeOfSSID = ccSSID;

			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCSetConfigEapData:: calling pfnWZCEapolGetInterfaceParams");

			if ((dwRet = pWZCContext->pfnWZCEapolGetInterfaceParams( NULL,
																	pwcGUID,
																	&IntfParams ) ) == NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"IntfParams.dwEapFlags: %lx", IntfParams.dwEapFlags );
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"IntfParams.dwEapType: %ld", IntfParams.dwEapType );
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"IntfParams.dwSizeOfSSID: %ld", IntfParams.dwSizeOfSSID );
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"IntfParams.dwReserved2: %ld", IntfParams.dwReserved2 );
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"IntfParams.dwVersion: %ld", IntfParams.dwVersion );

				//
				// Setup 802.1X
				//
				IntfParams.dwEapFlags = EAPOL_ENABLED | EAPOL_MACHINE_AUTH_ENABLED;
				IntfParams.dwEapType = dwEapType;
				IntfParams.dwReserved2 = 0;

				if ((dwRet = pWZCContext->pfnWZCEapolSetInterfaceParams( NULL,
																		pwcGUID,
																		&IntfParams ) ) == NO_ERROR )
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"pfnWZCEapolSetInterfaceParams successfull");

					//
					// Setup the EAP Data
					//
					dwRet = pWZCContext->pfnWZCEapolSetCustomAuthData ( NULL,
																		pwcGUID,
																		dwEapType,															
																		( DWORD ) ccSSID,
																		( PBYTE ) pcSSID,
																		( PBYTE ) pbConfigData,
																		cbConfigData );

					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"pfnWZCEapolSetCustomAuthData returned %ld", dwRet );
				}
			}
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pcSSID );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}
#endif // SW2_WZC_LIB_XP_SP2

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCSetConfigEapData returning %ld", dwRet );

	return dwRet;
}

DWORD
WZCIsEapType( IN PSW2_WZC_LIB_CONTEXT pWZCContext,
				IN WCHAR *pwcGUID, 
				IN WCHAR *pwcSSID, 
				IN DWORD dwEapType, 
				IN PBYTE pbConfigData, 
				IN DWORD cbConfigData )
{
	EAPOL_INTF_PARAMS		IntfParams;
	PCHAR					pcSSID;
	DWORD					ccSSID;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	ccSSID = ( DWORD ) wcslen( pwcSSID );

	if ((pcSSID = ( PCHAR ) malloc( ccSSID + 1)))
	{
		memset( pcSSID, 0, ccSSID );

		if (WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID + 1, NULL, NULL ) > 0 )
		{
			memset( &IntfParams, 0, sizeof( EAPOL_INTF_PARAMS ) );

			memcpy( &IntfParams.bSSID, pcSSID, ccSSID );
			IntfParams.dwSizeOfSSID = ccSSID;

			if ((dwRet = pWZCContext->pfnWZCEapolGetInterfaceParams( NULL,
																	pwcGUID,
																	&IntfParams ) ) == NO_ERROR )
			{
/*
				printf( "IntfParams.dwEapFlags: %lx", IntfParams.dwEapFlags );
				printf( "IntfParams.dwEapType: %ld", IntfParams.dwEapType );
				printf( "IntfParams.dwSizeOfSSID: %ld", IntfParams.dwSizeOfSSID );
				printf( "IntfParams.dwReserved2: %ld", IntfParams.dwReserved2 );
				printf( "IntfParams.dwVersion: %ld", IntfParams.dwVersion );
*/
				//
				// Setup 802.1X
				//
				IntfParams.dwEapFlags = EAPOL_ENABLED | EAPOL_MACHINE_AUTH_ENABLED;
				IntfParams.dwEapType = dwEapType;
				IntfParams.dwReserved2 = 0;

				if ((dwRet = pWZCContext->pfnWZCEapolSetInterfaceParams( NULL,
																		pwcGUID,
																		&IntfParams ) ) == NO_ERROR )
				{
					//
					// Setup the EAP Data
					//
					dwRet = pWZCContext->pfnWZCEapolSetCustomAuthData ( NULL,
																		pwcGUID,
																		dwEapType,															
																		( DWORD ) ccSSID,
																		( PBYTE ) pcSSID,
																		( PBYTE ) pbConfigData,
																		cbConfigData );
				}
			}
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pcSSID );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

#ifdef SW2_WZC_LIB_XP_SP1
DWORD
WZCGetSignalStrength_1106( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT LONG *plSignalStrength )
{
	INTF_ENTRY_1106			Intf;
	DWORD					dwOIDFlags;
	WZC_WLAN_CONFIG			WZCCfg;
	int						i;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid =  pwcGUID;

	dwOIDFlags = 0;

	//
	// Refresh INTF_LIST_SCAN
	//
	if ((dwRet = pWZCContext->pfnWZCRefreshInterface_1106( NULL,
															INTF_LIST_SCAN | INTF_WEPSTATUS,
															&Intf,
															&dwOIDFlags ) ) == NO_ERROR )
	{
		for( i=0; i < 10; i++ )
		{	
			dwRet = WZCGetCurrentConfig( pWZCContext, pwcGUID, &WZCCfg );
		
			if (dwRet == ERROR_NO_DATA )
				Sleep( 1000 );
			else
				break;
		}

		if (i == 10 )
		{
			dwRet = ERROR_NO_DATA;
		}
		else if (dwRet == NO_ERROR )
		{
			*plSignalStrength = WZCCfg.Rssi;
		}
	}

	return dwRet;
}

DWORD
WZCGetSignalStrength_1181( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT LONG *plSignalStrength )
{
	INTF_ENTRY_1181			Intf;
	DWORD					dwOIDFlags;
	WZC_WLAN_CONFIG			WZCCfg;
	int						i;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid =  pwcGUID;

	dwOIDFlags = 0;

	//
	// Refresh INTF_LIST_SCAN
	//
	if ((dwRet = pWZCContext->pfnWZCRefreshInterface_1181( NULL,
															INTF_LIST_SCAN | INTF_WEPSTATUS,
															&Intf,
															&dwOIDFlags ) ) == NO_ERROR )
	{
		for( i=0; i < 10; i++ )
		{	
			dwRet = WZCGetCurrentConfig( pWZCContext, pwcGUID, &WZCCfg );
		
			if (dwRet == ERROR_NO_DATA )
				Sleep( 1000 );
			else
				break;
		}

		if (i == 10 )
		{
			dwRet = ERROR_NO_DATA;
		}
		else if (dwRet == NO_ERROR )
		{
			*plSignalStrength = WZCCfg.Rssi;
		}
	}

	return dwRet;
}
#endif // SW2_WZC_LIB_XP_SP1

//
// Will return Received signal strength (Rssi) in Dbm
// Refreshes interface belonging to pwcGUID
// Waits till BSSIDLIST is back up, retrieves the current SSID WLAN_CONFIG 
// and returns the Rssi of that Config
//
DWORD
WZCGetSignalStrength( IN PSW2_WZC_LIB_CONTEXT pWZCContext, 
						IN WCHAR *pwcGUID, OUT LONG *plSignalStrength )
{
	DWORD					dwRet = NO_ERROR;

#ifdef SW2_WZC_LIB_XP_SP2
	INTF_ENTRY				Intf;
	DWORD					dwOIDFlags;
	WZC_WLAN_CONFIG			WZCCfg;
	int						i;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid =  pwcGUID;

	dwOIDFlags = 0;

	//
	// Refresh INTF_LIST_SCAN
	//
	if ((dwRet = pWZCContext->pfnWZCRefreshInterface( NULL,
														INTF_LIST_SCAN | INTF_WEPSTATUS,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
		for( i=0; i < 10; i++ )
		{	
			dwRet = WZCGetCurrentConfig( pWZCContext, pwcGUID, &WZCCfg );
		
			if (dwRet == ERROR_NO_DATA )
				Sleep( 1000 );
			else
				break;
		}

		if (i == 10 )
		{
			dwRet = ERROR_NO_DATA;
		}
		else if (dwRet == NO_ERROR )
		{
			*plSignalStrength = WZCCfg.Rssi;
		}
	}
#endif

#ifdef SW2_WZC_LIB_XP_SP1

	if (pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCGetSignalStrength_1106( pWZCContext, pwcGUID, plSignalStrength );
	}
	else
	{
		dwRet = WZCGetSignalStrength_1181( pWZCContext, pwcGUID, plSignalStrength );
	}
#endif // SW2_WZC_LIB_XP_SP1

	return dwRet;
}

#ifdef SW2_WZC_LIB_XP_SP2
DWORD
WZCAddPreferedConfigSP2( IN PSW2_WZC_LIB_CONTEXT pWZCContext, 
						IN WCHAR *pwcGUID, 
						IN WZC_WLAN_CONFIG WZCCfgNew, 
						IN DWORD dwFlags, 
						IN BOOL bOverWrite, 
						IN BOOL bFirst )
{
	WCHAR							pwcAuthenticationMode[UNLEN];
	WCHAR							pwcEncryptionType[UNLEN];
	WCHAR							pwcConnectionType[UNLEN];
	WCHAR							*pwcSSID;
	ULONG							ulStatus = 0;
	GUID							guid;
	HRESULT							hrInit = S_OK;
	HRESULT							hr = S_OK;
	PSW2_WZC_CONFIG_LIST_ITEM		pWZCConfigListItem = NULL;
	PSW2_WZC_CONFIG_LIST_ITEM		pWZCTempConfigListItem = NULL;
	IProvisioningProfileWireless	*pIProvisioningProfileWireless;
	WCHAR							*pwcXMLTemplate;
	DWORD							ccXMLTemplate;
	DWORD							dwLen = 0;
	int								i;
	DWORD							dwRet;

	dwRet = NO_ERROR;
	
	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig_SP2");

	if (WZCCfgNew.AuthenticationMode == Ndis802_11AuthModeOpen )
		swprintf_s(pwcAuthenticationMode, sizeof(pwcAuthenticationMode)/sizeof(WCHAR),L"Open");
	else if (WZCCfgNew.AuthenticationMode == Ndis802_11AuthModeWPA )
		swprintf_s(pwcAuthenticationMode, sizeof(pwcAuthenticationMode)/sizeof(WCHAR),L"WPA");
	else if (WZCCfgNew.AuthenticationMode == Ndis802_11AuthModeWPA2 )
		swprintf_s(pwcAuthenticationMode, sizeof(pwcAuthenticationMode)/sizeof(WCHAR),L"WPA2");
	else
		return ERROR_NOT_SUPPORTED;

	if (WZCCfgNew.Privacy == 0 )
		swprintf_s(pwcEncryptionType, sizeof(pwcAuthenticationMode)/sizeof(WCHAR),L"WEP");
	else if (WZCCfgNew.Privacy == 1 ) 
		swprintf_s(pwcEncryptionType, sizeof(pwcAuthenticationMode)/sizeof(WCHAR),L"None");
	else if (WZCCfgNew.Privacy == 2 ) // special SecureW2 value for TKIP
		swprintf_s(pwcEncryptionType, sizeof(pwcAuthenticationMode)/sizeof(WCHAR),L"TKIP");
	else if (WZCCfgNew.Privacy == 3 )// special SecureW2 value for AES
		swprintf_s(pwcEncryptionType, sizeof(pwcAuthenticationMode)/sizeof(WCHAR),L"AES");
	else
		return ERROR_NOT_SUPPORTED;

	if (WZCCfgNew.ConnectionType == Ndis802_11ConnectionTypeESS )
		swprintf_s(pwcConnectionType, sizeof(pwcConnectionType)/sizeof(WCHAR),L"ESS");
	else if (WZCCfgNew.ConnectionType == Ndis802_11ConnectionTypeIBSS ) 
		swprintf_s(pwcConnectionType, sizeof(pwcConnectionType)/sizeof(WCHAR),L"IBSS");
	else
		return ERROR_NOT_SUPPORTED;

	ccXMLTemplate = ((((DWORD) wcslen( L"<?xml version=\"1.0\"?><wp:WirelessProfile xmlns=\"http://www.microsoft.com/provisioning/WirelessProfile\" xmlns:wp=\"http://www.microsoft.com/provisioning/WirelessProfile\"><wp:version>1</wp:version><wp:ssid></wp:ssid><wp:connectionType></wp:connectionType><wp:authentication></wp:authentication><wp:encryption></wp:encryption><wp:keyProvidedAutomatically>true</wp:keyProvidedAutomatically><wp:IEEE802.1XEnabled>true</wp:IEEE802.1XEnabled><wp:EAPMethod>PEAP</wp:EAPMethod></wp:WirelessProfile>" ) )
		+ WZCCfgNew.Ssid.SsidLength
		+ (DWORD) wcslen( pwcConnectionType )
		+ (DWORD) wcslen( pwcAuthenticationMode )
		+ (DWORD) wcslen( pwcEncryptionType ) + 1) * (DWORD) sizeof(WCHAR));
				
	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig_SP2::allocating %ld bytes for pwcXMLTemplate", ccXMLTemplate );

	if ((pwcXMLTemplate = ( WCHAR* ) malloc( ccXMLTemplate)))
	{
		//
		// Create SSID
		//
		memset( &guid, 0, sizeof( GUID ) );

		if ((pwcSSID = ( WCHAR* ) malloc( ( WZCCfgNew.Ssid.SsidLength + 1 ) * sizeof ( WCHAR))) )
		{
			if (MultiByteToWideChar( CP_ACP, 0, (PCHAR)WZCCfgNew.Ssid.Ssid, -1, pwcSSID, WZCCfgNew.Ssid.SsidLength + 1 ) > 0 )
			{
				swprintf_s( pwcXMLTemplate, 
					ccXMLTemplate/sizeof(WCHAR),
					L"<?xml version=\"1.0\"?><wp:WirelessProfile xmlns=\"http://www.microsoft.com/provisioning/WirelessProfile\" xmlns:wp=\"http://www.microsoft.com/provisioning/WirelessProfile\"><wp:version>1</wp:version><wp:ssid>%s</wp:ssid><wp:connectionType>%s</wp:connectionType><wp:authentication>%s</wp:authentication><wp:encryption>%s</wp:encryption><wp:keyProvidedAutomatically>true</wp:keyProvidedAutomatically><wp:IEEE802.1XEnabled>true</wp:IEEE802.1XEnabled><wp:EAPMethod>PEAP</wp:EAPMethod></wp:WirelessProfile>",
					pwcSSID,
					pwcConnectionType,
					pwcAuthenticationMode,
					pwcEncryptionType);

				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig_SP2::pwcXMLTemplate: %s", pwcXMLTemplate );

				if (pWZCContext->dwWZCSDllVersion >= WZCS_DLL_VERSION_5_1_2600_2149 )
				{
					hrInit = CoInitialize(NULL);

					if (hrInit == S_OK || hrInit == S_FALSE )
					{
						SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig_SP2::CoInitialize Succeeded");

						if ((hr = CoCreateInstance(	CLSID_NetProvisioning, 
														NULL,
														CLSCTX_ALL, 
														IID_IProvisioningProfileWireless, 
														(void **)&pIProvisioningProfileWireless)) == S_OK  )
						{
							SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig_SP2::CoCreateInstance Succeeded");

							CLSIDFromString( pwcGUID,
											&guid );

							if ((hr = pIProvisioningProfileWireless->CreateProfile( 
										pwcXMLTemplate,
										NULL,
										&guid,
										&ulStatus ) ) == S_OK )
							{
								SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig_SP2::CreateProfile succesfull");
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig_SP2::CreateProfile failed: %ld, status: %ld, %ld", hr, ulStatus, GetLastError() );

								if (ulStatus==WZC_PROFILE_SET_ERROR_DUPLICATE_NETWORK)
									dwRet = NO_ERROR;
								else
									dwRet = ulStatus;
							}
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig_SP2::CoCreateInstance failed: %ld", GetLastError() );
						}

						if (hrInit == S_OK )
							CoUninitialize();
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig_SP2::CoInitialize FAILED %ld, %ld", hr, GetLastError() );

						dwRet = ERROR_OPEN_FAILED;
					}
				}
				else
					dwRet = ERROR_NOT_SUPPORTED;

				//
				// Set priority
				//
				if (dwRet == NO_ERROR && bFirst)
				{
					if ((dwRet = WZCGetPrefSSIDList( pWZCContext, pwcGUID, &pWZCConfigListItem ) ) == NO_ERROR )
					{
						pWZCTempConfigListItem = pWZCConfigListItem;

						i = 0;

						while( pWZCTempConfigListItem )
						{
							if (strcmp((PCHAR)pWZCTempConfigListItem->WZCConfig.Ssid.Ssid, (PCHAR)WZCCfgNew.Ssid.Ssid ) == 0 )
							{
								SW2Dump(SW2_TRACE_LEVEL_DEBUG, (PBYTE)&pWZCTempConfigListItem->WZCConfig, 
									sizeof(pWZCTempConfigListItem->WZCConfig));

								//
								// Found Match
								//

								//
								// Set flags, which will set connectionMode (0=auto, 1=manual)
								//
								pWZCTempConfigListItem->WZCConfig.dwCtlFlags = 
									pWZCTempConfigListItem->WZCConfig.dwCtlFlags | WZCCfgNew.dwCtlFlags;

								//
								// Ignore if already at top of list
								//
								if (i > 0 )
								{
									//
									// Remove from list
									//
									WZCConfigItemRemove( pWZCTempConfigListItem );

									//
									// Add to list
									// 
									WZCConfigItemPrePend( pWZCConfigListItem, pWZCTempConfigListItem, TRUE );
								}

								break;
							}

							pWZCTempConfigListItem = pWZCTempConfigListItem->pNext;
							i++;
						}

						dwRet = WZCSetPrefSSIDList( pWZCContext, pwcGUID, pWZCConfigListItem );

						WZCConfigItemDeleteList( &pWZCConfigListItem );
					}
				}
			}
			else
				dwRet = ERROR_NOT_ENOUGH_MEMORY;

			free( pwcSSID );
		}
		else
			dwRet = ERROR_NOT_ENOUGH_MEMORY;

		free( pwcXMLTemplate );
	}
	else
		dwRet = ERROR_NOT_ENOUGH_MEMORY;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfigSP2 returning: %ld", dwRet );

	return dwRet;
}
#endif // SW2_WZC_LIB_XP_SP2

DWORD
WZCAddPreferedConfig(	IN PSW2_WZC_LIB_CONTEXT pWZCContext, 
						IN WCHAR *pwcGUID, 
						IN WZC_WLAN_CONFIG WZCCfgNew, 
						IN DWORD dwFlags, 
						IN BOOL bOverWrite, 
						IN BOOL bFirst )
{
	DWORD						dwRet;
#ifdef SW2_WZC_LIB_XP_SP2
	dwRet =  WZCAddPreferedConfigSP2( pWZCContext, 
										pwcGUID, 
										WZCCfgNew, 
										dwFlags, 
										bOverWrite, 
										bFirst );
#else

#ifdef SW2_WZC_LIB_VISTA
	dwRet = ERROR_NOT_SUPPORTED;
#else
	PSW2_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;
	PSW2_WZC_CONFIG_LIST_ITEM	p;
	WZC_WLAN_CONFIG				WZCCfg;

	dwRet = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig");

	dwRet = WZCGetPrefSSIDList( pWZCContext, pwcGUID, &pWZCConfigListItem );

	if (dwRet == ERROR_NO_DATA )
	{
		//
		// List is empty, create one
		//
		dwRet = NO_ERROR;

		if (!( pWZCConfigListItem = WZCConfigItemCreate( pWZCContext, WZCCfgNew, SW2_WZC_LIB_CONFIG_PREF)))
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}
		else
		{
			dwRet = WZCSetPrefSSIDList( pWZCContext, pwcGUID, pWZCConfigListItem );
	
			while( pWZCConfigListItem->pNext )
				WZCConfigItemDelete( &( pWZCConfigListItem->pNext ) );

			WZCConfigItemDelete( &pWZCConfigListItem );	
		}
	}
	else
	{
		if (dwRet == NO_ERROR )
		{
			//
			// Found list
			//
			if ((dwRet = WZCConfigItemGet(pWZCConfigListItem, (PCHAR) WZCCfgNew.Ssid.Ssid, &p)) == NO_ERROR)
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig::found in list");

				//
				// Config already in list
				//
				if (bOverWrite && bFirst )
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig::overwriting and setting to first");

					//
					// Overwrite it and set it to first item in list
					//
					memcpy( &WZCCfg, &WZCCfgNew, sizeof( WZC_WLAN_CONFIG ) );

					if ((dwRet = WZCConfigItemPrePend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, WZCCfg, dwFlags ), TRUE ) ) == NO_ERROR )
					{
						pWZCConfigListItem = pWZCConfigListItem->pPrev;

						WZCConfigItemDelete( &p );
					}
				}
				else if (bFirst )
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig::setting to first");

					//
					// Don't overwrite but set to first in list
					//
					if ((dwRet = WZCConfigItemPrePend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, p->WZCConfig, p->dwFlags ), TRUE ) ) == NO_ERROR )
					{
						pWZCConfigListItem = pWZCConfigListItem->pPrev;

						WZCConfigItemDelete( &p );
					}
				}
				else if (bOverWrite )
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig::overwriting");

					//
					// Just overwrite
					//
					memcpy( &p->WZCConfig, &WZCCfgNew, sizeof( WZC_WLAN_CONFIG ) );

					p->dwFlags = dwFlags;
				}
				else
					dwRet = ERROR_ALREADY_EXISTS;
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig::NOT found in list");

				//
				// Not in list
				//
				if (bFirst )
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig::setting to first in list");

					if ((dwRet = WZCConfigItemPrePend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, WZCCfgNew, dwFlags ), TRUE ) ) == NO_ERROR )
					{
						pWZCConfigListItem = pWZCConfigListItem->pPrev;
					}
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig::inserting in to list");

					if ((dwRet = WZCConfigItemAppend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, WZCCfgNew, dwFlags ), TRUE ) ) == NO_ERROR )
					{
						SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig::appended");
					}
				}
			}

			if (pWZCConfigListItem )
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig::OK");
			}

			dwRet = WZCSetPrefSSIDList( pWZCContext, pwcGUID, pWZCConfigListItem );

			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig::deleting list");

			while( pWZCConfigListItem->pNext )
				WZCConfigItemDelete( &( pWZCConfigListItem->pNext ) );

			WZCConfigItemDelete( &pWZCConfigListItem );
		}
	}
#endif // SW2_WZC_LIB_VISTA

#endif // SW2_WZC_LIB_XP_SP2

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCAddPreferedConfig::returning: %ld", dwRet );

	return dwRet;

}

DWORD
WZCRemovePreferedConfigVISTA( IN PSW2_WZC_LIB_CONTEXT pWZCContext, 
							IN WCHAR *pwcGUID, 
							IN WZC_WLAN_CONFIG WZCCfg )
{
	DWORD	dwRet;

	dwRet = NO_ERROR;

	/*
	SHELLEXECUTEINFO	se;
	

	swprintf_s( pwcParameters, 
				sizeof(pwcParameters)/sizeof(WCHAR), 
				TEXT( "profile %s" ),
				pConfigData->pwcProfileId );

	ZeroMemory( &se, sizeof(se) );

	se.cbSize = sizeof( se );
	se.hwnd = hWndParent;
	se.fMask = SEE_MASK_NOCLOSEPROCESS;
	se.lpDirectory = NULL;
	se.lpVerb = L"runas";
	se.lpFile = L"netsh.exe";
	se.lpParameters = pwcParameters;
	se.nShow = SW_SHOWNORMAL;

	if (ShellExecuteEx( &se ) )
	{
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"RasEapInvokeConfigUI:: creating process succesfull, waiting for process to end");
	
		SetWindowPos( se.hwnd, 
				HWND_TOP, 
				0,0,0,0, 
				SWP_SHOWWINDOW | SWP_NOSIZE |SWP_NOMOVE );

		WaitForSingleObject( se.hProcess, INFINITE );
		CloseHandle( se.hProcess );
	}
	else
	{
		dwRet = GetLastError();

		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"RasEapInvokeConfigUI:: creating process failed: %ld", dwRet );
	}

	if ((dwRet = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
								L"SOFTWARE\\Microsoft\\WZCSVC\\Parameters\\Interfaces",
								0,
								KEY_ALL_ACCESS,
								&hKey1 ) ) == ERROR_SUCCESS )
	{
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfigSP2::Opened Interfaces entry");

		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfigSP2::opening GUID: %s", pwcGUID );

		if ((dwRet = RegOpenKeyEx( hKey1,
									pwcGUID,
									0,
									KEY_QUERY_VALUE | KEY_SET_VALUE,
									&hKey2 ) ) == ERROR_SUCCESS )
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"Opened guid key: %s", pwcGUID );

			//
			// Loop through Eap Entry till we find an
			// entry with the same SSID or no more entries 
			// are found
			//
			j = 0;

			memset( pwcWZCEntryName, 0, sizeof( pwcWZCEntryName ) );
			memset( pbWZCEntryValue, 0, sizeof( pbWZCEntryValue ) );

			cbWZCEntryValue = sizeof( pbWZCEntryValue );
			cwcWZCEntryName = sizeof( pwcWZCEntryName );

			while( RegEnumValue( hKey2,
								 j,
								 pwcWZCEntryName,
								 &cwcWZCEntryName,
								 NULL,
								 &dwWZCEntryType,
								 pbWZCEntryValue,
								 &cbWZCEntryValue ) == ERROR_SUCCESS )
			{
				SW_TRACE( ( TEXT( "WZCRemovePreferedConfigSP2::opened eap entry: %s, value: %ld", 
							pwcWZCEntryName, cbWZCEntryValue ) );
				
				if (wcsstr( pwcWZCEntryName, L"Static#" ) )
				{
					//
					// Sanity check, should contain enough data
					//
					if (cbWZCEntryValue > 16 )
					{
						//
						// Retrieve SSID Length
						//
						memcpy( &dwSSIDLength, &( pbWZCEntryValue[16] ), sizeof( dwSSIDLength ) );

						SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfigSP2::retrieved dwSSIDLength: %ld", dwSSIDLength );

						memset( pcSSIDValue, 0, sizeof( pcSSIDValue ) );

						if (dwSSIDLength == WZCCfg.Ssid.SsidLength )
						{
							memcpy( pcSSIDValue, &( pbWZCEntryValue[16 + sizeof( dwSSIDLength )] ), dwSSIDLength );

							if (strcmp( pcSSIDValue, WZCCfg.Ssid.Ssid ) == 0 )
							{
								// found correct SSID
								SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfigSP2::SSID Value Match");

								RegDeleteValue( hKey2, pwcWZCEntryName );

								break;
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfigSP2::SSID Value Mismatch");
							}
						}
						else
							SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfigSP2::SSID Length MisMatch");
					}
				}

				j++;
				memset( pwcWZCEntryName, 0, sizeof( pwcWZCEntryName ) );
				memset( pbWZCEntryValue, 0, sizeof( pbWZCEntryValue ) );
				cbWZCEntryValue = sizeof( pbWZCEntryValue );
				cwcWZCEntryName = sizeof( pwcWZCEntryName );
			} // while

					
			RegCloseKey(hKey2);
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfigSP2::failed to open guid key: %ld", dwRet );

			dwRet = ERROR_OPEN_FAILED;
		}

		RegCloseKey(hKey1);
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfigSP2::failed to open interfaces key: %ld", dwRet );

		dwRet = ERROR_OPEN_FAILED;
	}
*/
	return dwRet;
}

DWORD
WZCRemovePreferedConfigSP2( IN PSW2_WZC_LIB_CONTEXT pWZCContext, 
							IN WCHAR *pwcGUID, 
							IN WZC_WLAN_CONFIG WZCCfg )
{
	HKEY	hKey1;
	HKEY	hKey2;
	WCHAR	pwcWZCEntryName[UNLEN];
	DWORD	cwcWZCEntryName;
	BYTE	pbWZCEntryValue[1024];
	DWORD	cbWZCEntryValue;
	DWORD	dwWZCEntryType;
	DWORD	dwSSIDLength;
	CHAR	pcSSIDValue[32];
	int		j;
	DWORD	dwRet;

	dwRet = NO_ERROR;

	if ((dwRet = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
								L"SOFTWARE\\Microsoft\\WZCSVC\\Parameters\\Interfaces",
								0,
								KEY_ALL_ACCESS,
								&hKey1 ) ) == ERROR_SUCCESS )
	{
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfigSP2::Opened Interfaces entry");

		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfigSP2::opening GUID: %s", pwcGUID );

		if ((dwRet = RegOpenKeyEx( hKey1,
									pwcGUID,
									0,
									KEY_QUERY_VALUE | KEY_SET_VALUE,
									&hKey2 ) ) == ERROR_SUCCESS )
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"Opened guid key: %s", pwcGUID );

			//
			// Loop through Eap Entry till we find an
			// entry with the same SSID or no more entries 
			// are found
			//
			j = 0;

			memset( pwcWZCEntryName, 0, sizeof( pwcWZCEntryName ) );
			memset( pbWZCEntryValue, 0, sizeof( pbWZCEntryValue ) );

			cbWZCEntryValue = sizeof( pbWZCEntryValue );
			cwcWZCEntryName = sizeof( pwcWZCEntryName );

			while( RegEnumValue( hKey2,
								 j,
								 pwcWZCEntryName,
								 &cwcWZCEntryName,
								 NULL,
								 &dwWZCEntryType,
								 pbWZCEntryValue,
								 &cbWZCEntryValue ) == ERROR_SUCCESS )
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfigSP2::opened eap entry: %s, value: %ld", 
							pwcWZCEntryName, cbWZCEntryValue );
				
				if (wcsstr( pwcWZCEntryName, L"Static#" ) )
				{
					//
					// Sanity check, should contain enough data
					//
					if (cbWZCEntryValue > 16 )
					{
						//
						// Retrieve SSID Length
						//
						memcpy( &dwSSIDLength, &( pbWZCEntryValue[16] ), sizeof( dwSSIDLength ) );

						SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfigSP2::retrieved dwSSIDLength: %ld", dwSSIDLength );

						memset( pcSSIDValue, 0, sizeof( pcSSIDValue ) );

						if (dwSSIDLength == WZCCfg.Ssid.SsidLength )
						{
							memcpy( pcSSIDValue, &( pbWZCEntryValue[16 + sizeof( dwSSIDLength )] ), dwSSIDLength );

							if (strcmp(pcSSIDValue, (PCHAR)WZCCfg.Ssid.Ssid) == 0)
							{
								// found correct SSID
								SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfigSP2::SSID Value Match");

								RegDeleteValue( hKey2, pwcWZCEntryName );

								break;
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfigSP2::SSID Value Mismatch");
							}
						}
						else
							SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfigSP2::SSID Length MisMatch");
					}
				}

				j++;
				memset( pwcWZCEntryName, 0, sizeof( pwcWZCEntryName ) );
				memset( pbWZCEntryValue, 0, sizeof( pbWZCEntryValue ) );
				cbWZCEntryValue = sizeof( pbWZCEntryValue );
				cwcWZCEntryName = sizeof( pwcWZCEntryName );
			} // while

					
			RegCloseKey(hKey2);
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfigSP2::failed to open guid key: %ld", dwRet );

			dwRet = ERROR_OPEN_FAILED;
		}

		RegCloseKey(hKey1);
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfigSP2::failed to open interfaces key: %ld", dwRet );

		dwRet = ERROR_OPEN_FAILED;
	}

	return dwRet;
}

DWORD
WZCRemovePreferedConfig( IN PSW2_WZC_LIB_CONTEXT pWZCContext, 
							IN WCHAR *pwcGUID, 
							IN WZC_WLAN_CONFIG WZCCfg )
{
	DWORD						dwRet;
#ifdef SW2_WZC_LIB_VISTA
	dwRet =  WZCRemovePreferedConfigVISTA( pWZCContext, 
											pwcGUID, 
											WZCCfg );
#else
#ifdef SW2_WZC_LIB_XP_SP2
	dwRet =  WZCRemovePreferedConfigSP2( pWZCContext, 
										pwcGUID, 
										WZCCfg );
#else
	PSW2_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;
	PSW2_WZC_CONFIG_LIST_ITEM	p;

	dwRet = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfig");

	if ((dwRet = WZCGetPrefSSIDList( pWZCContext, pwcGUID, &pWZCConfigListItem ) ) == NO_ERROR )
	{
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfig::got list");

		if ((dwRet = WZCConfigItemGet(pWZCConfigListItem, (PCHAR) WZCCfg.Ssid.Ssid, &p)) == NO_ERROR)
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfig::found item");

			if (p->pPrev )
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfig::not first in list so deleting");

				WZCConfigItemDelete( &p );
			}
			else
			{
				//
				// item is at first of list so reset list after deleting
				//
				if (p->pNext )
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfig::not last in list");

					pWZCConfigListItem = p->pNext;

					WZCConfigItemDelete( &p );
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfig::last in list");

					WZCConfigItemDelete( &pWZCConfigListItem );
				}
			}

			dwRet = WZCSetPrefSSIDList( pWZCContext, pwcGUID, pWZCConfigListItem );
		}

		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfig::deleting");

		if (pWZCConfigListItem )
		{
			while( pWZCConfigListItem->pNext )
				WZCConfigItemDelete( &( pWZCConfigListItem->pNext ) );

			WZCConfigItemDelete( &pWZCConfigListItem );
		}
	}	

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCRemovePreferedConfig::returning %ld", dwRet );

#endif // SW2_WZC_LIB_XP_SP2
#endif // SW2_WZC_LIB_VISTA
	return dwRet;
}

#ifdef SW2_WZC_LIB_2K_XP_SP0
DWORD
WZCEnumAdapters_2K( IN PSW2_WZC_LIB_CONTEXT pWZCContext, OUT PSW2_WZC_LIB_ADAPTERS pAdapters )
{
	HANDLE					hFile;
	WCHAR					*pNdisuioDevice = L"\\\\.\\\\Ndisuio";
	DWORD					dwBytesReturned = 0;
	int						i = 0;
	CHAR					pcBuf[1024];
	PNDISUIO_QUERY_BINDING	pQueryBinding;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCEnumAdapters_2K");

	if ((hFile = CreateFile( pNdisuioDevice,
								GENERIC_READ|GENERIC_WRITE,
								0,
								NULL,
								OPEN_EXISTING,
								FILE_ATTRIBUTE_NORMAL,
								(HANDLE) INVALID_HANDLE_VALUE)))
	{
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCEnumAdapters_2K::CreateFile successfull");

		//
		// Bind the file handle to the driver
		//
		if (DeviceIoControl(hFile,
							IOCTL_NDISUIO_BIND_WAIT,
							NULL,
							0,
							NULL,
							0,
							&dwBytesReturned,
							NULL ) )
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"IOCTL_NDISUIO_BIND_WAIT successfull");

			dwBytesReturned = 0;

			//
			// Enumerate adapters
			//
			pQueryBinding = ( PNDISUIO_QUERY_BINDING ) pcBuf;

			for( i=0; i < SW2_WZC_LIB_MAX_ADAPTER; i++ )
			{
				pQueryBinding->BindingIndex = i;

				if (DeviceIoControl( hFile,
									IOCTL_NDISUIO_QUERY_BINDING,
									pQueryBinding,
									sizeof( NDISUIO_QUERY_BINDING ),
									pcBuf,
									sizeof( pcBuf ),
									&dwBytesReturned,
									NULL ) )
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"IOCTL_NDISUIO_BIND_WAIT successfull");

					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"pQueryBinding->BindingIndex: %ld", pQueryBinding->BindingIndex );
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"pQueryBinding->DeviceNameLength: %ld", pQueryBinding->DeviceNameLength );
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"pQueryBinding->DeviceDescrLength: %ld", pQueryBinding->DeviceDescrLength );
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"pQueryBinding->DeviceNameOffset: %ld", pQueryBinding->DeviceNameOffset );
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"pQueryBinding->DeviceDescrOffset: %ld", pQueryBinding->DeviceDescrOffset );

					memset( pAdapters->pwcGUID[i], 0, UNLEN );

					memcpy( pAdapters->pwcGUID[i], (PUCHAR) pQueryBinding+pQueryBinding->DeviceNameOffset + 16, pQueryBinding->DeviceNameLength - 16 );

					memset( pcBuf, 0, sizeof( pcBuf ) );
				}
				else
				{
					dwRet = GetLastError();

					if (dwRet == ERROR_NO_MORE_ITEMS )
					{
						dwRet = NO_ERROR;
					}

					break;
				}
			}

			SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"quiting loop");

			pAdapters->dwNumGUID = i;
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}
	else
	{
		dwRet = ERROR_NO_DATA;
	}

	return dwRet;
}

DWORD
WZCEnumAdapters_XP_SP0( IN PSW2_WZC_LIB_CONTEXT pWZCContext, OUT PSW2_WZC_LIB_ADAPTERS pAdapters )
{
	DWORD				dwRet;
	INTFS_KEY_TABLE		Intfs;
	DWORD				i;

	dwRet = NO_ERROR;

	memset( &Intfs, 0, sizeof( Intfs ) );

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCEnumAdapters_XP_SP0");

	if ((dwRet = pWZCContext->pfnWZCEnumInterfaces( NULL,
													&Intfs ) ) == NO_ERROR )
	{
		if (Intfs.dwNumIntfs > 0 )
		{
			if (Intfs.dwNumIntfs > SW2_WZC_LIB_MAX_ADAPTER )
				pAdapters->dwNumGUID = SW2_WZC_LIB_MAX_ADAPTER;
			else
				pAdapters->dwNumGUID = Intfs.dwNumIntfs;

			for( i=0; i < pAdapters->dwNumGUID; i++ )
			{
				if ((wcslen( Intfs.pIntfs->wszGuid ) + 1 ) <= UNLEN )
					wcscpy_s( pAdapters->pwcGUID[i], 
							sizeof( pAdapters->pwcGUID[i])/sizeof(WCHAR),
							Intfs.pIntfs->wszGuid );

				Intfs.pIntfs->wszGuid++;
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}

	return dwRet;
}
#endif // SW2_WZC_LIB_2K_XP_SP0

DWORD
WZCEnumAdapters( IN PSW2_WZC_LIB_CONTEXT pWZCContext, OUT PSW2_WZC_LIB_ADAPTERS pAdapters )
{
	DWORD				dwRet = NO_ERROR;

#ifdef SW2_WZC_LIB_2K_XP_SP0

	dwRet = NO_ERROR;

	if (pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_0_6034 ||
		pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_0_6604 ||
		pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_VISTA )
	{
		//
		// Windows 2K
		//
		dwRet = WZCEnumAdapters_2K( pWZCContext, pAdapters );
	}
	else if (pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600 )
	{
		dwRet = WZCEnumAdapters_XP_SP0( pWZCContext, pAdapters );
	}

#else
	INTFS_KEY_TABLE		Intfs;
	DWORD				i;

	memset( &Intfs, 0, sizeof( Intfs ) );

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCEnumAdapters");

	if ((dwRet = pWZCContext->pfnWZCEnumInterfaces( NULL,
													&Intfs ) ) == NO_ERROR )
	{
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCEnumAdapters::Intfs.dwNumIntfs: %ld", Intfs.dwNumIntfs );

		if (Intfs.dwNumIntfs > 0 )
		{
			if (Intfs.dwNumIntfs > SW2_WZC_LIB_MAX_ADAPTER )
				pAdapters->dwNumGUID = SW2_WZC_LIB_MAX_ADAPTER;
			else
				pAdapters->dwNumGUID = Intfs.dwNumIntfs;

			for( i=0; i < pAdapters->dwNumGUID; i++ )
			{
				if ((wcslen( Intfs.pIntfs->wszGuid ) + 1 ) <= UNLEN )
					wcscpy_s( pAdapters->pwcGUID[i], 
								sizeof(pAdapters->pwcGUID[i])/sizeof(WCHAR),
								Intfs.pIntfs->wszGuid );

				Intfs.pIntfs->wszGuid++;
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}

#endif

	return dwRet;
}

DWORD
WZCLogon( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WCHAR *pwcSSID )
{
	PSW2_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;
	PSW2_WZC_CONFIG_LIST_ITEM	p;
	WZC_WLAN_CONFIG				WZCCfg;
	EAPOL_INTF_PARAMS			IntfParams;
	PCHAR						pcSSID = NULL;
	DWORD						ccSSID;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	memset( &IntfParams, 0, sizeof( EAPOL_INTF_PARAMS ) );

	if (pwcSSID )
	{
		ccSSID = ( DWORD ) wcslen( pwcSSID );

		if ((pcSSID = ( PCHAR ) malloc( ccSSID + 1)))
		{
			if (WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID + 1, NULL, NULL ) > 0 )
			{
				memcpy( &IntfParams.bSSID, pcSSID, ccSSID );
				IntfParams.dwSizeOfSSID = ccSSID;
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}

			if (dwRet != NO_ERROR )
				free( pcSSID );
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}
	}

	if (dwRet == NO_ERROR )
	{
		//
		// Set the top the SSID to the top of the list
		//
		if ((dwRet = WZCGetPrefSSIDList( pWZCContext, pwcGUID, &pWZCConfigListItem ) ) == NO_ERROR )
		{
			if ((dwRet = WZCConfigItemGet( pWZCConfigListItem, pcSSID, &p ) ) == NO_ERROR )
			{
				//
				// Found config in list
				//
				memcpy( &WZCCfg, &p->WZCConfig, sizeof( WZC_WLAN_CONFIG ) );

				if ((dwRet = WZCConfigItemPrePend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, WZCCfg, SW2_WZC_LIB_CONFIG_PREF ), TRUE ) ) == NO_ERROR )
				{
					pWZCConfigListItem = pWZCConfigListItem->pPrev;

					WZCConfigItemDelete( &p );

					dwRet = WZCSetPrefSSIDList( pWZCContext, pwcGUID, pWZCConfigListItem );
				}
			}

			//
			// Cleanup
			//

			while( pWZCConfigListItem->pNext )
				WZCConfigItemDelete( &( pWZCConfigListItem->pNext ) );

			WZCConfigItemDelete( &pWZCConfigListItem );
		}

		//
		// Turn on 802.1X to make sure
		//
		if ((dwRet = pWZCContext->pfnWZCEapolGetInterfaceParams( NULL,
																	pwcGUID,
																	&IntfParams ) ) == NO_ERROR )
		{

			IntfParams.dwEapFlags = IntfParams.dwEapFlags | EAPOL_ENABLED;

			if ((dwRet = pWZCContext->pfnWZCEapolSetInterfaceParams( NULL,
																	pwcGUID,
																	&IntfParams ) ) == NO_ERROR )
			{
				//
				// Turn on ZerConf to make sure
				//
				if ((dwRet = WZCSetZeroConfState( pWZCContext, pwcGUID, TRUE ) ) == NO_ERROR )
				{
					dwRet = WZCSetCurrentSSID( pWZCContext, pwcGUID, pwcSSID );
				}
			}
		}

		dwRet = WZCSetCurrentSSID( pWZCContext, pwcGUID, pwcSSID );

		if (pcSSID )
			free( pcSSID );
	}

	return dwRet;
}

DWORD
WZCLogoff( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WCHAR *pwcSSID )
{
	EAPOL_INTF_PARAMS	IntfParams;
	PCHAR				pcSSID;
	DWORD				ccSSID;
	DWORD				dwRet;

	dwRet = NO_ERROR;

	memset( &IntfParams, 0, sizeof( EAPOL_INTF_PARAMS ) );

	ccSSID = ( DWORD ) wcslen( pwcSSID );

	if ((pcSSID = ( PCHAR ) malloc( ccSSID + 1)))
	{
		if (WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID + 1, NULL, NULL ) > 0 )
		{
			memcpy( IntfParams.bSSID, pcSSID, ccSSID );
			IntfParams.dwSizeOfSSID = ccSSID;

			if ((dwRet = pWZCContext->pfnWZCEapolGetInterfaceParams( NULL,
																		pwcGUID,
																		&IntfParams ) ) == NO_ERROR )
			{
				//
				// Turn it off
				//
				IntfParams.dwEapFlags = IntfParams.dwEapFlags & 0x7fffffff;

				if ((dwRet = pWZCContext->pfnWZCEapolSetInterfaceParams( NULL,
																		pwcGUID,
																		&IntfParams ) ) == NO_ERROR )
				{
/*
					dwRet = NO_ERROR;

					while( dwRet == NO_ERROR )
					{
						if ((dwRet = WZCGetMediaState( pWZCContext, pwcGUID ) ) == NO_ERROR )
						{
							printf( "waiting...")));
						}

						Sleep( 1000 );
					}

					if (dwRet == ERROR_MEDIA_OFFLINE )
					{

						dwRet = WZCSetMediaState( pWZCContext, pwcGUID, TRUE );
*/
						dwRet = WZCSetCurrentSSID( pWZCContext, pwcGUID, L"                               " );

						if ((dwRet = WZCSetZeroConfState( pWZCContext, pwcGUID, FALSE ) ) == NO_ERROR )
						{
							//
							// Turn 802.1X back on
							//
							IntfParams.dwEapFlags = IntfParams.dwEapFlags | EAPOL_ENABLED;

							dwRet = pWZCContext->pfnWZCEapolSetInterfaceParams( NULL,
																				pwcGUID,
																				&IntfParams );
						}
					//}
				}
			}
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pcSSID );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

#ifdef SW2_WZC_LIB_XP_SP1
DWORD
WZCGetCurrentEapState( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, EAPOL_INTF_STATE *pIntfState )
{
	DWORD	dwRet;

	dwRet = NO_ERROR;

	memset( pIntfState, 0, sizeof( EAPOL_INTF_STATE ) );

	dwRet = pWZCContext->pfnWZCEapolQueryState( NULL,
												pwcGUID,
												pIntfState );
	return dwRet;
}
#endif // SW2_WZC_LIB_XP_SP1

DWORD
WZCEnd( IN PSW2_WZC_LIB_CONTEXT pWZCContext )
{
	DWORD	dwRet;

	dwRet = NO_ERROR;
#ifndef SW2_WZC_LIB_VISTA
	FreeLibrary( pWZCContext->hWZCDll );
#endif // SW2_WZC_LIB_VISTA
	free( pWZCContext );

	return dwRet;
}
