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
#ifndef SW2_WZC_LIB_H
#define SW2_WZC_LIB_H

// ------------------------------------
// Includes
// ------------------------------------

#ifdef SW2_WZC_LIB_XP_SP2
#include "wzcsapi_xp_sp2.h"
#endif

#ifdef SW2_WZC_LIB_XP_SP1
#include "wzcsapi_xp_sp1.h"
#endif

#include <raserror.h>
#include <lmcons.h>

// ------------------------------------
// Defines
// ------------------------------------

#ifdef SW2_WZC_LIB_2K_XP_SP0
#define INTF_PREFLIST INTF_STSSIDLIST
#endif

#define SW2_WZC_LIB_MAX_ADAPTER	5
#define SW2_WZC_LIB_MAX_SSID		20

#define SW2_WZC_LIB_CONFIG_BSSID 0x01
#define SW2_WZC_LIB_CONFIG_WEP	0x02
#define SW2_WZC_LIB_CONFIG_PREF	0x04
#define SW2_WZC_LIB_CONFIG_SW2	0x08

#define SW2_WZC_LIB_CONFIG_BSSID 0x01
#define SW2_WZC_LIB_CONFIG_WEP	0x02
#define SW2_WZC_LIB_CONFIG_PREF	0x04
#define SW2_WZC_LIB_CONFIG_SW2	0x08

#define SW2_WZC_LIB_CONFIG_8021X_GUEST		0x20
#define SW2_WZC_LIB_CONFIG_8021X_COMPUTER	0x40
#define SW2_WZC_LIB_CONFIG_8021X_ENABLED		0x80

// ------------------------------------
// WZCSAPI DLL Functions
// ------------------------------------

typedef DWORD ( APIENTRY *PFN_WZCEnumInterfaces )( IN LPWSTR pSrvAddr, IN OUT PINTFS_KEY_TABLE pIntfs );

#ifdef SW2_WZC_LIB_XP_SP2
typedef DWORD ( APIENTRY *PFN_WZCQueryInterface )( IN LPWSTR pSrvAddr, IN DWORD dwInFlags, IN OUT PINTF_ENTRY pIntf, OUT LPDWORD pdwOutFlags);
typedef DWORD ( APIENTRY *PFN_WZCSetInterface )( IN LPWSTR pSrvAddr, IN DWORD dwInFlags, IN OUT PINTF_ENTRY pIntf, OUT LPDWORD pdwOutFlags);
typedef DWORD ( APIENTRY *PFN_WZCRefreshInterface )( IN LPWSTR pSrvAddr, IN DWORD dwInFlags, IN OUT PINTF_ENTRY pIntf, OUT LPDWORD pdwOutFlags);
typedef DWORD ( APIENTRY *PFN_WZCDeleteIntfObj )( IN PINTF_ENTRY pIntf );
#endif

#ifdef SW2_WZC_LIB_XP_SP1
typedef DWORD ( APIENTRY *PFN_WZCQueryInterface_1106 )( IN LPWSTR pSrvAddr, IN DWORD dwInFlags, IN OUT PINTF_ENTRY_1106 pIntf, OUT LPDWORD pdwOutFlags);
typedef DWORD ( APIENTRY *PFN_WZCSetInterface_1106 )( IN LPWSTR pSrvAddr, IN DWORD dwInFlags, IN OUT PINTF_ENTRY_1106 pIntf, OUT LPDWORD pdwOutFlags);
typedef DWORD ( APIENTRY *PFN_WZCRefreshInterface_1106 )( IN LPWSTR pSrvAddr, IN DWORD dwInFlags, IN OUT PINTF_ENTRY_1106 pIntf, OUT LPDWORD pdwOutFlags);
typedef DWORD ( APIENTRY *PFN_WZCDeleteIntfObj_1106 )( IN PINTF_ENTRY_1106 pIntf );

typedef DWORD ( APIENTRY *PFN_WZCQueryInterface_1181 )( IN LPWSTR pSrvAddr, IN DWORD dwInFlags, IN OUT PINTF_ENTRY_1181 pIntf, OUT LPDWORD pdwOutFlags);
typedef DWORD ( APIENTRY *PFN_WZCSetInterface_1181 )( IN LPWSTR pSrvAddr, IN DWORD dwInFlags, IN OUT PINTF_ENTRY_1181 pIntf, OUT LPDWORD pdwOutFlags);
typedef DWORD ( APIENTRY *PFN_WZCRefreshInterface_1181 )( IN LPWSTR pSrvAddr, IN DWORD dwInFlags, IN OUT PINTF_ENTRY_1181 pIntf, OUT LPDWORD pdwOutFlags);
typedef DWORD ( APIENTRY *PFN_WZCDeleteIntfObj_1181 )( IN PINTF_ENTRY_1181 pIntf );
#endif

#ifdef SW2_WZC_LIB_2K_XP_SP0
typedef DWORD ( APIENTRY *PFN_WZCQueryInterface )( IN LPWSTR pSrvAddr, IN DWORD dwInFlags, IN OUT PINTF_ENTRY pIntf, OUT LPDWORD pdwOutFlags);
typedef DWORD ( APIENTRY *PFN_WZCSetInterface )( IN LPWSTR pSrvAddr, IN DWORD dwInFlags, IN OUT PINTF_ENTRY pIntf, OUT LPDWORD pdwOutFlags);
typedef DWORD ( APIENTRY *PFN_WZCRefreshInterface )( IN LPWSTR pSrvAddr, IN DWORD dwInFlags, IN OUT PINTF_ENTRY pIntf, OUT LPDWORD pdwOutFlags);
typedef DWORD ( APIENTRY *PFN_WZCDeleteIntfObj )( IN PINTF_ENTRY pIntf );
#endif

typedef DWORD ( APIENTRY *PFN_WZCGetEapUserInfo )( IN WCHAR *pwszGUID, IN DWORD dwEapTypeId, IN DWORD dwSizOfSSID, IN BYTE *pbSSID, IN OUT PBYTE pbUserInfo, IN OUT DWORD *pdwInfoSize );
typedef DWORD ( APIENTRY *PFN_WZCEapolReAuthenticate )( IN LPWSTR pSrvAddr, IN PWCHAR pwszGuid );
typedef DWORD ( APIENTRY *PFN_WZCEapolGetInterfaceParams )( IN LPWSTR pSrvAddr, IN PWCHAR pwszGuid, IN OUT EAPOL_INTF_PARAMS *pIntfParams );
typedef DWORD ( APIENTRY *PFN_WZCEapolSetInterfaceParams )( IN LPWSTR pSrvAddr, IN PWCHAR pwszGuid, IN OUT EAPOL_INTF_PARAMS *pIntfParams );
typedef DWORD ( APIENTRY *PFN_WZCEapolSetCustomAuthData )( IN LPWSTR pSrvAddr, IN PWCHAR pwszGuid, IN DWORD dwEapTypeId, IN DWORD dwSizeOfSSID, IN BYTE *pbSSID, IN PBYTE pbConnInfo, IN DWORD dwInfoSize );
typedef DWORD ( APIENTRY *PFN_WZCEapolGetCustomAuthData )( IN LPWSTR pSrvAddr, IN PWCHAR pwszGuid, IN DWORD dwEapTypeId, IN DWORD dwSizeOfSSID, IN BYTE *pbSSID, IN PBYTE pbConnInfo, IN DWORD *pdwInfoSize );

typedef DWORD ( APIENTRY *PFN_WZCGetEapUserInfo )( IN WCHAR *pwszGUID, IN DWORD dwEapTypeId, IN DWORD dwSizOfSSID, IN BYTE *pbSSID, IN OUT PBYTE pbUserInfo, IN OUT DWORD *pdwInfoSize );

#ifndef SW2_WZC_LIB_2K_XP_SP0
typedef DWORD ( APIENTRY *PFN_WZCQueryContext ) ( IN LPWSTR pSrvAddr, IN DWORD dwInFlags, OUT PWZC_CONTEXT pContext, OUT LPDWORD pdwOutFlags );

typedef DWORD ( APIENTRY *PFN_WZCEapolQueryState ) ( IN LPWSTR pSrvAddr, IN PWCHAR pwszGuid, OUT EAPOL_INTF_STATE * pIntfState);
#endif // SW2_WZC_LIB_2K_XP_SP0

// ------------------------------------
// Enums/structs
// ------------------------------------

typedef struct _SW2_WZC_LIB_CONTEXT
{
	HINSTANCE						hWZCDll;
	DWORD							dwWZCSDllVersion;

	PFN_WZCEnumInterfaces			pfnWZCEnumInterfaces;

#ifdef SW2_WZC_LIB_XP_SP1
	PFN_WZCQueryInterface_1106		pfnWZCQueryInterface_1106;
	PFN_WZCSetInterface_1106		pfnWZCSetInterface_1106;
	PFN_WZCRefreshInterface_1106	pfnWZCRefreshInterface_1106;

	PFN_WZCQueryInterface_1181		pfnWZCQueryInterface_1181;
	PFN_WZCSetInterface_1181		pfnWZCSetInterface_1181;
	PFN_WZCRefreshInterface_1181	pfnWZCRefreshInterface_1181;
#else
	PFN_WZCQueryInterface			pfnWZCQueryInterface;
	PFN_WZCSetInterface				pfnWZCSetInterface;
	PFN_WZCRefreshInterface			pfnWZCRefreshInterface;
#endif

	PFN_WZCEapolReAuthenticate		pfnWZCEapolReAuthenticate;
	PFN_WZCEapolGetInterfaceParams	pfnWZCEapolGetInterfaceParams;
	PFN_WZCEapolSetInterfaceParams	pfnWZCEapolSetInterfaceParams;
	PFN_WZCEapolSetCustomAuthData	pfnWZCEapolSetCustomAuthData;
	PFN_WZCEapolGetCustomAuthData	pfnWZCEapolGetCustomAuthData;

	PFN_WZCGetEapUserInfo			pfnWZCGetEapUserInfo;

#ifndef SW2_WZC_LIB_2K_XP_SP0
	PFN_WZCQueryContext				pfnWZCQueryContext;

	PFN_WZCEapolQueryState			pfnWZCEapolQueryState;
#endif

} SW2_WZC_LIB_CONTEXT, *PSW2_WZC_LIB_CONTEXT;

typedef enum _SW2_WZCS_DLL_VERSION
{
	WZCS_DLL_VERSION_5_0_6034,
	WZCS_DLL_VERSION_5_0_6604,
	WZCS_DLL_VERSION_5_1_2600,
	WZCS_DLL_VERSION_5_1_2600_1106,
	WZCS_DLL_VERSION_5_1_2600_1181,
	WZCS_DLL_VERSION_5_1_2600_1276,
	WZCS_DLL_VERSION_5_1_2600_2149,
	WZCS_DLL_VERSION_5_1_VISTA

} SW2_WZCS_DLL_VERSION;

typedef struct _SW2_WZC_LIB_ADAPTERS
{
	DWORD	dwNumGUID;
	WCHAR	pwcGUID[SW2_WZC_LIB_MAX_ADAPTER][UNLEN];

} SW2_WZC_LIB_ADAPTERS, *PSW2_WZC_LIB_ADAPTERS;

typedef struct _SW2_WZC_CONFIG_LIST_ITEM
{
    struct _SW2_WZC_CONFIG_LIST_ITEM *pPrev, *pNext;
	DWORD							dwFlags;
    WZC_WLAN_CONFIG					WZCConfig;

} SW2_WZC_CONFIG_LIST_ITEM, *PSW2_WZC_CONFIG_LIST_ITEM;
/*
#ifndef SW2_WZC_LIB_VISTA
typedef enum _SW2_NDIS_802_11_AUTHENTICATION_MODE
{
	Ndis802_11AuthModeWPA2 = 6,
	Ndis802_11AuthModeWPA2PSK

} SW2_NDIS_802_11_AUTHENTICATION_MODE, *PSW2_NDIS_802_11_AUTHENTICATION_MODE;
#endif // SW2_WZC_LIB_VISTA
*/

typedef enum _SW2_NDIS_802_11_NETWORK_INFRASTRUCTURE
{
    Ndis802_11InfrastructureNonBroadcast = 4,
    
} SW2_NDIS_802_11_NETWORK_INFRASTRUCTURE, *PSW2_NDIS_802_11_NETWORK_INFRASTRUCTURE;

typedef enum _SW2_NDIS_802_11_NETWORK_CONNECTIONMODE
{
    Ndis802_11AutoConnect,
    Ndis802_11ManualConnect

} SW2_NDIS_802_11_NETWORK_CONNECTIONMODE, *PSW2_NDIS_802_11_NETWORK_CONNECTIONMODE;

// ------------------------------------
// Functions
// ------------------------------------

DWORD	WZCInit( IN PSW2_WZC_LIB_CONTEXT *ppWZCContext );
DWORD	WZCEnd( IN PSW2_WZC_LIB_CONTEXT pWZCContext );

DWORD	WZCEnumAdapters( IN PSW2_WZC_LIB_CONTEXT pWZCContext, OUT PSW2_WZC_LIB_ADAPTERS pAdapters );

DWORD	WZCInitConfig( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WZC_WLAN_CONFIG *pWZCCfgNew, IN WCHAR *pwcSSID, IN DWORD dwInfrastructureMode );

DWORD	WZCAddPreferedConfig( IN PSW2_WZC_LIB_CONTEXT pWZCContext, 
							 IN WCHAR *pwcGUID, 
							 IN WZC_WLAN_CONFIG WZCCfgNew, 
							 IN DWORD dwFlags, 
							 IN BOOL bOverWrite, 
							 IN BOOL bFirst );

DWORD	WZCAddPreferedConfig2( IN PSW2_WZC_LIB_CONTEXT pWZCContext, 
							 IN WCHAR *pwcGUID, 
							 IN WZC_WLAN_CONFIG WZCCfgNew, 
							 IN DWORD dwFlags, 
							 IN BOOL bOverWrite, 
							 IN BOOL bFirst, 
							 IN PBYTE pbConfigData, 
							 IN DWORD cbConfigData );

DWORD	WZCRemovePreferedConfig( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WZC_WLAN_CONFIG WZCCfgNew );

DWORD	WZCAddBConfig( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WZC_WLAN_CONFIG WZCCfgNew );
DWORD	WZCRemoveBConfig( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WZC_WLAN_CONFIG WZCCfgNew );

DWORD	WZCGetCurrentConfig( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT WZC_WLAN_CONFIG *pWZCCfg );

DWORD	WZCGetConfigEapData( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WCHAR *pwcSSID, IN DWORD dwEapType, OUT PBYTE *ppbConfigData, OUT DWORD *pcbConfigData );
DWORD	WZCSetConfigEapData( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WCHAR * pwcSSID, IN DWORD dwEapType, IN DWORD dwFlags, IN PBYTE pbConfigData, IN DWORD cbConfigData );

DWORD	WZCGetCurrentSSID( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT WCHAR ** ppwcSSID );
DWORD	WZCSetCurrentSSID( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WCHAR * pwcSSID );

DWORD	WZCGetSignalStrength( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT LONG *pdwSignalStrength );

DWORD	WZCGetEapUserData( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN DWORD dwEapTypeId, IN OUT PBYTE pbUserInfo, IN OUT DWORD cbUserInfo );

DWORD	WZCLogon( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WCHAR *pwcSSID );
DWORD	WZCLogoff( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WCHAR *pwcSSID );

DWORD	WZCSetMediaState( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN BOOL bOn );
DWORD	WZCGetMediaState( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID );

DWORD	WZCGetPrefSSIDList( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT PSW2_WZC_CONFIG_LIST_ITEM *ppWZCConfigItem );
DWORD	WZCSetPrefSSIDList( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigItem );

DWORD	WZCGetBSSIDList( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT PSW2_WZC_CONFIG_LIST_ITEM *ppWZCConfigItem );
DWORD	WZCSetBSSIDList( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigItem );

DWORD	WZCGetCompleteSSIDList( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, PSW2_WZC_CONFIG_LIST_ITEM	*ppWZCConfigListItem );

DWORD	WZCRefreshList( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID );

PSW2_WZC_CONFIG_LIST_ITEM WZCConfigItemCreate(  IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WZC_WLAN_CONFIG WZCCfg, IN DWORD dwFlags );
VOID	WZCConfigItemDelete( IN PSW2_WZC_CONFIG_LIST_ITEM *ppWZCConfigItem );
VOID	WZCConfigItemRemove( IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigItem );
VOID	WZCConfigItemDeleteList( IN PSW2_WZC_CONFIG_LIST_ITEM *ppWZCConfigItem );
DWORD	WZCConfigItemPrePend( IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigItem1, IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigItem2, IN BOOLEAN bFirst );
DWORD	WZCConfigItemAppend( IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigItem1, IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigItem2, IN BOOLEAN bLast );
DWORD	WZCConfigItemInsert( IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigItemPrev, IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigItemNext, IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigItem );
DWORD	WZCConfigItemGet( IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigItemStart, IN PCHAR pcSSID, OUT PSW2_WZC_CONFIG_LIST_ITEM *ppWZCConfigItem );

#ifndef SW2_WZC_LIB_2K_XP_SP0
DWORD	WZCGetCurrentEapState( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, EAPOL_INTF_STATE *pIntfState );
#endif // SW2_WZC_LIB_2K_XP_SP0

DWORD	WZCSetZeroConfState( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN BOOL bOn );

#endif
