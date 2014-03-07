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

PSW2_WZC_CONFIG_LIST_ITEM 
WZCConfigItemCreate( IN PSW2_WZC_LIB_CONTEXT pWZCContext, IN WZC_WLAN_CONFIG WZCCfg, IN DWORD dwFlags )
{
	PSW2_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemCreate::(%ld)", sizeof( WZC_WLAN_CONFIG ) );
	SW2Dump( SW2_TRACE_LEVEL_DEBUG,  ( PBYTE ) &WZCCfg, sizeof( WZC_WLAN_CONFIG ) );

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemCreate::WZCCfg.Length: %ld", WZCCfg.Length );
	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemCreate::WZCCfg.dwCtlFlags: %ld", WZCCfg.dwCtlFlags );
	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemCreate::WZCCfg.MacAddress(%ld)", sizeof( NDIS_802_11_MAC_ADDRESS ) );
	SW2Dump( SW2_TRACE_LEVEL_DEBUG,  ( PBYTE ) &( WZCCfg.MacAddress ), sizeof( NDIS_802_11_MAC_ADDRESS ) );
	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemCreate::WZCCfg.Ssid(%ld)", sizeof( NDIS_802_11_SSID ) );
	SW2Dump( SW2_TRACE_LEVEL_DEBUG,  ( PBYTE ) &( WZCCfg.Ssid ), sizeof( NDIS_802_11_SSID ) );
	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemCreate::WZCCfg.Privacy: %ld", WZCCfg.Privacy );
	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemCreate::WZCCfg.Rssi(%ld)", sizeof( NDIS_802_11_RSSI ) );
	SW2Dump( SW2_TRACE_LEVEL_DEBUG,  ( PBYTE ) &( WZCCfg.Rssi ), sizeof( NDIS_802_11_RSSI ) );
	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemCreate::WZCCfg.NetworkTypeInUse: %ld", WZCCfg.NetworkTypeInUse );
	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemCreate::WZCCfg.InfrastructureMode: %ld", WZCCfg.InfrastructureMode );
	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemCreate::WZCCfg.SupportedRates(%ld)",sizeof( NDIS_802_11_RATES ) );
	SW2Dump( SW2_TRACE_LEVEL_DEBUG,  ( PBYTE ) &( WZCCfg.SupportedRates ), sizeof( NDIS_802_11_RATES ) );

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemCreate::WZCCfg.KeyIndex: %ld", WZCCfg.KeyIndex );
	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemCreate::WZCCfg.KeyLength: %ld", WZCCfg.KeyLength );
	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemCreate::WZCCfg.KeyMaterial(%ld)", WZCCTL_MAX_WEPK_MATERIAL );
	SW2Dump( SW2_TRACE_LEVEL_DEBUG,  ( PBYTE ) WZCCfg.KeyMaterial, WZCCTL_MAX_WEPK_MATERIAL );
	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemCreate::WZCCfg.AuthenticationMode: %ld", WZCCfg.AuthenticationMode );

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemCreate::WZCCfg.rdUserData(%ld)", WZCCfg.rdUserData.dwDataLen );
	SW2Dump( SW2_TRACE_LEVEL_DEBUG,  ( PBYTE ) WZCCfg.rdUserData.pData, WZCCfg.rdUserData.dwDataLen );
	
 	if ((pWZCConfigListItem = ( PSW2_WZC_CONFIG_LIST_ITEM ) malloc( sizeof( SW2_WZC_CONFIG_LIST_ITEM))) )
	{
		pWZCConfigListItem->pPrev = NULL;
		pWZCConfigListItem->pNext = NULL;
		pWZCConfigListItem->WZCConfig = WZCCfg;
		pWZCConfigListItem->dwFlags = dwFlags;

		if (pWZCContext->dwWZCSDllVersion >= WZCS_DLL_VERSION_5_1_2600_1106 )
		{
			if (WZCCfg.Privacy == 1 )
				pWZCConfigListItem->dwFlags |= SW2_WZC_LIB_CONFIG_WEP;
		}
		else
		{
			if (WZCCfg.Privacy == 0 )
				pWZCConfigListItem->dwFlags |= SW2_WZC_LIB_CONFIG_WEP;
		}
	}
	else
	{
		pWZCConfigListItem = NULL;
	}

	return pWZCConfigListItem;
}

VOID
WZCConfigItemRemove( IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigListItem )
{
	if (pWZCConfigListItem->pNext )
		pWZCConfigListItem->pNext->pPrev = pWZCConfigListItem->pPrev;

	if (pWZCConfigListItem->pPrev )
		pWZCConfigListItem->pPrev->pNext = pWZCConfigListItem->pNext;
}

VOID
WZCConfigItemDelete( IN PSW2_WZC_CONFIG_LIST_ITEM *ppWZCConfigListItem )
{
	PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigListItem = *ppWZCConfigListItem;

	if (pWZCConfigListItem->pNext )
		pWZCConfigListItem->pNext->pPrev = pWZCConfigListItem->pPrev;

	if (pWZCConfigListItem->pPrev )
		pWZCConfigListItem->pPrev->pNext = pWZCConfigListItem->pNext;

	free( *ppWZCConfigListItem );

	*ppWZCConfigListItem = NULL;
}

VOID
WZCConfigItemDeleteList(  IN PSW2_WZC_CONFIG_LIST_ITEM *ppWZCConfigListItem )
{
	PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigListItem;
	
	if (*ppWZCConfigListItem != NULL)
	{
		pWZCConfigListItem = *ppWZCConfigListItem;

		while( pWZCConfigListItem->pNext )
			WZCConfigItemDelete( &( pWZCConfigListItem->pNext ) );

		while( pWZCConfigListItem->pPrev )
			WZCConfigItemDelete( &( pWZCConfigListItem->pPrev ) );

		free( *ppWZCConfigListItem );

		*ppWZCConfigListItem = NULL;
	}
}

DWORD
WZCConfigItemPrePend( IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigListItem1, 
						IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigListItem2,
						IN BOOLEAN bFirst )
{
	PSW2_WZC_CONFIG_LIST_ITEM	pWZCConfigListItemFirst;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	if (pWZCConfigListItem1 && pWZCConfigListItem2 )
	{
		if (bFirst )
		{
			pWZCConfigListItemFirst = pWZCConfigListItem1;

			while( pWZCConfigListItemFirst->pPrev )
			{
				pWZCConfigListItemFirst = pWZCConfigListItemFirst->pPrev;
			}

			pWZCConfigListItemFirst->pPrev= pWZCConfigListItem2;
			pWZCConfigListItem2->pNext = pWZCConfigListItemFirst;
		}
		else
		{
			if (pWZCConfigListItem1->pPrev )
			{
				//
				// Item has a next item so insert the bugger
				//
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemPrePend::inserting");

				WZCConfigItemInsert( pWZCConfigListItem1->pPrev, pWZCConfigListItem1, pWZCConfigListItem2 );
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemPrePend::prepending");

				pWZCConfigListItem1->pPrev = pWZCConfigListItem2;
				pWZCConfigListItem2->pNext = pWZCConfigListItem1;
			}
		}
	}
	else
	{
		dwRet = ERROR_NO_DATA;
	}

	return dwRet;
}

DWORD
WZCConfigItemAppend( IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigListItem1, 
						IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigListItem2,
						IN BOOLEAN bLast )
{
	PSW2_WZC_CONFIG_LIST_ITEM	pWZCConfigListItemLast;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemAppend");

	if (pWZCConfigListItem1 && pWZCConfigListItem2 )
	{
		if (bLast )
		{
			pWZCConfigListItemLast = pWZCConfigListItem1;

			while( pWZCConfigListItemLast->pNext )
			{
				pWZCConfigListItemLast = pWZCConfigListItemLast->pNext;
			}

			pWZCConfigListItemLast->pNext = pWZCConfigListItem2;
			pWZCConfigListItem2->pPrev = pWZCConfigListItemLast;
		}
		else
		{
			if (pWZCConfigListItem1->pNext )
			{
				//
				// Item has a next item so insert the bugger
				//
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemAppend::inserting");

				WZCConfigItemInsert( pWZCConfigListItem1, pWZCConfigListItem1->pNext, pWZCConfigListItem2 );
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemAppend::appending");

				pWZCConfigListItem1->pNext = pWZCConfigListItem2;
				pWZCConfigListItem2->pPrev = pWZCConfigListItem1;
			}
		}
	}
	else
	{
		dwRet = ERROR_NO_DATA;
	}

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemAppend::returning");

	return dwRet;
}


DWORD
WZCConfigItemInsert( IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigListItemPrev, IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigListItemNext, IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigListItem )
{
	DWORD	dwRet;

	dwRet = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemInsert");

	if (pWZCConfigListItemPrev && pWZCConfigListItemNext && pWZCConfigListItem )
	{
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemInsert:: inserting");

		pWZCConfigListItemPrev->pNext = pWZCConfigListItem;
		pWZCConfigListItemNext->pPrev = pWZCConfigListItem;

		pWZCConfigListItem->pPrev = pWZCConfigListItemPrev;
		pWZCConfigListItem->pNext = pWZCConfigListItemNext;
	}
	else
	{
		dwRet = ERROR_NO_DATA;
	}

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, L"WZCConfigItemInsert:: returning");

	return dwRet;
}

DWORD
WZCConfigItemGet( IN PSW2_WZC_CONFIG_LIST_ITEM pWZCConfigListItemStart, IN PCHAR pcSSID, OUT PSW2_WZC_CONFIG_LIST_ITEM *ppWZCConfigListItem )
{
	PSW2_WZC_CONFIG_LIST_ITEM	p;
	DWORD						dwRet;
	DWORD						ccSSID;

	dwRet = NO_ERROR;

	if (pcSSID )
	{
		ccSSID = (DWORD) strlen( pcSSID );

		if ((ccSSID > 0 ) && 
			( ccSSID <= NDIS_802_11_LENGTH_SSID ) )
		{
			p = pWZCConfigListItemStart;

			while( p )
			{
				if (memcmp( p->WZCConfig.Ssid.Ssid, pcSSID, ccSSID ) == 0 )
				{
					p->WZCConfig.Ssid.SsidLength = ccSSID;

					*ppWZCConfigListItem = p;

					break;
				}
				else
				{
					p = p->pNext;
				}
			}

			if (!p )
				dwRet = ERROR_NO_DATA;
		}
		else
			dwRet = ERROR_NO_DATA;
	}
	else
		dwRet = ERROR_NO_DATA;

	return dwRet;
}