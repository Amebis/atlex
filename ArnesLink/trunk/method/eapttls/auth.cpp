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
// Name: AuthHandleInnerAuthentication
// Description: This function is called when the TLS tunnel has been setup and the inner authentication must be done
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
AuthHandleInnerAuthentication(IN PSW2_SESSION_DATA	pSessionData,
							  OUT PSW2EAPPACKET		pSendPacket,
							  IN  DWORD             cbSendPacket,
							  IN  PSW2EAPOUTPUT		pEapOutput)
{
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerAuthentication()" ) );

	switch( pSessionData->TLSSession.TLSState )
	{
		case SW2_TLS_STATE_Change_Cipher_Spec:
		case SW2_TLS_STATE_Inner_Authentication:

			if( wcscmp( L"PAP", pSessionData->ProfileData.pwcInnerAuth ) == 0 )
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerAuthentication::using PAP" ) );

				dwReturnCode = AuthHandleInnerPAPAuthentication(pSessionData, 
														pSendPacket,
														cbSendPacket,
														pEapOutput);
			}
			else if( wcscmp( L"EAP", pSessionData->ProfileData.pwcInnerAuth ) == 0 )
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerAuthentication::using EAP" ) );

				dwReturnCode = AuthHandleInnerEAPAuthentication(pSessionData, 
															pSendPacket,
															cbSendPacket,
															pEapOutput );
			}
			else if( wcscmp( L"EAPHOST", pSessionData->ProfileData.pwcInnerAuth ) == 0 )
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerAuthentication::using EAPHOST" ) );

				dwReturnCode = AuthHandleInnerEAPHOSTAuthentication(pSessionData, 
																pSendPacket,
																cbSendPacket,
																pEapOutput );
			}
			else
			{
				dwReturnCode = ERROR_NOT_SUPPORTED;
			}

			pSessionData->TLSSession.TLSState = SW2_TLS_STATE_Inner_Authentication;

		break;

		default:

			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_ERROR::AuthHandleInnerAuthentication::unknown authentication state" ) );

			dwReturnCode = ERROR_PPP_INVALID_PACKET;

		break;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerAuthentication::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: AuthMakeDiameterAttribute
// Description: This function builds a diameter attribute
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
AuthMakeDiameterAttribute( DWORD dwType,
						   PBYTE pbData,
						   DWORD cbData,
						   PBYTE *ppbDiameter,
						   DWORD *pcbDiameter )
{
	DWORD	dwPadding;
	PBYTE	pbDiameter;
	DWORD	cbDiameter;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthMakeDiameterAttribute()" ) );

	// length of AVP must be multiple of 4 octets
	//
	dwPadding = ( 0x08 + cbData ) % 4;
	
	if( dwPadding != 0 )
		dwPadding = 4 - dwPadding;

	*pcbDiameter = 0x08 + cbData + dwPadding;

	if ((dwReturnCode = SW2AllocateMemory(*pcbDiameter, (PVOID*) ppbDiameter)) == NO_ERROR)
	{
		pbDiameter = *ppbDiameter;
		cbDiameter = *pcbDiameter;

		memset( pbDiameter, 0, cbDiameter );

		SW2_HostToWireFormat32( dwType, &( pbDiameter[0] ) );

		//
		// Not vendor specific and important so
		// set the M bit
		// 01000000
		//
		pbDiameter[4] = 0x40;

		//
		// Length of AVP (3 bytes)
		// avp_header(7) + lenght of Password
		//
		SW2_HostToWireFormat24( ( WORD ) ( 0x08 + cbData ), &( pbDiameter[5] ) );

		memcpy( &( pbDiameter[8] ), pbData, cbData );
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::AuthMakeDiameterAttribute::not enough memory" ) );

		dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthMakeDiameterAttribute::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}
