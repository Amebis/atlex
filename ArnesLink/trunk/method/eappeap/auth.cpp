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

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerAuthentication" ) );

	switch( pSessionData->TLSSession.TLSState )
	{
		case SW2_TLS_STATE_Change_Cipher_Spec:
		case SW2_TLS_STATE_Resume_Session_Ack:
		case SW2_TLS_STATE_Inner_Authentication:

			if( wcscmp( L"EAP", pSessionData->ProfileData.pwcInnerAuth ) == 0 )
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerAuthentication::EAP" ) );

				dwReturnCode = AuthHandleInnerEAPAuthentication(pSessionData, 
															pSendPacket,
															cbSendPacket,
															pEapOutput );
			}
			else if( wcscmp( L"EAPHOST", pSessionData->ProfileData.pwcInnerAuth ) == 0 )
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerAuthentication::EAPHOST" ) );

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

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerAuthentication::returning: %ld" ), dwReturnCode );

	return dwReturnCode;
}
