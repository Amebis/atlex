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
// Name: AuthHandleInnerPAPAuthentication
// Description: This function is called when the TLS tunnel has been setup and the inner authentication must be done
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
AuthHandleInnerPAPAuthentication(	IN PSW2_SESSION_DATA	pSessionData,
									OUT PSW2EAPPACKET		pSendPacket,
									IN  DWORD               cbSendPacket,
									IN	PSW2EAPOUTPUT		pEapOutput )
{
	PBYTE				pbMessage;
	DWORD				cbMessage;
	PBYTE				pbRecord;
	DWORD				cbRecord;
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerPAPAuthentication" ) );

	//
	// If the authentication has failed simply return no error when using PAP
	// no need to de-initialize anything as with EAP
	//
	if( ( dwReturnCode = AuthMakeClientPAPMessage( pSessionData, &pbMessage, &cbMessage ) ) == NO_ERROR )
	{
		if( ( dwReturnCode = TLSMakeApplicationRecord( &(pSessionData->TLSSession),
												pbMessage, 
												cbMessage, 
												&pbRecord, 
												&cbRecord, 
												TRUE ) ) == NO_ERROR )
		{
			dwReturnCode = TLSAddMessage( pbRecord, 
									cbRecord, 
									cbRecord,
									pSendPacket, 
									cbSendPacket );

			pEapOutput->eapAction = SW2EAPACTION_Send;

			SW2FreeMemory((PVOID*)&pbRecord);
			cbRecord = 0;
		}

		SW2FreeMemory((PVOID*)&pbMessage);
		cbMessage = 0;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerPAPAuthentication::returning: %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: AuthMakeClientPAPMessage
// Description: This function is called when we want to use PAP as the Inner Authentication
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
AuthMakeClientPAPMessage( IN PSW2_SESSION_DATA pSessionData, PBYTE *ppbMessage, DWORD *pcbMessage )
{
	PBYTE	pbUsernameAVP;
	DWORD	cbUsernameAVP;
	PCHAR	pcUsername;
	DWORD	ccUsername;
	PCHAR	pcRealm;
	DWORD	ccRealm;
	PBYTE	pbPasswordAVP;
	DWORD	cbPasswordAVP;
	PCHAR	pcPassword;
	DWORD	ccPassword;
	PBYTE	pbMessage;
	DWORD	cbMessage;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	//
	// Build the AVPS for PAP
	//
	ccRealm = ( DWORD ) wcslen( pSessionData->UserData.pwcDomain );

	if( ccRealm > 0 )
	{
		ccUsername = ( DWORD ) wcslen( pSessionData->UserData.pwcUsername ) + 1 + ccRealm;

		if ((dwReturnCode = SW2AllocateMemory(ccRealm + 1, (PVOID*) &pcRealm)) == NO_ERROR)
		{
			WideCharToMultiByte( CP_ACP, 0, pSessionData->UserData.pwcDomain, -1, pcRealm, ccRealm + 1, NULL, NULL );

			if ((dwReturnCode = SW2AllocateMemory(ccUsername + 1, (PVOID*) &pcUsername)) == NO_ERROR)
			{
				WideCharToMultiByte( CP_ACP, 0, pSessionData->UserData.pwcUsername, -1, pcUsername, ccUsername + 1, NULL, NULL );

				strcat( pcUsername, "@" );

				strcat( pcUsername, pcRealm );
			}

			SW2FreeMemory((PVOID*)&pcRealm);
			ccRealm = 0;
		}
	}
	else
	{
		ccUsername = ( DWORD ) wcslen( pSessionData->UserData.pwcUsername );

		if ((dwReturnCode = SW2AllocateMemory(ccUsername + 1, (PVOID*) &pcUsername)) == NO_ERROR)
		{
			WideCharToMultiByte( CP_ACP, 0, pSessionData->UserData.pwcUsername, -1, pcUsername, ccUsername + 1, NULL, NULL );
		}
	}

	if( dwReturnCode == NO_ERROR )
	{
		ccPassword = ( DWORD ) wcslen( pSessionData->UserData.pwcPassword );

		if ((dwReturnCode = SW2AllocateMemory(ccPassword + 1, (PVOID*) &pcPassword)) == NO_ERROR)
		{
			WideCharToMultiByte( CP_ACP, 0, pSessionData->UserData.pwcPassword, -1, pcPassword, ccPassword + 1, NULL, NULL );
		}
	}
	else
	{
		SW2FreeMemory((PVOID*)&pcUsername);
		ccUsername = 0;
	}

	if( dwReturnCode == NO_ERROR )
	{
		if( ( dwReturnCode = AuthMakeDiameterAttribute( 0x01, (PBYTE) pcUsername, ccUsername, &pbUsernameAVP, &cbUsernameAVP ) ) == NO_ERROR )
		{
			if( ( dwReturnCode = AuthMakeDiameterAttribute( 0x02, (PBYTE) pcPassword, ccPassword, &pbPasswordAVP, &cbPasswordAVP ) ) == NO_ERROR )
			{
				*pcbMessage = cbUsernameAVP + cbPasswordAVP;

				if ((dwReturnCode = SW2AllocateMemory(*pcbMessage, (PVOID*) ppbMessage)) == NO_ERROR)
				{
					pbMessage = *ppbMessage;
					cbMessage = *pcbMessage;

					memcpy( pbMessage, pbUsernameAVP, cbUsernameAVP );
					memcpy( &( pbMessage[cbUsernameAVP] ), pbPasswordAVP, cbPasswordAVP );
				}

				SW2FreeMemory((PVOID*)&pbPasswordAVP);
				cbPasswordAVP = 0;
			}

			SW2FreeMemory((PVOID*)&pbUsernameAVP);
			pbUsernameAVP = 0;
		}

		SW2FreeMemory((PVOID*)&pcPassword);
		ccPassword = 0;

		SW2FreeMemory((PVOID*)&pcUsername);
		ccUsername = 0;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthMakeClientPAPMessage::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}
