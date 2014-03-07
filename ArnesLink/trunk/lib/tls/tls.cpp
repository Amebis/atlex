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

DWORD TLSInit(PSW2_TLS_SESSION pTLSSession)
{
	DWORD i;
	DWORD dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSInit" ) );

	pTLSSession->dwSeqNum = -1;

	pTLSSession->TLSState = SW2_TLS_STATE_Start;
	
	memset(pTLSSession->pbPMS, 0, TLS_PMS_SIZE);

	pTLSSession->dwEncKey = 0;
	pTLSSession->dwEncKeySize = 0;
	
	pTLSSession->dwMacKey = 0;
	pTLSSession->dwMacKeySize = 0;

	if( pTLSSession->hReadKey )
		CryptDestroyKey( pTLSSession->hReadKey );

	if( pTLSSession->hWriteKey )
		CryptDestroyKey( pTLSSession->hWriteKey );

	memset(pTLSSession->pbWriteMAC, 0, TLS_MAX_MAC);
	memset(pTLSSession->pbReadMAC, 0, TLS_MAX_MAC);

	for( i=0; i < TLS_MAX_CERT;i++)
	{
		memset(pTLSSession->pbCertificate[i], 0, TLS_MAX_CERT_SIZE);
		pTLSSession->cbCertificate[i] = 0;
	}

	pTLSSession->dwCertCount = 0;

	memset(pTLSSession->pbRandomClient, 0, TLS_RANDOM_SIZE);
	memset(pTLSSession->pbRandomServer, 0, TLS_RANDOM_SIZE);

	memset(pTLSSession->pbCipher, 0, sizeof(pTLSSession->pbCipher));;

	pTLSSession->bCompression = 0;

	for( i=0; ( DWORD ) i < pTLSSession->dwHandshakeMsgCount; i++ )
	{
		SW2FreeMemory((PVOID*)&pTLSSession->pbHandshakeMsg[i]);
		pTLSSession->cbHandshakeMsg[i] = 0;
	}

	pTLSSession->dwHandshakeMsgCount = 0;

	memset(pTLSSession->pbReceiveMsg, 0, TLS_MAX_MSG);
	pTLSSession->cbReceiveMsg = 0;
	pTLSSession->dwReceiveCursor = 0;

	pTLSSession->bCipherSpec = FALSE;
	pTLSSession->bServerFinished = FALSE;
	pTLSSession->bSentFinished = FALSE;
	pTLSSession->bCertRequest = FALSE;

	memset(pTLSSession->pbState, 0, sizeof(RADIUS_MAX_STATE));
	pTLSSession->cbState = 0;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSInit::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

DWORD TLSCleanup(PSW2_TLS_SESSION pTLSSession)
{
	DWORD dwReturnCode = NO_ERROR;
	DWORD i;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSCleanup" ) );

	if( pTLSSession->hReadKey )
		CryptDestroyKey( pTLSSession->hReadKey );

	if( pTLSSession->hWriteKey )
		CryptDestroyKey( pTLSSession->hWriteKey );

	//
	// Cleanup handshake msgs
	//
	for( i=0; ( DWORD ) i < pTLSSession->dwHandshakeMsgCount; i++ )
		SW2FreeMemory((PVOID*)&(pTLSSession->pbHandshakeMsg[i]));

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSCleanup::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

DWORD TLSResetReceiveMsg(IN PSW2_TLS_SESSION pTLSSession)
{
	DWORD dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSResetReceiveMsg" ) );

	memset( pTLSSession->pbReceiveMsg, 0, sizeof( pTLSSession->pbReceiveMsg ) );
	pTLSSession->cbReceiveMsg = 0;
	pTLSSession->dwReceiveCursor = 0;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSResetReceiveMsg::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSGenSessionID
// Description: Generate a new SSL Session ID
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSGenSessionID( IN OUT BYTE pbSessionID[TLS_SESSION_ID_SIZE],
				IN OUT DWORD *pcbSessionID,
				IN DWORD dwMaxSessionID )
{
	DWORD			dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSGenSessionID" ) );

	*pcbSessionID = dwMaxSessionID;

	if( ( dwReturnCode = SW2_GenSecureRandom( pbSessionID, TLS_RANDOM_SIZE ) ) == NO_ERROR )
	{
		SW2Trace( SW2_TRACE_LEVEL_DEBUG, TEXT( "SW2_TRACE_LEVEL_DEBUG::TLSGenSessionID::random bytes(%ld)" ), TLS_SESSION_ID_SIZE );
		SW2Dump( SW2_TRACE_LEVEL_DEBUG, pbSessionID, TLS_SESSION_ID_SIZE );
	}

	return dwReturnCode;
}

//
// Name: TLSGenRandom
// Description: Generate the 32 random bytes for the client
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSGenRandom( IN OUT BYTE pbRandom[TLS_RANDOM_SIZE] )
{
	DWORD			dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSGenRandom" ) );

	dwReturnCode = SW2_GenSecureRandom( pbRandom, TLS_RANDOM_SIZE );

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSGenRandom:: returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSGenPMS
// Description: Generate the 48 random bytes for the PMS (Pre Master Secret)
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSGenPMS( IN OUT BYTE pbPMS[TLS_PMS_SIZE] )
{
	DWORD			dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSGenPMS" ) );

	pbPMS[0] = 0x03;
	pbPMS[1] = 0x01;

	dwReturnCode = SW2_GenSecureRandom( &pbPMS[2], TLS_PMS_SIZE - 2 );

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSGenPMS:: returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSMakeFragResponse
// Description: This function builds the frag response message
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSMakeFragResponse( IN BYTE bPacketId, 
					IN PSW2EAPPACKET pSendPacket, 
					IN DWORD cbSendPacket,
					IN BYTE bEapProtocolId,
					IN BYTE bFlags)
{
	DWORD		dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeFragResponse" ) );

	//
	// Build send packet
	//
	pSendPacket->Code = EAPCODE_Response;
	pSendPacket->Id = bPacketId;

	//
	// Length of total packet, EAP_PACKET header (5)
	//
	SW2_HostToWireFormat16( 0x06, pSendPacket->Length );

	//
	// Which EAP are we using?
	//
	pSendPacket->Data[0] = bEapProtocolId;

	pSendPacket->Data[1] = bFlags;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeFragResponse returning" ) );

	return dwReturnCode;
}

//
// Name: TLSReadMessage
// Description: This function reads in fragmented message and puts the result in the pbFragmentedMessage
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSReadMessage(		IN PSW2_TLS_SESSION		pTLSSession,
					IN	BYTE				bPacketId,
					IN  PSW2EAPPACKET		pReceivePacket,
					IN	PSW2EAPPACKET		pSendPacket,
					IN  DWORD               cbSendPacket,
					IN	PSW2EAPOUTPUT		pEapOutput,
					OUT	BYTE				*pbMethodVersion,
					IN  DWORD				dwEAPPacketLength,
					IN  BYTE				bEapProtocolId,
					IN  BYTE				bVersion)
{
	DWORD	dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSReadMessage" ) );

	dwReturnCode = NO_ERROR;

	//
	// First read TLS version
	//
	*pbMethodVersion = pReceivePacket->Data[1] & EAP_METHOD_VERSION;

	if( dwEAPPacketLength < 7 )
	{
		memset( pTLSSession->pbReceiveMsg, 0, sizeof( pTLSSession->pbReceiveMsg ) );

		pTLSSession->cbReceiveMsg = 0;
	}
	else if( pReceivePacket->Data[1] & TLS_REQUEST_MORE_FRAG )
	{
		//
		// First look how big the complete message is
		// Then request other fragments
		//
		if( pTLSSession->cbReceiveMsg == 0 )
		{
			//
			// First fragmented message
			//
			if( pReceivePacket->Data[1] & TLS_REQUEST_LENGTH_INC )
			{
				//
				// Length of total fragmented EAP-TLS packet
				//
				pTLSSession->cbReceiveMsg = SW2_WireToHostFormat32( &( pReceivePacket->Data[2] ) );

				SW2Trace( SW2_TRACE_LEVEL_DEBUG, TEXT( "SW2_TRACE_LEVEL_DEBUG::TLSReadMessage::total message length: %ld" ), pTLSSession->cbReceiveMsg );

				if( pTLSSession->cbReceiveMsg <= TLS_MAX_MSG )
				{
					memset( pTLSSession->pbReceiveMsg, 0, pTLSSession->cbReceiveMsg);

					if( pReceivePacket->Data[1] & TLS_REQUEST_LENGTH_INC )
					{						
						//
						// Copy Fragmented data (length of message - EAP header(10) )
						//
						pTLSSession->dwReceiveCursor = dwEAPPacketLength - 10;

						memcpy( pTLSSession->pbReceiveMsg, &( pReceivePacket->Data[6] ), pTLSSession->dwReceiveCursor); 
					}
					else
					{
						pTLSSession->dwReceiveCursor = dwEAPPacketLength - 6;

						memcpy( pTLSSession->pbReceiveMsg, &( pReceivePacket->Data[2] ), pTLSSession->dwReceiveCursor ); 
					}
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
						TEXT( "SW2_TRACE_LEVEL_ERROR::TLSReadMessage::Not enough memory for pbReceiveMsg" ) );

					dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

					pEapOutput->eapAction = SW2EAPACTION_None;
				}
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_WARNING, 
					TEXT( "SW2_TRACE_LEVEL_WARNING::TLSReadMessage::NOT TLS_REQUEST_MORE_FRAG::NOT IMPLEMENTED" ) );

				//
				// NOT IMPLEMENTED YET
				//
				//
				// Length is not include
				// don't now how to react yet
				// NOTE: should we continue?
				//
				dwReturnCode = ERROR_PPP_INVALID_PACKET;

				pEapOutput->eapAction = SW2EAPACTION_Discard;
			}
		}
		else
		{
			//
			// Nth fragmented message
			//

			//
			// Just copy memory from previous frag cursor till length of message
			//

			if( pReceivePacket->Data[1] & TLS_REQUEST_LENGTH_INC )
			{
				//
				// If length is included then copy from 6th byte and onwards
				//
				memcpy( &( pTLSSession->pbReceiveMsg[pTLSSession->dwReceiveCursor] ), &( pReceivePacket->Data[6] ), dwEAPPacketLength - 10 ); 
				pTLSSession->dwReceiveCursor = pTLSSession->dwReceiveCursor + dwEAPPacketLength - 10;
			}
			else
			{
				//
				// If length is not included then copy from 2nd byte and onwards
				//
				memcpy( &( pTLSSession->pbReceiveMsg[pTLSSession->dwReceiveCursor] ), &( pReceivePacket->Data[2] ), dwEAPPacketLength - 6 ); 
				pTLSSession->dwReceiveCursor = pTLSSession->dwReceiveCursor + dwEAPPacketLength - 6;
			}
		}

		if( dwReturnCode == NO_ERROR )
		{
			//
			//
			// When an EAP-TLS peer receives an EAP-Request packet with the M bit
			// set (MORE_FRAGMENTS), it MUST respond with an EAP-Response with EAP-Type=EAPTYPE and
			// no data
			//
			if( ( dwReturnCode = TLSMakeFragResponse( bPacketId, 
					pSendPacket, cbSendPacket, 
					bEapProtocolId, bVersion )) == NO_ERROR )
			{
				pEapOutput->eapAction = SW2EAPACTION_Send;
			}
			else
			{
				pEapOutput->eapAction = SW2EAPACTION_None;
			}
		}
	}
	else
	{
		if( pTLSSession->cbReceiveMsg != 0 )
		{
			if( pReceivePacket->Data[1] & TLS_REQUEST_LENGTH_INC )
			{
				//
				// If length is included then copy from 6th byte and onwards
				//
				memcpy( &( pTLSSession->pbReceiveMsg[pTLSSession->dwReceiveCursor] ), &( pReceivePacket->Data[6] ), dwEAPPacketLength - 10 ); 
			}
			else
			{
				//
				// If length is included then copy from 6th byte and onwards
				//
				if( pReceivePacket->Data[1] & TLS_REQUEST_LENGTH_INC )
				{
					//
					// If length is included then copy from 6th byte and onwards
					//
					memcpy( &( pTLSSession->pbReceiveMsg[pTLSSession->dwReceiveCursor] ), &( pReceivePacket->Data[6] ), dwEAPPacketLength - 10 ); 
				}
				else
				{
					//
					// If length is not included then copy from 2nd byte and onwards
					//
					memcpy( &( pTLSSession->pbReceiveMsg[pTLSSession->dwReceiveCursor] ), &( pReceivePacket->Data[2] ), dwEAPPacketLength - 6 ); 
				}
			}
		}
		else
		{
			//
			// Normal unfragmented message
			//
			//
			// Length of total fragmented EAP-TLS packet
			//

			if( pReceivePacket->Data[1] & TLS_REQUEST_LENGTH_INC )
			{
				pTLSSession->cbReceiveMsg = SW2_WireToHostFormat32( &( pReceivePacket->Data[2] ) );	
			}
			else
			{
				pTLSSession->cbReceiveMsg = dwEAPPacketLength - 6;	
			}

			if( pTLSSession->cbReceiveMsg <= TLS_MAX_MSG )
			{
				//
				// If length is included then copy from 6th byte and onwards
				//
				if( pReceivePacket->Data[1] & TLS_REQUEST_LENGTH_INC )
				{
					//
					// If length is included then copy from 6th byte and onwards
					//
					memcpy( &( pTLSSession->pbReceiveMsg[pTLSSession->dwReceiveCursor] ), &( pReceivePacket->Data[6] ), dwEAPPacketLength - 10 ); 
				}
				else
				{
					//
					// If length is not included then copy from 2nd byte and onwards
					//
					memcpy( &( pTLSSession->pbReceiveMsg[pTLSSession->dwReceiveCursor] ), &( pReceivePacket->Data[2] ), dwEAPPacketLength - 6 ); 
				}
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::TLSReadMessage::Not enough memory for pTLSSession->pbReceiveMsg" ) );

				dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

				pEapOutput->eapAction = SW2EAPACTION_None;
			}
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSReadMessage::returning: %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSSendMessage
// Description: Create the SendPacket
//				This function will fragment the actual EAP packet into segments
//				if the packet is to large
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
TLSSendMessage(	IN PBYTE				pbSendMsg,	
				IN DWORD				cbSendMsg,
				IN OUT	DWORD			*pdwSendCursor,
				IN BYTE					bPacketId,
				IN PSW2EAPPACKET		pSendPacket, 
				IN DWORD				cbSendPacket,
				OUT PSW2EAPOUTPUT		pEapOutput )
{
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSSendMessage" ) );

	//
	// First let see if we need to fragment the message
	//
	if( cbSendMsg > TLS_MAX_FRAG_SIZE )
	{
		if( *pdwSendCursor == 0 )
		{
			pSendPacket->Data[1] |= TLS_REQUEST_LENGTH_INC | TLS_REQUEST_MORE_FRAG;

			//
			// Add message
			//
			if( ( dwReturnCode = TLSAddMessage( &( pbSendMsg[0] ),
										TLS_MAX_FRAG_SIZE, // EAP Packet size
										cbSendMsg, // Total EAP Message
										pSendPacket,
										cbSendPacket ) ) == NO_ERROR )
			{
				*pdwSendCursor = TLS_MAX_FRAG_SIZE;

				pEapOutput->eapAction = SW2EAPACTION_Send;
			}
		}
		else
		{
			if( ( *pdwSendCursor + TLS_MAX_FRAG_SIZE ) > cbSendMsg )
			{
				//
				// Add message
				//
				if( ( dwReturnCode = TLSAddMessage( &( pbSendMsg[*pdwSendCursor] ),
											cbSendMsg - *pdwSendCursor, // EAP Packet size
											cbSendMsg, // Total EAP Message
											pSendPacket,
											cbSendPacket ) ) == NO_ERROR )
				{
					*pdwSendCursor += TLS_MAX_FRAG_SIZE;

					pEapOutput->eapAction = SW2EAPACTION_Send;
				}
			}
			else
			{
				//
				// Nth message
				//
				pSendPacket->Data[1] |= TLS_REQUEST_MORE_FRAG;

				//
				// Add message
				//
				if( ( dwReturnCode = TLSAddMessage( &( pbSendMsg[*pdwSendCursor] ),
											TLS_MAX_FRAG_SIZE, // EAP Packet size
											cbSendMsg, // Total EAP Message
											pSendPacket,
											cbSendPacket ) ) == NO_ERROR )
				{
					*pdwSendCursor += TLS_MAX_FRAG_SIZE;

					pEapOutput->eapAction = SW2EAPACTION_Send;
				}
			}
		}
	}
	else if( cbSendMsg == 0 )
	{
		if( ( dwReturnCode = TLSAddMessage( pbSendMsg,
									cbSendMsg,
									cbSendMsg,
									pSendPacket, 
									cbSendPacket ) ) == NO_ERROR )
		{
			pEapOutput->eapAction = SW2EAPACTION_Send;
		}
	}
	else
	{
		pSendPacket->Data[1] |= TLS_REQUEST_LENGTH_INC;

		if( ( dwReturnCode = TLSAddMessage( pbSendMsg,
									cbSendMsg,
									cbSendMsg,
									pSendPacket, 
									cbSendPacket ) ) == NO_ERROR )
		{
			pEapOutput->eapAction = SW2EAPACTION_Send;
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSSendMessage::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSAddHandshakeMessage
// Description: This function adds a message to the handshake buffer used for the finished message
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSAddHandshakeMessage(	IN OUT DWORD *pdwHandshakeMsgCount,
						IN OUT PBYTE pbHandshakeMsg[TLS_MAX_HS],
						IN OUT DWORD cbHandshakeMsg[TLS_MAX_HS],
						IN PBYTE pbMessage, 
						IN DWORD cbMessage )
{
	DWORD	dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_DEBUG, TEXT( "SW2_TRACE_LEVEL_DEBUG::TLSAddHandshakeMessage::slot(%ld):msg(%ld)" ), *pdwHandshakeMsgCount, cbMessage );
	
	dwReturnCode = NO_ERROR;

	cbHandshakeMsg[*pdwHandshakeMsgCount] = cbMessage;
	
	if ((dwReturnCode = SW2AllocateMemory(cbHandshakeMsg[*pdwHandshakeMsgCount], (PVOID*)&(pbHandshakeMsg[*pdwHandshakeMsgCount])))==NO_ERROR)
	{
		memcpy( pbHandshakeMsg[*pdwHandshakeMsgCount], pbMessage, cbHandshakeMsg[*pdwHandshakeMsgCount] );

		( *pdwHandshakeMsgCount )++;
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			TEXT( "SW2_TRACE_LEVEL_ERROR::TLSAddHandshakeMessage::ERROR:Not enough memory for pbHandshakeMsg[%ld]" ), *pdwHandshakeMsgCount );

		dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSAddHandshakeMessage::returning %x" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSInitTLSResponsePacket
// Description: Initialises the send message for a TLS response packet
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSInitTLSResponsePacket(	IN BYTE				bPacketId,
							IN PSW2EAPPACKET	pSendPacket,
						    IN DWORD			cbSendPacket,
							IN BYTE				bEapProtocolId,
							IN BYTE				bFlags)
{
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSInitTTLSResponsePacket: packet id: %ld" ), bPacketId );

	memset( pSendPacket, 0, cbSendPacket );

	//
	// Build send packet
	//
	pSendPacket->Code = EAPCODE_Response;
	pSendPacket->Id = bPacketId;

	//
	// Length of total packet
	//
	SW2_HostToWireFormat16( ( WORD ) 0x06, pSendPacket->Length );

	//
	// Which protocol are we using?
	//
	pSendPacket->Data[0] = bEapProtocolId;

	//
	// Length is included in EAP-TTLS packet
	//
	//pSendPacket->Data[1] = TLS_REQUEST_LENGTH_INC | bFlags;
	pSendPacket->Data[1] = bFlags;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSInitTTLSResponsePacket::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSInitTLSRequestPacket
// Description: Initialises the send message for a TLS request packet
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSInitTLSRequestPacket(	IN BYTE				bPacketId,
							IN PSW2EAPPACKET	pSendPacket,
						    IN DWORD			cbSendPacket,
							IN BYTE				bEapProtocolId,
							IN BYTE				bVersion)
{
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSInitTLSRequestPacket: packet id: %ld" ), bPacketId );

	memset( pSendPacket, 0, cbSendPacket );

	//
	// Build send packet
	//
	pSendPacket->Code = EAPCODE_Request;
	pSendPacket->Id = bPacketId + 1;

	//
	// Length of total packet
	//
	SW2_HostToWireFormat16( ( WORD ) 0x06, pSendPacket->Length );

	//
	// Which protocol are we using?
	//
	pSendPacket->Data[0] = bEapProtocolId;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSInitTLSRequestPacket returning" ) );

	return dwReturnCode;
}

//
// Name: TLSInitTLSAcceptPacket
// Description: Initialises the accept message for a TLS request packet
// Author: Tom Rixom
// Created: 21 August 2004
//
DWORD
TLSInitTLSAcceptPacket(	IN BYTE				bPacketId,
						IN PSW2EAPPACKET	pSendPacket,
						IN DWORD			cbSendPacket)
{
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSInitTLSAcceptPacket: packet id: %ld" ), bPacketId );

	memset( pSendPacket, 0, cbSendPacket );

	//
	// Build send packet
	//
	pSendPacket->Code = EAPCODE_Success;
	pSendPacket->Id = bPacketId + 1;

	//
	// Length of total packet
	//
	SW2_HostToWireFormat16( ( WORD ) 0x04, pSendPacket->Length );

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSInitTLSAcceptPacket returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSInitTLSRejectPacket
// Description: Initialises the reject message for a TLS request packet
// Author: Tom Rixom
// Created: 21 August 2004
//
DWORD
TLSInitTLSRejectPacket(	IN BYTE				bPacketId,
						IN PSW2EAPPACKET	pSendPacket,
						IN DWORD			cbSendPacket)
{
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSInitTLSRejectPacket: packet id: %ld" ), bPacketId );

	memset( pSendPacket, 0, cbSendPacket );

	//
	// Build send packet
	//
	pSendPacket->Code = EAPCODE_Failure;
	pSendPacket->Id = bPacketId + 1;

	//
	// Length of total packet
	//
	SW2_HostToWireFormat16( ( WORD ) 0x04, pSendPacket->Length );

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSInitTLSRejectPacket returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSAddRecord
// Description: Adds a record to the send message
// Author: Tom Rixom
// Created: 13 August 2003
//
DWORD
TLSAddRecord(	IN	PBYTE	pbRecord,
				IN  DWORD	cbRecord,
				IN	PBYTE	pbMessage,
				IN	DWORD	*pcbMessage )
{
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	//
	// First check if we have room
	//
	if( ( cbRecord + *pcbMessage ) <= TLS_MAX_MSG )
	{
		//
		// Copy message
		//
		memcpy( &( pbMessage[*pcbMessage] ), pbRecord, cbRecord );

		*pcbMessage += cbRecord;
	}
	else
		dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

	return dwReturnCode;
}

//
// Name: TLSAddMessage
// Description: Adds a message to the send packet
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSAddMessage(	IN PBYTE			pbMessage,
				IN DWORD			cbMessage,
				IN DWORD			cbTotalMessage,
				IN PSW2EAPPACKET	pSendPacket,
				IN DWORD			cbSendPacket )
{
	DWORD	dwPacketLength = SW2_WireToHostFormat16( &pSendPacket->Length[0] );
	DWORD	dwRecordLength = SW2_WireToHostFormat32( &pSendPacket->Data[2] );
	DWORD	dwCursor;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
			TEXT( "SW2_TRACE_LEVEL_INFO::TLSAddMessage" ) );

	if( ( dwPacketLength + cbMessage ) > cbSendPacket )
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			TEXT( "SW2_TRACE_LEVEL_ERROR::TLSAddMessage::packet (%ld) too big for buffer" ), ( dwPacketLength + cbMessage ) );

		return ERROR_NOT_ENOUGH_MEMORY;
	}

	if( pSendPacket->Data[1] & TLS_REQUEST_LENGTH_INC )
	{
		//
		// Update length of total packet
		//
		if( dwRecordLength == 0 )
		{
			//
			// If this is the first packet we are adding we need to also
			// add the extra length
			//
			SW2_HostToWireFormat16( ( DWORD ) ( dwPacketLength + 0x04 + cbMessage ), pSendPacket->Length );

			dwCursor = dwPacketLength;
		}
		else
		{
			SW2_HostToWireFormat16( ( DWORD ) ( dwPacketLength + cbMessage ), pSendPacket->Length );

			dwCursor = dwPacketLength - 0x04;
		}

		//
		// Update length of EAP-TLS packet
		//
		SW2_HostToWireFormat32( ( DWORD ) ( dwRecordLength + cbTotalMessage ), &( pSendPacket->Data[2] ) );
	}
	else
	{
		SW2_HostToWireFormat16( ( DWORD ) ( dwPacketLength + cbMessage ), pSendPacket->Length );

		dwCursor = dwPacketLength - 0x04;
	}

	memcpy( &( pSendPacket->Data[dwCursor] ), pbMessage, cbMessage );

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSAddMessage::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSMakeApplicationRecord
// Description: build a application record
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSMakeApplicationRecord(	IN PSW2_TLS_SESSION pTLSSession,
							IN PBYTE		pbMessage,
							IN DWORD		cbMessage,
							IN PBYTE		*ppbRecord,
							IN DWORD		*pcbRecord,
							IN BOOL			bEncrypt )
{
	PBYTE	pbTLSMessage;
	DWORD	cbTLSMessage;
	PBYTE	pbTempRecord;
	DWORD	cbTempRecord;
	PBYTE	pbRecord;
	DWORD	cbRecord;
	DWORD	dwCursor = 0;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeApplicationRecord" ) );

	//
	// Do we need to encrypt the application record?
	//
	if( bEncrypt )
	{
		//
		// First build a application record (no encryption)
		//
		if( ( dwReturnCode = TLSMakeApplicationRecord( pTLSSession,
														pbMessage, 
														cbMessage, 
														&pbTempRecord, 
														&cbTempRecord, 
														FALSE ) ) == NO_ERROR )
		{
			//
			// Encrypt this record which will be add to the final handshake record
			//
			dwReturnCode = TLSEncBlock( pTLSSession,
								pbTempRecord, 
								cbTempRecord, 
								&pbTLSMessage, 
								&cbTLSMessage );

			SW2FreeMemory((PVOID*)&pbTempRecord);
			cbTempRecord = 0;

			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeApplicationRecord:: encrypted %ld bytes" ),
				cbTLSMessage );
		}
	}
	else
	{
		pbTLSMessage = pbMessage;
		cbTLSMessage = cbMessage;
	}

	if (dwReturnCode == NO_ERROR)
	{
		cbRecord = 0x05+cbTLSMessage;

		if ((dwReturnCode = SW2AllocateMemory(cbRecord, (PVOID*) &pbRecord))==NO_ERROR)
		{
			//
			// ssl record header
			//
			pbRecord[dwCursor++] = 0x17;			// ssl record type is application = 23
			pbRecord[dwCursor++] = 0x03;			// ssl major version number
			pbRecord[dwCursor++] = 0x01;			// ssl minor version number

			SW2_HostToWireFormat16( cbTLSMessage, &( pbRecord[dwCursor] ) );

			dwCursor+=2;

			memcpy( &( pbRecord[dwCursor] ), pbTLSMessage, cbTLSMessage );

			dwCursor += cbTLSMessage;

			*ppbRecord = pbRecord;
			*pcbRecord = cbRecord;
		}

		//
		// If we used encryption then we must free the allocated TLSMessage
		//
		if( bEncrypt )
		{
			SW2FreeMemory((PVOID*)&pbTLSMessage);
			cbTLSMessage = 0;
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeApplicationRecord:: returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSMakeHandshakeRecord
// Description: build a handshake record
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSMakeHandshakeRecord( IN PSW2_TLS_SESSION pTLSSession,
						IN PBYTE		pbMessage,
						IN DWORD		cbMessage,
						IN PBYTE		*ppbRecord,
						IN DWORD		*pcbRecord,
						IN BOOL			bEncrypt )
{
	PBYTE	pbTLSMessage;
	DWORD	cbTLSMessage;
	PBYTE	pbRecord;
	DWORD	cbRecord;
	PBYTE	pbTempRecord;
	DWORD	cbTempRecord;
	DWORD	dwCursor = 0;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeHandshakeRecord, %ld" ), bEncrypt );

	//
	// Do we need to encrypt the handshake record?
	//
	if( bEncrypt )
	{
		//
		// First build a handshake record (no encryption)
		//
		if( ( dwReturnCode = TLSMakeHandshakeRecord( pTLSSession,
												pbMessage, 
												cbMessage, 
												&pbTempRecord, 
												&cbTempRecord, 
												FALSE ) ) == NO_ERROR )
		{
			//
			// Encrypt this record which will be add to the final handshake record
			//
			dwReturnCode = TLSEncBlock( pTLSSession,
									pbTempRecord, 
									cbTempRecord, 
									&pbTLSMessage, 
									&cbTLSMessage );

			SW2FreeMemory((PVOID*)&pbTempRecord);
			cbTempRecord = 0;
		}
	}
	else
	{
		pbTLSMessage = pbMessage;
		cbTLSMessage = cbMessage;
	}

	if( dwReturnCode != NO_ERROR )
		return dwReturnCode;

	cbRecord = 0x05+cbTLSMessage;

	if ((dwReturnCode = SW2AllocateMemory(cbRecord, (PVOID*)&pbRecord))==NO_ERROR)
	{
		//
		// ssl record header
		//
		pbRecord[dwCursor++] = 0x16;			// ssl record type is handshake = 22
		pbRecord[dwCursor++] = 0x03;			// ssl major version number
		pbRecord[dwCursor++] = 0x01;			// ssl minor version number

		SW2_HostToWireFormat16( cbTLSMessage, &( pbRecord[dwCursor] ) );

		dwCursor+=2;

		memcpy( &( pbRecord[dwCursor] ), pbTLSMessage, cbTLSMessage );

		dwCursor += cbTLSMessage;

		*ppbRecord = pbRecord;
		*pcbRecord = cbRecord;

		//
		// If we used encryption then we must free the allocated TLSMessage
		//
		if( bEncrypt )
		{
			SW2FreeMemory((PVOID*)&pbTLSMessage);
			cbTLSMessage = 0;
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeHandshakeRecord:: returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSMakeClientHelloMessage
// Description: This function will build the TLS ClientHello record
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSMakeClientHelloMessage(	IN BYTE				pbRandomClient[TLS_RANDOM_SIZE],
							IN PBYTE			pbTLSSessionID,
							IN DWORD			cbTLSSessionID,
							OUT PBYTE			*ppbTLSMessage,
							OUT DWORD			*pcbTLSMessage,
							OUT DWORD			*pdwEncKey,
							OUT DWORD			*pdwEncKeySize,
							OUT DWORD			*pdwMacKey,
							OUT DWORD			*pdwMacKeySize )
{
	PBYTE	pbTLSMessage;
	DWORD	cbTLSMessage;
	DWORD	dwCursor = 0;
	DWORD	dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeClientHelloMessage" ) );

	dwReturnCode = NO_ERROR;

	cbTLSMessage = 0x0D+TLS_RANDOM_SIZE+cbTLSSessionID;

	if ((dwReturnCode = SW2AllocateMemory(cbTLSMessage, (PVOID*) &pbTLSMessage))==NO_ERROR)
	{
		//
		// ssl handshake header
		//
		pbTLSMessage[dwCursor++] = 0x01;   // message type is client_hello = 1

		// length of fragment is length of total message ( cbTLSMessage ) - header( 4 )
		SW2_HostToWireFormat24( ( DWORD ) ( cbTLSMessage  - 4 ), &( pbTLSMessage[dwCursor] ) );

		dwCursor+=3;

		//
		// Version 3.1 ( WORD )
		// 00000011 00000001
		// 
		pbTLSMessage[dwCursor++] = 0x03;

		pbTLSMessage[dwCursor++] = 0x01;

		if( ( dwReturnCode = TLSGenRandom( pbRandomClient ) ) == NO_ERROR )
		{
			//
			// Random
			//
			memcpy( &( pbTLSMessage[dwCursor] ), pbRandomClient, TLS_RANDOM_SIZE );

			dwCursor += TLS_RANDOM_SIZE;

			//
			// Session ID size
			//
			pbTLSMessage[dwCursor++] = ( BYTE ) cbTLSSessionID;

			//
			// SessionID
			//			
			memcpy( &( pbTLSMessage[dwCursor] ), pbTLSSessionID, cbTLSSessionID );

			dwCursor+=cbTLSSessionID;

			//
			// Length of cypher_suite:
			//
			SW2_HostToWireFormat16( ( DWORD ) ( 0x02 ), &( pbTLSMessage[dwCursor] ) );

			dwCursor+=2;

			//
			// TLS_RSA_WITH_3DES_EDE_CBC_SHA { 0x00, 0x0A }
			// TLS_RSA_WITH_RC4_128_MD5      { 0x00,0x04 }
			// TLS_RSA_WITH_RC4_128_SHA1     { 0x00,0x05 }
			//
			*pdwEncKey = CALG_3DES;
			*pdwEncKeySize = 24;

			*pdwMacKey = CALG_SHA1;
			*pdwMacKeySize = 20;

			pbTLSMessage[dwCursor++] = 0x00;
			pbTLSMessage[dwCursor++] = 0x0A;
	 
			//
			// Compression
			//
			pbTLSMessage[dwCursor++] = 0x01;   // length of compression section
			pbTLSMessage[dwCursor++] = 0x00;	// no compression

			*ppbTLSMessage = pbTLSMessage;
			*pcbTLSMessage = cbTLSMessage;
		}
		else
		{
			SW2FreeMemory((PVOID*)&pbTLSMessage);
			cbTLSMessage = 0;
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeClientHelloMessage::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSMakeServerHelloMessage
// Description: This function will build the TLS ServerHello record
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
TLSMakeServerHelloMessage(	IN BYTE				pbRandomServer[TLS_RANDOM_SIZE],
							IN PBYTE			pbTLSSessionID,
							IN DWORD			cbTLSSessionID,
							OUT PBYTE			*ppbTLSMessage,
							OUT DWORD			*pcbTLSMessage,
							OUT DWORD			*pdwEncKey,
							OUT DWORD			*pdwEncKeySize,
							OUT DWORD			*pdwMacKey,
							OUT DWORD			*pdwMacKeySize )
{
	PBYTE	pbTLSMessage;
	DWORD	cbTLSMessage;
	DWORD	dwCursor = 0;
	DWORD	dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeServerHelloMessage" ) );

	dwReturnCode = NO_ERROR;

	cbTLSMessage = 0x0A+TLS_RANDOM_SIZE+cbTLSSessionID;

	if ((dwReturnCode = SW2AllocateMemory(cbTLSMessage, (PVOID*)&pbTLSMessage))==NO_ERROR)
	{
		memset( pbTLSMessage, 0, cbTLSMessage );

		//
		// ssl handshake header
		//
		pbTLSMessage[dwCursor++] = 0x02;   // message type is server_hello = 2

		// length of fragment is length of total message ( cbTLSMessage ) - header( 4 )
		SW2_HostToWireFormat24( ( DWORD ) ( cbTLSMessage  - 4 ), &( pbTLSMessage[dwCursor] ) );

		dwCursor+=3;

		//
		// Version 3.1 ( WORD )
		// 00000011 00000001
		// 
		pbTLSMessage[dwCursor++] = 0x03;

		pbTLSMessage[dwCursor++] = 0x01;

		if( ( dwReturnCode = TLSGenRandom( pbRandomServer ) ) == NO_ERROR )
		{
			//
			// Random
			//
			memcpy( &( pbTLSMessage[dwCursor] ), pbRandomServer, TLS_RANDOM_SIZE );

			dwCursor += TLS_RANDOM_SIZE;

			//
			// Session ID size
			//
			pbTLSMessage[dwCursor++] = ( BYTE ) cbTLSSessionID;

			//
			// SessionID
			//			
			memcpy( &( pbTLSMessage[dwCursor] ), pbTLSSessionID, cbTLSSessionID );

			dwCursor+=cbTLSSessionID;

			//
			// TLS_RSA_WITH_3DES_EDE_CBC_SHA { 0x00, 0x0A }
			// TLS_RSA_WITH_RC4_128_MD5      { 0x00,0x04 }
			// TLS_RSA_WITH_RC4_128_SHA1     { 0x00,0x05 }
			//
			*pdwEncKey = CALG_3DES;
			*pdwEncKeySize = 24;

			*pdwMacKey = CALG_SHA1;
			*pdwMacKeySize = 20;

			pbTLSMessage[dwCursor++] = 0x00;
			pbTLSMessage[dwCursor++] = 0x0A;
	 
			//
			// Compression
			//
			pbTLSMessage[dwCursor++] = 0x00;	// no compression

			*ppbTLSMessage = pbTLSMessage;
			*pcbTLSMessage = cbTLSMessage;
		}
		else
		{
			SW2FreeMemory((PVOID*)&pbTLSMessage);
			cbTLSMessage = 0;
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeServerHelloMessage::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSMakeCertificateRequestMessage
// Description: This function will build Certificate Request
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
TLSMakeCertificateRequestMessage(	IN PBYTE	*ppbTLSMessage,
									IN DWORD	*pcbTLSMessage )
{
	PBYTE		pbTLSMessage;
	DWORD		cbTLSMessage;
	DWORD		dwCursor = 0;
	DWORD		dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeCertificateRequestMessage" ) );

	dwReturnCode = NO_ERROR;

	*pcbTLSMessage = 0x04;

	if ((dwReturnCode = SW2AllocateMemory(*pcbTLSMessage, (PVOID*)ppbTLSMessage))==NO_ERROR)
	{
		pbTLSMessage = *ppbTLSMessage;
		cbTLSMessage = *pcbTLSMessage;

		memset( pbTLSMessage, 0, cbTLSMessage );

		//
		// ssl handshake header
		//
		pbTLSMessage[dwCursor++] = 0x0D;   // message type is server_done = 13

		// length of fragment is length of total message ( 0 )
		SW2_HostToWireFormat24( 0x00 , &( pbTLSMessage[dwCursor] ) );
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeCertificateRequestMessage::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSMakeServerHelloDoneMessage
// Description: This function will build the Server Hello Done Message
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
TLSMakeServerHelloDoneMessage(	IN PBYTE			*ppbTLSMessage,
								IN DWORD			*pcbTLSMessage )
{
	PBYTE		pbTLSMessage;
	DWORD		cbTLSMessage;
	DWORD		dwCursor = 0;
	DWORD		dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeServerHelloDoneMessage" ) );

	dwReturnCode = NO_ERROR;

	*pcbTLSMessage = 0x04;

	if ((dwReturnCode = SW2AllocateMemory(*pcbTLSMessage, (PVOID*)ppbTLSMessage))==NO_ERROR)
	{
		pbTLSMessage = *ppbTLSMessage;
		cbTLSMessage = *pcbTLSMessage;

		memset( pbTLSMessage, 0, cbTLSMessage );

		//
		// ssl handshake header
		//
		pbTLSMessage[dwCursor++] = 0x0E;   // message type is server_done = 14

		// length of fragment is length of total message ( 0 )
		SW2_HostToWireFormat24( 0x00 , &( pbTLSMessage[dwCursor] ) );
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeServerHelloDoneMessage::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSMakeChangeCipherSpecRecord
// Description: Adds a change cipher spec handshake record to the send message
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSMakeChangeCipherSpecRecord(	IN PBYTE			*ppbRecord,
								IN DWORD			*pcbRecord )
{
	PBYTE	pbRecord;
	DWORD	cbRecord;
	DWORD	dwCursor = 0;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeChangeCipherSpecRecord" ) );

	*pcbRecord = 0x06;

	if ((dwReturnCode = SW2AllocateMemory(*pcbRecord, (PVOID*)ppbRecord))==NO_ERROR)
	{
		pbRecord = *ppbRecord;
		cbRecord = *pcbRecord;

		//
		// ssl record header
		//
		pbRecord[dwCursor++] = 0x14;			// ssl record type is change cipher spec = 20
		pbRecord[dwCursor++] = 0x03;			// ssl major version number
		pbRecord[dwCursor++] = 0x01;			// ssl minor version number

		SW2_HostToWireFormat16( 0x01, &( pbRecord[dwCursor] ) ); // length of message

		dwCursor+=2;

		pbRecord[dwCursor++] = 0x01;	
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeChangeCipherSpecRecord::returning %ld" ), dwReturnCode);

	return dwReturnCode;
}

//
// Name: TLSMakeClientCertificateMessage
// Description: This function will build the Client Certificate Message
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
TLSMakeClientCertificateMessage( 	OUT PBYTE			*ppbTLSMessage,
									OUT DWORD			*pcbTLSMessage )
{
	PBYTE	pbTLSMessage;
	DWORD	cbTLSMessage;
	DWORD	dwCursor = 0;
	DWORD	dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeCertificateMessage" ) );

	dwReturnCode = NO_ERROR;

	*pcbTLSMessage = 0x07;

	if ((dwReturnCode = SW2AllocateMemory(*pcbTLSMessage, (PVOID*)ppbTLSMessage))==NO_ERROR)
	{
		pbTLSMessage = *ppbTLSMessage;
		cbTLSMessage = *pcbTLSMessage;

		memset( pbTLSMessage, 0, cbTLSMessage );

		pbTLSMessage[dwCursor++] = 0x0B;   // message type is certificate

		SW2_HostToWireFormat24( ( DWORD ) ( 0x03 ), &( pbTLSMessage[dwCursor] ) );

		dwCursor+=3;

		SW2_HostToWireFormat24( ( DWORD ) ( 0x00 ), &( pbTLSMessage[dwCursor] ) );

		dwCursor+=3;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeCertificateMessage::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSMakeServerCertificateMessage
// Description: This function will build the Server Certificate Message
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
TLSMakeServerCertificateMessage( 	IN PBYTE		pbServerCertSHA1,
									OUT PBYTE		*ppbTLSMessage,
									OUT DWORD		*pcbTLSMessage )
{
	PCCERT_CONTEXT	pCertContext = NULL;
	PCCERT_CONTEXT	pChainCertContext = NULL;
	PBYTE			pbTLSMessage;
	DWORD			cbTLSMessage;
	DWORD			dwCursor = 0;
	int				i = 0;
	DWORD			dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeServerCertificateMessage" ) );

	dwReturnCode = NO_ERROR;

	//
	// First find certificate in local store ("MY")
	//
	if( ( dwReturnCode = SW2_GetCertificate( pbServerCertSHA1, &pCertContext ) ) == NO_ERROR )
	{
		//
		// Retrieve Certificate Hierarchy
		//
		CERT_CHAIN_PARA				ChainParams;
		PCCERT_CHAIN_CONTEXT		pChainContext;
		CERT_ENHKEY_USAGE			EnhkeyUsage;
		CERT_USAGE_MATCH			CertUsage;  
		DWORD						dwFlags;

		//
		// Initialize the certificate chain validation
		//
		EnhkeyUsage.cUsageIdentifier = 0;
		EnhkeyUsage.rgpszUsageIdentifier = NULL;

		CertUsage.dwType = USAGE_MATCH_TYPE_AND;
		CertUsage.Usage  = EnhkeyUsage;

		memset( &ChainParams, 0, sizeof( CERT_CHAIN_PARA ) );

		ChainParams.dwUrlRetrievalTimeout = 1;
		
		ChainParams.cbSize = sizeof( CERT_CHAIN_PARA );
		ChainParams.RequestedUsage = CertUsage;

		dwFlags =	CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL |
					CERT_CHAIN_CACHE_END_CERT;

		if( pCertContext )
		{
			//
			// Check the certificate chain
			// do not check urls as we do not have any IP connectivity
			//
			if( CertGetCertificateChain( HCCE_LOCAL_MACHINE, 
											pCertContext, 
											NULL,
											NULL,
											&ChainParams,
											0,
											NULL,
											&pChainContext ) )
			{
				if( pChainContext->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR )
				{
					if( pChainContext->rgpChain[0] )
					{
						DWORD	dwCertListLength = 0;

						//
						// Have to determine length of message first
						//
						*pcbTLSMessage = 0;

						//
						// First retrieve total length of all certificates
						//
						for( i = 0; ( DWORD ) i < pChainContext->rgpChain[0]->cElement; i++ )
						{
							pChainCertContext = pChainContext->rgpChain[0]->rgpElement[i]->pCertContext;

							//
							// Length is current length + header(length:3) + certificate(pChainCertContext->cbCertEncoded:?)
							//
							dwCertListLength = dwCertListLength + 0x03 + pChainCertContext->cbCertEncoded;
						}

						//
						// Now add certificate message header(type:1+msg_length:3+certlistlength:3)
						//
						*pcbTLSMessage = dwCertListLength + 0x07;

						//
						// Built initial certificate message
						//
						if ((dwReturnCode = SW2AllocateMemory(*pcbTLSMessage, (PVOID*)ppbTLSMessage))==NO_ERROR)
						{
							pbTLSMessage = *ppbTLSMessage;
							cbTLSMessage = *pcbTLSMessage;

							memset( pbTLSMessage, 0, cbTLSMessage );

							pbTLSMessage[dwCursor++] = 0x0B;   // message type is certificate

							//
							// length of  set later, skip
							//
							SW2_HostToWireFormat24( dwCertListLength + ( DWORD ) ( 0x03 ), &( pbTLSMessage[dwCursor] ) ); // length of message

							dwCursor+=3;

							//
							// Certificate list length is set later, skip
							//
							SW2_HostToWireFormat24( dwCertListLength, &( pbTLSMessage[dwCursor] ) ); // list length

							dwCursor+=3;

							for( i = 0; ( DWORD ) i < pChainContext->rgpChain[0]->cElement; i++ )
							{
								pChainCertContext = pChainContext->rgpChain[0]->rgpElement[i]->pCertContext;

								//
								// Length of certificate
								//
								SW2_HostToWireFormat24( pChainCertContext->cbCertEncoded, &( pbTLSMessage[dwCursor] ) ); // length of message

								dwCursor+=3;

								memcpy( &( pbTLSMessage[dwCursor] ), pChainCertContext->pbCertEncoded, pChainCertContext->cbCertEncoded );

								//
								// Certificate
								//
								dwCursor+=pChainCertContext->cbCertEncoded;
							}
						}
					}
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSMakeServerCertificateMessage(), chain could not be validated( %x )" ), pChainContext->TrustStatus.dwErrorStatus );

					dwReturnCode = ERROR_CANTOPEN;
				}
			}
			else
				dwReturnCode = ERROR_CANTOPEN;

			CertFreeCertificateChain( pChainContext );
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_ERROR::TLSMakeServerCertificateMessage(), CertGetCertificateChain(), FAILED: %x" ), GetLastError() );

			dwReturnCode = ERROR_INTERNAL_ERROR;
		}

        if( pCertContext )
			CertFreeCertificateContext( pCertContext );
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeServerCertificateMessage::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSMakeClientKeyExchangeMessage
// Description: This function will build the Client Key Exchange Message
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
TLSMakeClientKeyExchangeMessage( 	IN PBYTE				pbEncPMS,
									IN DWORD				cbEncPMS,
									OUT PBYTE				*ppbTLSMessage,
									OUT DWORD				*pcbTLSMessage )
{
	PBYTE		pbTLSMessage;
	DWORD		cbTLSMessage;
	PBYTE		pbSwapped;
	DWORD		dwCursor = 0;
	DWORD		dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeClientKeyExchangeMessage" ) );

	dwReturnCode = NO_ERROR;

	*pcbTLSMessage = 0x06 + cbEncPMS;

	if ((dwReturnCode = SW2AllocateMemory(*pcbTLSMessage, (PVOID*)ppbTLSMessage))==NO_ERROR)
	{
		pbTLSMessage = *ppbTLSMessage;
		cbTLSMessage = *pcbTLSMessage;

		memset( pbTLSMessage, 0, cbTLSMessage );

		pbTLSMessage[dwCursor++] = 0x10;		// message type is client_exchange

		SW2_HostToWireFormat24( ( WORD ) ( 0x02 + cbEncPMS ), &( pbTLSMessage[dwCursor] ) ); // length of message

		dwCursor+=3;

		//
		// cke header
		//
		SW2_HostToWireFormat16( ( WORD ) cbEncPMS, &( pbTLSMessage[dwCursor] ) ); // length of encrypted data

		dwCursor+=2;

		//
		// Copy the encrypted block
		//	
		//
		// but first swap it because of big and little engines... or sumtin like dat... ;)
		//
		if ((dwReturnCode = SW2AllocateMemory(cbEncPMS, (PVOID*)&pbSwapped))==NO_ERROR)
		{				
			SW2_SwapArray( pbEncPMS, pbSwapped, cbEncPMS );
			memcpy( &( pbTLSMessage[dwCursor] ), pbSwapped, cbEncPMS );

			SW2FreeMemory((PVOID*)&pbSwapped);
		}
		else
		{
			SW2FreeMemory((PVOID*)ppbTLSMessage);
			*pcbTLSMessage = 0;
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeClientKeyExchangeMessage::returning: %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSMakeFinishedMessage
// Description: This function will build the Finished Message
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
TLSMakeFinishedMessage(	IN PSW2_TLS_SESSION pTLSSession,
						IN PCHAR			pcLabel,
						IN DWORD			ccLabel,
						IN PBYTE			pbMS,
						IN DWORD			cbMS,
						OUT PBYTE			*ppbTLSMessage,
						OUT DWORD			*pcbTLSMessage )
{
	BYTE	pbFinished[TLS_FINISH_SIZE];
	DWORD	cbFinished = sizeof( pbFinished );
	PBYTE	pbHash;
	DWORD	cbHash;
	PBYTE	pbMD5;
	DWORD	cbMD5;
	PBYTE	pbSHA1;
	DWORD	cbSHA1;
	PBYTE	pbData;
	DWORD	cbData;
	DWORD	dwOffset;
	DWORD	dwI = 0;
	int		i = 0;
	PBYTE	pbTLSMessage;
	DWORD	cbTLSMessage;
	DWORD	dwCursor = 0;
	DWORD	dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeFinishedMessage" ) );

	dwReturnCode = NO_ERROR;

	*pcbTLSMessage = 0x04+TLS_FINISH_SIZE;

	if ((dwReturnCode = SW2AllocateMemory(*pcbTLSMessage, (PVOID*)ppbTLSMessage))==NO_ERROR)
	{
		pbTLSMessage = *ppbTLSMessage;
		cbTLSMessage = *pcbTLSMessage;

		memset( pbTLSMessage, 0, cbTLSMessage );

		pbTLSMessage[dwCursor++] = 0x14; // finish message

		SW2_HostToWireFormat24( ( WORD ) TLS_FINISH_SIZE, &( pbTLSMessage[dwCursor] ) );

		dwCursor+=3;

		if (pTLSSession->hCSP )
		{
			//
			// first calculate length of total handshake msg
			//
			cbData = 0;

			for( dwI=0; dwI < pTLSSession->dwHandshakeMsgCount; dwI++ )
				cbData = cbData + pTLSSession->cbHandshakeMsg[dwI];

			if ((dwReturnCode = SW2AllocateMemory(cbData, (PVOID*)&pbData))==NO_ERROR)
			{
				dwOffset = 0;

				for( dwI=0; dwI < pTLSSession->dwHandshakeMsgCount; dwI++ )
				{
					memcpy( &( pbData[dwOffset] ), pTLSSession->pbHandshakeMsg[dwI], pTLSSession->cbHandshakeMsg[dwI] );
					dwOffset = dwOffset+pTLSSession->cbHandshakeMsg[dwI];
				}

				if( ( TLSGetMD5( pTLSSession->hCSP, pbData, cbData, &pbMD5, &cbMD5 ) ) == NO_ERROR )
				{
					if( ( TLSGetSHA1( pTLSSession->hCSP, pbData, cbData, &pbSHA1, &cbSHA1 ) ) == NO_ERROR )
					{
						cbHash = cbMD5 + cbSHA1;

						if ((dwReturnCode = SW2AllocateMemory(cbHash, (PVOID*)&pbHash))==NO_ERROR)
						{
							memcpy( pbHash, pbMD5, cbMD5 );
							memcpy( &( pbHash[cbMD5] ), pbSHA1, cbSHA1 );

							if( ( dwReturnCode = TLS_PRF( pTLSSession->hCSP, 
													pbMS, 
													cbMS, 
													( PBYTE ) pcLabel, 
													ccLabel, 
													pbHash, 
													cbHash, 
													pbFinished, 
													cbFinished ) ) == NO_ERROR )
							{
								memcpy( &( pbTLSMessage[dwCursor] ), pbFinished, cbFinished );

								dwCursor+=cbFinished;
							}

							SW2FreeMemory((PVOID*)&pbHash);
						}

						SW2FreeMemory((PVOID*)&pbSHA1);
					}

					SW2FreeMemory((PVOID*)&pbMD5);
				}

				SW2FreeMemory((PVOID*)&pbData);
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_ERROR::TLSMakeFinishedMessage::ERROR::no handle to help CSP" ) );

			dwReturnCode = ERROR_ENCRYPTION_FAILED;
		}

		if( dwReturnCode != NO_ERROR )
		{
			SW2FreeMemory((PVOID*)ppbTLSMessage);
			*pcbTLSMessage = 0;
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSMakeFinishedMessage::returning error: %x" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSVerifyFinishedMessage
// Description: This function verifies the server finished message
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSVerifyFinishedMessage(	IN PSW2_TLS_SESSION	pTLSSession,
							IN PCHAR			pcLabel,
							IN DWORD			ccLabel,
							IN PBYTE			pbMS,
							IN DWORD			cbMS,
							IN PBYTE			pbVerifyFinished,
							IN DWORD			cbVerifyFinished )
{
	PBYTE	pbHash;
	DWORD	cbHash;
	PBYTE	pbMD5;
	DWORD	cbMD5;
	PBYTE	pbSHA1;
	DWORD	cbSHA1;
	PBYTE	pbData;
	DWORD	cbData;
	DWORD	dwOffset;
	DWORD	dwI = 0;
	int		i = 0;
	PBYTE	pbFinished;
	DWORD	cbFinished;
	DWORD	dwCursor = 0;
	DWORD	dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSVerifyFinished" ) );

	dwReturnCode = NO_ERROR;

	cbFinished = TLS_FINISH_SIZE;

	if( cbFinished != cbVerifyFinished )
		return ERROR_ENCRYPTION_FAILED;

	if ((dwReturnCode = SW2AllocateMemory(cbFinished, (PVOID*)&pbFinished))==NO_ERROR)
	{
		memset( pbFinished, 0, cbFinished );

		if( pTLSSession->hCSP )
		{
			//
			// first calculate length of total handshake msg
			//
			cbData = 0;

			for( dwI=0; dwI < pTLSSession->dwHandshakeMsgCount; dwI++ )
				cbData = cbData + pTLSSession->cbHandshakeMsg[dwI];

			if ((dwReturnCode = SW2AllocateMemory(cbData, (PVOID*)&pbData))==NO_ERROR)
			{
				dwOffset = 0;

				for( dwI=0; dwI < pTLSSession->dwHandshakeMsgCount; dwI++ )
				{
					memcpy( &( pbData[dwOffset] ), pTLSSession->pbHandshakeMsg[dwI], pTLSSession->cbHandshakeMsg[dwI] );
					dwOffset = dwOffset+pTLSSession->cbHandshakeMsg[dwI];
				}

				if( ( TLSGetMD5( pTLSSession->hCSP, pbData, cbData, &pbMD5, &cbMD5 ) ) == NO_ERROR )
				{
					if( ( TLSGetSHA1( pTLSSession->hCSP, pbData, cbData, &pbSHA1, &cbSHA1 ) ) == NO_ERROR )
					{
						cbHash = cbMD5 + cbSHA1;

						if ((dwReturnCode = SW2AllocateMemory(cbHash, (PVOID*)&pbHash))==NO_ERROR)
						{
							memcpy( pbHash, pbMD5, cbMD5 );
							memcpy( &( pbHash[cbMD5] ), pbSHA1, cbSHA1 );

							if( ( dwReturnCode = TLS_PRF( pTLSSession->hCSP, pbMS, cbMS, ( PBYTE ) pcLabel, ccLabel, pbHash, cbHash, pbFinished, cbFinished ) ) == NO_ERROR )
							{
								for( i=0; ( DWORD ) i < cbFinished; i++ )
								{
									if( pbFinished[i] != pbVerifyFinished[i] )
									{
										dwReturnCode = ERROR_ENCRYPTION_FAILED;
										break;
									}
								}
							}

							SW2FreeMemory((PVOID*)&pbHash);
						}

						SW2FreeMemory((PVOID*)&pbSHA1);
					}

					SW2FreeMemory((PVOID*)&pbMD5);
				}

				SW2FreeMemory((PVOID*)&pbData);
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_ERROR::TLSVerifyFinished::ERROR::no handle to help CSP" ) );

			dwReturnCode = ERROR_ENCRYPTION_FAILED;
		}

		SW2FreeMemory((PVOID*)&pbFinished);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSVerifyFinished::returning error: %x" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSParseHandshakeRecord
// Description: This function parses a handshake message and acts accordingly
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSParseHandshakeRecord(	IN PSW2_TLS_SESSION pTLSSession, 
							IN PBYTE pbRecord, 
							IN DWORD cbRecord )
{
	DWORD		dwRecordLength;
	DWORD		dwCursor = 0;
	DWORD		dwCertificateListLength = 0;
	DWORD		dwCertCount = 0;
	DWORD		dwServerKeyExchangeLength;
	DWORD		dwCertRequestLength;
	DWORD		dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSParseHandshakeRecord" ) );

	//
	// Loop through message
	//
	while( dwCursor < cbRecord && dwReturnCode == NO_ERROR )
	{
		switch( pbRecord[dwCursor] )
		{
			case 0x02: //server_hello

				dwCursor++;

				if( dwCursor > cbRecord )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}

				//
				// Length of record is 3 bytes!!
				// skip first byte and read in integer
				//
				dwCursor+=3;

				if( dwCursor > cbRecord )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}

				//
				// Check TLS version
				//
				if( ( pbRecord[dwCursor] == 0x03 ) && ( pbRecord[dwCursor+1] == 0x01 ) )
				{
					dwCursor+=2;

					if( dwCursor > cbRecord )
					{
						dwReturnCode = ERROR_PPP_INVALID_PACKET;

						break;
					}

					//
					// Copy Random data
					//
					memcpy( pTLSSession->pbRandomServer, &( pbRecord[dwCursor] ), TLS_RANDOM_SIZE );

					dwCursor += TLS_RANDOM_SIZE;

					if( dwCursor > cbRecord )
					{
						dwReturnCode = ERROR_PPP_INVALID_PACKET;

						break;
					}

					//
					// Session length
					//
					pTLSSession->cbTLSSessionID = ( int ) pbRecord[dwCursor];

					if( pTLSSession->cbTLSSessionID > 0 )
					{
						dwCursor++;

						if( dwCursor > cbRecord )
						{
							dwReturnCode = ERROR_PPP_INVALID_PACKET;

							break;
						}

						//
						// Save session ID
						//
						memcpy( pTLSSession->pbTLSSessionID, &( pbRecord[dwCursor] ), pTLSSession->cbTLSSessionID );

#ifndef _WIN32_WCE
						//
						// set the time this session ID was set
						//
						time( &( pTLSSession->tTLSSessionID ) );
#endif

						dwCursor = dwCursor + pTLSSession->cbTLSSessionID;
					}
					else
					{
						//
						// previous securew2 version required a session id, according to RFC this
						// is not correct as an empty one simply means do not cache this session
						//
						memset( pTLSSession->pbTLSSessionID, 0, sizeof( pTLSSession->pbTLSSessionID ) );

						dwCursor++;
					}

					if( dwCursor > cbRecord )
					{
						dwReturnCode = ERROR_PPP_INVALID_PACKET;

						break;
					}

					pTLSSession->pbCipher[0] = pbRecord[dwCursor];

					dwCursor++;

					if( dwCursor > cbRecord )
					{
						dwReturnCode = ERROR_PPP_INVALID_PACKET;

						break;
					}

					pTLSSession->pbCipher[1] = pbRecord[dwCursor];

					//
					// Found the cipher message, should be either 0x13 or 0x0A
					//
					if( pTLSSession->pbCipher[0] == 0x00 &&
						pTLSSession->pbCipher[1] == 0x0A )
					{
						//
						// TLS_RSA_WITH_3DES_EDE_CBC_SHA { 0x00, 0x0A }
						//
						//
						//
						// Connect to help CSP
						//
						dwReturnCode = SW2_CryptAcquireContext(&pTLSSession->hCSP,
																	NULL,
																	MS_ENHANCED_PROV,
																	PROV_RSA_FULL);
					}
					else if( pTLSSession->pbCipher[0] == 0x00 &&
							pTLSSession->pbCipher[1] == 0x13 )
					{
						//
						// TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA { 0x00, 0x13 }
						//
						dwReturnCode = SW2_CryptAcquireContext(&pTLSSession->hCSP,
																	NULL,
																	MS_ENH_DSS_DH_PROV,
																	PROV_DH_SCHANNEL);
					}
					else
					{
						//
						// this is not possible, except if the RADIUS TLS implementation is screwy
						//
						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::TLSParseHandshakeRecord::cipher not supported" ) );

						dwReturnCode = ERROR_ENCRYPTION_FAILED;
					}

					if( dwReturnCode != NO_ERROR )
						break;

					dwCursor++;

					if( dwCursor > cbRecord )
					{
						dwReturnCode = ERROR_PPP_INVALID_PACKET;

						break;
					}

					pTLSSession->bCompression = pbRecord[dwCursor];

					dwCursor++;
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
						TEXT( "SW2_TRACE_LEVEL_ERROR::TLSParseHandshakeRecord::ERROR::TLS:incorrect version" ) );

					dwReturnCode = ERROR_PPP_INVALID_PACKET;
				}

			break;

			case 0x0B: // certificate

				dwCursor++;

				if( dwCursor > cbRecord )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}

				dwCursor+=3;

				if( dwCursor > cbRecord )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}

				dwCertificateListLength = SW2_WireToHostFormat24( &( pbRecord[dwCursor] ) );

				dwCursor+=3;

				if( dwCursor > cbRecord )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}

				dwCertCount = 0;

				//
				// Loop through cert list until done or we have read in TLS_MAX_CERT certs
				//
				while( ( dwCursor <= dwCertificateListLength ) 
					&& ( dwCertCount < TLS_MAX_CERT ) 
					&& dwReturnCode == NO_ERROR )
				{
					pTLSSession->cbCertificate[dwCertCount] = SW2_WireToHostFormat24( &( pbRecord[dwCursor] ) );

					dwCursor+=3;

					if( dwCursor > cbRecord )
					{
						dwReturnCode = ERROR_PPP_INVALID_PACKET;

						break;
					}

					if( pTLSSession->cbCertificate[dwCertCount] <= TLS_MAX_CERT_SIZE )
					{
						memcpy( pTLSSession->pbCertificate[dwCertCount], &( pbRecord[dwCursor] ), pTLSSession->cbCertificate[dwCertCount] );
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::TLSParseHandshakeRecord::Not enough memory for certificate[%ld]: %ld" ), 
							dwCertCount, pTLSSession->cbCertificate[dwCertCount]);

						dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

						break;
					}

					dwCursor += pTLSSession->cbCertificate[dwCertCount];

					dwCertCount++;
				}

				//
				// Save number of certificates
				//
				pTLSSession->dwCertCount = dwCertCount;// - 1;

			break;

			case 0x0C: // server_key_exchange
				
				//
				//
				//
				dwCursor++;

				if( dwCursor > cbRecord )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}

				dwServerKeyExchangeLength = SW2_WireToHostFormat24( &( pbRecord[dwCursor] ) );

				dwCursor+=3;

				if( dwCursor > cbRecord )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}

				dwCursor = dwCursor + dwServerKeyExchangeLength;

			break;

			case 0x0D: // certificate request

				dwCursor++;

				if( dwCursor > cbRecord )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}

				dwCertRequestLength = SW2_WireToHostFormat24( &( pbRecord[dwCursor] ) );

				dwCursor+=3;

				if( dwCursor > cbRecord )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}

				dwCursor += dwCertRequestLength;

				pTLSSession->bCertRequest = TRUE;

			break;

			case 0x0E: // ServerDone

				dwCursor++;

				if( dwCursor > cbRecord )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}

				dwCursor+=3;

			break;

			case 0x14: // Finished message

				dwCursor++;

				if( dwCursor > cbRecord )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}

				dwRecordLength = SW2_WireToHostFormat24( &( pbRecord[dwCursor] ) );

				dwCursor+=3;

				if( dwCursor > cbRecord )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}

				//
				// Verify the finished message
				//
				if( ( dwReturnCode = TLSVerifyFinishedMessage( pTLSSession,
																TLS_SERVER_FINISHED_LABEL,
																sizeof( TLS_SERVER_FINISHED_LABEL ) -1,
																pTLSSession->pbMS,
																TLS_MS_SIZE,
																&( pbRecord[dwCursor] ), 
																dwRecordLength ) ) == NO_ERROR )
					pTLSSession->bServerFinished = TRUE;

				dwCursor += dwRecordLength;

			break;

			default:

				SW2Trace( SW2_TRACE_LEVEL_WARNING, 
					TEXT( "SW2_TRACE_LEVEL_WARNING::TLSParseHandshakeRecord::WARNING::unknown TLS record: %x" ), pbRecord[dwCursor] );

				dwCursor++;

			break;
		}
	}

	//
	// Add the message for finished message hash
	//
	TLSAddHandshakeMessage( &pTLSSession->dwHandshakeMsgCount,
							pTLSSession->pbHandshakeMsg,
							pTLSSession->cbHandshakeMsg,
							pbRecord, 
							cbRecord );

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSParseHandshakeRecord::returning: %x" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSParseApplicationDataRecord
// Description: This function parses a application data message (DIAMETER AVPs) and acts accordingly
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSParseApplicationDataRecord(	IN PSW2_TLS_SESSION pTLSSession, 
								IN PBYTE pbRecord, 
								IN DWORD cbRecord )
{
	DWORD		dwAVPLength;
	DWORD		dwDataLength;
	DWORD		dwCode;
	DWORD		dwPadding;
	BYTE		bFlags;
	DWORD		dwCursor = 0;
	DWORD		dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSParseApplicationDataRecord" ) );

	if( cbRecord < 1 )
		return dwReturnCode;

	//
	// Loop through message
	//
	while( dwCursor < cbRecord && dwReturnCode == NO_ERROR )
	{
		dwCode = SW2_WireToHostFormat32( &( pbRecord[dwCursor] ) );

		dwCursor+=4;

		if( dwCursor > cbRecord )
		{
			dwReturnCode = ERROR_PPP_INVALID_PACKET;

			break;
		}

		bFlags = pbRecord[dwCursor];

		dwCursor++;

		if( dwCursor > cbRecord )
		{
			dwReturnCode = ERROR_PPP_INVALID_PACKET;

			break;
		}

		//
		// Length of total AVP
		//
		dwAVPLength = SW2_WireToHostFormat24(&( pbRecord[dwCursor] ) );

		dwCursor+=3;

		if( dwCursor > cbRecord )
		{
			dwReturnCode = ERROR_PPP_INVALID_PACKET;

			break;
		}

		//
		// TODO: if AVP FLags contains the V (Vendor bit) then the following 4 bytes are
		// the vendor field
		//

		//
		// Calculate padding
		//
		// length of AVP must be multiple of 4 octets
		//
		dwPadding = ( dwAVPLength ) % 4;

		if( dwPadding != 0 )
			dwPadding = 4 - dwPadding;

		//
		// Length of rest of packet is
		//
		// dwDataLength = dwAVPLength - code (4) - Flags(1) - Length of msg (3)
		//
		dwDataLength = dwAVPLength - 4 - 1 - 3;

		switch( dwCode )
		{
			case 0x4F: // Eap-Message
				
				if( dwDataLength <= TLS_MAX_EAPMSG )
				{
					pTLSSession->cbInnerEapMessage = dwDataLength;

					memset( pTLSSession->pbInnerEapMessage, 0, sizeof( pTLSSession->pbInnerEapMessage ) );
					memcpy( pTLSSession->pbInnerEapMessage, &( pbRecord[dwCursor] ), pTLSSession->cbInnerEapMessage );
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_WARNING, 
						TEXT( "SW2_TRACE_LEVEL_WARNING::TLSParseApplicationDataRecord::could not copy Eap-Message attribute, message too large" ) );
				}

			break;

			case 0x50: // Message-Authenticator

				SW2Trace( SW2_TRACE_LEVEL_DEBUG, TEXT( "SW2_TRACE_LEVEL_DEBUG::TLSParseApplicationDataRecord::Message-Authenticator(%ld)" ), dwDataLength );
				SW2Dump( SW2_TRACE_LEVEL_DEBUG, &( pbRecord[dwCursor] ), dwDataLength );

				//
				// Is ignored
				//
			
			break;

			case 0x18: // State

				SW2Trace( SW2_TRACE_LEVEL_DEBUG, TEXT( "SW2_TRACE_LEVEL_DEBUG::TLSParseApplicationDataRecord::State(%ld)" ), dwDataLength );
				SW2Dump( SW2_TRACE_LEVEL_DEBUG, &( pbRecord[dwCursor] ), dwDataLength );

				if( dwDataLength <= RADIUS_MAX_STATE )
				{
					pTLSSession->cbState = dwDataLength;

					memset( pTLSSession->pbState, 0, sizeof( pTLSSession->pbState ) );
					memcpy( pTLSSession->pbState, &( pbRecord[dwCursor] ), pTLSSession->cbState );
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_WARNING, 
						TEXT( "SW2_TRACE_LEVEL_WARNING::TLSParseApplicationDataRecord::could not copy State attribute" ) );
				}

			break;

			default:

				SW2Trace( SW2_TRACE_LEVEL_WARNING, 
					TEXT( "SW2_TRACE_LEVEL_WARNING::TLSParseApplicationDataRecord::WARNING::unknown record: %x" ), pbRecord[dwCursor] );

			break;
		}

		dwCursor+=dwDataLength+dwPadding;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSParseApplicationDataRecord::returning: %x" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSParseInnerApplicationDataRecord
// Description: This function parses an inner application data message and acts accordingly
// Author: Tom Rixom
// Created: 23 December 2006
//
DWORD
TLSParseInnerApplicationDataRecord( IN PSW2_TLS_SESSION pSessionData, 
									IN PBYTE pbRecord, 
									IN DWORD cbRecord )
{
	DWORD		dwCursor = 0;
	DWORD		dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSParseInnerApplicationDataRecord" ) );

	if( cbRecord < 1 )
		return dwReturnCode;

	dwReturnCode = ERROR_NOT_SUPPORTED;

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSParseApplicationDataRecord::returning: %x" ), dwReturnCode );

	return dwReturnCode;
}



//
// Name: TLSGenRSAEncPMS
// Description: This Encrypt the PMS (Pre Master Secret) using RSA
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
TLSGenRSAEncPMS( IN PSW2_TLS_SESSION pTLSSession, 
				PBYTE *ppbEncPMS, 
				DWORD *pcbEncPMS )
{
	PCCERT_CONTEXT		pCertContext;
	HCRYPTKEY			hPubKeyServer;
	DWORD				dwBufLen;
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSGenRSAEncPMS" ) );

	if( pTLSSession->hCSP )
	{
		//
		// First decode the certificate so Windows can read it.
		//
		if( ( pCertContext = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
															pTLSSession->pbCertificate[0], 
															pTLSSession->cbCertificate[0] ) ) )
		{
			//
			// Import the public key
			//
			if( CryptImportPublicKeyInfo( pTLSSession->hCSP,
											X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
											&pCertContext->pCertInfo->SubjectPublicKeyInfo,
											&hPubKeyServer ) )
			{
				//
				// First generate 48 bytes encrypted PMS
				//
				if( ( dwReturnCode = TLSGenPMS( pTLSSession->pbPMS ) ) == NO_ERROR )
				{
					*pcbEncPMS = TLS_PMS_SIZE;

					if( !CryptEncrypt( hPubKeyServer,
										0,
										TRUE,
										0,
										NULL,
										pcbEncPMS,
										0 ) )
					{
						dwReturnCode = GetLastError();
					}

					if( dwReturnCode == NO_ERROR || dwReturnCode == ERROR_MORE_DATA )
					{
						dwReturnCode = NO_ERROR;

						dwBufLen = *pcbEncPMS;

						if ((dwReturnCode = SW2AllocateMemory(*pcbEncPMS, (PVOID*)ppbEncPMS))==NO_ERROR)
						{
							memcpy( *ppbEncPMS, pTLSSession->pbPMS, TLS_PMS_SIZE );

							*pcbEncPMS = TLS_PMS_SIZE;

							if( !CryptEncrypt( hPubKeyServer,
												0,
												TRUE,
												0,
												*ppbEncPMS,
												pcbEncPMS,
												dwBufLen ) )
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, 
									TEXT( "SW2_TRACE_LEVEL_ERROR::TLSGenRSAEncPMS::CryptEncrypt:: FAILED (%ld)" ), GetLastError() );

								dwReturnCode = ERROR_ENCRYPTION_FAILED;
							}

							if( dwReturnCode != NO_ERROR )
								SW2FreeMemory((PVOID*)&ppbEncPMS);
						}
					}
				}

				CryptDestroyKey( hPubKeyServer );
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::TLSGenRSAEncPMS::CryptImportPublicKeyInfo:: FAILED (%ld)" ), 
					GetLastError() );

				dwReturnCode = ERROR_ENCRYPTION_FAILED;
			}						
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_ERROR::TLSGenRSAEncPMS::CertCreateCertificateContext:: FAILED (%ld)" ), 
				GetLastError() );

			dwReturnCode = ERROR_ENCRYPTION_FAILED;
		}

		CertFreeCertificateContext( pCertContext );
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			TEXT( "SW2_TRACE_LEVEL_ERROR::TLSGenRSAEncPMS::ERROR::no handle to help CSP" ) );

		dwReturnCode = ERROR_ENCRYPTION_FAILED;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSGenRSAEncPMS::returning: %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSDeriveKeys
// Description: Derives the required session keys and macs
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
TLSDeriveKeys( IN PSW2_TLS_SESSION pTLSSession )
{
	HCRYPTKEY			hPubKey;
	CHAR				pcLabel[] = TLS_KEY_EXPANSION_LABEL;
	DWORD				ccLabel = sizeof( pcLabel ) - 1;
	BYTE				pbTemp[TLS_RANDOM_SIZE * 2];
	PBYTE				pbKeyMaterial;
	DWORD				cbKeyMaterial;
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSDeriveKeys" ) );

	if( pTLSSession->hCSP )
	{
		//
		// client_write_MAC_secret[SecurityParameters.hash_size]
		// server_write_MAC_secret[SecurityParameters.hash_size]
		// client_write_key[SecurityParameters.key_material_length]
		// server_write_key[SecurityParameters.key_material_length]
		// client_write_IV[SecurityParameters.IV_size]
		// server_write_IV[SecurityParameters.IV_size]
		//
		cbKeyMaterial = ( pTLSSession->dwMacKeySize + pTLSSession->dwEncKeySize + 8 ) * 2;

		if ((dwReturnCode = SW2AllocateMemory(cbKeyMaterial, (PVOID*)&pbKeyMaterial))==NO_ERROR)
		{
			//
			// key_block = PRF(SecurityParameters.master_secret,
			//                  "key expansion",
			//					SecurityParameters.server_random +
			//					SecurityParameters.client_random);

			memcpy( pbTemp, pTLSSession->pbRandomServer, TLS_RANDOM_SIZE );
			memcpy( pbTemp + TLS_RANDOM_SIZE, pTLSSession->pbRandomClient, TLS_RANDOM_SIZE );

			if( ( dwReturnCode = TLS_PRF( pTLSSession->hCSP, pTLSSession->pbMS, TLS_MS_SIZE, ( PBYTE ) pcLabel, ccLabel, pbTemp, sizeof( pbTemp ), pbKeyMaterial, cbKeyMaterial ) ) == NO_ERROR )
			{
				//
				// WriteMAC key
				//
				memcpy( pTLSSession->pbWriteMAC, pbKeyMaterial, pTLSSession->dwMacKeySize );

				//
				// Read MAC key
				//
				memcpy( pTLSSession->pbReadMAC, pbKeyMaterial+pTLSSession->dwMacKeySize, pTLSSession->dwMacKeySize );

				if( CreatePrivateExponentOneKey( pTLSSession->hCSP,
													AT_KEYEXCHANGE,
													&hPubKey ) )
				{
					//
					// Write Enc Key
					//
					if( ImportPlainSessionBlob( pTLSSession->hCSP, 
												hPubKey, 
												pTLSSession->dwEncKey, 
												pbKeyMaterial + ( pTLSSession->dwMacKeySize * 2 ), 
												pTLSSession->dwEncKeySize,
												&pTLSSession->hWriteKey ) )
					{
						//
						// IV
						//
						if( CryptSetKeyParam( pTLSSession->hWriteKey,
												KP_IV,
												pbKeyMaterial + ( ( pTLSSession->dwMacKeySize + pTLSSession->dwEncKeySize ) * 2 ),
												0 ) )
						{
							//
							// Read Enc Key
							//
							if( ImportPlainSessionBlob( pTLSSession->hCSP, 
														hPubKey, 
														pTLSSession->dwEncKey, 
														pbKeyMaterial + ( pTLSSession->dwMacKeySize * 2 ) + pTLSSession->dwEncKeySize, 
														pTLSSession->dwEncKeySize,
														&pTLSSession->hReadKey ) )
							{
								//
								// IV
								//
								if( !CryptSetKeyParam( pTLSSession->hReadKey,
														KP_IV,
														pbKeyMaterial + ( ( pTLSSession->dwMacKeySize + pTLSSession->dwEncKeySize ) * 2 ) + 8,
														0 ) )
								{
									dwReturnCode = ERROR_ENCRYPTION_FAILED;
								}
							}
							else
							{
								dwReturnCode = ERROR_ENCRYPTION_FAILED;
							}
						}
						else
						{
							dwReturnCode = ERROR_ENCRYPTION_FAILED;
						}
					}

					CryptDestroyKey( hPubKey );
				}
				else
					dwReturnCode = ERROR_ENCRYPTION_FAILED;
			}

			if( dwReturnCode != NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::TLSDeriveKeys::an error occured %ld" ), GetLastError() );
			}

			SW2FreeMemory((PVOID*)&pbKeyMaterial);
		}
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			TEXT( "SW2_TRACE_LEVEL_ERROR::TLSDeriveKeys::no handle to help CSP" ) );

		dwReturnCode = ERROR_ENCRYPTION_FAILED;

	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSDeriveKeys::returning: %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_GenSecureRandom
// Description: Generate secure random data
// Author: Tom Rixom
// Created: 03 October 2005
//
DWORD
SW2_GenSecureRandom( PBYTE pbRandom, DWORD cbRandom )
{
	DWORD		dwReturnCode;
	HCRYPTPROV	hCSP;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_GenSecureRandom(%ld)" ), cbRandom );

	if( ( dwReturnCode = SW2_CryptAcquireContext( &hCSP, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL ) ) == NO_ERROR )
	{
		if( !CryptGenRandom( hCSP,
							cbRandom,
							pbRandom ) )
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_GenSecureRandom::CryptGenRandom Failed: %ld, %ld" ), dwReturnCode, GetLastError() );

			dwReturnCode = ERROR_ENCRYPTION_FAILED;
		}

		CryptReleaseContext( hCSP, 0 );
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_GenSecureRandom::returning %ld" ), dwReturnCode);

	return dwReturnCode;
}

//
// Name: TLSDecBlock
// Description: Decrypt a encrypted SSL record
//				Padding is not implemented yet
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSDecBlock( 	IN PSW2_TLS_SESSION pTLSSession,
				IN PBYTE			pbEncBlock,
				IN DWORD			cbEncBlock,
				OUT PBYTE			*ppbRecord,
				OUT DWORD			*pcbRecord )
{
	BYTE		bPadding;
	PBYTE		pbDecBlock;
	DWORD		cbDecBlock;
	DWORD		dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSDecBlock" ) );

	if( pTLSSession->hCSP )
	{
		cbDecBlock = cbEncBlock;

		if ((dwReturnCode = SW2AllocateMemory(cbDecBlock, (PVOID*)&pbDecBlock))==NO_ERROR)
		{
			memcpy( pbDecBlock, pbEncBlock, cbDecBlock );

			if( CryptDecrypt( pTLSSession->hReadKey,
								0,
								FALSE,
								0,
								pbDecBlock,
								&cbDecBlock ) )
			{
				//
				// Strip MAC and padding
				//
				bPadding = ( BYTE ) pbDecBlock[cbDecBlock-1];

				*pcbRecord = cbDecBlock - pTLSSession->dwMacKeySize - bPadding -1;

				if( *pcbRecord > 0 )
				{
					//
					// Check padding NOT IMPLEMENTED
					//
/*
					SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSDecBlock::looping for %ld", ( cbDecBlock - ( DWORD ) bPadding );

					for( i = cbDecBlock; ( DWORD ) i > ( cbDecBlock - ( DWORD ) bPadding ); i-- )
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSDecBlock::i:%ld" ), i );
						SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSDecBlock::%x" ), pbDecBlock[i] );

						if( pbDecBlock[i] != bPadding )
						{
							SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSDecBlock::padding failed" ) );
							dwReturnCode = ERROR_ENCRYPTION_FAILED;
							i = -1;
						}
					}
*/
					if( dwReturnCode == NO_ERROR )
					{
						if ((dwReturnCode = SW2AllocateMemory(*pcbRecord, (PVOID*)ppbRecord))==NO_ERROR)
						{
							memcpy( *ppbRecord, pbDecBlock, *pcbRecord );
						}
					}
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
						TEXT( "SW2_TRACE_LEVEL_ERROR::TLSDecBlock::incorrect padding" ) );
					
					//
					// padding failed but continue to parse rest of packets
					//
					dwReturnCode = ERROR_PPP_INVALID_PACKET;
				}
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::TLSDecBlock::CryptDecrypt:: FAILED (%ld)" ), GetLastError() );

				dwReturnCode = ERROR_ENCRYPTION_FAILED;
			}

			SW2FreeMemory((PVOID*)&pbDecBlock);
		}
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			TEXT( "SW2_TRACE_LEVEL_ERROR::TLSDecBlock::ERROR::no handle to help CSP" ) );

		dwReturnCode = ERROR_ENCRYPTION_FAILED;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSDecBlock::returning %ld" ), dwReturnCode );
	
	return dwReturnCode;
}

//
// Name: TLSEncBlock
// Description: Encrypts an SSL record using the specified Keys and MACs
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSEncBlock(	IN PSW2_TLS_SESSION pTLSSession,
				IN PBYTE			pbData,
				IN DWORD			cbData,
				OUT PBYTE			*ppbEncBlock,
				OUT DWORD			*pcbEncBlock )
{
	CHAR				pbSeqNum[] = {0, 0, 0, 0, 0, 0, 0, 0 };
	PBYTE				pbTemp;
	DWORD				cbTemp;
	BYTE				pbHash[20];
	PBYTE				pbSwapped;
	PBYTE				pbEncBlock;
	DWORD				cbEncBlock;
	BYTE				bPadding;
	DWORD				dwDataLen;
	DWORD				dwReturnCode;
	int					i;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSEncBlock" ) );

	if( pTLSSession->hCSP )
	{
		//
		// Sequence number starts at -1
		// and is incremented before use
		//
		( pTLSSession->dwSeqNum )++;

		//
		// Hash the seq_num
		//
		SW2_HostToWireFormat32( pTLSSession->dwSeqNum, (PBYTE) &( pbSeqNum[4] ) );

		//
		// First calculate the HMAC
		//
		cbTemp = sizeof( pbSeqNum ) + cbData;

		if ((dwReturnCode = SW2AllocateMemory(cbTemp, (PVOID*)&pbTemp))==NO_ERROR)
		{
			memcpy( pbTemp, pbSeqNum, sizeof( pbSeqNum ) );
			memcpy( pbTemp + sizeof( pbSeqNum ), pbData, cbData );

			dwReturnCode = TLS_HMAC( pTLSSession->hCSP, 
								pTLSSession->dwMacKey, 
								pTLSSession->pbWriteMAC, 
								pTLSSession->dwMacKeySize, 
								pbTemp, 
								cbTemp, 
								pbHash, 
								pTLSSession->dwMacKeySize );

			SW2FreeMemory((PVOID*)&pbTemp);
		}

		if( dwReturnCode == NO_ERROR )
		{
			//
			// Calculate the padding needed
			//
			//
			// Length of block-ciphered struct before padding
			// Length of Content(21-5=16) + MAC + 1(length byte)
			//
			bPadding = ( BYTE ) ( cbData - 5 + pTLSSession->dwMacKeySize + 1 ) % 8;

			if( ( int ) bPadding != 0 )
				bPadding = ( BYTE ) ( 8 - ( int ) bPadding );

			//
			// Total length of encrypted block is content(cbData) + MAC + Padding(2) +paddingLength(1)
			//
			cbEncBlock = cbData - 5 + pTLSSession->dwMacKeySize + ( ( int ) bPadding ) + 1;

			if ((dwReturnCode = SW2AllocateMemory(cbEncBlock, (PVOID*)&pbEncBlock))==NO_ERROR)
			{
				//
				// Copy the content block
				//
				memcpy( pbEncBlock, pbData + 5, cbData - 5 );

				//
				// Copy the HMAC, swapped because of little endian big endian thing
				//
				if ((dwReturnCode = SW2AllocateMemory(pTLSSession->dwMacKeySize, (PVOID*)&pbSwapped))==NO_ERROR)
				{
					SW2_SwapArray( pbHash, pbSwapped, pTLSSession->dwMacKeySize );

					memcpy( &( pbEncBlock[cbData-5] ), pbHash, pTLSSession->dwMacKeySize );

					//
					// The padding
					//
					for( i=0; i < ( int ) bPadding; i++ )
						pbEncBlock[cbData-5+pTLSSession->dwMacKeySize+i] = bPadding;

					//
					// Length of padding
					//
					pbEncBlock[cbData-5+pTLSSession->dwMacKeySize+( int )bPadding] = bPadding;

					dwDataLen = *pcbEncBlock = cbEncBlock;

					if ((dwReturnCode = SW2AllocateMemory(*pcbEncBlock, (PVOID*)ppbEncBlock))==NO_ERROR)
					{
						memcpy( *ppbEncBlock, pbEncBlock, cbEncBlock );

						if( !CryptEncrypt( pTLSSession->hWriteKey,
											0,
											FALSE,
											0,
											*ppbEncBlock,
											&dwDataLen,
											*pcbEncBlock ) )
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, 
								TEXT( "SW2_TRACE_LEVEL_ERROR::TLSEncBlock::CryptEncrypt:: FAILED (%ld)" ), GetLastError() );

							dwReturnCode = ERROR_ENCRYPTION_FAILED;

							SW2FreeMemory((PVOID*)ppbEncBlock);
						}
					}

					SW2FreeMemory((PVOID*)&pbSwapped);
				}

				SW2FreeMemory((PVOID*)&pbEncBlock);
			}
		}
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			TEXT( "SW2_TRACE_LEVEL_ERROR::TLSEncBlock::ERROR::no handle to help CSP" ) );

		dwReturnCode = ERROR_ENCRYPTION_FAILED;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::TLSEncBlock::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: TLSComputeMS
// Description: Compute the SSL Master Secret
//				Calling this function also removes the PMS from memory
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSComputeMS(	IN HCRYPTPROV				hCSP,
				IN PBYTE					pbRandomClient,
				IN PBYTE					pbRandomServer,
				IN OUT PBYTE				pbPMS,
				IN OUT PBYTE				pbMS )
{
	CHAR	pcLabel[] = "master secret";
	DWORD	cbLabel = sizeof( pcLabel ) - 1;
	BYTE	pbTemp[TLS_RANDOM_SIZE*2];
	DWORD	dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSComputeMS" ) );

	dwReturnCode = NO_ERROR;

	memcpy( pbTemp, pbRandomClient, TLS_RANDOM_SIZE );
	memcpy( pbTemp+TLS_RANDOM_SIZE, pbRandomServer, TLS_RANDOM_SIZE );

	dwReturnCode = TLS_PRF( hCSP, 
					pbPMS, 
					TLS_PMS_SIZE, 
					( PBYTE ) pcLabel, 
					cbLabel, 
					pbTemp, 
					sizeof( pbTemp ), 
					pbMS, 
					TLS_MS_SIZE );

	//
	// Get rid of pre master secret
	//
	memset( pbPMS, 0, TLS_PMS_SIZE );

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSComputeMS:: returning: %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: CreatePrivateExponentOneKey
// Description: Helper function for importing the SSL session keys
//				Tricks MS into importing clear text PKCS blobs
// Author: Tom Rixom
// Created: 17 December 2002
//
BOOL 
CreatePrivateExponentOneKey( HCRYPTPROV hProv, 
								  DWORD dwKeySpec,
                                  HCRYPTKEY *hPrivateKey)
{
   BOOL fReturn = FALSE;
   BOOL fResult;
   int n;
   LPBYTE keyblob = NULL;
   DWORD dwkeyblob;
   DWORD dwBitLen;
   BYTE *ptr;

   __try
   {
      *hPrivateKey = 0;

      if ((dwKeySpec != AT_KEYEXCHANGE) && (dwKeySpec != AT_SIGNATURE))  __leave;

	  // Generate the private key
      fResult = CryptGenKey(hProv, dwKeySpec, CRYPT_EXPORTABLE, hPrivateKey);
      if (!fResult) __leave;

      // Export the private key, we'll convert it to a private
      // exponent of one key
      fResult = CryptExportKey(*hPrivateKey, 0, PRIVATEKEYBLOB, 0, NULL, &dwkeyblob);
      if (!fResult) __leave;      

      keyblob = (LPBYTE)LocalAlloc(LPTR, dwkeyblob);
      if (!keyblob) __leave;

      fResult = CryptExportKey(*hPrivateKey, 0, PRIVATEKEYBLOB, 0, keyblob, &dwkeyblob);
      if (!fResult) __leave;


      CryptDestroyKey(*hPrivateKey);
      *hPrivateKey = 0;

      // Get the bit length of the key
      memcpy(&dwBitLen, &keyblob[12], 4);      

      // Modify the Exponent in Key BLOB format
      // Key BLOB format is documented in SDK

      // Convert pubexp in rsapubkey to 1
      ptr = &keyblob[16];
      for (n = 0; n < 4; n++)
      {
         if (n == 0) ptr[n] = 1;
         else ptr[n] = 0;
      }

      // Skip pubexp
      ptr += 4;
      // Skip modulus, prime1, prime2
      ptr += (dwBitLen/8);
      ptr += (dwBitLen/16);
      ptr += (dwBitLen/16);

      // Convert exponent1 to 1
      for (n = 0; ( DWORD ) n < (dwBitLen/16); n++)
      {
         if (n == 0) ptr[n] = 1;
         else ptr[n] = 0;
      }

      // Skip exponent1
      ptr += (dwBitLen/16);

      // Convert exponent2 to 1
      for (n = 0; ( DWORD ) n < (dwBitLen/16); n++)
      {
         if (n == 0) ptr[n] = 1;
         else ptr[n] = 0;
      }

      // Skip exponent2, coefficient
      ptr += (dwBitLen/16);
      ptr += (dwBitLen/16);

      // Convert privateExponent to 1
      for (n = 0; ( DWORD ) n < (dwBitLen/8); n++)
      {
         if (n == 0) ptr[n] = 1;
         else ptr[n] = 0;
      }
      
      // Import the exponent-of-one private key.      
      if (!CryptImportKey(hProv, keyblob, dwkeyblob, 0, 0, hPrivateKey))
      {                 
         __leave;
      }

      fReturn = TRUE;
   }
   __finally
   {
      if (keyblob) LocalFree(keyblob);

      if (!fReturn)
      {
         if (*hPrivateKey) CryptDestroyKey(*hPrivateKey);
      }
   }

   return fReturn;
}

//
// Name: GenerateSessionKeyWithAlgorithm
// Description: Helper function for importing the SSL session keys
// Author: Tom Rixom
// Created: 17 December 2002
//
BOOL 
GenerateSessionKeyWithAlgorithm(HCRYPTPROV hProv, 
                                     ALG_ID Alg,
                                     HCRYPTKEY *hSessionKey)
{   
   BOOL fResult;

   *hSessionKey = 0;

   fResult = CryptGenKey(hProv, Alg, CRYPT_EXPORTABLE, hSessionKey);
   if (!fResult)
   {
      return FALSE;
   }
   
   return TRUE;   
}

//
// Name: DeriveSessionKeyWithAlgorithm
// Description: Helper function for importing the SSL session keys
// Author: Tom Rixom
// Created: 17 December 2002
//
BOOL 
DeriveSessionKeyWithAlgorithm(HCRYPTPROV hProv, 
                                   ALG_ID Alg,
                                   LPBYTE lpHashingData,
                                   DWORD dwHashingData,
                                   HCRYPTKEY *hSessionKey)
{
   BOOL fResult;
   BOOL fReturn = FALSE;
   HCRYPTHASH hHash = 0;

   __try
   {
      *hSessionKey = 0;

      fResult = CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash);
      if (!fResult) __leave;

      fResult = CryptHashData(hHash, lpHashingData, dwHashingData, 0);
      if (!fResult) __leave;

      fResult = CryptDeriveKey(hProv, Alg, hHash, CRYPT_EXPORTABLE, hSessionKey);
      if (!fResult) __leave;

      fReturn = TRUE;
   }
   __finally
   {      
      if (hHash) CryptDestroyHash(hHash);
   }

   return fReturn;
}

//
// Name: ExportPlainSessionBlob
// Description: Helper function for exporting the SSL session key
// Author: Tom Rixom
// Created: 17 December 2002
//
BOOL 
ExportPlainSessionBlob(HCRYPTKEY hPublicKey,
                            HCRYPTKEY hSessionKey,
                            LPBYTE *pbKeyMaterial ,
                            DWORD *dwKeyMaterial )
{
   BOOL fReturn = FALSE;
   BOOL fResult;
   DWORD dwSize, n;
   LPBYTE pbSessionBlob = NULL;
   DWORD dwSessionBlob;
   LPBYTE pbPtr;

   __try
   {
      *pbKeyMaterial  = NULL;
      *dwKeyMaterial  = 0;

      fResult = CryptExportKey(hSessionKey, hPublicKey, SIMPLEBLOB,
                               0, NULL, &dwSessionBlob );
      if (!fResult) __leave;

      pbSessionBlob  = (LPBYTE)LocalAlloc(LPTR, dwSessionBlob );
      if (!pbSessionBlob) __leave;

      fResult = CryptExportKey(hSessionKey, hPublicKey, SIMPLEBLOB,
                               0, pbSessionBlob , &dwSessionBlob );
      if (!fResult) __leave;

      // Get session key size in bits
      dwSize = sizeof(DWORD);
      fResult = CryptGetKeyParam(hSessionKey, KP_KEYLEN, (LPBYTE)dwKeyMaterial, &dwSize, 0);
      if (!fResult) __leave;

      // Get the number of bytes and allocate buffer
      *dwKeyMaterial /= 8;
      *pbKeyMaterial = (LPBYTE)LocalAlloc(LPTR, *dwKeyMaterial);
      if (!*pbKeyMaterial) __leave;

      // Skip the header
      pbPtr = pbSessionBlob;
      pbPtr += sizeof(BLOBHEADER);
      pbPtr += sizeof(ALG_ID);

      // We are at the beginning of the key
      // but we need to start at the end since 
      // it's reversed
      pbPtr += (*dwKeyMaterial - 1);
      
      // Copy the raw key into our return buffer      
      for (n = 0; n < *dwKeyMaterial; n++)
      {
         (*pbKeyMaterial)[n] = *pbPtr;
         pbPtr--;
      }      
      
      fReturn = TRUE;
   }
   __finally
   {
      if (pbSessionBlob) LocalFree(pbSessionBlob);

      if ((!fReturn) && (*pbKeyMaterial ))
      {
         LocalFree(*pbKeyMaterial );
         *pbKeyMaterial  = NULL;
         *dwKeyMaterial  = 0;
      }
   }

   return fReturn;
}

//
// Name: ImportPlainSessionBlob
// Description: Helper function for importing the SSL session key
// Author: Tom Rixom
// Created: 17 December 2002
//
BOOL 
ImportPlainSessionBlob(HCRYPTPROV hProv,
                            HCRYPTKEY hPrivateKey,
                            ALG_ID dwAlgId,
                            LPBYTE pbKeyMaterial ,
                            DWORD dwKeyMaterial ,
                            HCRYPTKEY *hSessionKey)
{
	BOOL fResult;   
	BOOL fReturn = FALSE;
	BOOL fFound = FALSE;
	LPBYTE pbSessionBlob = NULL;
	DWORD dwSessionBlob, dwSize, n;
	DWORD dwPublicKeySize;
	DWORD dwProvSessionKeySize;
	ALG_ID dwPrivKeyAlg;
	LPBYTE pbPtr; 
	DWORD dwFlags = CRYPT_FIRST;
	PROV_ENUMALGS_EX ProvEnum;
	HCRYPTKEY hTempKey = 0;

	__try
	{
		// Double check to see if this provider supports this algorithm
		// and key size
		do
		{        
			 dwSize = sizeof(ProvEnum);
			 fResult = CryptGetProvParam(hProv, PP_ENUMALGS_EX, (LPBYTE)&ProvEnum,
										 &dwSize, dwFlags);
			 if (!fResult) break;

			 dwFlags = 0;

			 if (ProvEnum.aiAlgid == dwAlgId) fFound = TRUE;
                     
		} while (!fFound);

		if (!fFound) __leave;

		// We have to get the key size(including padding)
		// from an HCRYPTKEY handle.  PP_ENUMALGS_EX contains
		// the key size without the padding so we can't use it.
		fResult = CryptGenKey(hProv, dwAlgId, 0, &hTempKey);

		if( !fResult ) 
			__leave;

		dwSize = sizeof(DWORD);

		fResult = CryptGetKeyParam( hTempKey, KP_KEYLEN, ( LPBYTE ) &dwProvSessionKeySize, &dwSize, 0);

		if (!fResult) __leave;      
			CryptDestroyKey(hTempKey);

		hTempKey = 0;

		// Get private key's algorithm
		dwSize = sizeof(ALG_ID);
		fResult = CryptGetKeyParam(hPrivateKey, KP_ALGID, (LPBYTE)&dwPrivKeyAlg, &dwSize, 0);
		if (!fResult) __leave;

		// Get private key's length in bits
		dwSize = sizeof(DWORD);
		fResult = CryptGetKeyParam(hPrivateKey, KP_KEYLEN, (LPBYTE)&dwPublicKeySize, &dwSize, 0);
		if (!fResult) __leave;

		// calculate Simple blob's length
		dwSessionBlob = (dwPublicKeySize/8) + sizeof(ALG_ID) + sizeof(BLOBHEADER);

		// allocate simple blob buffer
		pbSessionBlob = (LPBYTE)LocalAlloc(LPTR, dwSessionBlob);
		if (!pbSessionBlob) __leave;

		pbPtr = pbSessionBlob;

		// SIMPLEBLOB Format is documented in SDK
		// Copy header to buffer
		((BLOBHEADER *)pbPtr)->bType = SIMPLEBLOB;
		((BLOBHEADER *)pbPtr)->bVersion = 2;
		((BLOBHEADER *)pbPtr)->reserved = 0;
		((BLOBHEADER *)pbPtr)->aiKeyAlg = dwAlgId;
		pbPtr += sizeof(BLOBHEADER);

		// Copy private key algorithm to buffer
		*((DWORD *)pbPtr) = dwPrivKeyAlg;
		pbPtr += sizeof(ALG_ID);

		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::reversing" ) );

		// Place the key material in reverse order
		for( n = 0; n < dwKeyMaterial; n++ )
		{
			pbPtr[n] = pbKeyMaterial[dwKeyMaterial-n-1];
		}

		// 3 is for the first reserved byte after the key material + the 2 reserved bytes at the end.
		dwSize = dwSessionBlob - (sizeof(ALG_ID) + sizeof(BLOBHEADER) + dwKeyMaterial + 3);
		pbPtr += (dwKeyMaterial+1);

		// Generate random data for the rest of the buffer
		// (except that last two bytes)
		fResult = CryptGenRandom(hProv, dwSize, pbPtr);
		if (!fResult) __leave;

		for (n = 0; n < dwSize; n++)
		{
			if (pbPtr[n] == 0) pbPtr[n] = 1;
		}

		pbSessionBlob[dwSessionBlob - 2] = 2;

		fResult = CryptImportKey(hProv, pbSessionBlob , dwSessionBlob, 
							   hPrivateKey, CRYPT_EXPORTABLE | CRYPT_NO_SALT, hSessionKey);
		if (!fResult) __leave;

		fReturn = TRUE;           
	}
	__finally
	{
		if (hTempKey) CryptDestroyKey(hTempKey);
		if (pbSessionBlob) LocalFree(pbSessionBlob);
	}
   
	return fReturn;
}

//
// Name: TLS_HMAC
// Description: Helper function for implementing TLS according to
//				http://www.ietf.org/rfc/rfc2104.txt
//				Functions are named to mirror function in RFC
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLS_HMAC( HCRYPTPROV hCSP,
			DWORD dwAlgID,
			IN PBYTE pbOrigKey, 
			IN DWORD cbOrigKey, 
			IN PBYTE pbSeed, 
			IN DWORD cbSeed, 
			PBYTE pbData, 
			DWORD cbData )
{
	HCRYPTHASH	hHash;
	PBYTE		pbKey;
	DWORD		cbKey;
	BYTE		pbK_ipad[64];    // inner padding - key XORd with ipad
	BYTE		pbK_opad[64];    // outer padding - key XORd with opad
	BYTE		pbTempKey[20];
	DWORD		cbTempKey;
	int			i;
	DWORD		dwReturnCode;

	dwReturnCode = NO_ERROR;

	if( dwAlgID == CALG_MD5 )
	{
		cbTempKey = 16;
	}
	else if( dwAlgID == CALG_SHA1 )
	{
		cbTempKey = 20;
	}
	else
		return ERROR_NOT_SUPPORTED;
	//
	// if key is longer than 64 bytes reset it to key=MD5(key)
	//
	memset( pbTempKey, 0, sizeof( pbTempKey ) );

	if( cbOrigKey > 64 )
	{
		if( CryptCreateHash( hCSP,
							dwAlgID,
							0,
							0,
							&hHash ) )
		{
			if( CryptHashData( hHash,
								pbOrigKey,
								cbOrigKey,
								0 ) )
			{
				if( CryptGetHashParam( hHash,
											HP_HASHVAL,
											pbTempKey,
											&cbTempKey,
											0 ) )
				{
					pbKey = pbTempKey;
					cbKey = cbTempKey;
				}
				else
				{
					dwReturnCode = ERROR_ENCRYPTION_FAILED;
				}
			}
			else
			{
				dwReturnCode = ERROR_ENCRYPTION_FAILED;
			}

			CryptDestroyHash( hHash );
		}
		else
		{
			dwReturnCode = ERROR_ENCRYPTION_FAILED;
		}
	}
	else
	{
		pbKey = pbOrigKey;
		cbKey = cbOrigKey;
	}

	if( dwReturnCode == NO_ERROR )
	{

		//
		// the HMAC_MD5 transform looks like:
		//
		// MD5(K XOR opad, MD5(K XOR ipad, text))
		//
		// where K is an n byte key
		// ipad is the byte 0x36 repeated 64 times
		// opad is the byte 0x5c repeated 64 times
		// and text is the data being protected
		//

		//
		// start out by storing key in pads
		//
		memset( pbK_ipad, 0, sizeof( pbK_ipad ) );
		memset( pbK_opad, 0, sizeof( pbK_opad ) );

		memcpy( pbK_ipad, pbKey, cbKey );
		memcpy( pbK_opad, pbKey, cbKey );

		//
		// XOR key with ipad and opad values
		//
		for( i=0; i<64; i++ ) 
		{
			pbK_ipad[i] ^= 0x36;
			pbK_opad[i] ^= 0x5c;
		}

		//
		// perform inner MD5
		//
		if( CryptCreateHash( hCSP,
							dwAlgID,
							0,
							0,
							&hHash ) )
		{
			if( CryptHashData( hHash,
								pbK_ipad,
								sizeof( pbK_ipad ),
								0 ) )
			{
				if( CryptHashData( hHash,
									pbSeed,
									cbSeed,
									0 ) )
				{
					if( !CryptGetHashParam( hHash,
												HP_HASHVAL,
												pbData,
												&cbData,
												0 ) )
					{
						dwReturnCode = ERROR_ENCRYPTION_FAILED;
					}
				}
				else
				{
					dwReturnCode = ERROR_ENCRYPTION_FAILED;
				}
			}
			else
			{
				dwReturnCode = ERROR_ENCRYPTION_FAILED;
			}

			CryptDestroyHash( hHash );
		}
		else
		{
			dwReturnCode = ERROR_ENCRYPTION_FAILED;
		}

		if( dwReturnCode == NO_ERROR )
		{
			//
			// perform outer MD5
			//
			if( CryptCreateHash( hCSP,
								dwAlgID,
								0,
								0,
								&hHash ) )
			{
				if( CryptHashData( hHash,
									pbK_opad,
									sizeof( pbK_opad ),
									0 ) )
				{
					if( CryptHashData( hHash,
										pbData,
										cbData,
										0 ) )
					{
						if( !CryptGetHashParam( hHash,
													HP_HASHVAL,
													pbData,
													&cbData,
													0 ) )
						{
							dwReturnCode = ERROR_ENCRYPTION_FAILED;
						}
					}
					else
					{
						dwReturnCode = ERROR_ENCRYPTION_FAILED;
					}
				}
				else
				{
					dwReturnCode = ERROR_ENCRYPTION_FAILED;
				}

				CryptDestroyHash( hHash );
			}
			else
			{
				dwReturnCode = ERROR_ENCRYPTION_FAILED;
			}
		}
	}

	return dwReturnCode;
}

//
// Name: TLS_P_hash
// Description: Helper function for implementing TLS according to
//				http://www.ietf.org/rfc/rfc2104.txt
//				Functions are named to mirror function in RFC
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLS_P_hash( IN HCRYPTPROV hCSP, 
			IN DWORD dwAlgID, 
			IN PBYTE pbSecret,
			IN DWORD cbSecret,
			IN PBYTE pbSeed,
			IN DWORD cbSeed,
			OUT PBYTE pbData, 
			IN DWORD cbData  )
{
	PBYTE		pbTemp;
	DWORD		cbTemp;
	BYTE		pbA[20];
	DWORD		cbA;
	PBYTE		pbBuf;
	DWORD		cbBuf;
	DWORD		dwMAC;
	DWORD		dwIterations;
	int			i;
    DWORD		dwReturnCode;

	dwReturnCode = NO_ERROR;

	if( dwAlgID == CALG_MD5 )
	{
		dwMAC = 16;
	}
	else if( dwAlgID == CALG_SHA1 )
	{
		dwMAC = 20;
	}
	else
		return ERROR_NOT_SUPPORTED;

	cbA = dwMAC;

	dwIterations = cbData / dwMAC;

	dwIterations = cbData % dwMAC == 0 ? dwIterations : dwIterations + 1;

	cbBuf = dwIterations * dwMAC;

	//
	// Create temporary buffer, must be at least big enough for dwMAC + cbSeed
	//
	cbTemp = dwMAC + cbSeed;

	if ((dwReturnCode = SW2AllocateMemory(cbTemp, (PVOID*)&pbTemp))==NO_ERROR)
	{
		//
		// Create buffer large enough for required material
		//
		if ((dwReturnCode = SW2AllocateMemory(cbBuf, (PVOID*)&pbBuf))==NO_ERROR)
		{
			memset( pbBuf, 0, cbBuf );

			//
			// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
			//						  HMAC_hash(secret, A(2) + seed) +
			//						  HMAC_hash(secret, A(3) + seed) + ...
			//
			// Where + indicates concatenation.
			//
			// A() is defined as:
			//		A(0) = seed
			//		A(i) = HMAC_hash(secret, A(i-1))
			//

			//
			// A(1) = P_MD5(secret, seed)
			//
			if( ( dwReturnCode = TLS_HMAC( hCSP, dwAlgID, pbSecret, cbSecret, pbSeed, cbSeed, pbA, cbA ) ) == NO_ERROR )
			{
				for( i=0; ( DWORD ) i < dwIterations; i++ )
				{
					//
					// P_MD5(secret, A(i) + seed )
					//
					memset( pbTemp, 0, cbTemp );
					memcpy( pbTemp, pbA, cbA );
					memcpy( pbTemp + cbA, pbSeed, cbSeed );
					cbTemp = cbA + cbSeed;

					if( ( dwReturnCode = TLS_HMAC( hCSP, dwAlgID, pbSecret, cbSecret, pbTemp, cbTemp, pbBuf + ( i * dwMAC ), dwMAC ) ) ==NO_ERROR )
					{
						//
						// A(i) = P_MD5(secret, a(i-1))
						//
						dwReturnCode = TLS_HMAC( hCSP, dwAlgID, pbSecret, cbSecret, pbA, cbA, pbA, cbA );
					}
		
					if( dwReturnCode != NO_ERROR )
						break;
				} // for

				//
				// Copy required data
				//
				if( dwReturnCode == NO_ERROR )
				{
					memcpy( pbData, pbBuf, cbData );
				}
			}

			SW2FreeMemory((PVOID*)&pbBuf);
		}

		SW2FreeMemory((PVOID*)&pbTemp);
	}

	return dwReturnCode;
}

//
// Name: TLS_PRF
// Description: Helper function for implementing TLS according to
//				http://www.ietf.org/rfc/rfc2104.txt
//				Functions are named to mirror function in RFC
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLS_PRF( IN HCRYPTPROV hCSP, 
		IN PBYTE pbSecret,
		IN DWORD cbSecret, 
		IN PBYTE pbLabel, 
		IN DWORD cbLabel, 
		IN PBYTE pbSeed,
		IN DWORD cbSeed,
		IN OUT PBYTE pbData,
		IN DWORD cbData )
{
	PBYTE		S1, S2;
	DWORD		L_S1, L_S2;
	PBYTE		pbMD5;
	PBYTE		pbSHA1;
	PBYTE		pbTemp;
	DWORD		cbTemp;
	int			i;
	DWORD		dwReturnCode;

	dwReturnCode = NO_ERROR;

	//
	// Split secret into two halves
	//
	if( cbSecret % 2 == 0 )
	{
		L_S1 = cbSecret / 2;
	}
	else 
	{
		L_S1 = cbSecret / 2 + 1;
	}

	L_S2 = L_S1;

	S1 = pbSecret;

	S2 = pbSecret + L_S1;

	//
	// Create clear exchange key
	//
	cbTemp = cbLabel + cbSeed;

	if ((dwReturnCode = SW2AllocateMemory(cbTemp, (PVOID*)&pbTemp))==NO_ERROR)
	{
		memcpy( pbTemp, pbLabel, cbLabel );
		memcpy( pbTemp + cbLabel, pbSeed, cbSeed );

		if ((dwReturnCode = SW2AllocateMemory(cbData, (PVOID*)&pbMD5))==NO_ERROR)
		{
			if( ( dwReturnCode = TLS_P_hash( hCSP, CALG_MD5, S1, L_S1, pbTemp, cbTemp, pbMD5, cbData ) ) == NO_ERROR )
			{
				if ((dwReturnCode = SW2AllocateMemory(cbData, (PVOID*)&pbSHA1))==NO_ERROR)
				{
					if( ( dwReturnCode = TLS_P_hash( hCSP, CALG_SHA1, S2, L_S2, pbTemp, cbTemp, pbSHA1, cbData ) ) == NO_ERROR )
					{
						//
						// Xor
						//
						for( i = 0; ( DWORD ) i < cbData; i ++ )
							pbData[i] = pbMD5[i] ^ pbSHA1[i];
					}

					SW2FreeMemory((PVOID*)&pbSHA1);
				}
			}

			SW2FreeMemory((PVOID*)&pbMD5);
		}

		SW2FreeMemory((PVOID*)&pbTemp);
	}

	return dwReturnCode;
}

//
// Name: TLSBuildResponsePacket
// Description: This function builds the next response message
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSBuildResponsePacket( IN PSW2_TLS_SESSION		pTLSSession,
					    IN BYTE					bPacketId,
						OUT PSW2EAPPACKET		pSendPacket,
						IN  DWORD               cbSendPacket,
						IN PSW2EAPOUTPUT		pEapOutput,
						IN BYTE					bEapProtocolId,
						IN BYTE					bFlags)
{
	PBYTE			pbTLSMessage;
	DWORD			cbTLSMessage;
	PBYTE			pbRecord;
	DWORD			cbRecord;
	PBYTE			pbEncPMS;
	DWORD			cbEncPMS;
	DWORD			dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSBuildResponsePacket" ) );

	dwReturnCode = NO_ERROR;

	switch( pTLSSession->TLSState )
	{
		case SW2_TLS_STATE_Start:

			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::TLSBuildResponsePacket::SW2_TLS_STATE_Start" ) );

			if( ( dwReturnCode = TLSInitTLSResponsePacket(bPacketId, 
															pSendPacket, 
															cbSendPacket,
															bEapProtocolId,
															bFlags) ) == NO_ERROR )
			{
				if( ( dwReturnCode = TLSMakeClientHelloMessage( pTLSSession->pbRandomClient,
														pTLSSession->pbTLSSessionID,
														pTLSSession->cbTLSSessionID,
														&pbTLSMessage, 
														&cbTLSMessage, 
														&pTLSSession->dwEncKey, 
														&pTLSSession->dwEncKeySize,
														&pTLSSession->dwMacKey,
														&pTLSSession->dwMacKeySize ) ) == NO_ERROR )
				{
					if( ( dwReturnCode = TLSMakeHandshakeRecord( pTLSSession,
															pbTLSMessage, 
															cbTLSMessage, 
															&pbRecord, 
															&cbRecord, 
															pTLSSession->bCipherSpec ) ) == NO_ERROR )
					{

						if( ( dwReturnCode = TLSAddMessage( pbRecord, 
													cbRecord, 
													cbRecord,
													pSendPacket, 
													cbSendPacket ) ) == NO_ERROR )
						{
							//
							// Save for later use with finished message
							//
							dwReturnCode = TLSAddHandshakeMessage( &( pTLSSession->dwHandshakeMsgCount ), 
													pTLSSession->pbHandshakeMsg,
													pTLSSession->cbHandshakeMsg,
													pbTLSMessage,
													cbTLSMessage );

							pEapOutput->eapAction = SW2EAPACTION_Send;

							pTLSSession->TLSState = SW2_TLS_STATE_Server_Hello;
						}

						SW2FreeMemory((PVOID*)&pbRecord);
						cbRecord = 0;
					}

					SW2FreeMemory((PVOID*)&pbTLSMessage);
					cbTLSMessage = 0;
				}
			}

		break;

		case SW2_TLS_STATE_Verify_Cert_UI:

			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::TLSBuildResponsePacket::SW2_TLS_STATE_Verify_Cert_UI" ) );

		case SW2_TLS_STATE_Server_Hello:

			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::TLSBuildResponsePacket::SW2_TLS_STATE_Server_Hello" ) );

			if( ( dwReturnCode = TLSInitTLSResponsePacket( bPacketId, 
													pSendPacket, 
													cbSendPacket,
													bEapProtocolId,
													bFlags) ) == NO_ERROR )
			{
				//
				// If a certificate was requested then respond with an empty certificate list
				//
				if( pTLSSession->bCertRequest )
				{
					//
					// Add certificate handshake record
					//
					if( ( dwReturnCode = TLSMakeClientCertificateMessage( &pbTLSMessage, 
																	&cbTLSMessage ) ) == NO_ERROR )
					{
						if( ( dwReturnCode = TLSMakeHandshakeRecord(pTLSSession, 
																pbTLSMessage, 
																cbTLSMessage, 
																&pbRecord, 
																&cbRecord, 
																pTLSSession->bCipherSpec ) ) == NO_ERROR )
						{
							if( ( dwReturnCode = TLSAddMessage( pbRecord, 
														cbRecord, 
														cbRecord,
														pSendPacket, 
														cbSendPacket ) ) == NO_ERROR )
							{
								dwReturnCode = TLSAddHandshakeMessage( &( pTLSSession->dwHandshakeMsgCount ), 
														pTLSSession->pbHandshakeMsg,
														pTLSSession->cbHandshakeMsg,
														pbTLSMessage, 
														cbTLSMessage );
							}

							SW2FreeMemory((PVOID*)&pbRecord);
							cbRecord = 0;
						}

						SW2FreeMemory((PVOID*)&pbTLSMessage);
						cbTLSMessage = 0;
					}
				}
				
				//
				// Add client key exchange handshake record
				//
				if( dwReturnCode == NO_ERROR )
				{
					//
					// Generate and encrypt the pre_master_secret or
					// ClientDiffieHellmanPublic
					//
					if( pTLSSession->pbCipher[0] == 0x00 &&
						pTLSSession->pbCipher[1] == 0x0A )
					{
						dwReturnCode = TLSGenRSAEncPMS( pTLSSession, &pbEncPMS, &cbEncPMS );
					}
					else if( pTLSSession->pbCipher[0] == 0x00 &&
							pTLSSession->pbCipher[1] == 0x13 )
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::TLSBuildResponsePacket::SW2_TLS_STATE_Server_Hello::Diffie Helman requested but not supported" ) );

						dwReturnCode = ERROR_NOT_SUPPORTED;
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::TLSBuildResponsePacket::SW2_TLS_STATE_Server_Hello::Unsupported cipher requested :%ld-%ld" ),
							pTLSSession->pbCipher[0], 
							pTLSSession->pbCipher[1] );
						//
						// Will never reach this point but....
						//
						dwReturnCode = ERROR_ENCRYPTION_FAILED;
					}

					if( dwReturnCode == NO_ERROR )
					{
						if( ( dwReturnCode = TLSComputeMS( pTLSSession->hCSP,
													pTLSSession->pbRandomClient,
													pTLSSession->pbRandomServer,
													pTLSSession->pbPMS,
													pTLSSession->pbMS ) ) == NO_ERROR )
						{
							if( ( dwReturnCode = TLSMakeClientKeyExchangeMessage( pbEncPMS, cbEncPMS, &pbTLSMessage, &cbTLSMessage ) ) == NO_ERROR )
							{
								if( ( dwReturnCode = TLSMakeHandshakeRecord( pTLSSession,
																		pbTLSMessage, 
																		cbTLSMessage, 
																		&pbRecord, 
																		&cbRecord, 
																		pTLSSession->bCipherSpec ) ) == NO_ERROR )
								{
									if( ( dwReturnCode = TLSAddMessage( pbRecord, 
																cbRecord, 
																cbRecord,
																pSendPacket, 
																cbSendPacket ) ) == NO_ERROR )
									{
										dwReturnCode = TLSAddHandshakeMessage( &( pTLSSession->dwHandshakeMsgCount ), 
																pTLSSession->pbHandshakeMsg,
																pTLSSession->cbHandshakeMsg,
																pbTLSMessage, 
																cbTLSMessage );
									}

									SW2FreeMemory((PVOID*)&pbRecord);
									cbRecord = 0;
								}

								SW2FreeMemory((PVOID*)&pbTLSMessage);
								cbTLSMessage = 0;
							}
						}

						SW2FreeMemory((PVOID*)&pbEncPMS);
						cbEncPMS = 0;
					}
				}

				//
				// Add change cipher spec record
				//
				if( dwReturnCode == NO_ERROR )
				{
					if( ( dwReturnCode = TLSMakeChangeCipherSpecRecord( &pbRecord, &cbRecord ) ) == NO_ERROR )
					{
						dwReturnCode = TLSAddMessage( pbRecord, 
												cbRecord, 
												cbRecord,
												pSendPacket, 
												cbSendPacket );

						SW2FreeMemory((PVOID*)&pbRecord);
						cbRecord  = 0;
					}
				}

				//
				// Change the cipher_spec
				//
				pTLSSession->bCipherSpec = TRUE;

				//
				// Add finished handshake record
				//
				if( dwReturnCode == NO_ERROR )
				{
					if( ( dwReturnCode = TLSDeriveKeys( pTLSSession ) ) == NO_ERROR )
					{
						if( ( dwReturnCode = TLSMakeFinishedMessage( pTLSSession,
																TLS_CLIENT_FINISHED_LABEL,
																sizeof( TLS_CLIENT_FINISHED_LABEL ) - 1,
																pTLSSession->pbMS,
																TLS_MS_SIZE,
																&pbTLSMessage, 
																&cbTLSMessage ) ) == NO_ERROR )
						{
							if( ( dwReturnCode = TLSMakeHandshakeRecord( pTLSSession,
																pbTLSMessage, 
																cbTLSMessage, 
																&pbRecord, 
																&cbRecord, 
																pTLSSession->bCipherSpec ) ) == NO_ERROR )
							{
								if( ( dwReturnCode = TLSAddMessage( pbRecord, 
															cbRecord, 
															cbRecord,
															pSendPacket, 
															cbSendPacket ) ) == NO_ERROR )
								{
									//
									// It is now safe add the client finished message needed to verify the 
									// server finished message
									//
									if( ( dwReturnCode = TLSAddHandshakeMessage( &( pTLSSession->dwHandshakeMsgCount ), 
																pTLSSession->pbHandshakeMsg,
																pTLSSession->cbHandshakeMsg,
																pbTLSMessage,
																cbTLSMessage ) ) == NO_ERROR )
									{
										//
										// We have sent our finished message!
										//
										pTLSSession->bSentFinished = TRUE;

										pEapOutput->eapAction = SW2EAPACTION_Send;

										pTLSSession->TLSState = SW2_TLS_STATE_Change_Cipher_Spec;
									}
								}

								SW2FreeMemory((PVOID*)&pbRecord);
								cbRecord = 0;
							}

							SW2FreeMemory((PVOID*)&pbTLSMessage);
							cbTLSMessage = 0;
						}
					}
				}
			}

		break;

		case SW2_TLS_STATE_Resume_Session:

			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::TLSBuildResponsePacket::SW2_TLS_STATE_Resume_Session" ) );

			if( ( dwReturnCode = TLSInitTLSResponsePacket( bPacketId, 
															pSendPacket, 
															cbSendPacket,
															bEapProtocolId,
															bFlags ) ) == NO_ERROR )
			{
				//
				// Add change cipher spec record
				//
				if( dwReturnCode == NO_ERROR )
				{
					if( ( dwReturnCode = TLSMakeChangeCipherSpecRecord( &pbRecord, &cbRecord ) ) == NO_ERROR )
					{
						dwReturnCode = TLSAddMessage( pbRecord, cbRecord, cbRecord, pSendPacket, cbSendPacket );

						SW2FreeMemory((PVOID*)&pbRecord);
						cbRecord  = 0;
					}
				}

				//
				// Add finished handhshake record
				//
				if( dwReturnCode == NO_ERROR )
				{
					if( ( dwReturnCode = TLSMakeFinishedMessage( pTLSSession,
																TLS_CLIENT_FINISHED_LABEL,
																sizeof( TLS_CLIENT_FINISHED_LABEL ) - 1,
																pTLSSession->pbMS,
																TLS_MS_SIZE,
																&pbTLSMessage, 
																&cbTLSMessage ) ) == NO_ERROR )
					{
						if( ( dwReturnCode = TLSMakeHandshakeRecord( pTLSSession,
																pbTLSMessage, 
																cbTLSMessage, 
																&pbRecord, 
																&cbRecord, 
																pTLSSession->bCipherSpec ) ) == NO_ERROR )
						{
							if( ( dwReturnCode = TLSAddMessage( pbRecord, 
														cbRecord, 
														cbRecord,
														pSendPacket, 
														cbSendPacket ) ) == NO_ERROR )
							{
								//
								// It is now safe add the client finished message needed to verify the 
								// server finished message
								//
								if( ( dwReturnCode = TLSAddHandshakeMessage( &( pTLSSession->dwHandshakeMsgCount ), 
																pTLSSession->pbHandshakeMsg,
																pTLSSession->cbHandshakeMsg,
																pbTLSMessage, 
																cbTLSMessage ) ) == NO_ERROR )
								{
									//
									// We have sent our finished message!
									//
									pTLSSession->bSentFinished = TRUE;

									pEapOutput->eapAction = SW2EAPACTION_Send;

									pTLSSession->TLSState = SW2_TLS_STATE_Resume_Session_Ack;
								}
							}

							SW2FreeMemory((PVOID*)&pbRecord);
							cbRecord = 0;
						}

						SW2FreeMemory((PVOID*)&pbTLSMessage);
						cbTLSMessage = 0;
					}
				}
			}
			
		break;

		case SW2_TLS_STATE_Resume_Session_Ack:

			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::TLSBuildResponsePacket::SW2_TLS_STATE_Resume_Session_Ack" ) );

			if( ( dwReturnCode = TLSMakeFragResponse( bPacketId, 
												pSendPacket, 
												cbSendPacket,
												bEapProtocolId,
												bFlags ) ) == NO_ERROR )
			{
				pEapOutput->eapAction = SW2EAPACTION_Send;

				pTLSSession->TLSState = SW2_TLS_STATE_Inner_Authentication;
			}

		break;

		case SW2_TLS_STATE_Change_Cipher_Spec:
		case SW2_TLS_STATE_Inner_Authentication:

			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::TLSBuildResponsePacket::SW2_TLS_STATE_Inner_Authentication" ) );

		break;

		default:

			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_INFO::TLSBuildResponsePacket::invalid state" ) );

			dwReturnCode = ERROR_PPP_INVALID_PACKET;

		break;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSBuildResponsePacket:: returning: %ld" ), dwReturnCode );

	return dwReturnCode;
}