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
// Name: TLSParseServerPacket
// Description: This function parses a server packet message and acts accordingly
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSParseServerPacket(IN PSW2_SESSION_DATA pSessionData)
{
	DWORD				dwRecordLength;
	DWORD				dwCursor = 0;
	PSW2_TLS_SESSION	pTLSSession = &(pSessionData->TLSSession);
	PBYTE				pbEAPMsg = pTLSSession->pbReceiveMsg;
	DWORD				cbEAPMsg = pTLSSession->cbReceiveMsg;
	PBYTE				pbRecord;
	DWORD				cbRecord;
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::TLSParseServerPacket" ) );

	//
	// Check for TTLS
	//
	while( ( dwCursor < cbEAPMsg ) && ( dwReturnCode == NO_ERROR ) )
	{
		//
		// ssl record header
		//
		if( pbEAPMsg[dwCursor] == 0x16 ) // handshake message
		{
			dwCursor++;

			//
			// Check major minor number
			//
			if( ( pbEAPMsg[dwCursor] = 0x03 ) && ( pbEAPMsg[dwCursor+1] == 0x01 ) )
			{		
				SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
					TEXT( "SW2_TRACE_LEVEL_DEBUG::TLSParseServerPacket::found handshake message" ) );

				dwCursor+=2;

				if( dwCursor > cbEAPMsg )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}

				dwRecordLength = SW2_WireToHostFormat16( &( pbEAPMsg[dwCursor] ) );

				dwCursor+=2;

				if( dwCursor > cbEAPMsg )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}

				if( pTLSSession->bCipherSpec )
				{
					if( ( dwReturnCode = TLSDecBlock( pTLSSession,
												&( pbEAPMsg[dwCursor] ), 
												dwRecordLength, 
												&pbRecord, 
												&cbRecord ) ) == NO_ERROR )
					{
						dwReturnCode = TLSParseHandshakeRecord( pTLSSession, pbRecord, cbRecord );

						SW2FreeMemory((PVOID*)&pbRecord);
						cbRecord = 0;
					}
				}
				else
					dwReturnCode = TLSParseHandshakeRecord( pTLSSession, &( pbEAPMsg[dwCursor] ), dwRecordLength );

				dwCursor+=dwRecordLength;
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT("SW2_TRACE_LEVEL_ERROR::TLSParseServerPacket::incorrect SSL version" ) );

				dwReturnCode = ERROR_PPP_INVALID_PACKET;
			}
		}
		else if( pbEAPMsg[dwCursor] == 0x14 ) // change_cipher_spec message
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
				TEXT("SW2_TRACE_LEVEL_DEBUG::TLSParseServerPacket::found changed cipher_spec message" ) );

			dwCursor++;

			if( dwCursor > cbEAPMsg )
			{
				dwReturnCode = ERROR_PPP_INVALID_PACKET;

				break;
			}

			//
			// Check major minor number
			//
			if( ( pbEAPMsg[dwCursor] = 0x03 ) && ( pbEAPMsg[dwCursor+1] == 0x01 ) )
			{			
				dwCursor+=2;

				if( dwCursor > cbEAPMsg )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}				
				
				dwRecordLength = SW2_WireToHostFormat16( &( pbEAPMsg[dwCursor] ) );

				dwCursor+=2;

				if( dwCursor > cbEAPMsg )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}

				if( pbEAPMsg[dwCursor] != 0x01 )
				{
					//
					// ChangeCypherSpec should be value 1 from now on 
					// indicating we are encrypting the line
					//
					pTLSSession->bCipherSpec = FALSE;

					dwReturnCode = ERROR_NO_REMOTE_ENCRYPTION;
				}
				else
				{
					//
					// If we receive a change_cipher_spec 1 from the server
					// and we are not in change_cipher_spec 1 mode this could
					// mean a session resumption
					// If we also want to resume a session then import the 
					// previous master_key and derive the encryption keys
					// (to read the server finished message)
					// and set the change_cipher_spec to 1
					//
					if( !pTLSSession->bCipherSpec )
					{
						if( pSessionData->ProfileData.bUseSessionResumption )
						{
							if( ( dwReturnCode = TLSDeriveKeys( pTLSSession ) ) == NO_ERROR )
								pTLSSession->bCipherSpec = TRUE;						
						}
						else
							dwReturnCode = ERROR_PPP_INVALID_PACKET;
					}

					dwCursor++;
				}
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT("SW2_TRACE_LEVEL_ERROR::TLSParseServerPacket::ERROR::incorrect SSL version" ) );

				dwReturnCode = ERROR_PPP_INVALID_PACKET;

				break;
			}
		} 
		else if( pbEAPMsg[dwCursor] == 0x17 ) // application data
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
				TEXT("SW2_TRACE_LEVEL_DEBUG::TLSParseServerPacket::application data" ) );

			dwCursor++;

			if( dwCursor > cbEAPMsg )
			{
				dwReturnCode = ERROR_PPP_INVALID_PACKET;

				break;
			}

			//
			// Check major minor number
			//
			if( ( pbEAPMsg[dwCursor] = 0x03 ) && ( pbEAPMsg[dwCursor+1] == 0x01 ) )
			{			
				dwCursor+=2;

				if( dwCursor > cbEAPMsg )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}				
				
				dwRecordLength = SW2_WireToHostFormat16( &( pbEAPMsg[dwCursor] ) );

				dwCursor+=2;

				if( dwCursor > cbEAPMsg )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}

				if( ( dwReturnCode = TLSDecBlock( pTLSSession, 
												&pbEAPMsg[dwCursor], 
												dwRecordLength, 
												&pbRecord, 
												&cbRecord ) ) == NO_ERROR )
				{
					//
					// When in MS mode then we must add the (stripped) EAP headers
					//

					SW2Dump( SW2_TRACE_LEVEL_DEBUG, pbRecord, cbRecord);

					if( cbRecord <= TLS_MAX_EAPMSG )
					{
						if (pSessionData->bCurrentMethodVersion == 0)
						{
							//
							// When in MS PEAPv0 mode then we must add the (stripped) EAP headers
							//

							//
							// But of course extensions are not stripped... so we skip them
							//
							if (cbRecord >= 5 && pbRecord[4] == 0x21)
							{
								//
								// Handle normally
								//
								pTLSSession->cbInnerEapMessage = cbRecord;

								memset( pTLSSession->pbInnerEapMessage, 0, sizeof( pTLSSession->pbInnerEapMessage ) );
								memcpy( pTLSSession->pbInnerEapMessage, pbRecord, pTLSSession->cbInnerEapMessage );
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
									TEXT("SW2_TRACE_LEVEL_DEBUG::TLSParseServerPacket::PEAPV0, adding stripped EAP headers" ) );

								pTLSSession->cbInnerEapMessage = 0x04 + cbRecord;

								memset( pTLSSession->pbInnerEapMessage, 0, sizeof( pTLSSession->pbInnerEapMessage ) );

								//
								// Request
								//
								pTLSSession->pbInnerEapMessage[0] = 0x01; // Code
								pTLSSession->pbInnerEapMessage[1] = pSessionData->bPacketId; // Id
								SW2_HostToWireFormat16( ( DWORD ) pTLSSession->cbInnerEapMessage, &( pTLSSession->pbInnerEapMessage[2] ) ); // length

								memcpy( &( pTLSSession->pbInnerEapMessage[4] ), pbRecord, cbRecord );
							}
						}
						else
						{
							pTLSSession->cbInnerEapMessage = cbRecord;

							memset( pTLSSession->pbInnerEapMessage, 0, sizeof( pTLSSession->pbInnerEapMessage ) );
							memcpy( pTLSSession->pbInnerEapMessage, pbRecord, pTLSSession->cbInnerEapMessage );
						}
					}
					else
					{
						dwReturnCode = ERROR_PPP_INVALID_PACKET;
					}

					SW2FreeMemory((PVOID*)&pbRecord);
					cbRecord = 0;
				}
				else
				{
					if( dwReturnCode == ERROR_PPP_INVALID_PACKET )
						dwReturnCode = NO_ERROR;
					else
						break;
				}

				dwCursor = dwCursor + dwRecordLength;
			}
			else
			{
				dwReturnCode = ERROR_PPP_INVALID_PACKET;

				break;
			}
		}
		else if( pbEAPMsg[dwCursor] == 0x18 ) // inner application data
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
				TEXT("SW2_TRACE_LEVEL_DEBUG::TLSParseServerPacket::innner application data" ) );

			dwCursor++;

			if( dwCursor > cbEAPMsg )
			{
				dwReturnCode = ERROR_PPP_INVALID_PACKET;

				break;
			}

			//
			// Check major minor number
			//
			if( ( pbEAPMsg[dwCursor] = 0x03 ) && ( pbEAPMsg[dwCursor+1] == 0x01 ) )
			{			
				dwCursor++;
				dwCursor++;

				if( dwCursor > cbEAPMsg )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}				
				
				dwRecordLength = SW2_WireToHostFormat16( &( pbEAPMsg[dwCursor] ) );

				dwCursor++;
				dwCursor++;

				if( dwCursor > cbEAPMsg )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}

				if( ( dwReturnCode = TLSDecBlock( pTLSSession, 
												&pbEAPMsg[dwCursor], 
												dwRecordLength, 
												&pbRecord, 
												&cbRecord ) ) == NO_ERROR )
				{
					dwReturnCode = TLSParseInnerApplicationDataRecord( pTLSSession, pbRecord, cbRecord );

					SW2FreeMemory((PVOID*)&pbRecord);
					cbRecord = 0;
				}
				else
				{
					if( dwReturnCode == ERROR_PPP_INVALID_PACKET )
						dwReturnCode = NO_ERROR;
					else
						break;
				}

				dwCursor = dwCursor + dwRecordLength;
			}
			else
			{
				dwReturnCode = ERROR_PPP_INVALID_PACKET;

				break;
			}
		}
		else if( pbEAPMsg[dwCursor] == 0x15 ) // alert!
		{
			SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
				TEXT("SW2_TRACE_LEVEL_DEBUG::TLSParseServerPacket::SSL alert data" ) );

			dwCursor++;

			if( dwCursor > cbEAPMsg )
			{
				dwReturnCode = ERROR_PPP_INVALID_PACKET;

				break;
			}

			//
			// Check major minor number
			//
			if( ( pbEAPMsg[dwCursor] = 0x03 ) && ( pbEAPMsg[dwCursor+1] == 0x01 ) )
			{			
				dwCursor++;
				dwCursor++;

				if( dwCursor > cbEAPMsg )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}				
				
				dwRecordLength = SW2_WireToHostFormat16( &( pbEAPMsg[dwCursor] ) );

				dwCursor++;
				dwCursor++;

				if( dwCursor > cbEAPMsg )
				{
					dwReturnCode = ERROR_PPP_INVALID_PACKET;

					break;
				}

				SW2Trace( SW2_TRACE_LEVEL_DEBUG, TEXT( "SW2_TRACE_LEVEL_DEBUG::TLSParseServerPacket::alert data (%ld)" ), dwRecordLength );
				SW2Dump( SW2_TRACE_LEVEL_DEBUG, &pbEAPMsg[dwCursor], dwRecordLength );

				pTLSSession->bFoundAlert;

				dwReturnCode = ERROR_NOT_AUTHENTICATED;

				dwCursor = dwCursor + dwRecordLength;
			}
			else
			{
				dwReturnCode = ERROR_PPP_INVALID_PACKET;

				break;
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_ERROR::TLSParseServerPacket::unknown SSL record: %x" ), pbEAPMsg[dwCursor] );

			dwReturnCode = ERROR_PPP_INVALID_PACKET;
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::TLSParseServerPacket::returning: %ld" ), dwReturnCode );

	return dwReturnCode;
}