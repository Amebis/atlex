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
// Name: AuthHandleInnerEAPAuthentication
// Description: This function is called when the TLS tunnel has been 
// setup and the inner authentication must be done using EAPHost
// Author: Tom Rixom
// Created: 26 Juli 2007
//
DWORD
AuthHandleInnerEAPHOSTAuthentication(IN PSW2_SESSION_DATA	pSessionData,
									 IN PSW2EAPPACKET		pSendPacket,
									 IN DWORD               cbSendPacket,
									 IN	PSW2EAPOUTPUT		pEapOutput )
{
#ifndef SW2_EAP_HOST
	return ERROR_NOT_SUPPORTED;
#else
	EapPacket					*pInnerEapHostReceivePacket;
	DWORD						dwSizeOfInnerEapHostReceivePacket;
	EapPacket					*pInnerEapHostSendPacket;
	DWORD						dwSizeOfInnerEapHostSendPacket;
	EapHostPeerResponseAction	eapHostPeerResponseAction;
	EAP_ERROR					*pEapError = NULL;
	PBYTE						pbUIContextData;
	DWORD						cbUIContextData;
	BYTE				pbMA[] = { 0x00, 0x00, 0x00, 0x00, 
									0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00 };
	PBYTE				pbAVP;
	DWORD				cbAVP;
	PBYTE				pbMAAVP;
	DWORD				cbMAAVP;
	PBYTE				pbEAPAVP;
	DWORD				cbEAPAVP;
	PBYTE				pbStateAVP;
	DWORD				cbStateAVP;
	PBYTE				pbEAPAttribute;
	DWORD				cbEAPAttribute;
	PCHAR				pcInnerEapIdentity;
	DWORD				ccInnerEapIdentity;
	PBYTE				pbRecord;
	DWORD				cbRecord;
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPHOSTAuthentication" ) );

	switch( pSessionData->InnerSessionData.InnerEapState )
	{
		case SW2_INNER_EAP_STATE_Start:

			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPHOSTAuthentication::SW2_INNER_EAP_STATE_Start" ) );

			//
			// Build the AVPS for EAP
			//
			ccInnerEapIdentity = ( DWORD ) wcslen( pSessionData->UserData.InnerEapUserData.pwcIdentity );

			!!if( ( pcInnerEapIdentity = ( PCHAR ) malloc( ccInnerEapIdentity + 1 ) ) )
			{
				WideCharToMultiByte( CP_ACP, 0, pSessionData->UserData.InnerEapUserData.pwcIdentity, -1, pcInnerEapIdentity, ccInnerEapIdentity + 1, NULL, NULL );
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPHOSTAuthentication::not enough memory" ) );

				dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
			}

			if( dwReturnCode == NO_ERROR )
			{
				if( ( dwReturnCode = AuthMakeEAPResponseAttribute( 0x01, 0x00, ( PBYTE ) pcInnerEapIdentity, ccInnerEapIdentity, &pbEAPAttribute, &cbEAPAttribute ) ) == NO_ERROR )
				{
					if( ( dwReturnCode = AuthMakeDiameterAttribute( 0x4F, pbEAPAttribute, cbEAPAttribute, &pbEAPAVP, &cbEAPAVP ) ) == NO_ERROR )
					{
						//
						// Add empty message authenticator
						//
						if( ( dwReturnCode = AuthMakeDiameterAttribute( 0x50, 
																pbMA, 
																sizeof( pbMA ), 
																&pbMAAVP, 
																&cbMAAVP ) ) == NO_ERROR )
						{
							cbAVP = cbEAPAVP + cbMAAVP;

							!!if( ( pbAVP = ( PBYTE ) malloc( cbAVP ) ) )
							{
								memcpy( pbAVP, pbEAPAVP, cbEAPAVP );
								memcpy( pbAVP + cbEAPAVP, pbMAAVP, cbMAAVP );

								if( ( dwReturnCode = TLSMakeApplicationRecord( pSessionData->hCSP, 
																		pSessionData->hWriteKey,
																		pSessionData->dwMacKey,
																		pSessionData->dwMacKeySize,
																		pSessionData->pbWriteMAC,
																		&( pSessionData->dwSeqNum ),
																		pbAVP, 
																		cbAVP, 
																		&pbRecord, 
																		&cbRecord, 
																		pSessionData->bCipherSpec ) ) == NO_ERROR )
								{
									dwReturnCode = TLSAddMessage(	pbRecord, 
															cbRecord, 
															cbRecord,
															pSendPacket, 
															cbSendPacket );

									pEapOutput->Action = EAPACTION_Send;

									pSessionData->InnerSessionData.InnerEapState = SW2_INNER_EAP_STATE_MakeMessage;

									SW2FreeMemory((PVOID*)&pbRecord);
									cbRecord = 0;
								}

								SW2FreeMemory((PVOID*)&pbAVP);
								cbAVP = 0;
							}
							else
								dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;

							SW2FreeMemory((PVOID*)&pbMAAVP);
							cbMAAVP = 0;
						}


						SW2FreeMemory((PVOID*)&pbEAPAVP);
						cbEAPAVP = 0;
					}

					SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPHOSTAuthentication::freeing pbEAPAttribute" ) );

					SW2FreeMemory((PVOID*)&pbEAPAttribute);
					cbEAPAttribute = 0;
				}

				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPHOSTAuthentication::freeing pcInnerEapIdentity" ) );

				SW2FreeMemory((PVOID*)&pcInnerEapIdentity);
				ccInnerEapIdentity= 0;
			}

		break;

		case SW2_INNER_EAP_STATE_MakeMessage:

			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPHOSTAuthentication::SW2_INNER_EAP_STATE_MakeMessage" ) );

			if( pSessionData->TLSSession.pbInnerEapMessage )
			{
				pInnerEapHostReceivePacket = ( EapPacket *) pSessionData->TLSSession.pbInnerEapMessage;
				
				dwSizeOfInnerEapHostReceivePacket = SW2_WireToHostFormat16( pInnerEapHostReceivePacket->Length );

				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication::SW2_INNER_EAP_STATE_MakeMessage:pInnerEapHostReceivePacket(%ld)" ), 
					dwSizeOfInnerEapHostReceivePacket );
				SW2Dump( SW2_TRACE_LEVEL_DEBUG,  ( PBYTE ) pInnerEapHostReceivePacket, dwSizeOfInnerEapHostReceivePacket );

				//
				// Let's see what is in the packet
				//
				switch( pInnerEapHostReceivePacket->Code )
				{
					case EAPCODE_Request:

						SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPHOSTAuthentication::SW2_INNER_EAP_STATE_MakeMessage::EAPCODE_Request" ) );

					case EAPCODE_Success:

						SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPHOSTAuthentication::SW2_INNER_EAP_STATE_MakeMessage::EAPCODE_Success" ) );

					case EAPCODE_Failure:
						
						SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPHOSTAuthentication::SW2_INNER_EAP_STATE_MakeMessage::EAPCODE_Failure" ) );

						if( pInnerEapHostReceivePacket->Data[0] != 
							pSessionData->InnerSessionData.pInnerEapConfigData->eapMethodType.eapType.type )
						{
							//
							// Not for our Inner EAP DLL so send NAK request for our auth type
							//
							SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPHOSTAuthentication::request for %x" ), pInnerEapHostReceivePacket->Data[0] );

							if( ( dwReturnCode = AuthMakeEAPResponseAttribute( 0x03, 
										pInnerEapHostReceivePacket->Id, 
										( PBYTE ) &( pSessionData->InnerSessionData.pInnerEapConfigData->eapMethodType.eapType.type ), 
										1, 
										&pbEAPAttribute, 
										&cbEAPAttribute ) ) == NO_ERROR )
							{
								//
								// Add EAP Message
								//
								if( ( dwReturnCode = AuthMakeDiameterAttribute( 0x4F, pbEAPAttribute, cbEAPAttribute, &pbEAPAVP, &cbEAPAVP ) ) == NO_ERROR )
								{
									//
									// Add empty message authenticator
									//
									if( ( dwReturnCode = AuthMakeDiameterAttribute( 0x50, 
																			pbMA, 
																			sizeof( pbMA ), 
																			&pbMAAVP, 
																			&cbMAAVP ) ) == NO_ERROR )
									{
										if( pSessionData->TLSSession.cbState > 0 )
										{
											//
											// Copy state attribute into response
											//
											if( ( dwReturnCode = AuthMakeDiameterAttribute( 0x18, 
																			pSessionData->TLSSession.pbState, 
																			pSessionData->TLSSession.cbState, 
																			&pbStateAVP, 
																			&cbStateAVP ) ) == NO_ERROR )
											{
												cbAVP = cbEAPAVP + cbMAAVP + cbStateAVP;

												!!if( ( pbAVP = ( PBYTE ) malloc( cbAVP ) ) )
												{
													memcpy( pbAVP, pbEAPAVP, cbEAPAVP );
													memcpy( pbAVP + cbEAPAVP, pbMAAVP, cbMAAVP );
													memcpy( pbAVP + cbEAPAVP + cbMAAVP, pbStateAVP, cbStateAVP );
												}
												else
													dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
											}
										}
										else
										{
											//
											// copy only EAP-MESSAGE and Message Authenticator
											//
											cbAVP = cbEAPAVP + cbMAAVP;

											!!if( ( pbAVP = ( PBYTE ) malloc( cbAVP ) ) )
											{
												memcpy( pbAVP, pbEAPAVP, cbEAPAVP );
												memcpy( pbAVP + cbEAPAVP, pbMAAVP, cbMAAVP );
											}
											else
												dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
										}

										if( dwReturnCode == NO_ERROR )
										{
											if( ( dwReturnCode = TLSMakeApplicationRecord( pSessionData->hCSP, 
																					pSessionData->hWriteKey,
																					pSessionData->dwMacKey,
																					pSessionData->dwMacKeySize,
																					pSessionData->pbWriteMAC,
																					&( pSessionData->dwSeqNum ),
																					pbAVP, 
																					cbAVP, 
																					&pbRecord, 
																					&cbRecord, 
																					pSessionData->bCipherSpec ) ) == NO_ERROR )
											{
												dwReturnCode = TLSAddMessage(	pbRecord, 
																		cbRecord, 
																		cbRecord,
																		pSendPacket, 
																		cbSendPacket );

												pEapOutput->Action = EAPACTION_Send;

												pSessionData->InnerSessionData.InnerEapState = SW2_INNER_EAP_STATE_MakeMessage;

												SW2FreeMemory((PVOID*)&pbRecord);
												cbRecord = 0;
											}

											SW2FreeMemory((PVOID*)&pbAVP);
											cbAVP = 0;
										}

										SW2FreeMemory((PVOID*)&pbMAAVP);
										cbMAAVP = 0;
									}

									SW2FreeMemory((PVOID*)&pbEAPAVP);
									cbEAPAVP = 0;
								}

								SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPHOSTAuthentication::freeing pbEAPAttribute" ) );

								SW2FreeMemory((PVOID*)&pbEAPAttribute);
								cbEAPAttribute = 0;
							}
						}

					break;

					case EAPCODE_Response:

					default:

						dwReturnCode  = ERROR_PPP_INVALID_PACKET;

					break;
				}
			}
			else
			{
				pInnerEapHostReceivePacket = NULL;
				dwSizeOfInnerEapHostReceivePacket = 0;
			}

			//
			// If we haven't sent anything yet and no error has occured then continue
			//
			if( ( pEapOutput->Action != EAPACTION_Send ) && 
				( dwReturnCode == NO_ERROR ) )
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPHOSTAuthentication::building sendpacket" ) );

				if( ( dwReturnCode = EapHostPeerProcessReceivedPacket(
						pSessionData->InnerSessionData.eapSessionId,//Session Id	
						dwSizeOfInnerEapHostReceivePacket,			//Length of the Packet
						(PBYTE) pInnerEapHostReceivePacket,			//Packet
						&eapHostPeerResponseAction,					//EapHostPeerResponseAction
						&pEapError
						) ) == NO_ERROR )
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPHOSTAuthentication::EapHostPeerResponseAction: %ld" ), eapHostPeerResponseAction );
					
					switch( eapHostPeerResponseAction )
					{
						case EapHostPeerResponseInvokeUi:

							SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::RasEapGetEAPHOSTIdentity::EapHostPeerResponseInvokeUi" ) );

							cbUIContextData = 0;

							if( ( dwReturnCode = EapHostPeerGetUIContext(
											pSessionData->InnerSessionData.eapSessionId,
											&cbUIContextData,
											&pbUIContextData,
											&pEapError ) ) == NO_ERROR )
							{
								pEapOutput->fInvokeInteractiveUI = TRUE;

								pSessionData->bInteractiveUIType = UI_TYPE_INNER_EAPHOST;

								pSessionData->InnerSessionData.InnerEapState = SW2_INNER_EAP_STATE_InteractiveUI;

								//
								// Copy Inner UI Context Data
								// 
								if( cbUIContextData <= EAP_MAX_INNER_UI_DATA )
								{
									pSessionData->cbInnerUIContextData = cbUIContextData;

									memcpy( pSessionData->pbInnerUIContextData,
											pbUIContextData,
											cbUIContextData );

									pEapOutput->pUIContextData = ( PBYTE ) pSessionData;

									pEapOutput->dwSizeOfUIContextData = 
															sizeof( SW2_SESSION_DATA );

									pEapOutput->Action = EAPACTION_NoAction;
								}
								else
									dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
								}
							else
							{
								if( pEapError )
									EapHostPeerFreeEapError( pEapError );
							}

						break;

						case EapHostPeerResponseSend:
							
							SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::RasEapGetEAPHOSTIdentity::EapHostPeerResponseSend" ) );

							dwSizeOfInnerEapHostSendPacket = 0;

							if( ( dwReturnCode = EapHostPeerGetSendPacket(
											pSessionData->InnerSessionData.eapSessionId, 
											&dwSizeOfInnerEapHostSendPacket,
											( PBYTE * ) &pInnerEapHostSendPacket,
											&pEapError ) ) == NO_ERROR )
							{
								SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::RasEapGetEAPHOSTIdentity::EapHostPeerGetSendPacket succeeded, sending packet(%ld):" ), dwSizeOfInnerEapHostSendPacket );
								SW2Dump( SW2_TRACE_LEVEL_DEBUG,  ( PBYTE ) pInnerEapHostSendPacket, dwSizeOfInnerEapHostSendPacket );

								//
								// Build response attribute
								//
								if( ( dwReturnCode = AuthMakeDiameterAttribute( 0x4F, ( PBYTE ) pInnerEapHostSendPacket, SW2_WireToHostFormat16( pInnerEapHostSendPacket->Length ), &pbEAPAVP, &cbEAPAVP ) ) == NO_ERROR )
								{
									//
									// Add empty message authenticator
									//
									if( ( dwReturnCode = AuthMakeDiameterAttribute( 0x50, 
																			pbMA, 
																			sizeof( pbMA ), 
																			&pbMAAVP, 
																			&cbMAAVP ) ) == NO_ERROR )
									{
										if( pSessionData->TLSSession.cbState > 0 )
										{
											//
											// Copy state attribute into response
											//
											if( ( dwReturnCode = AuthMakeDiameterAttribute( 0x18, 
																			pSessionData->TLSSession.pbState, 
																			pSessionData->TLSSession.cbState, 
																			&pbStateAVP, 
																			&cbStateAVP ) ) == NO_ERROR )
											{
												cbAVP = cbEAPAVP + cbMAAVP + cbStateAVP;

												!!if( ( pbAVP = ( PBYTE ) malloc( cbAVP ) ) )
												{
													memcpy( pbAVP, pbEAPAVP, cbEAPAVP );
													memcpy( pbAVP + cbEAPAVP, pbMAAVP, cbMAAVP );
													memcpy( pbAVP + cbEAPAVP + cbMAAVP, pbStateAVP, cbStateAVP );
												}
												else
													dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
											}
										}
										else
										{
											//
											// copy only EAP-MESSAGE and Message Authenticator
											//
											cbAVP = cbEAPAVP + cbMAAVP;

											!!if( ( pbAVP = ( PBYTE ) malloc( cbAVP ) ) )
											{
												memcpy( pbAVP, pbEAPAVP, cbEAPAVP );
												memcpy( pbAVP + cbEAPAVP, pbMAAVP, cbMAAVP );
											}
											else
												dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
										}

										if( dwReturnCode == NO_ERROR )
										{
											if( ( dwReturnCode = TLSMakeApplicationRecord( pSessionData->hCSP, 
																					pSessionData->hWriteKey,
																					pSessionData->dwMacKey,
																					pSessionData->dwMacKeySize,
																					pSessionData->pbWriteMAC,
																					&( pSessionData->dwSeqNum ),
																					pbAVP, 
																					cbAVP, 
																					&pbRecord, 
																					&cbRecord, 
																					pSessionData->bCipherSpec ) ) == NO_ERROR )
											{
												dwReturnCode = TLSAddMessage(	pbRecord, 
																		cbRecord, 
																		cbRecord,
																		pSendPacket, 
																		cbSendPacket );

												pEapOutput->Action = EAPACTION_Send;

												pSessionData->InnerSessionData.InnerEapState = SW2_INNER_EAP_STATE_MakeMessage;

												SW2FreeMemory((PVOID*)&pbRecord);
												cbRecord = 0;
											}

											SW2FreeMemory((PVOID*)&pbAVP);
											cbAVP = 0;
										}

										SW2FreeMemory((PVOID*)&pbMAAVP);
										cbMAAVP = 0;
									}

									SW2FreeMemory((PVOID*)&pbEAPAVP);
									cbEAPAVP = 0;
								}
							}
							else
							{
								if( pEapError )
									EapHostPeerFreeEapError( pEapError );
							}

						break;

						default:

							dwReturnCode = ERROR_NOT_SUPPORTED;

						break;
					}
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPHOSTAuthentication::pInnerEapHostReceivePacket FAILED: %ld" ), dwReturnCode );

					if( pEapError )
						EapHostPeerFreeEapError( pEapError );
				}
			}

		break;

		case SW2_INNER_EAP_STATE_Finished:

			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPHOSTAuthentication::SW2_INNER_EAP_STATE_Finished" ) );

			//
			// should never get here
			//
			dwReturnCode = ERROR_PPP_INVALID_PACKET;

		break;

		default:

			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPHOSTAuthentication::unknown inner authentication state" ) );

			dwReturnCode = ERROR_PPP_INVALID_PACKET;

		break;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPHOSTAuthentication::returning, action: %x, authcode: %x, error: %x" ), pEapOutput->Action, pEapOutput->dwAuthResultCode, dwReturnCode );

	return dwReturnCode;
#endif // SW2_EAP_HOST
}

//
// Name: AuthHandleInnerEAPAuthentication
// Description: This function is called when the TLS tunnel has been 
// setup and the inner authentication must be done using EAP
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
AuthHandleInnerEAPAuthentication(IN PSW2_SESSION_DATA	pSessionData,
								 IN PSW2EAPPACKET		pSendPacket,
								 IN DWORD               cbSendPacket,
								 IN	PSW2EAPOUTPUT		pEapOutput )
{
	PPP_EAP_PACKET		*pInnerEapReceivePacket;
	PPP_EAP_PACKET		*pInnerEapSendPacket;
	DWORD				cbInnerEapSendPacket;
	PPP_EAP_OUTPUT		InnerEapOutput;
	BYTE				pbMA[] = { 0x00, 0x00, 0x00, 0x00, 
									0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00 };
	PBYTE				pbEAPAttribute;
	DWORD				cbEAPAttribute;
	PCHAR				pcInnerEapIdentity;
	DWORD				ccInnerEapIdentity;
	PBYTE				pbRecord;
	DWORD				cbRecord;
	BYTE				pbExtensionPacket[] = { 0x03, // eap extension type
												0x00, 0x02, // eap extension length value
												0x00, 0x00 }; // value (success/failure) 
	DWORD				dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication" ) );

	//
	// Reset InteractiveUI every time we get a InnerMakeMessage
	//
	pSessionData->InnerSessionData.InnerEapInput.fDataReceivedFromInteractiveUI = FALSE;

	pSessionData->InnerSessionData.InnerEapInput.dwSizeOfDataFromInteractiveUI = 0;

	switch( pSessionData->InnerSessionData.InnerEapState )
	{
		case SW2_INNER_EAP_STATE_Start:

			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication::SW2_INNER_EAP_STATE_Start" ) );

			//
			// Build initial packet for the EAP method, which is an EMPTY packet
			//
			pEapOutput->eapAction = SW2EAPACTION_Send;

			pSessionData->InnerSessionData.InnerEapState = SW2_INNER_EAP_STATE_Identity;

		break;

		case SW2_INNER_EAP_STATE_Identity:

			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication::SW2_INNER_EAP_STATE_Identity" ) );

			if (pSessionData->TLSSession.cbInnerEapMessage > 0)
			{
				if ((pInnerEapReceivePacket = ( PPP_EAP_PACKET *) pSessionData->TLSSession.pbInnerEapMessage ) )
				{				
					//
					// Let's see what is in the packet
					//
					switch( pInnerEapReceivePacket->Code )
					{
						case EAPCODE_Request:

							// should be an Identity packet
							if( pInnerEapReceivePacket->Data[0] == 1)
							{
								if( ( pEapOutput->eapAction != SW2EAPACTION_Send ) 
									&& ( dwReturnCode == NO_ERROR ) )
								{
									//
									// Build the identity AVP for EAP
									//
									ccInnerEapIdentity = ( DWORD ) 
										wcslen( pSessionData->UserData.InnerEapUserData.pwcIdentity );

									if ((dwReturnCode = SW2AllocateMemory(ccInnerEapIdentity + 1, (PVOID*) &pcInnerEapIdentity)) == NO_ERROR)
									{
										WideCharToMultiByte( CP_ACP, 0, pSessionData->UserData.InnerEapUserData.pwcIdentity, -1, pcInnerEapIdentity, ccInnerEapIdentity + 1, NULL, NULL );
									}
									else
									{
										SW2Trace( SW2_TRACE_LEVEL_ERROR, 
											TEXT( "SW2_TRACE_LEVEL_ERROR::AuthHandleInnerEAPAuthentication::not enough memory" ) );

										dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
									}

									if( dwReturnCode == NO_ERROR )
									{
										if( ( dwReturnCode = AuthMakeEAPResponseAttribute( &(pSessionData->TLSSession), 
																							0x01, 
																							pInnerEapReceivePacket->Id, 
																							pSessionData->bCurrentMethodVersion,
																							( PBYTE ) pcInnerEapIdentity, 
																							ccInnerEapIdentity, 
																							&pbEAPAttribute, 
																							&cbEAPAttribute ) ) == NO_ERROR )
										{
											if( ( dwReturnCode = TLSMakeApplicationRecord( &(pSessionData->TLSSession), 
																							pbEAPAttribute, 
																							cbEAPAttribute, 
																							&pbRecord, 
																							&cbRecord, 
																							TRUE ) ) == NO_ERROR )
											{
												dwReturnCode = TLSAddMessage(pbRecord, 
																		cbRecord, 
																		cbRecord,
																		pSendPacket, 
																		cbSendPacket );

												pEapOutput->eapAction = SW2EAPACTION_Send;

												pSessionData->InnerSessionData.InnerEapState = SW2_INNER_EAP_STATE_MakeMessage;

												SW2FreeMemory((PVOID*)&pbRecord);

												cbRecord = 0;
											}

											SW2FreeMemory((PVOID*)&pbEAPAttribute);
											cbEAPAttribute = 0;
										}

										SW2FreeMemory((PVOID*)&pcInnerEapIdentity);
										ccInnerEapIdentity= 0;
									}
								}
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, 
									TEXT( "SW2_TRACE_LEVEL_ERROR::AuthHandleInnerEAPAuthentication::expected identity packet, but received an something else (%x)" ), 
									pInnerEapReceivePacket->Data[0]);

								dwReturnCode  = ERROR_PPP_INVALID_PACKET;
							}

						break;

						default:

							SW2Trace( SW2_TRACE_LEVEL_ERROR, 
								TEXT( "SW2_TRACE_LEVEL_ERROR::AuthHandleInnerEAPAuthentication::received an invalid packet code: %x" ), pInnerEapReceivePacket->Code);

							dwReturnCode  = ERROR_PPP_INVALID_PACKET;

						break;
					}
				}
				else
					dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_WARNING, 
					TEXT( "SW2_TRACE_LEVEL_WARNING::SW2EapMethodProcess::SW2_SW2_TLS_STATE_Start::pReceivePacket == NULL" ) );
			}

		break;

		case SW2_INNER_EAP_STATE_InteractiveUI:

			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication::SW2_INNER_EAP_STATE_InteractiveUI" ) );

			if (pSessionData->pbDataFromInteractiveUI &&
				pSessionData->dwSizeOfDataFromInteractiveUI > 0)
			{
				pSessionData->InnerSessionData.InnerEapInput.fDataReceivedFromInteractiveUI = TRUE;

				pSessionData->InnerSessionData.InnerEapInput.dwSizeOfDataFromInteractiveUI = pSessionData->dwSizeOfDataFromInteractiveUI;

				pSessionData->InnerSessionData.InnerEapInput.pDataFromInteractiveUI = pSessionData->pbDataFromInteractiveUI;
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, 
					TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication::SW2_INNER_EAP_STATE_InteractiveUI::User has not exited from dialog yet" ) );

				pEapOutput->eapAction = SW2EAPACTION_None;
			}

		case SW2_INNER_EAP_STATE_MakeMessage:

			SW2Trace( SW2_TRACE_LEVEL_INFO, 
				TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication::SW2_INNER_EAP_STATE_MakeMessage" ) );

			if( pSessionData->TLSSession.cbInnerEapMessage > 0)
			{
				if( ( pInnerEapReceivePacket = ( PPP_EAP_PACKET *) pSessionData->TLSSession.pbInnerEapMessage ) )
				{
					//
					// Let's see what is in the packet
					//
					switch( pInnerEapReceivePacket->Code )
					{
						case EAPCODE_Success:

							SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication::SW2_INNER_EAP_STATE_MakeMessage::EAPCODE_Success" ) );

							//
							// Some servers also use the EAP extension in PEAPv1
							// but because we can never check to see if the extension should have
							// been sent we only check this if PEAPv0 is used...
							//
							if (pSessionData->bCurrentMethodVersion == EAP_PEAP_V0
								&& !pSessionData->bSentEapExtensionSuccess)
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, 
									TEXT( "SW2_TRACE_LEVEL_ERROR::AuthHandleInnerEAPAuthentication::SW2_INNER_EAP_STATE_MakeMessage::received a success message but we did not send or receive the EapExtension" ) );

								dwReturnCode  = ERROR_PPP_INVALID_PACKET;
							}

						break;

						case EAPCODE_Failure:
							
							SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication::SW2_INNER_EAP_STATE_MakeMessage::EAPCODE_Failure" ) );

							// we received a failure, respond with an ack

							pEapOutput->eapAction = SW2EAPACTION_Send;

							pSessionData->InnerSessionData.InnerEapState = SW2_INNER_EAP_STATE_Identity;

						break;

						case EAPCODE_Request:

							SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication::SW2_INNER_EAP_STATE_MakeMessage::EAPCODE_Request" ) );

							if (dwReturnCode == NO_ERROR)
							{
								if( pInnerEapReceivePacket->Data[0] == 0x21 )
								{
									//
									// we received an eap extended request (PEAPv0)
									// but as some server misuse this extension in PEAPV1 we will accept it...
									//
									if (pSessionData->bCurrentMethodVersion > 0)
									{
										SW2Trace( SW2_TRACE_LEVEL_WARNING, 
											TEXT( "SW2_TRACE_LEVEL_WARNING::AuthHandleInnerEAPAuthentication::incorrect extension response packet received, but handling anyway as it will brake authentication..." ) );
									}

									//
									// Did we receive a success eap extension?
									//
									if (pInnerEapReceivePacket->Data[6] == 1)
									{
										SW2Trace( SW2_TRACE_LEVEL_INFO, 
											TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication::received an eap extension SUCCESS" ) );
									}
									else
									{
										SW2Trace( SW2_TRACE_LEVEL_INFO, 
											TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication::received an eap extension FAILURE" ) );
									}

									//
									// copy over the eap extension success/failure message
									//
									pbExtensionPacket[4] = pInnerEapReceivePacket->Data[6];

									//
									// Respond
									//
									if( ( dwReturnCode = AuthMakeEAPResponseAttribute( &(pSessionData->TLSSession),
																						0x21, 
																						pInnerEapReceivePacket->Id, 
																						0x80, // mandatory field set
																						pbExtensionPacket,
																						sizeof(pbExtensionPacket), 
																						&pbEAPAttribute, 
																						&cbEAPAttribute ) ) == NO_ERROR )
									{
										if( ( dwReturnCode = TLSMakeApplicationRecord( &(pSessionData->TLSSession), 
																							pbEAPAttribute, 
																							cbEAPAttribute, 
																							&pbRecord, 
																							&cbRecord, 
																							TRUE ) ) == NO_ERROR )
										{
											dwReturnCode = TLSAddMessage(pbRecord, 
																	cbRecord, 
																	cbRecord,
																	pSendPacket, 
																	cbSendPacket );

											pEapOutput->eapAction = SW2EAPACTION_Send;

											pSessionData->InnerSessionData.InnerEapState = SW2_INNER_EAP_STATE_MakeMessage;

											SW2FreeMemory((PVOID*)&pbRecord);
											cbRecord = 0;
										}

										SW2FreeMemory((PVOID*)&pbEAPAttribute);
										cbEAPAttribute = 0;

										//
										// Save the fact that we sent an eap extension success packet
										//
										if (dwReturnCode == NO_ERROR &&
											pInnerEapReceivePacket->Data[6] == 1)
											pSessionData->bSentEapExtensionSuccess = TRUE;
									}
								}
								else if( pInnerEapReceivePacket->Data[0] != 
																pSessionData->InnerSessionData.pInnerEapConfigData->dwEapType )
								{
									//
									// Not for our Inner EAP DLL so send NACK request for our auth type
									//
									SW2Trace( SW2_TRACE_LEVEL_WARNING, 
										TEXT( "SW2_TRACE_LEVEL_WARNING::AuthHandleInnerEAPAuthentication::request for invalid method (%x), sending NACK" ), 
										pInnerEapReceivePacket->Data[0] );

									if( ( dwReturnCode = AuthMakeEAPResponseAttribute( &(pSessionData->TLSSession),
																						0x03, 
																						pInnerEapReceivePacket->Id, 
																						pSessionData->bCurrentMethodVersion,
																						( PBYTE ) &( pSessionData->InnerSessionData.pInnerEapConfigData->dwEapType ),
																						1, 
																						&pbEAPAttribute, 
																						&cbEAPAttribute ) ) == NO_ERROR )
									{
										if( ( dwReturnCode = TLSMakeApplicationRecord( &(pSessionData->TLSSession), 
																							pbEAPAttribute, 
																							cbEAPAttribute, 
																							&pbRecord, 
																							&cbRecord, 
																							TRUE ) ) == NO_ERROR )
										{
											dwReturnCode = TLSAddMessage(pbRecord, 
																	cbRecord, 
																	cbRecord,
																	pSendPacket, 
																	cbSendPacket );

											pEapOutput->eapAction = SW2EAPACTION_Send;

											pSessionData->InnerSessionData.InnerEapState = SW2_INNER_EAP_STATE_MakeMessage;

											SW2FreeMemory((PVOID*)&pbRecord);
											cbRecord = 0;
										}

										SW2FreeMemory((PVOID*)&pbEAPAttribute);
										cbEAPAttribute = 0;
									}
								}
							}

						break;

						case EAPCODE_Response:

						default:

							SW2Trace( SW2_TRACE_LEVEL_ERROR, 
								TEXT( "SW2_TRACE_LEVEL_ERROR::AuthHandleInnerEAPAuthentication::invalid packet" ) );

							dwReturnCode  = ERROR_PPP_INVALID_PACKET;

						break;
					}
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
						TEXT( "SW2_TRACE_LEVEL_ERROR::AuthHandleInnerEAPAuthentication::could not allocate data for pInnerEapReceivePacket" ) );

					dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
				}

			}
			else
				pInnerEapReceivePacket = NULL;

			//
			// If we haven't sent anything yet and no error has occured then continue
			//
			if( ( pEapOutput->eapAction != SW2EAPACTION_Send ) && 
				( dwReturnCode == NO_ERROR ) )
			{
				//
				// InnerEapSendPacket must be our cbSendPacket 
				// (1490) - 90 (header information needed to transport through ttls)
				//
				cbInnerEapSendPacket = cbSendPacket - 90;

				if ((dwReturnCode = SW2AllocateMemory(cbInnerEapSendPacket, (PVOID*) &pInnerEapSendPacket)) == NO_ERROR)
				{
					memset( pInnerEapSendPacket, 0, cbInnerEapSendPacket );

					memset( &InnerEapOutput, 0, sizeof( InnerEapOutput ) );

					if( ( dwReturnCode = pSessionData->InnerSessionData.pInnerEapMakeMessage( 
											pSessionData->InnerSessionData.pbInnerEapSessionData,
											pInnerEapReceivePacket,
											pInnerEapSendPacket,
											cbInnerEapSendPacket,
											&InnerEapOutput,
											&( pSessionData->InnerSessionData.InnerEapInput ) ) ) == NO_ERROR )
					{
						pSessionData->UserData.InnerEapUserData.fSaveUserData = InnerEapOutput.fSaveUserData;
						pSessionData->InnerSessionData.pInnerEapConfigData->fSaveConnectionData = InnerEapOutput.fSaveConnectionData;

						//
						// Let's see what the module wants us to do
						//
						if (pSessionData->UserData.InnerEapUserData.fSaveUserData)
						{
							SW2Trace( SW2_TRACE_LEVEL_INFO, 
								TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication::saving inner user data" ) );

							//
							// Save the EapOutPut.pUserData
							//
							if( InnerEapOutput.dwSizeOfUserData <= EAP_MAX_INNER_USER_DATA )
							{
								pSessionData->UserData.InnerEapUserData.cbUserData = InnerEapOutput.dwSizeOfUserData;

								memcpy( pSessionData->UserData.InnerEapUserData.pbUserData, InnerEapOutput.pUserData, InnerEapOutput.dwSizeOfUserData );
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_WARNING, 
									TEXT( "SW2_TRACE_LEVEL_WARNING::AuthHandleInnerEAPAuthentication::not enough memory to store inner user data" ) );
							}
						}

						if (pSessionData->InnerSessionData.pInnerEapConfigData->fSaveConnectionData)
						{
							SW2Trace( SW2_TRACE_LEVEL_INFO, 
								TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication::saving inner connection data" ) );

							//
							// Save the EapOutPut.pConnectionData
							//
							if( InnerEapOutput.dwSizeOfConnectionData <= EAP_MAX_INNER_CONNECTION_DATA )
							{
								pSessionData->InnerSessionData.pInnerEapConfigData->cbConnectionData = InnerEapOutput.dwSizeOfConnectionData;

								memcpy( pSessionData->InnerSessionData.pInnerEapConfigData->pbConnectionData, 
									InnerEapOutput.pConnectionData, 
									InnerEapOutput.dwSizeOfConnectionData );
							}
							else
							{
								SW2Trace( SW2_TRACE_LEVEL_WARNING, 
									TEXT( "SW2_TRACE_LEVEL_WARNING::AuthHandleInnerEAPAuthentication::not enough memory to store inner connection data" ) );
							}
						}

						pEapOutput->eapAction = SW2EAPACTION_None;

						if( InnerEapOutput.fInvokeInteractiveUI )
						{
							SW2Trace( SW2_TRACE_LEVEL_INFO, 
								TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication::inner eap method requested interactive ui" ) );

							pEapOutput->eapAction = SW2EAPACTION_InvokeUI;

							pSessionData->bInteractiveUIType = UI_TYPE_INNER_EAP;

							pSessionData->InnerSessionData.InnerEapState = SW2_INNER_EAP_STATE_InteractiveUI;

							//
							// Copy Inner UI Context Data
							// 
							if( InnerEapOutput.dwSizeOfUIContextData <= EAP_MAX_INNER_UI_DATA )
							{
								pSessionData->cbInnerUIContextData = InnerEapOutput.dwSizeOfUIContextData;

								memcpy( pSessionData->pbInnerUIContextData,
										InnerEapOutput.pUIContextData,
										pSessionData->cbInnerUIContextData );
							}
							else
								dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
						}
						else 
						{
							switch( InnerEapOutput.Action )
							{
								case EAPACTION_Authenticate:

									//
									// Not sure what to do now...
									//
									SW2Trace( SW2_TRACE_LEVEL_WARNING, 
										TEXT( "SW2_TRACE_LEVEL_WARNING::AuthHandleInnerEAPAuthentication::EAPACTION_Authenticate" ) );

								break;

								case EAPACTION_NoAction:

									SW2Trace( SW2_TRACE_LEVEL_INFO, 
										TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication::EAPACTION_NoAction" ) );
								
								case EAPACTION_Done:

									SW2Trace( SW2_TRACE_LEVEL_INFO, 
										TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication::EAPACTION_Done" ) );

									//
									// Inner EAP method is happy so we send an ACK to complete inner SUCCESS/FAILURE
									//
									switch( pInnerEapReceivePacket->Code )
									{
										case EAPCODE_Success:
										case EAPCODE_Failure:

											pEapOutput->eapAction = SW2EAPACTION_Send;

											pSessionData->InnerSessionData.InnerEapState = SW2_INNER_EAP_STATE_Identity;
											pSessionData->InnerSessionData.bHandledInnerAccessReject = TRUE;

										break;

										default:
											
											pEapOutput->eapAction = SW2EAPACTION_Done;

										break;
									}

								break;

								case EAPACTION_SendAndDone:

									SW2Trace( SW2_TRACE_LEVEL_INFO, 
										TEXT( "SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication::EAPACTION_SendAndDone" ) );

								case EAPACTION_Send:
								case EAPACTION_SendWithTimeout:
								case EAPACTION_SendWithTimeoutInteractive:

									//
									// Build response attribute, strip headers if using PEAPv0
									//
									if (pSessionData->bCurrentMethodVersion == 0)
									{
										dwReturnCode = TLSMakeApplicationRecord( &(pSessionData->TLSSession), 
																					(PBYTE) pInnerEapSendPacket->Data, 
																					SW2_WireToHostFormat16( pInnerEapSendPacket->Length) - 4, 
																					&pbRecord, 
																					&cbRecord, 
																					TRUE );
									}
									else
									{
										dwReturnCode = TLSMakeApplicationRecord( &(pSessionData->TLSSession), 
																					(PBYTE) pInnerEapSendPacket, 
																					SW2_WireToHostFormat16( pInnerEapSendPacket->Length ), 
																					&pbRecord, 
																					&cbRecord, 
																					TRUE );
									}

									if (dwReturnCode == NO_ERROR)
									{
										dwReturnCode = TLSAddMessage(	pbRecord, 
																		cbRecord, 
																		cbRecord,
																		pSendPacket, 
																		cbSendPacket );

										pEapOutput->eapAction = SW2EAPACTION_Send;

										pSessionData->InnerSessionData.InnerEapState = SW2_INNER_EAP_STATE_MakeMessage;

										SW2FreeMemory((PVOID*)&pbRecord);
										cbRecord = 0;
									}

								default:
								break;
							}
						}
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::AuthHandleInnerEAPAuthentication::pInnerEapMakeMessage FAILED: %ld" ), dwReturnCode );
					}

					SW2FreeMemory((PVOID*)&pInnerEapSendPacket);
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
						TEXT( "SW2_TRACE_LEVEL_ERROR::AuthHandleInnerEAPAuthentication::could not allocate data for pInnerEapSendPacket" ) );

					dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
				}
			}
		break;

		case SW2_INNER_EAP_STATE_Finished:

			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_ERROR::AuthHandleInnerEAPAuthentication::SW2_INNER_EAP_STATE_Finished" ) );

			//
			// should never get here
			//
			dwReturnCode = ERROR_PPP_INVALID_PACKET;

		break;

		default:

			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_ERROR::AuthHandleInnerEAPAuthentication::unknown inner authentication state" ) );

			dwReturnCode = ERROR_PPP_INVALID_PACKET;

		break;
	}

	SW2Trace(SW2_TRACE_LEVEL_INFO, 
		TEXT("SW2_TRACE_LEVEL_INFO::AuthHandleInnerEAPAuthentication::returning: %ld" ), dwReturnCode);

	return dwReturnCode;
}

//
// Name: AuthMakeEAPResponseAttribute
// Description: This function builds a EAP response attribute
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
AuthMakeEAPResponseAttribute(	IN PSW2_TLS_SESSION pTLSSession,
								IN BYTE bType,
								IN BYTE bPacketId,
								IN BYTE bFlags,
								IN PBYTE pbData,
								IN DWORD cbData,
								OUT PBYTE *ppbEAPAttribute,
								OUT DWORD *pcbEAPAttribute )
{
	PBYTE	pbEAPAttribute;
	DWORD	cbEAPAttribute;
	DWORD	dwCursor;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::AuthMakeEAPResponseAttribute" ) );

	if ((bFlags & EAP_PEAP_V1)||
		(bType == 0x21)) // extension packet does require headers..... weird MS
	{
		if (bType == 1 || bType == 3)  // Identity or NACK
			*pcbEAPAttribute = 0x05 + cbData;
		else
			*pcbEAPAttribute = 0x06 + cbData;
	}
	else
	{
		if (bType == 1 || bType == 3) // Identity or NACK
			*pcbEAPAttribute = 0x01 + cbData;
		else
			*pcbEAPAttribute = 0x02 + cbData;
	}

	if ((dwReturnCode = SW2AllocateMemory(*pcbEAPAttribute, (PVOID*) ppbEAPAttribute)) == NO_ERROR)
	{
		pbEAPAttribute = *ppbEAPAttribute;
		cbEAPAttribute = *pcbEAPAttribute;

		memset( pbEAPAttribute, 0, cbEAPAttribute );

		dwCursor = 0;

		//
		// Response
		//
		if ((bFlags & EAP_PEAP_V1)||
			(bType == 0x21)) // extension packet does require headers..... weird MS
		{
			pbEAPAttribute[dwCursor++] = 0x02; // code
			pbEAPAttribute[dwCursor++] = bPacketId; // id

			SW2_HostToWireFormat16( cbEAPAttribute, &( pbEAPAttribute[dwCursor] ) ); // total length of packet
			dwCursor+=2;
		}

		pbEAPAttribute[dwCursor++] = bType; // type

		if (bType != 1 && bType != 3) // Identity or NACK
			pbEAPAttribute[dwCursor++] = bFlags; // flags

		memcpy( &( pbEAPAttribute[dwCursor] ), pbData, cbData );
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			TEXT( "SW2_TRACE_LEVEL_ERROR::AuthMakeEAPResponseAttribute::not enough memory" ) );

		dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::AuthMakeEAPResponseAttribute::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}
