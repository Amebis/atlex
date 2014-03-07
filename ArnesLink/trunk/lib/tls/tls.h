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
#ifndef WINVER				// Allow use of features specific to Windows XP or later.
#define WINVER 0x0501		// Change this to the appropriate value to target other versions of Windows.
#endif

#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0501	// Change this to the appropriate value to target other versions of Windows.
#endif						

#ifndef _WIN32_WINDOWS		// Allow use of features specific to Windows 98 or later.
#define _WIN32_WINDOWS 0x0410 // Change this to the appropriate value to target Windows Me or later.
#endif

#ifndef _WIN32_IE			// Allow use of features specific to IE 6.0 or later.
#define _WIN32_IE 0x0600	// Change this to the appropriate value to target other versions of IE.
#endif

//#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers

#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS

#include <windows.h>
#include <wincrypt.h>
#include <time.h>

#include "..\common\common.h"

//
// TLS
//
#define TLS_SESSION_ID_SIZE				32
#define TLS_MAX_ENC_PMS_SIZE			128

#define TLS_FINISH_SIZE					12

#define TLS_MAX_HS						10
#define TLS_MAX_CERT					10
#define	TLS_MAX_CERT_SIZE				10240
#define TLS_MAX_CERT_NAME				256
#define TLS_MAX_RECORD_SIZE				1024
#define TLS_MAX_FRAG_SIZE				1024

#define	TLS_MAX_MAC						20

#define	TLS_MAX_MASTER_KEY				2048

#define TLS_MAX_MSG						16384

#define TLS_MAX_EAPMSG					8192

#define TLS_REQUEST_LENGTH_INC			0x80
#define TLS_REQUEST_MORE_FRAG			0x40
#define TLS_REQUEST_START				0x20

#define TLS_CLIENT_FINISHED_LABEL		"client finished"
#define TLS_SERVER_FINISHED_LABEL		"server finished"

#define TLS_KEY_EXPANSION_LABEL			"key expansion"

#define TLS_RANDOM_SIZE					32

#define TLS_PMS_SIZE					48
#define TLS_MS_SIZE						48

#define EAP_TTLS_V0						0
#define EAP_TTLS_V1						1

#define EAP_PEAP_V0						0
#define EAP_PEAP_V1						1
#define EAP_PEAP_V2						2

#define EAP_KEYING_MATERIAL_LABEL_TTLS_V0	"ttls keying material"
#define EAP_KEYING_MATERIAL_LABEL_TTLS_V1	"ttls v1 keying material"
#define EAP_KEYING_MATERIAL_LABEL_PEAP_V0	"client EAP encryption"
#define EAP_KEYING_MATERIAL_LABEL_PEAP_V1	"client EAP encryption"

//
// RADIUS
//
#define RADIUS_MAX_STATE				64

typedef struct _SW2_TLS_SESSION_DATA 
{
	HCRYPTPROV				hCSP;

	SW2_TLS_STATE			TLSState;

	SW2_TLS_STATE			LastTLSState;

	BYTE					pbPMS[TLS_PMS_SIZE];

	DWORD					dwEncKey;
	DWORD					dwEncKeySize;

	DWORD					dwMacKey;
	DWORD					dwMacKeySize;

	HCRYPTKEY				hReadKey;
	HCRYPTKEY				hWriteKey;
	BYTE					pbWriteMAC[TLS_MAX_MAC];
	BYTE					pbReadMAC[TLS_MAX_MAC];

	BYTE					pbCertificate[TLS_MAX_CERT][TLS_MAX_CERT_SIZE];
	DWORD					cbCertificate[TLS_MAX_CERT];

	DWORD					dwCertCount;

	BYTE					pbRandomClient[TLS_RANDOM_SIZE];

	BYTE					pbRandomServer[TLS_RANDOM_SIZE];

	BYTE					pbCipher[2];

	BYTE					bCompression;

	PBYTE					pbHandshakeMsg[TLS_MAX_HS];
	DWORD					cbHandshakeMsg[TLS_MAX_HS];
	DWORD					dwHandshakeMsgCount;

	BYTE					pbReceiveMsg[TLS_MAX_MSG];
	DWORD					cbReceiveMsg;
	DWORD					dwReceiveCursor;

	DWORD					dwSeqNum;

	BOOL					bCipherSpec;

	BOOL					bServerFinished;

	BOOL					bFoundAlert; // send if something was wrong

	BOOL					bSentFinished; // we have sent our finished message

	BOOL					bCertRequest; // server requested certificate

	BYTE					pbState[RADIUS_MAX_STATE];

	DWORD					cbState;

	int						cbTLSSessionID;
	BYTE					pbTLSSessionID[TLS_SESSION_ID_SIZE];
	time_t					tTLSSessionID; // the time this TTLS session ID was set

	BYTE					pbMS[TLS_MS_SIZE];

	BYTE					pbInnerEapMessage[TLS_MAX_EAPMSG];
	DWORD					cbInnerEapMessage;

} SW2_TLS_SESSION, *PSW2_TLS_SESSION;

DWORD TLSInit(IN PSW2_TLS_SESSION SessionData);
DWORD TLSCleanup(PSW2_TLS_SESSION pTLSSession);

DWORD TLSResetReceiveMsg(IN PSW2_TLS_SESSION pTLSSession);

DWORD
TLSInitTLSAcceptPacket(	IN BYTE				bPacketId,
							IN PSW2EAPPACKET	pSendPacket,
						    IN DWORD			cbSendPacket);
DWORD
TLSInitTLSRejectPacket(	IN BYTE				bPacketId,
							IN PSW2EAPPACKET	pSendPacket,
						    IN DWORD			cbSendPacket);

DWORD
TLSInitTLSResponsePacket(	IN BYTE				bPacketId,
							IN PSW2EAPPACKET	pSendPacket,
						    IN DWORD			cbSendPacket,
							IN BYTE				bEapProtocolId,
							IN BYTE				bFlags);
DWORD
TLSAddMessage(	IN PBYTE			pbMessage,
				IN DWORD			cbMessage,
				IN DWORD			cbTotalMessage,
				IN PSW2EAPPACKET	pSendPacket,
				IN DWORD			cbSendPacket );

DWORD
SW2_GenSecureRandom( PBYTE pbRandom, DWORD cbRandom );

DWORD
TLSEncBlock(	IN PSW2_TLS_SESSION pTLSSession,
				IN PBYTE		pbData,
				IN DWORD		cbData,
				OUT PBYTE		*ppbEncBlock,
				OUT DWORD		*pcbEncBlock );

DWORD
TLSDecBlock( 	IN PSW2_TLS_SESSION pTLSSession,
				IN PBYTE		pbEncBlock,
				IN DWORD		cbEncBlock,
				OUT PBYTE		*ppbRecord,
				OUT DWORD		*pcbRecord );

DWORD
TLS_PRF( IN HCRYPTPROV hCSP, 
		IN PBYTE pbSecret,
		IN DWORD cbSecret, 
		IN PBYTE pbLabel, 
		IN DWORD cbLabel, 
		IN PBYTE pbSeed,
		IN DWORD cbSeed,
		IN OUT PBYTE pbData,
		IN DWORD cbData );

DWORD
TLSDeriveKeys( IN PSW2_TLS_SESSION pSessionData );

DWORD
TLSGenRSAEncPMS( IN PSW2_TLS_SESSION pSessionData, 
				PBYTE *ppbEncPMS, 
				DWORD *pcbEncPMS );

DWORD
TLSComputeMS(	IN HCRYPTPROV				hCSP,
				IN PBYTE					pbRandomClient,
				IN PBYTE					pbRandomServer,
				IN OUT PBYTE				pbPMS,
				IN OUT PBYTE				pbMS );

BOOL 
CreatePrivateExponentOneKey( HCRYPTPROV hProv, 
								  DWORD dwKeySpec,
                                  HCRYPTKEY *hPrivateKey);

BOOL 
ImportPlainSessionBlob(HCRYPTPROV hProv,
                            HCRYPTKEY hPrivateKey,
                            ALG_ID dwAlgId,
                            LPBYTE pbKeyMaterial ,
                            DWORD dwKeyMaterial ,
                            HCRYPTKEY *hSessionKey);

DWORD
TLS_HMAC( HCRYPTPROV hCSP,
			DWORD dwAlgID,
			IN PBYTE pbOrigKey, 
			IN DWORD cbOrigKey, 
			IN PBYTE pbSeed, 
			IN DWORD cbSeed, 
			PBYTE pbData, 
			DWORD cbData );

DWORD				TLSMakeFragResponse(	IN BYTE				bPacketId,
											IN PSW2EAPPACKET	pSendPacket, 
											IN DWORD			cbSendPacket );

DWORD				TLSMakeApplicationRecord(	IN PSW2_TLS_SESSION pTLSSession,
												IN PBYTE		pbMessage,
												IN DWORD		cbMessage,
												IN PBYTE		*ppbRecord,
												IN DWORD		*pcbRecord,
												IN BOOL			bEncrypt );

DWORD				TLSMakeHandshakeRecord( IN PSW2_TLS_SESSION pTLSSession,
											IN PBYTE		pbMessage,
											IN DWORD		cbMessage,
											IN PBYTE*		ppbRecord,
											IN DWORD*		pcbRecord,
											IN BOOL			bEncrypt );

DWORD				TLSMakeChangeCipherSpecRecord(	IN PBYTE			*ppbRecord,
													IN DWORD			*pcbRecord );

DWORD				TLSMakeClientHelloMessage(	IN BYTE				pbRandomClient[TLS_RANDOM_SIZE],
												IN PBYTE			pbTLSSessionID,
												IN DWORD			cbTLSSessionID,
												OUT PBYTE			*ppbTLSMessage,
												OUT DWORD			*pcbTLSMessage,
												OUT DWORD			*pdwEncKey,
												OUT DWORD			*pdwEncKeySize,
												OUT DWORD			*pdwMacKey,
												OUT DWORD			*pdwMacKeySize );

DWORD				TLSMakeServerHelloMessage(	IN BYTE				pbRandomServer[TLS_RANDOM_SIZE],
												IN PBYTE			pbTLSSessionID,
												IN DWORD			cbTLSSessionID,
												OUT PBYTE			*ppbTLSMessage,
												OUT DWORD			*pcbTLSMessage,
												OUT DWORD			*pdwEncKey,
												OUT DWORD			*pdwEncKeySize,
												OUT DWORD			*pdwMacKey,
												OUT DWORD			*pdwMacKeySize );

DWORD				TLSMakeCertificateRequestMessage(	IN PBYTE	*ppbTLSMessage,
														IN DWORD	*pcbTLSMessage );

DWORD				TLSMakeServerHelloDoneMessage(	IN PBYTE	*ppbTLSMessage,
													IN DWORD	*pcbTLSMessage );

DWORD				TLSMakeClientCertificateMessage(	OUT PBYTE			*ppbTLSMessage,
														OUT DWORD			*pcTLSMessage );

DWORD				TLSMakeServerCertificateMessage( 	PBYTE				pbServerCert,
														OUT PBYTE			*ppbTLSMessage,
														OUT DWORD			*pcbTLSMessage );

DWORD				TLSMakeClientKeyExchangeMessage(	IN PBYTE			pbEncPMS,
														IN DWORD			cbEncPMS,
														OUT PBYTE			*ppbTLSMessage,
														OUT DWORD			*pcTLSMessage );

DWORD				TLSMakeFinishedMessage(	IN PSW2_TLS_SESSION pTLSSession,
											IN PCHAR			pcLabel,
											IN DWORD			ccLabel,
											IN PBYTE			pbMS,
											IN DWORD			cbMS,
											OUT PBYTE			*ppbTLSMessage,
											OUT DWORD			*pcbTLSMessage );

DWORD				TLSVerifyFinishedMessage(	IN HCRYPTPROV		hCSP,
												IN DWORD			dwHandshakeMsgCount,
												IN PBYTE			pbHandshakeMsg[TLS_MAX_HS],
												IN DWORD			cbHandshakeMsg[TLS_MAX_HS],
												IN PCHAR			pcLabel,
												IN DWORD			ccLabel,
												IN PBYTE			pbMS,
												IN DWORD			cbMS,
												IN PBYTE			pbVerifyFinished,
												IN DWORD			cbVerifyFinished );

//
// TTLS
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
					IN  BYTE				bVersion);

DWORD				TLSSendMessage(	IN PSW2_TLS_SESSION		pTLSSession,
									IN BYTE					bPacketId,
									IN PSW2EAPPACKET		pSendPacket, 
									IN DWORD				cbSendPacket,
									IN PSW2EAPOUTPUT		pEapOutput );

DWORD
TLSBuildResponsePacket( IN PSW2_TLS_SESSION		pTLSSession,
					    IN BYTE					bPacketId,
						OUT PSW2EAPPACKET		pSendPacket,
						IN  DWORD               cbSendPacket,
						IN PSW2EAPOUTPUT		pEapOutput,
						IN BYTE					bEapProtocolId,
						IN BYTE					bFlags);

DWORD
TLSParseHandshakeRecord(	IN PSW2_TLS_SESSION pTLSSession, 
							IN PBYTE pbRecord, 
							IN DWORD cbRecord );

DWORD
TLSParseApplicationDataRecord(	IN PSW2_TLS_SESSION pTLSSession, 
								IN PBYTE pbRecord, 
								IN DWORD cbRecord );

DWORD
TLSParseInnerApplicationDataRecord( IN PSW2_TLS_SESSION pSessionData, 
									IN PBYTE pbRecord, 
									IN DWORD cbRecord );

DWORD
TLSGenerateKeyMaterial(IN HCRYPTPROV	hCSP,
					 BYTE			bEapType,
					IN DWORD		bCurrentMethodVersion,
					IN PBYTE		pbRandomClient,
					IN PBYTE		pbRandomServer,
					IN PBYTE		pbMS,
					IN PBYTE		pbChallenge,
					IN DWORD		cbChallenge);