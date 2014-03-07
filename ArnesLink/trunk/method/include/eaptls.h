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

#define _CRT_SECURE_NO_DEPRECATE
#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS

#include "..\include\common.h"

#include <tchar.h>
#include <shellapi.h>
#include <commctrl.h>
#include <Commdlg.h>
#include <math.h>
#include <stdio.h>
#include <wincrypt.h>

#ifndef _WIN32_WCE
#include <Iphlpapi.h>
#endif // _WIN32_WCE

//
// In CE the WC_DIALOG is not present, so set it
//
#ifndef WC_DIALOG
#define WC_DIALOG L"Dialog"
#endif 

//--------------------
// Definitions
//--------------------
#define SW2_MAX_CONFIG_TAB				5

#define UI_TYPE_VERIFY_CERT				0x20
#define UI_TYPE_INNER_EAP				0x40
#define UI_TYPE_INNER_EAPHOST			0x50
#define UI_TYPE_ERROR					0x60
#define UI_TYPE_CREDENTIALS				0x80

//
// Inner RASEAP functions
//
//
// RAS EAP functions
//
typedef DWORD ( APIENTRY * PINNEREAPGETINFO ) ( IN DWORD dwEapTypeId, IN PPP_EAP_INFO *pEapInfo );

typedef DWORD ( APIENTRY * PINNEREAPGETIDENTITY ) (	IN DWORD dwEapTypeId,
													IN HWND hwndParent,
													IN DWORD dwFlags,
													IN const WCHAR * pwszPhonebook,
													IN const WCHAR * pwszEntry,
													IN BYTE * pConnectionDataIn,
													IN DWORD dwSizeOfConnectionDataIn,
													IN BYTE * pUserDataIn,
													IN DWORD dwSizeOfUserDataIn,
													OUT BYTE ** ppbUserDataOut,
													OUT DWORD * pdwSizeOfUserDataOut,
													OUT WCHAR ** ppwszIdentity );

typedef DWORD ( APIENTRY * PINNEREAPINVOKECONFIGUI ) ( IN DWORD dwEapTypeId,
														IN HWND hwndParent,
														IN DWORD dwFlags,
														IN BYTE* pConnectionDataIn,
														IN DWORD dwSizeOfConnectionDataIn,
														OUT BYTE** ppConnectionDataOut,
														OUT DWORD* pdwSizeOfConnectionDataOut );

typedef DWORD ( APIENTRY * PINNEREAPFREEMEMORY ) ( IN  BYTE *pMemory );

typedef DWORD ( APIENTRY * PINNEREAPINITIALIZE )( IN BOOL fInitialize );

typedef DWORD ( APIENTRY * PINNEREAPBEGIN )( OUT VOID **ppWorkBuffer, IN PPP_EAP_INPUT *pPppEapInput );

typedef DWORD ( APIENTRY * PINNEREAPEND )( IN VOID *pWorkBuffer );

typedef DWORD ( APIENTRY * PINNEREAPMAKEMESSAGE )(	IN VOID *pWorkBuf,
													IN PPP_EAP_PACKET *pReceivePacket,
													IN PPP_EAP_PACKET *pSendPacket,
													IN DWORD cbSendPacket,
													IN PPP_EAP_OUTPUT *pEapOutput,
													IN PPP_EAP_INPUT *pEapInput );

typedef DWORD ( APIENTRY * PINNEREAPINVOKEINTERACTIVEUI ) (	IN DWORD	dwEapTypeId,
															IN  HWND	hWndParent,
															IN  PBYTE	pUIContextData,
															IN  DWORD	dwSizeofUIContextData,
															OUT PBYTE*	ppDataFromInteractiveUI,
															OUT DWORD*	lpdwSizeOfDataFromInteractiveUI );


//--------------------
// Structs
//--------------------

typedef struct _EAP_NAME_DIALOG
{
    WCHAR               pwcIdentity[UNLEN + 1 ];
    WCHAR               pwcPassword[PWLEN + 1 ];
	WCHAR				pwcDomain[UNLEN + 1 ];

} EAP_NAME_DIALOG, *PEAP_NAME_DIALOG;

typedef struct _SW2_INNER_SESSION_DATA
{
    PBYTE					pbInnerEapSessionData;

	BOOL					bInnerEapExtSuccess;
	BOOL					bHandledInnerAccessReject;

	HINSTANCE				hInnerEapInstance;
	PINNEREAPINITIALIZE		pInnerEapInitialize;
	PINNEREAPBEGIN			pInnerEapBegin;
	PINNEREAPEND			pInnerEapEnd;
	PINNEREAPMAKEMESSAGE	pInnerEapMakeMessage;
	PPP_EAP_INPUT			InnerEapInput;
	PPP_EAP_OUTPUT			InnerEapOutput;

	BYTE					pInnerEapDataFromInteractiveUI[MAX_UI_CONTEXT_DATA];
	DWORD					dwInnerEapSizeOfDataFromInteractiveUI;

	SW2_INNER_EAP_STATE		InnerEapState;

	//
	// Stuff needed for inner EAP authentication
	//
	PSW2_INNER_EAP_CONFIG_DATA	pInnerEapConfigData;

#ifdef SW2_EAP_HOST
	EAP_SESSIONID				eapSessionId;
#endif // SW2_EAP_HOST

} SW2_INNER_SESSION_DATA, *PSW2_INNER_SESSION_DATA;

typedef struct _SW2_CONFIG_DATA
{
	WCHAR						pwcProfileId[UNLEN];
	HWND						hWndTabs[2];

} SW2_CONFIG_DATA, *PSW2_CONFIG_DATA;

typedef struct _SW2_SESSION_DATA 
{
	BYTE					bCurrentMethodVersion;
	BYTE					bNewMethodVersion;

	DWORD					dwLastSW2Error;
	SW2_EAP_FUNCTION		LastEapFunction;

    DWORD					fFlags;

	WCHAR					pwcCurrentProfileId[UNLEN];

	BYTE					pbInnerUIContextData[EAP_MAX_INNER_UI_DATA];
	DWORD					cbInnerUIContextData;

	HANDLE					hTokenImpersonateUser;

	SW2_TLS_SESSION			TLSSession;

	BYTE					bPacketId;

	BYTE					bInteractiveUIType;
	BOOL					bServerCertificateLocal;

	BOOL					bVerifyMSExtension;

	SW2_USER_DATA			UserData;

	SW2_PROFILE_DATA		ProfileData;

	SW2_INNER_SESSION_DATA	InnerSessionData;

	SW2EAPATTRIBUTE			*pUserAttributes;

	PBYTE					pbDataFromInteractiveUI;
	DWORD					dwSizeOfDataFromInteractiveUI;

	BOOL					bSentEapExtensionSuccess;

} SW2_SESSION_DATA, *PSW2_SESSION_DATA;

//--------------------
// Functions
//--------------------

//
// Inner Authentication
//
DWORD				AuthHandleInnerAuthentication(IN PSW2_SESSION_DATA	pSessionData,
												  OUT PSW2EAPPACKET		pSendPacket,
												  IN  DWORD				cbSendPacket,
												  IN PSW2EAPOUTPUT		pEapOutput );

DWORD				AuthHandleInnerPAPAuthentication(IN PSW2_SESSION_DATA	pSessionData,
													 OUT PSW2EAPPACKET		pSendPacket,
													 IN  DWORD				cbSendPacket,
													 IN PSW2EAPOUTPUT		pEapOutput );

DWORD				AuthHandleInnerEAPAuthentication(IN PSW2_SESSION_DATA	pSessionData,
													 OUT PSW2EAPPACKET		pSendPacket,
													 IN  DWORD				cbSendPacket,
													 IN PSW2EAPOUTPUT		pEapOutput );

DWORD				AuthHandleInnerEAPHOSTAuthentication(IN PSW2_SESSION_DATA	pSessionData,
														 OUT PSW2EAPPACKET		pSendPacket,
														 IN  DWORD				cbSendPacket,
														 IN PSW2EAPOUTPUT		pEapOutput );

DWORD				AuthMakeDiameterAttribute( DWORD dwType,
												PBYTE pbAttribute,
												DWORD cbAttribute,
												PBYTE *ppbDiameter,
												DWORD *pcbDiameter );

//
// PAP
//
DWORD				AuthMakeClientPAPMessage( IN PSW2_SESSION_DATA pSessionData, PBYTE *ppbMessage, DWORD *pcbMessage );

//
//
// EAP
//
DWORD
AuthMakeEAPResponseAttribute(	IN PSW2_TLS_SESSION pTLSSession,
								IN BYTE bType,
								IN BYTE bPacketId,
								IN BYTE bFlags,
								IN PBYTE pbData,
								IN DWORD cbData,
								OUT PBYTE *ppbEAPAttribute,
								OUT DWORD *pcbEAPAttribute );

DWORD SW2EapMethodGetUserIdentity(IN DWORD				dwFlags,
								  IN PSW2_PROFILE_DATA	pProfileData, 								 
								  IN PSW2_USER_DATA		pUserData,
								  OUT BOOL				*pfInvokeUI);

DWORD SW2EapMethodGetEAPIdentity(IN HWND				hWndParent,
								 IN DWORD				dwFlags,
								 IN PSW2_PROFILE_DATA	pProfileData, 
								 IN PSW2_USER_DATA		pUserData);

DWORD SW2EapMethodGetEAPHOSTIdentity(IN DWORD				dwFlags,
									 IN PSW2_PROFILE_DATA	pProfileData, 									 
									 IN PSW2_USER_DATA		pUserData,
									 OUT BOOL				*pfInvokeUI);

DWORD SW2EapMethodInvokeUserIdentityUI(IN HWND				hWndParent,
									   IN PSW2_PROFILE_DATA	pProfileData, 
									   IN PSW2_USER_DATA	pUserData);

//
// Dialog
//
INT_PTR	CALLBACK	ConfigProfileNewDlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
INT_PTR	CALLBACK	ProfileDlgProc(	IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
INT_PTR CALLBACK	ConfigDlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
INT_PTR CALLBACK	CredentialsDlgProc(	IN  HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM  lParam );
INT_PTR CALLBACK	TLSServerTrustDlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
INT_PTR CALLBACK	ConfigConnDlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
INT_PTR	CALLBACK	ConfigCADlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM  wParam, IN  LPARAM  lParam );
INT_PTR CALLBACK	ConfigCertDlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
INT_PTR	CALLBACK	ConfigAuthDlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
INT_PTR CALLBACK	ConfigUserDlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
INT_PTR CALLBACK	ConfigProfileDlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
DWORD				ConfigUpdateCertificateView( IN HWND hWnd, IN PSW2_SESSION_DATA pSessionData );

#ifndef _WIN32_WCE
DWORD	WINAPI		SW2_RenewIP( LPVOID lpvoid );
#endif // _WIN32_WCE

//
// Certificates
//
DWORD				SW2_VerifyCertificateChain( IN PSW2_SESSION_DATA pSessionData, IN PCCERT_CONTEXT pCertContext );

DWORD				SW2_VerifyCertificateInStore( IN PCCERT_CONTEXT pCertContext );
DWORD				SW2_CertGetTrustedRootCAList( HWND hWnd, BYTE pbTrustedCA[SW2_MAX_CA][20], DWORD dwNrOfTrustedRootCAInList );
DWORD				SW2_CertGetRootCAList( IN HWND hWnd, IN BYTE pbTrustedRootCAList[SW2_MAX_CA][20], IN DWORD dwNrOfTrustedRootCAInList );
DWORD				SW2_CertAddTrustedRootCA( IN DWORD dwSelected, IN OUT BYTE pbTrustedRootCA[SW2_MAX_CA][20], IN OUT DWORD *dwNrOfTrustedCAInList );
DWORD				SW2_CertRemoveTrustedRootCA( IN DWORD dwSelected, IN OUT BYTE pbTrustedRootCA[SW2_MAX_CA][20], IN OUT DWORD *dwNrOfTrustedCAInList );

DWORD				SW2_CertCheckEnhkeyUsage( IN PCCERT_CONTEXT pCertContext );

DWORD				SW2_CertVerifyServerName(IN PSW2_SESSION_DATA pSessionData, PCCERT_CONTEXT pCertContext);

DWORD				SW2_VerifyServerCertificate( IN PSW2_PROFILE_DATA pProfileData, IN PCCERT_CONTEXT pCertContext );

DWORD				SW2_VerifyCertificateInList( IN SW2_PROFILE_DATA ProfileData, IN PBYTE pbSHA1 );


//
// TLS
//
DWORD				TLSParseServerPacket( IN PSW2_SESSION_DATA pSessionData );

DWORD				SW2_MakeMPPEKey(IN PBYTE					pbKeyMaterial,
									IN DWORD					cbKeyMaterial,
									IN OUT SW2EAPATTRIBUTE 		**ppUserAttributes );

DWORD				SW2_GenerateKeyMaterial(IN HCRYPTPROV	hCSP,
											 IN BYTE		bEapType,
											IN DWORD		bCurrentMethodVersion,
											IN PBYTE		pbRandomClient,
											IN PBYTE		pbRandomServer,
											IN PBYTE		pbMS,
											IN PBYTE		pbChallenge,
											IN DWORD		cbChallenge);

//
// TTLS
//
DWORD				SW2_GenerateImplicitChallenge(IN HCRYPTPROV	hCSP,
												 IN BYTE		bEapType,
												IN DWORD		bCurrentMethodVersion,
												IN PBYTE		pbRandomClient,
												IN PBYTE		pbRandomServer,
												IN PBYTE		pbMS,
												IN PBYTE		pbChallenge,
												IN DWORD		cbChallenge);

DWORD				SW2_GetCertificate(	PBYTE pbServerCertSHA1, OUT PCCERT_CONTEXT *ppCertContext );
