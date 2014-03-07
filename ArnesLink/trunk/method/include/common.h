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
#include "..\..\lib\common\common.h"
#include "..\..\lib\tls\tls.h"

#ifdef _WIN32_WCE
#include "..\..\resource\eap_default\resource_CE.h"
#else
#include "..\..\resource\eap_default\resource.h"
#endif

#include "..\..\resource\include\reseap.h"

//-------------------
// GLOBALS
//-------------------
#define SW2_CONFIG_VERSION				0x07

#ifdef _WIN32_WCE
#define EAP_EAP_METHOD_LOCATION			L"Comm\\EAP\\Extension"
#else
#define EAP_EAP_METHOD_LOCATION			L"SYSTEM\\CurrentControlSet\\Services\\RasMan\\PPP\\EAP"
#endif // _WIN32_WCE

#define SW2_XOR							"8FC8E6CF371C2D049BBC243E84F2A3766ED907EF09601139284E83C268B032C63EE448A7BCE76F64149AC82AC2DE5613E76F190FF2DC41E31CBF5610BEAEC079F64AE45A884C74CFDC61A19D5C1C1CA44BD28A73D51DF25A9D5147B63164A60459670224BB0F42376D7E1551632AE72F0FF44CBED3C5F313ED6C408D641931BB"

extern PWCHAR							SW2_METHOD_PROFILE_LOCATION;

#define SW2_MANAGER_LOCATION			L"SOFTWARE\\SecureW2\\Manager"

#define SW2_MAX_ID						256
#define SW2_MAX_SERIAL					32
#define SW2_MAX_REGKEY					256
#define SW2_MAX_TIMESTAMP				256

#define SW2_MAX_BUFFER					1024

//
// CUSTOM DIALOG
// Contributed by Wyman Miles (Cornell University)
//
#define USERNAME_STR_LEN				16
#define PASSWORD_STR_LEN				16
#define CREDS_TITLEBAR_STR_LEN			32

// TTLS
#define TTLS_ANONYMOUS_USERNAME			L"anonymous"

//
// EAP
//
#define EAP_PROTOCOL_ID					21					// the EAP ID for TTLS is 21

#define EAP_MAX_INNER_UI_DATA			2048
#define EAP_MAX_INNER_USER_DATA			1792
#define EAP_MAX_INNER_CONNECTION_DATA	4096
#define MAX_UI_CONTEXT_DATA				4096

#define TLS_MAX_CIPHERSUITE				30

#ifndef _WIN32_WCE
#define SW2_MAX_CA						50
#else
#define SW2_MAX_CA						20
#endif // _WIN32_WCE

#define SW2_MAX_TAB						5

#define EAP_IMPLICIT_CHALLENGE_LABEL	"ttls challenge"

//--------------------
// Structs
//--------------------

typedef struct _SW2_INNER_EAP_CONFIG_DATA
{
	BOOL				fSaveConnectionData;

	BYTE				pbConnectionData[EAP_MAX_INNER_CONNECTION_DATA];
	DWORD				cbConnectionData;

	DWORD				dwEapType;
	WCHAR				pwcEapFriendlyName[UNLEN];
	WCHAR				pwcEapConfigUiPath[UNLEN];
	WCHAR				pwcEapIdentityPath[UNLEN];
	WCHAR				pwcEapInteractiveUIPath[UNLEN];
	WCHAR				pwcEapPath[UNLEN];

	DWORD				dwInvokeUsernameDlg;
	DWORD				dwInvokePasswordDlg;

#ifdef SW2_EAP_HOST
	EAP_METHOD_TYPE			eapMethodType;
#endif // SW2_EAP_HOST

} SW2_INNER_EAP_CONFIG_DATA, *PSW2_INNER_EAP_CONFIG_DATA;

typedef struct _SW2_INNER_EAP_USER_DATA 
{
	WCHAR			pwcIdentity[UNLEN];
	WCHAR			pwcPassword[PWLEN];
	BYTE			pbUserData[EAP_MAX_INNER_USER_DATA];
	DWORD			cbUserData;
	BOOL			fSaveUserData;

} SW2_INNER_EAP_USER_DATA, *PSW2_INNER_EAP_USER_DATA;

//
// INNER EAP DLL entrypoint functions
// have to define them before using them in SESSION_DATA
//

#ifdef SW2_EAP_HOST
//
// Declaration of Callback function pointer that gets called when the client
// needs to re-authenticate due to change in state of health. (related to NAP)
//
typedef void (CALLBACK *PNOTIFICATIONHANDLER) (
                 IN GUID connectionId,
                 IN void* pContextData
                 );

//
// EapHost functions
//
typedef DWORD (APIENTRY* PINNEREAPHOSTPEERINITIALIZE)();

typedef void (APIENTRY* PINNEREAPHOSTPEERUNINITIALIZE)();

typedef DWORD (APIENTRY* PINNEREAPHOSTPEERGETIDENTITY)(
  DWORD dwVersion,
  DWORD dwFlags,
  EAP_METHOD_TYPE eapMethodType,
  DWORD dwSizeofConnectionData,
  const BYTE* pConnectionData,
  DWORD dwSizeofUserData,
  const  BYTE* pUserData,
  HANDLE hTokenImpersonateUser,
  BOOL* pfInvokeUI,
  DWORD* pdwSizeofUserDataOut,
  BYTE** ppbUserDataOut,
  LPWSTR* ppwszIdentity,
  EAP_ERROR** ppEapError,
  BYTE** ppvReserved
);

typedef DWORD (APIENTRY* PINNEREAPHOSTPEERBEGINSESSION)(
   IN DWORD dwFlags,
   IN EAP_METHOD_TYPE eapType,
   IN const EapAttributes* const pAttributeArray,
   IN HANDLE hTokenImpersonateUser,
   IN DWORD dwSizeofConnectionData,
   IN const BYTE* const pConnectionData,
   IN DWORD dwSizeofUserData,
   IN const BYTE* const pUserData,
   IN DWORD dwMaxSendPacketSize,
   // If the supplicant is intrested in re-auth caused by SoH chagne,
   // it should provide a unique GUID.
   // When this function is called by PEAP inner method, it will be NULL.
   // 
   // When pConnectionId is NULL, func and pContextData will be ignored.
   IN const GUID* const pConnectionId,
   // if the function handler is NULL, pContextData will be ignored,
   // and it means the caller is not interested in SoH change notification
   // from EapQec.
   IN PNOTIFICATIONHANDLER func,
   // a pointer to some data that the supplicant want to associate with
   // the connection when NotificationHandler call back is called.
   // When NotificationHandler is called, it will be called as:
   // func(*pCOnnectionId, pContextData).
   IN void* pContextData,
   OUT EAP_SESSIONID* pSessionId,
   OUT EAP_ERROR** ppEapError
   );

typedef DWORD (APIENTRY* PINNEREAPHOSTPEERENDSESSION)(
   IN EAP_SESSIONID sessionHandle,
   OUT EAP_ERROR** ppEapError
   );

typedef DWORD (APIENTRY* PINNEREAPHOSTPEERPROCCESSRECEIVEDPACKET)(
   IN EAP_SESSIONID sessionHandle,
   IN DWORD cbReceivePacket,
   IN const BYTE* const pReceivePacket,
   OUT EapHostPeerResponseAction* pEapOutput,
   OUT EAP_ERROR** ppEapError
   );


typedef DWORD (APIENTRY* PINNEREAPHOSTPEERGETSENDPACKET)(
   IN EAP_SESSIONID sessionHandle,
	OUT DWORD* pcbSendPacket,
	OUT BYTE** ppSendPacket,
	OUT EAP_ERROR** ppEapError
	);
   

typedef DWORD (APIENTRY* PINNEREAPHOSTPEERGETRESULT)(
   IN EAP_SESSIONID sessionHandle,
	IN EapHostPeerMethodResultReason reason,
	OUT EapHostPeerMethodResult* ppResult, 
	OUT EAP_ERROR** ppEapError         
	   );


typedef DWORD (APIENTRY* PINNEREAPHOSTPEERGETUICONTEXT)(
   IN EAP_SESSIONID sessionHandle,
   OUT DWORD* pdwSizeOfUIContextData,
   OUT BYTE** ppUIContextData,
	OUT EAP_ERROR** ppEapError
   );


typedef DWORD (APIENTRY* PINNEREAPHOSTPEERSETUICONTEXT)(
   IN EAP_SESSIONID sessionHandle,
   IN DWORD dwSizeOfUIContextData,
   IN const BYTE* const pUIContextData,
   OUT EapHostPeerResponseAction* pEapOutput,
	OUT EAP_ERROR** ppEapError
	);


typedef DWORD (APIENTRY* PINNEREAPHOSTPEERGETRESPONSEATTRIBUTES)(
   IN EAP_SESSIONID sessionHandle,
   OUT EapAttributes* pAttribs,
	OUT EAP_ERROR** ppEapError
   );


typedef DWORD (APIENTRY* PINNEREAPHOSTPEERSETRESPONSEATTRIBUTES)(
   IN EAP_SESSIONID sessionHandle,
   IN const EapAttributes* const pAttribs,
   OUT EapHostPeerResponseAction* pEapOutput,
	OUT EAP_ERROR** ppEapError
   );


typedef DWORD (APIENTRY* PINNEREAPHOSTPEERGETAUTHSTATUS)(
   IN EAP_SESSIONID sessionHandle,
   IN EapHostPeerAuthParams authParam,
   OUT DWORD* pcbAuthData,
   OUT BYTE** ppAuthData,
   OUT EAP_ERROR** ppEapError   
   );


typedef DWORD (APIENTRY* PINNEREAPHOSTPEERCLEARCONNECTION)(
   IN GUID *connectionId,
   OUT EAP_ERROR** ppEapError
   );

typedef void (APIENTRY* PINNEREAPHOSTPEERFREEEAPERROR)(IN EAP_ERROR* pEapError); 

typedef void (APIENTRY* PINNEREAPHOSTPEERFREERUNTIMEMEMORY)( IN BYTE* pData );

#endif // SW2_EAP_HOST

typedef struct _SW2_USER_DATA 
{
	//
	// General user information
	//
	WCHAR					pwcUsername[UNLEN];
	WCHAR					pwcPassword[PWLEN];
	WCHAR					pwcDomain[UNLEN];

#ifndef _WIN32_WCE
	//
	// CUSTOM DIALOG
	// Contributed by Wyman Miles (Cornell University)
	//
	// overloaded from profile information
	//
	BOOL						bAllowCachePW; // TRUE == yes; FALSE == no
	WCHAR						pwcAltUsernameStr[UNLEN];
	WCHAR						pwcAltPasswordStr[PWLEN];
	WCHAR						pwcAltDomainStr[UNLEN];
	WCHAR						pwcAltCredsTitle[UNLEN];
	WCHAR						pwcProfileDescription[UNLEN];

	//
	// Adapter information
	//
	WCHAR					pwcPhonebook[UNLEN];
	WCHAR					pwcEntry[UNLEN];
#endif // _WIN32_WCE

	BOOL					bSaveUserCredentials;

	//
	//
	// Stuff needed for session resumption
	//
	int						cbTLSSessionID;
	BYTE					pbTLSSessionID[TLS_SESSION_ID_SIZE];
	time_t					tTLSSessionID; // the time this TTLS session ID was set

	BYTE					pbMS[TLS_MS_SIZE];

	//
	// To see what happened in a previous session
	// 
	SW2_EAP_REASON			prevEapReason;

	//
	// Stuff needed for inner EAP authentication
	//
	SW2_INNER_EAP_USER_DATA	InnerEapUserData;

} SW2_USER_DATA, *PSW2_USER_DATA;

typedef struct _SW2_PROFILE_DATA
{
	INT							iVersion;
	BYTE						bEapType;
	WCHAR						pwcUserName[UNLEN];
	WCHAR						pwcUserPassword[PWLEN];
	WCHAR						pwcUserDomain[UNLEN];

//
// CUSTOM DIALOG
// Contributed by Wyman Miles (Cornell University)
//
	BOOL						bAllowCachePW; // TRUE == yes; FALSE == no
#ifndef _WIN32_WCE
	WCHAR						pwcAltUsernameStr[UNLEN];
	WCHAR						pwcAltPasswordStr[PWLEN];
	WCHAR						pwcAltRePasswordStr[PWLEN];
	WCHAR						pwcAltDomainStr[UNLEN];
	WCHAR						pwcAltCredsTitle[UNLEN];
	WCHAR						pwcAltProfileStr[UNLEN];

	BOOL						bUseAlternateComputerCred;
	WCHAR						pwcCompName[UNLEN];
	WCHAR						pwcCompPassword[PWLEN];
	WCHAR						pwcCompDomain[UNLEN];
#endif // _WIN32_WCE

	WCHAR						pwcInnerAuth[UNLEN];

	BOOL						bUseAlternateIdentity;
	BOOL						bUseAnonymousIdentity;
	BOOL						bUseEmptyIdentity;
	WCHAR						pwcAlternateIdentity[UNLEN];

	BOOL						bVerifyServerCertificate;
	BOOL						bVerifyServerName;
	BOOL						bServerCertificateLocal;
	WCHAR						pwcServerName[UNLEN];

	BOOL						bPromptUser;
#ifndef _WIN32_WCE
	BOOL						bUseUserCredentialsForComputer;
#endif // _WIN32_WCE
	BOOL						bUseSessionResumption;

#ifndef _WIN32_WCE
	BOOL						bAllowNotifications;
	BOOL						bRenewIP;
#endif // _WIN32_WCE

	BOOL						bVerifyMSExtension;
	BOOL						bAllowNewConnection;

	HWND						hWndTabs[SW2_MAX_TAB];

	//
	// Current EAP ID this SecureW2 config is using
	//
	DWORD						dwCurrentInnerEapMethod;

	WCHAR						pwcCurrentProfileId[UNLEN];

	//
	// Currently the profile description is only used during 
	// installation on non Windows CE, to save space we ignore
	// this on Windows CE
	//
	// Windows CE only support registry keys up to 4096 bytes, so we need to save space
	//
	// 
#ifndef _WIN32_WCE
	WCHAR						pwcProfileDescription[UNLEN];
#endif _WIN32_WCE
	//
	// SHA1 of trusted root certificates
	//
	DWORD						dwNrOfTrustedRootCAInList;
	BYTE						pbTrustedRootCAList[SW2_MAX_CA][20];

#ifndef _WIN32_WCE
	BYTE						pbInnerEapConnectionData[EAP_MAX_INNER_CONNECTION_DATA];
	DWORD						cbInnerEapConnectionData;
#endif // _WIN32_WCE

} SW2_PROFILE_DATA, *PSW2_PROFILE_DATA;

typedef struct _SW2_GTC_CONFIG_DATA
{
	WCHAR	pwcIdentity[UNLEN];

} SW2_GTC_CONFIG_DATA, *PSW2_GTC_CONFIG_DATA;

//
// Profile
//
VOID				SW2_InitDefaultProfile( IN OUT PSW2_PROFILE_DATA pProfile, IN BYTE bEAPType);

DWORD				SW2_CreateProfile( IN WCHAR *pwcProfileID );
DWORD				SW2_DeleteProfile( IN WCHAR	*pwcProfileID );

DWORD				SW2_ReadProfile( IN WCHAR *pwcProfileID, 
									IN HANDLE hTokenImpersonateUser,
									IN OUT PSW2_PROFILE_DATA pProfileData );

DWORD				SW2_WriteCertificates( IN WCHAR *pwcProfileID, IN SW2_PROFILE_DATA ProfileData );
DWORD				SW2_ReadCertificates( IN WCHAR *pwcProfileID, IN PSW2_PROFILE_DATA ProfileData );

DWORD				SW2_WriteUserProfile( IN WCHAR *pwcProfileID, 
											IN HANDLE hTokenImpersonateUser,
											IN OUT SW2_PROFILE_DATA ProfileData );

DWORD				SW2_WriteComputerProfile( IN WCHAR *pwcProfileID, 
											IN HANDLE hTokenImpersonateUser,
											IN OUT SW2_PROFILE_DATA ProfileData );

DWORD				SW2_ReadInnerEapMethod( IN DWORD dwEapType, 
											IN WCHAR *pwcCurrentProfileId, 
											IN OUT PSW2_INNER_EAP_CONFIG_DATA pInnerEapConfigData );

DWORD				SW2_WriteInnerEapMethod( IN DWORD dwEapType, 
											IN WCHAR *pwcCurrentProfileId, 
											IN PBYTE pbConnectioNData,
											IN DWORD cbConnectionData);

//
// Registration key 
//
DWORD	SW2_XorData( PBYTE pbDataIn, DWORD cbDataIn, PBYTE pbKey, DWORD cbKey, PBYTE *ppbDataOut );
DWORD	SW2_SetBinRegKey( WCHAR *pwcKey, PBYTE pbValue, DWORD cbValue );
DWORD	SW2_RegGetDWORDValue( HKEY hKey, WCHAR *pwcValue, DWORD *pdwData );
DWORD	SW2_RegGetValue( HKEY hKey, WCHAR *pwcValue, PBYTE *ppbData, DWORD *pcbData );

//
// Utils
//
PBYTE				SW2_HexToByte( PCHAR String, DWORD *Length );

WCHAR*				SW2_HexDumpW( BYTE *xBytes, DWORD xByteLength, WCHAR *xBuffer, DWORD xBufferLength );
CHAR*				SW2_HexDumpA( BYTE *xBytes, DWORD xByteLength, CHAR *xBuffer, DWORD xBufferLength );

#ifdef UNICODE
#define SW2_HexDump  SW2_HexDumpW
#else
#define SW2_HexDump	 SW2_HexDumpA
#endif // UNICODE

//
// Error Handling
//
VOID				SW2_HandleInteractiveError( IN HWND hWndParent,
												IN DWORD dwError,
												IN SW2_EAP_FUNCTION EapFunction,
												IN SW2_TLS_STATE TLSState);

VOID				SW2_HandleError(IN DWORD dwError,
									IN SW2_EAP_FUNCTION EapFunction,
									IN SW2_TLS_STATE TLSState,
									IN BOOL *pbInvokeUI);

//
// Profile
//
DWORD				SW2_CreateAdminKey( IN HKEY hKey, 
										IN WCHAR *pwcSubKey, 
										OUT HKEY *phSubKey,
										OUT DWORD *pdwDisposition );

DWORD				SW2_CreateSecureKey( IN HKEY hKey, 
										IN WCHAR *pwcSubKey, 
										OUT HKEY *phSubKey,
										OUT DWORD *pdwDisposition );
