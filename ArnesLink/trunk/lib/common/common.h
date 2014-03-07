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
#ifndef COMMON_H
#define COMMON_H

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

#include <windows.h>
#include <wincrypt.h>

#ifndef _WIN32_WCE
#include <rtutils.h>
#endif // _WIN32_WCE
#include <lmcons.h>
#include <Raseapif.h>
#include <raserror.h>

#ifdef _WIN32_WCE
#include <Msxml2.h>
#else
#include <eaptypes.h>
#include <eapmethodtypes.h>
#include <eapmethodpeerapis.h>
#endif // _WIN32_WCE

#include <atlbase.h> // Includes CComVariant and CComBSTR.

extern DWORD		g_dwSW2TraceId;
extern HANDLE		g_localHeap;
extern HINSTANCE	g_hInstance;
extern HINSTANCE	g_hResource;
extern HINSTANCE	g_hLanguage;
extern HINSTANCE	g_hExternal;
// OS version information
extern DWORD		g_dwMajorVersion;
extern DWORD		g_dwMinorVersion;

// eap identification
#define			EAPVENDOR L"SecureW2"
extern BYTE		EAPTYPE;
extern PWCHAR	EAPID;
extern PWCHAR	EAPFRIENDLYID;
extern PWCHAR	EAPDLLNAME;
extern DWORD	EAPPROPERTIES;
extern DWORD	EAPUSERNAMEDLG;
extern DWORD	EAPPWDDLG;
extern DWORD	EAPMPPESUPPORTED;
extern DWORD	EAPSTANDALONESUPPORTED;

extern DWORD	VERSION;
extern DWORD	AUTHOR_ID;
extern DWORD	VENDOR_ID;
extern DWORD	VENDOR_TYPE;

// Common EAP types
#define EAP_TYPE_GTC		6
#define EAP_TYPE_TTLS		21
#define EAP_TYPE_PEAP		25

// EAP method-version mask
#define EAP_METHOD_VERSION	0x07

// register functions
extern DWORD SW2_RegisterEapHostDLL();
extern DWORD SW2_RegisterEapHostExtendedDLL();
extern DWORD SW2_UnregisterEapHostDLL();
extern DWORD SW2_UnregisterEapHostExtendedDLL();
extern DWORD SW2_RegisterRASEAPDLL();
extern DWORD SW2_UnregisterRASEAPDLL();

typedef enum SW2EAPATTRIBUTE_TYPE
{
    SW2EAPATTRIBUTE_Minimum = 0,
    SW2EAPATTRIBUTE_UserName,                   
    SW2EAPATTRIBUTE_UserPassword,               
    SW2EAPATTRIBUTE_MD5CHAPPassword,            
    SW2EAPATTRIBUTE_NASIPAddress,               
    SW2EAPATTRIBUTE_NASPort,                    
    SW2EAPATTRIBUTE_ServiceType,                
    SW2EAPATTRIBUTE_FramedProtocol,             
    SW2EAPATTRIBUTE_FramedIPAddress,            
    SW2EAPATTRIBUTE_FramedIPNetmask,            
    SW2EAPATTRIBUTE_FramedRouting = 10,         
    SW2EAPATTRIBUTE_FilterId,                   
    SW2EAPATTRIBUTE_FramedMTU,                  
    SW2EAPATTRIBUTE_FramedCompression,          
    SW2EAPATTRIBUTE_LoginIPHost,                
    SW2EAPATTRIBUTE_LoginService,               
    SW2EAPATTRIBUTE_LoginTCPPort,               
    SW2EAPATTRIBUTE_Unassigned17,               
    SW2EAPATTRIBUTE_ReplyMessage,               
    SW2EAPATTRIBUTE_CallbackNumber,             
    SW2EAPATTRIBUTE_CallbackId =20,             
    SW2EAPATTRIBUTE_Unassigned21,               
    SW2EAPATTRIBUTE_FramedRoute,                
    SW2EAPATTRIBUTE_FramedIPXNetwork,           
    SW2EAPATTRIBUTE_State,                      
    SW2EAPATTRIBUTE_Class,                      
    SW2EAPATTRIBUTE_VendorSpecific,             
    SW2EAPATTRIBUTE_SessionTimeout,             
    SW2EAPATTRIBUTE_IdleTimeout,                
    SW2EAPATTRIBUTE_TerminationAction,          
    SW2EAPATTRIBUTE_CalledStationId = 30,       
    SW2EAPATTRIBUTE_CallingStationId,           
    SW2EAPATTRIBUTE_NASIdentifier,              
    SW2EAPATTRIBUTE_ProxyState,                 
    SW2EAPATTRIBUTE_LoginLATService,            
    SW2EAPATTRIBUTE_LoginLATNode,               
    SW2EAPATTRIBUTE_LoginLATGroup,              
    SW2EAPATTRIBUTE_FramedAppleTalkLink,        
    SW2EAPATTRIBUTE_FramedAppleTalkNetwork,     
    SW2EAPATTRIBUTE_FramedAppleTalkZone,        
    SW2EAPATTRIBUTE_AcctStatusType = 40,        
    SW2EAPATTRIBUTE_AcctDelayTime,              
    SW2EAPATTRIBUTE_AcctInputOctets,            
    SW2EAPATTRIBUTE_AcctOutputOctets,           
    SW2EAPATTRIBUTE_AcctSessionId,              
    SW2EAPATTRIBUTE_AcctAuthentic,              
    SW2EAPATTRIBUTE_AcctSessionTime,            
    SW2EAPATTRIBUTE_AcctInputPackets,           
    SW2EAPATTRIBUTE_AcctOutputPackets,          
    SW2EAPATTRIBUTE_AcctTerminateCause,         
    SW2EAPATTRIBUTE_AcctMultiSessionId = 50,    
    SW2EAPATTRIBUTE_AcctLinkCount,              
    SW2EAPATTRIBUTE_AcctEventTimeStamp = 55,    
    SW2EAPATTRIBUTE_MD5CHAPChallenge = 60,      
    SW2EAPATTRIBUTE_NASPortType,                
    SW2EAPATTRIBUTE_PortLimit,                  
    SW2EAPATTRIBUTE_LoginLATPort,               
    SW2EAPATTRIBUTE_TunnelType,                 
    SW2EAPATTRIBUTE_TunnelMediumType,           
    SW2EAPATTRIBUTE_TunnelClientEndpoint,       
    SW2EAPATTRIBUTE_TunnelServerEndpoint,       
    SW2EAPATTRIBUTE_ARAPPassword = 70,          
    SW2EAPATTRIBUTE_ARAPFeatures,               
    SW2EAPATTRIBUTE_ARAPZoneAccess,             
    SW2EAPATTRIBUTE_ARAPSecurity,               
    SW2EAPATTRIBUTE_ARAPSecurityData,           
    SW2EAPATTRIBUTE_PasswordRetry,              
    SW2EAPATTRIBUTE_Prompt,                     
    SW2EAPATTRIBUTE_ConnectInfo,                
    SW2EAPATTRIBUTE_ConfigurationToken,         
    SW2EAPATTRIBUTE_EAPMessage,                 
    SW2EAPATTRIBUTE_Signature = 80,             
    SW2EAPATTRIBUTE_ARAPChallengeResponse = 84, 
    SW2EAPATTRIBUTE_AcctInterimInterval = 85,   
    SW2EAPATTRIBUTE_NASIPv6Address = 95,  
    SW2EAPATTRIBUTE_FramedInterfaceId, 
    SW2EAPATTRIBUTE_FramedIPv6Prefix, 
    SW2EAPATTRIBUTE_LoginIPv6Host, 
    SW2EAPATTRIBUTE_FramedIPv6Route,				
    SW2EAPATTRIBUTE_FramedIPv6Pool,				

	SW2EAPATTRIBUTE_ARAPGuestLogon = 8096,      
    SW2EAPATTRIBUTE_CertificateOID,             
    SW2EAPATTRIBUTE_EAPConfiguration,           
    SW2EAPATTRIBUTE_PEAPEmbeddedEAPTypeId,      
    SW2EAPATTRIBUTE_PEAPFastRoamedSession,      
    
	SW2EAPATTRIBUTE_EAPTLV = 8102,              
    SW2EAPATTRIBUTE_CredentialsChanged,
    SW2EAPATTRIBUTE_InnerEapMethodType,

	SW2EAPATTRIBUTE_ClearTextPassword = 8107,

	SW2EAPATTRIBUTE_QuarantineSoH     = 8150,
    SW2EAPATTRIBUTE_PeerId            = 9000,
    SW2EAPATTRIBUTE_ServerId,
    SW2EAPATTRIBUTE_MethodId,
    SW2EAPATTRIBUTE_EMSK,
    SW2EAPATTRIBUTE_Reserved = 0xFFFFFFFF       

} SW2EAPATTRIBUTE_TYPE;

typedef struct _SW2EAPATTRIBUTE
{
    SW2EAPATTRIBUTE_TYPE	aaType;
    DWORD					dwLength;
    PVOID					Value;

} SW2EAPATTRIBUTE, *PSW2EAPATTRIBUTE;

typedef struct SW2EAPPACKET
{
   BYTE Code;
   BYTE Id;
   BYTE Length[2];
   BYTE Data[1];
   // Any additional data following the first byte. The length of
   // the data can be deduced by the length fields.
} SW2EAPPACKET,*PSW2EAPPACKET;

typedef enum _SW2EAPCODE
{
   SW2EAPCODE_Minimum = 1,
   SW2EAPCODE_Request = 1,
   SW2EAPCODE_Response,
   SW2EAPCODE_Success,
   SW2EAPCODE_Failure,
   SW2EAPCODE_Maximum = SW2EAPCODE_Failure

} SW2EAPCODE;

typedef enum _SW2EAPACTION
{
	SW2EAPACTION_Discard = 0,
    SW2EAPACTION_Send,
	SW2EAPACTION_InvokeUI,
	SW2EAPACTION_None,
	SW2EAPACTION_Done

} SW2EAPACTION;

typedef struct _SW2EAPOUTPUT 
{
	SW2EAPACTION	eapAction;
	BOOL			bAllowNotifications;

} SW2EAPOUTPUT, *PSW2EAPOUTPUT;

typedef enum _SW2_EAP_FUNCTION
{
	SW2_EAP_FUNCTION_None,
	SW2_EAP_FUNCTION_Initialize,
	SW2_EAP_FUNCTION_DeInitialize,
	SW2_EAP_FUNCTION_InvokeConfigUI,
	SW2_EAP_FUNCTION_InvokeInteractiveUI,
	SW2_EAP_FUNCTION_GetIdentity,
	SW2_EAP_FUNCTION_InvokeIdentityUI,
	SW2_EAP_FUNCTION_GetUIContext,
	SW2_EAP_FUNCTION_SetUIContext,
	SW2_EAP_FUNCTION_Begin,
	SW2_EAP_FUNCTION_Process,
	SW2_EAP_FUNCTION_End,
	SW2_EAP_FUNCTION_GetResult,
	SW2_EAP_FUNCTION_FreeMemory

} SW2_EAP_FUNCTION;

typedef enum _SW2_TLS_STATE
{
	SW2_TLS_STATE_None,
    SW2_TLS_STATE_Start,
	SW2_TLS_STATE_Server_Hello,
	SW2_TLS_STATE_Verify_Cert_UI,
	SW2_TLS_STATE_Change_Cipher_Spec,
	SW2_TLS_STATE_Resume_Session,
	SW2_TLS_STATE_Resume_Session_Ack,
	SW2_TLS_STATE_Inner_Authentication,
	SW2_TLS_STATE_Error,
	SW2_TLS_STATE_Finished

} SW2_TLS_STATE;

typedef enum _SW2_INNER_EAP_STATE
{
    SW2_INNER_EAP_STATE_Start,
	SW2_INNER_EAP_STATE_Identity,
	SW2_INNER_EAP_STATE_EAPType,
	SW2_INNER_EAP_STATE_InteractiveUI,
	SW2_INNER_EAP_STATE_MakeMessage,
	SW2_INNER_EAP_STATE_Finished

} SW2_INNER_EAP_STATE;

typedef enum _SW2_EAP_REASON
{
   SW2_EAP_REASON_Unknown = 1,
   SW2_EAP_REASON_Success,
   SW2_EAP_REASON_Failure,
   SW2_EAP_REASON_Pending

} SW2_EAP_REASON;

typedef enum _SW2_AUTH_STATE
{
	SW2_AUTH_STATE_NONE,
	SW2_AUTH_STATE_IDENTITY,
	SW2_AUTH_STATE_START_SESSION,
	SW2_AUTH_STATE_VERIFY_CERT,
	SW2_AUTH_STATE_AUTHENTICATING,
	SW2_AUTH_STATE_END_SESSION,
	SW2_AUTH_STATE_UI,

} SW2_AUTH_STATE;

typedef enum _SW2_ERROR
{
    SW2_ERROR_NO_ERROR,
	SW2_ERROR_INTERNAL,
	SW2_ERROR_CRYPTO,
	SW2_ERROR_CERTIFICATE,
	SW2_ERROR_CERTIFICATE_INVALID_SERVERNAME,
	SW2_ERROR_CERTIFICATE_INVALID_USAGE,
	SW2_ERROR_CERTIFICATE_INVALID_TRUST,
	SW2_ERROR_TLS,
	SW2_ERROR_AUTH_FAILED,
	SW2_ERROR_INNER_AUTH,
	SW2_ERROR_NOT_SUPPORTED,
	SW2_ERROR_CANCELLED,
	SW2_ERROR_NO_DATA

} SW2_ERROR;

// eap method specific functions
DWORD SW2EapMethodInitialize();

DWORD SW2EapMethodDeInitialize();

DWORD SW2EapMethodBegin(IN DWORD	dwFlags,
						IN HANDLE	hTokenImpersonateUser,
						IN DWORD	dwSizeofConnectionData,
						IN PBYTE	pbConnectionData,
						IN DWORD	dwSizeofUserData,
						IN PBYTE	pbUserData,
						IN PWCHAR	pwcUsername,
						IN PWCHAR	pwcPassword,
						OUT PVOID	*pWorkBuffer);

DWORD SW2EapMethodEnd(IN PVOID pWorkBuffer);

DWORD SW2EapMethodFreeMemory(IN PVOID * ppMemory);

DWORD  SW2EapMethodInvokeConfigUI(IN HWND		hwndParent,
								  IN DWORD		dwFlags,
								  IN DWORD		dwSizeOfConnectionDataIn,
								  IN PBYTE		pbConnectionDataIn,
								  OUT DWORD		*pdwSizeOfConnectionDataOut,
								  OUT PBYTE		*ppbConnectionDataOut);

DWORD SW2EapMethodInvokeInteractiveUI(IN HWND		hwndParent,
									  IN DWORD		dwSizeofUIContextData,
									  IN PBYTE		pbUIContextData,
									  OUT DWORD		*pdwSizeOfDataFromInteractiveUI,
									  OUT PBYTE		*ppbDataFromInteractiveUI);
		 
DWORD SW2EapMethodInvokeIdentityUI(IN HWND			hWndParent,
								   IN DWORD			dwFlags,
								   IN DWORD			dwSizeOfConnectionDataIn,
								   IN const BYTE	*pbConnectionDataIn,										
								   IN DWORD			dwSizeOfUserDataIn,
								   IN const BYTE	*pbUserDataIn,
								   OUT DWORD		*pdwSizeOfUserDataOut,
								   OUT PBYTE		*ppUserDataOut,
								   OUT PWCHAR		*ppwcIdentity);

DWORD SW2EapMethodGetIdentity(IN DWORD		dwFlags,
							  IN DWORD		dwSizeofConnectionData,
							  IN const BYTE	*pbConnectionData,
							  IN DWORD		dwSizeofUserData,
							  IN const BYTE	*pbUserData,								
							  IN HANDLE		hTokenImpersonateUser,
							  OUT BOOL	*	bInvokeUI,
							  IN OUT DWORD	*pdwSizeOfUserDataOut,
							  OUT PBYTE		*ppUserDataOut,
							  OUT PWCHAR	*ppwcIdentity);

DWORD SW2EapMethodProcess(IN PVOID				pWorkBuffer,										
						  IN PSW2EAPPACKET		pReceivePacket,
						  IN DWORD				cbSendPacket,
						  OUT PSW2EAPPACKET		pSendPacket,
						  OUT SW2EAPOUTPUT		*pEapOutput);

DWORD SW2EapMethodGetUIContext(IN PVOID pWorkBuffer,
							   IN DWORD *pdwSizeOfUIContextData,
							   IN PBYTE	*ppbUIContextData);

DWORD SW2EapMethodSetUIContext(IN PVOID pWorkBuffer,
							   IN DWORD dwSizeOfUIContextData,
							   IN PBYTE	pbUIContextData);

DWORD SW2EapMethodGetResult(IN PVOID				pWorkBuffer,
							IN SW2_EAP_REASON		eapReason,
							OUT	BOOL				*pfResult,
							OUT BOOL				*pfSaveUserData,
							OUT	DWORD				*pdwSizeofUserData,
							OUT PBYTE				*ppbUserData,
							OUT BOOL				*pfSaveConnectionData,
							OUT	DWORD				*pdwSizeofConnectionData,
							OUT PBYTE				*ppbConnectionData,
							OUT	DWORD				*pdwNumberOfAttributes,
							OUT PSW2EAPATTRIBUTE	*pAttributes);

DWORD SW2EapMethodConfigXml2Blob(IN DWORD				dwFlags,
								 IN IXMLDOMDocument2	*pXMLConfigDoc,
								 OUT PBYTE				*ppbConfigOut,
								 OUT DWORD				*pdwSizeOfConfigOut);

DWORD SW2EapMethodConfigBlob2Xml(IN DWORD				dwFlags,
								 IN const BYTE			*pbConfig,
								 IN DWORD				dwSizeOfConfig,
								 OUT IXMLDOMDocument2	**ppXMLConfigDoc);

DWORD SW2EapMethodCredentialsXml2Blob(IN DWORD					dwFlags,
										IN IXMLDOMDocument2*	pXMLCredentialsDoc,
										IN 	const BYTE*			pbConfigIn,
										IN DWORD				dwSizeOfConfigIn,
										OUT	BYTE				** ppbCredentialsOut,
										OUT DWORD*				pdwSizeOfCredentialsOut);

#ifndef _WIN32_WCE
// SSO functions
DWORD	SW2EapMethodQueryCredentialInputFields(IN  HANDLE							hUserToken,
											   IN  DWORD							dwFlags,
											   IN  DWORD							dwSizeofConnectionData,
											   IN  PBYTE							pbConnectionData,
											   OUT	EAP_CONFIG_INPUT_FIELD_ARRAY	*pEapConfigInputFieldArray);

DWORD	SW2EapMethodQueryUserBlobFromCredentialInputFields(IN  HANDLE						hUserToken,
														   IN  DWORD						dwFlags,
														   IN  DWORD						dwEapConnDataSize,
														   IN  PBYTE						pbEapConnData,
														   IN  CONST EAP_CONFIG_INPUT_FIELD_ARRAY	*pEapConfigInputFieldArray,
														   OUT DWORD						*pdwUserBlobSize,
														   OUT PBYTE						*ppbUserBlob);
#endif // _WIN32_WCE

/*
DWORD WINAPI SW2EapMethodQueryUIBlobFromInteractiveUIInputFields(
	IN DWORD							dwVersion,
	IN DWORD							dwFlags,
	IN DWORD							dwSizeofUIContextData,
	IN const PBYTE						pUIContextData,
	IN const EAP_INTERACTIVE_UI_DATA	*pEapInteractiveUIData,
	IN OUT DWORD						*pdwSizeOfDataFromInteractiveUI,
	IN OUT PBYTE						*ppDataFromInteractiveUI);
*/
// tracing functions

#define SW2_TRACE_LEVEL_ERROR	0x00010000
#define SW2_TRACE_LEVEL_WARNING 0x00020000
#define SW2_TRACE_LEVEL_INFO	0x00040000
#define SW2_TRACE_LEVEL_DEBUG	0x00080000

#define SW2_TRACE_DEFAULT_MASK  0x00010000

VOID   
SW2Dump(
	IN DWORD dwTraceLevel,
    IN PBYTE pbData, 
	IN DWORD cbData
);

VOID SW2Trace(
	IN DWORD	dwTraceLevel,
    IN PWCHAR   pwcFormat, 
    ... 
	);

DWORD SW2SetDefaultTraceLevel(IN PWCHAR pwcEapId);
DWORD SW2RemoveTraceConfiguration(IN PWCHAR pwcEapId);

// memory functions
DWORD
SW2InitializeHeap(
);

DWORD
SW2DeInitializeHeap(
);

DWORD
SW2AllocateMemory(
    IN     DWORD dwSizeInBytes,
    IN OUT PVOID *pBuffer
);

DWORD
SW2FreeMemory(
    IN OUT PVOID *pBuffer
);

// utility functions
DWORD SW2_WireToHostFormat32(IN PBYTE pbWireFormat);
DWORD SW2_WireToHostFormat24(IN PBYTE pbWireFormat);
DWORD SW2_WireToHostFormat16(IN PBYTE pbWireFormat);

VOID SW2_HostToWireFormat32(IN DWORD dwHostFormat, IN OUT PBYTE pbWireFormat);
VOID SW2_HostToWireFormat24(IN DWORD dwHostFormat, IN OUT PBYTE pbWireFormat);
VOID SW2_HostToWireFormat16(IN DWORD dwHostFormat, IN OUT PBYTE pbWireFormat);

DWORD SW2_ToUpperString( IN PCHAR pcBufferIn, 
						OUT PCHAR *ppcBufferOut);

DWORD SW2_ByteToHex(IN DWORD	dwSizeOfData,
					IN PBYTE	pbData, 
					OUT PWCHAR	*ppwcBuffer);

DWORD SW2_HexToByte(IN PCHAR pcBufferIn, 
					OUT DWORD *pdwSizeOfBufferOut, 
					OUT PBYTE *ppbBufferOut);

PCHAR				SW2_ToUpperString( PCHAR String );
VOID				SW2_SwapArray( IN BYTE *xIn, OUT BYTE *xOut, IN int xLength );

BOOL				SW2_GetTextualSid( IN PSID pSid, OUT LPTSTR TextualSid, OUT LPDWORD lpdwBufferLen );
BOOL				SW2_IsAdmin();

DWORD SW2_PutXmlElementHex(IN IXMLDOMDocument2	*pXmlDoc, 
						   IN IXMLDOMNode		*pCurrentDOMNode,
						   IN PWCHAR			pwcElementName, 
						   IN DWORD				dwSizeOfElementValue,
						   IN PBYTE				pbElementValue);
							 

DWORD SW2_PutXmlElementBOOL(IN IXMLDOMDocument2	*pXmlDoc, 
							IN IXMLDOMNode		*pCurrentDOMNode,
							IN PWCHAR			pwcElementName,
							IN BOOL				bElementValue);

DWORD SW2_PutXmlElementDWORD(IN IXMLDOMDocument2	*pXmlDoc, 
							  IN IXMLDOMNode		*pCurrentDOMNode,
							  IN PWCHAR				pwcElementName, 
							  IN DWORD				dwElementValue);

DWORD SW2_PutXmlElementString(IN IXMLDOMDocument2	*pXmlDoc, 
							  IN IXMLDOMNode		*pCurrentDOMNode,
							  IN PWCHAR				pwcElementName, 
							  IN PWCHAR				pwcElementValue);

DWORD SW2_GetXmlElementValue(IN IXMLDOMDocument2	*pXmlDoc,
							 IN LPWSTR				pwcElementName, 
							 OUT PWCHAR				*ppwcElementValue);

DWORD SW2_GetXmlElementList(IN IXMLDOMDocument2		*pXmlDoc, 
							 IN LPWSTR				pwcElementName, 
							 OUT IXMLDOMNodeList	**ppDOMList);

DWORD SW2_GetXmlElementNode(IN IXMLDOMDocument2	*pXmlDoc, 
							IN LPWSTR			pwcElementName, 
							OUT IXMLDOMNode		**ppDOMNode);

#ifndef _WIN32_WCE
DWORD SW2_StartSVC(IN WCHAR *pwcService, IN BOOL bAutomatic);
DWORD SW2_StopSVC( IN WCHAR *pwcService);
#endif

//
// ERROR
//
DWORD
SW2_ReportEvent( WCHAR *pwcMsg, WORD wType, DWORD dwError );

// CRYPTO
DWORD	SW2_GetCertificate(	PBYTE pbServerCertSHA1, 
							OUT PCCERT_CONTEXT *ppCertContext );

DWORD TLSGetMD5( IN HCRYPTPROV hCSP, 
				IN PBYTE pbMsg, 
				IN DWORD cbMsg, 
				OUT PBYTE *ppbMD5, 
				OUT DWORD *pcbMD5 );

DWORD TLSGetSHA1( IN HCRYPTPROV hCSP,
					IN PBYTE pbMsg, 
					IN DWORD cbMsg, 
					OUT PBYTE *ppbSHA1, 
					OUT DWORD *pcbSHA1 );

DWORD SW2_CryptAcquireDefaultContext( HCRYPTPROV *phCSP, 
									 WCHAR *pwcContainer );


DWORD	SW2_CryptAcquireContext( HCRYPTPROV *phCSP, 
								WCHAR *pwcContainer,
								WCHAR *pwcCSPName, 
								DWORD dwType );

//
// Registry functions
//
DWORD SW2BackupEapMethod(IN BYTE EAPTYPE);
DWORD SW2RestoreEapMethod(IN BYTE EAPTYPE);

//
// external interface function pointers
//

typedef PVOID (APIENTRY* PSW2INITIALIZE) (IN INT iEapType); 

typedef VOID (APIENTRY* PSW2UNINITIALIZE) (IN PVOID pContext); 

typedef DWORD (APIENTRY* PSW2GETIDENTITY) (IN PVOID		pContext,
										  OUT PWCHAR	*ppwcIdentity,
										  OUT BOOL		*bInvokeUI,
										  OUT BOOL		*bSaveIdentity); 

typedef DWORD (APIENTRY* PSW2INVOKEIDENTITYUI) (IN PVOID	pContext, 
												IN HWND		hWndParent,
												OUT PWCHAR	*ppwcIdentity,
												OUT BOOL	*bSaveIdentity);  

typedef VOID (APIENTRY* PSW2FREEIDENTITY) (IN PWCHAR pwcIdentity); 

typedef DWORD (APIENTRY* PSW2GETRESPONSE) (IN PVOID		pContext,
										   IN PWCHAR	pwcIdentity,
										   IN PBYTE		pbChallenge,
										   IN DWORD		cbChallenge,
										   OUT BOOL		*bInvokeUI,
										   OUT PBYTE	*ppbResponse,
										   OUT DWORD	*pcbResponse);  

typedef DWORD (APIENTRY* PSW2INVOKERESPONSEUI) (IN PVOID	pContext,
											   IN HWND		hWndParent,
											   IN PWCHAR	pwcIdentity,
											   IN PBYTE		pbChallenge,
											   IN DWORD		cbChallenge,
											   OUT PBYTE	*ppbResponse,
											   OUT DWORD	*pcbResponse); 

typedef VOID (APIENTRY* PSW2FREERESPONSE) (IN PBYTE pbResponse);

typedef DWORD (APIENTRY* PSW2GETCREDENTIALS) (IN PVOID		pContext,
											 OUT PWCHAR		*ppwcIdentity,
											 OUT PWCHAR		*ppwcPassword,
											 OUT BOOL		*bInvokeUI,
											 OUT BOOL		*bSaveCredentials); 

typedef DWORD (APIENTRY* PSW2INVOKECREDENTIALSUI) (IN PVOID		pContext, 
												IN HWND			hWndParent,
												OUT PWCHAR		*ppwcIdentity,
												OUT PWCHAR		*ppwcPassword,
												OUT BOOL		*bSaveCredentials); 

typedef VOID (APIENTRY* PSW2FREECREDENTIALS) (IN PWCHAR pwcIdentity, IN PWCHAR pwcPassword); 

typedef DWORD (APIENTRY* PSW2HANDLERESULT) (IN PVOID			pContext, 
											IN SW2_EAP_REASON	eapReason);

typedef DWORD (APIENTRY* PSW2HANDLEERROR) (IN PVOID				pContext, 
											IN SW2_AUTH_STATE	AuthState, 
											IN SW2_ERROR		Error,
											OUT					BOOL *pbInvokeUI);

typedef DWORD (APIENTRY* PSW2HANDLEINTERACTIVEERROR) (IN PVOID				pContext, 
														IN HWND				hWndParent,
														IN SW2_AUTH_STATE	AuthState, 
														IN SW2_ERROR		Error);

//
// external interface context structure
//
typedef struct _SW2_RES_CONTEXT
{
	PVOID						pContext;

	PSW2INITIALIZE				pSW2Initialize;
	PSW2UNINITIALIZE			pSW2Uninitialize;

	PSW2GETIDENTITY				pSW2GetIdentity;
	PSW2INVOKEIDENTITYUI		pSW2InvokeIdentityUI;
	PSW2FREEIDENTITY			pSW2FreeIdentity;
	
	PSW2GETRESPONSE				pSW2GetResponse;
	PSW2INVOKERESPONSEUI		pSW2InvokeResponseUI;
	PSW2FREERESPONSE			pSW2FreeResponse;

	PSW2GETCREDENTIALS			pSW2GetCredentials;
	PSW2INVOKECREDENTIALSUI		pSW2InvokeCredentialsUI;
	PSW2FREECREDENTIALS			pSW2FreeCredentials;

	PSW2HANDLERESULT			pSW2HandleResult;

	PSW2HANDLEERROR				pSW2HandleError;
	PSW2HANDLEINTERACTIVEERROR	pSW2HandleInteractiveError;

} SW2_RES_CONTEXT, *PSW2_RES_CONTEXT;

//
// external interface context pointer
//
extern PSW2_RES_CONTEXT		g_ResContext;

//
// Function for external interface
//
DWORD SW2ConvertExternalErrorCode(IN DWORD dwReturnCode);
DWORD SW2LoadExternalInterface(IN HINSTANCE hInstance, IN PSW2_RES_CONTEXT pResContext);

VOID SW2_PrintMemoryInfo(IN PWCHAR pwcPrefix);

#endif // COMMON_H
