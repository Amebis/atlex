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
/*

Version 1.4.2

Changes

1.4.2 - 16 juli 2008
* Removed SW2_ERROR_NOT_SUPPORTED functionality as the external interface replaces the
  entire default resource implementation. Error can still be used.

1.4.1 - 3 juli 2008
* fixed incorrect API definition in SW2handleError

1.4 - 8 juni 2008
* fixed incorrect API definition (forgot APIENTRY)

1.3 - 6 juni 2008
* Added error SW2_ERROR_NOT_SUPPORTED functionality
* changed EapState to FunctionState
* changed SW2_EAP_STATE to SW2_AUTH_STATE

1.2 - 1 juni 2008
* Added new generic interface

General

1. In the SW2GetIdentity and SW2GetCredentials the external interface can use the BOOL bSaveIdentity 
   to instruct the SecureW2 EAP Module to store the identity during the users logon session. This 
   means there will be no calls to the SW2GetIdentity or SW2GetCredentials. This occurs as long as 
   the users is logged in or an authentication attempt fails;

2. IMPORTANT: In the previous version the SW2FreeIdentity, SW2FreeResponse, SW2FreeCredentials provided 
   the pContext parameter. In the new version the function now provided the actual pointer to be freed.

3. If The SecureW2 EAP Module is being tunneled using the SW2 TTLS module then, depending on the TTLS 
   configuration, the "outer" identity will be modified. For example tom@gtc could become 
   anonymous@gtc (this applies to all use cases).

Workflow

Initialization and Unitialization

1. At system startup the SecureW2 EAP module will be loaded by EapHost using 
   the DLLMain::DLL_PROCESS_ATTACH function;
2. The SecureW2 EAP module will then use the function LoadLibrary to look for the external 
   resource (sw2_ext.dll);
   a) if found LoadLibrary will call the function DLLMain::DLL_PROCESS_ATTACH;
3. The SecureW2 EAP module will then call the SW2Initialize() function, passing 
   the EapType paramater and stores the returned pContext pointer (PVOID).

1. At system shutdown the SecureW2 Eap module will be unloaded by EapHost using 
   the DLLMain::DLL_PROCESS_DETACH function;
2. The SecureW2 EAP module will then call the SW2Uninitialize() function of the external 
   resource providing the pContext pointer (returned rpreviously by SW2Initialize();
3. The SecureW2 EAP module will then use the function FreeLibrary to unload the 
   extension library file which will call the function DLLMain::DLL_PROCESS_DETACH;

Retrieving the Identity:

Use case 1: The identity is provided by the extension library file WITHOUT a user interface

1. EapHost will call the SecureW2 EAP module to retrieve the users identity (EapPeerGetIdentity);
2. The SecureW2 EAP module will in turn call the SW2GetIdentity function of the extension library;
3. The extension library returns a pointer to the users identity (ppwcIdentity) in the SW2GetIdentity 
   call and sets the BOOL bInvokeUI to FALSE;
4. The SecureW2 EAP Module copies the identity information into its own memory;
5. The SecureW2 EAP Module calls the SW2FreeIdentity function of the external resourse file providing the 
   pointer to the identity (ppwcIdentity) provided by the extension library;
6. The extension library frees the pointers;
7. The SecureW2 EAP Module returns the identity to EapHost;

Use case 2: The identity is provided by the extension library file WITH a user interface

1. EapHost will call The SecureW2 EAP Module to retrieve the users identity without 
   interaction (EapPeerGetIdentity);
2. The SecureW2 EAP Module will in turn call the SW2GetIdentity function of the extension library file 
   providing the pContext pointer;
3. The extension library does NOT return a pointer to the users identity (ppwcIdentity) in the 
   SW2GetIdentity call and sets the BOOL bInvokeUI to TRUE;
4. The SecureW2 EAP Module returns the need for user interaction to EapHost;
5. EapHost will call The SecureW2 EAP Module to retrieve the users identity with interaction (EapPeerInvokeIdentityUI);
6. The SecureW2 EAP Module will in turn call the SW2InvokeIdentityUI function of the extension library file providing 
   the pContext pointer and the window handle (hWnd) that MUST be used to show the dialog;
7. The extension library file interacts with the user;
8. The extension library returns a pointer to the users identity (ppwcIdentity) in the SW2InvokeIdentityUI call;
9. The SecureW2 EAP Module copies the identity information into its own memory;
10. The SecureW2 EAP Module calls the SW2FreeIdentity function of the external resourse file providing the 
   pointer to the identity (ppwcIdentity) provided by the extension library;
11. The extension library frees the pointers;
12. The SecureW2 EAP Module returns the identity to EapHost;

Retrieving the Response:

Use case 1: The response is provided by the extension library file WITHOUT a user interface

1. EapHost will call The SecureW2 EAP Module to handle the EAP messages (SW2EapPeerProcessRequestPacket);
2. The SecureW2 EAP Module receives a binary message/challenge (challenge);
3. The SecureW2 EAP Module will call the SW2GetResponse function of the extension library file 
   providing the pContext pointer, the identity the binary message/challenge (pbChallenge), 
   the length of the message/challenge (cbChallenge);
4. The extension library returns a pointer to the users binary response (ppbResponse) and the length of 
   the response (pcbResponse) in the SW2GetResponse call and sets the BOOL bInvokeUI to FALSE;
5. The SecureW2 EAP Module copies the response information into its own memory;
6. The SecureW2 EAP Module calls the SW2FreeResponse function of the external resourse file providing the 
   pointer to the binary response (ppbIdentity) provided by the extension library;
7. The extension library frees the pointers;
8. The SecureW2 EAP Module handles the binary response accordingly (sends this via EapHost to the RADIUS server);

Use case 2: The response is provided by the extension library file WITH a user interface

1. EapHost will call The SecureW2 EAP Module to handle the EAP messages (SW2EapPeerProcessRequestPacket);
2. The SecureW2 EAP Module receives a binary message/challenge (challenge);
3. The SecureW2 EAP Module will call the SW2GetResponse function of the extension library file providing 
   the pContext pointer, the identity and the binary message/challenge (pbChallenge);
4. The extension library does NOT return a pointer to the users binary response (ppbResponse) in the SW2GetResponse call 
   and sets the BOOL bInvokeUI to TRUE;
5. The SecureW2 EAP Module returns the need for user interaction to EapHost;
6. EapHost will call The SecureW2 EAP Module to retrieve the users response with interaction (EapPeerInvokeInteractiveUI);
7. The SecureW2 EAP Module will in turn call the SW2InvokeResponseUI function of the extension library file providing 
   the pContext pointer, the identity, the binary message/challenge (pbChallenge), the length of the message/challenge (cbChallenge) 
   and the window handle (hWnd) that MUST be used to show the dialog;
8. The extension library file interacts with the user;
9. The extension library returns a pointer to the users binary response (ppbResponse) and the length of the responsde (pcbResponse) 
   in the SW2InvokeResponseUI call;
10. The SecureW2 EAP Module copies the response information into its own memory;
11. The SecureW2 EAP Module calls the SW2FreeResponse function of the external resourse file providing the 
   pointer to the binary response (ppbIdentity) provided by the extension library;
12. The extension library frees the pointers;
13. The SecureW2 EAP Module handles the response accordingly (sends this via EapHost to the RADIUS server);

Retrieving the Credentials:

Use case 1: The identity is provided by the extension library file WITHOUT a user interface

1. EapHost will call the SecureW2 EAP module to retrieve the users identity (EapPeerGetIdentity);
2. The SecureW2 EAP module will in turn call the SW2GetCredentials function of the extension library;
3. The extension library returns a pointer to the users identity (ppwcIdentity) and password 
   (ppwcPassword) in the SW2GetCredentials call and sets the BOOL bInvokeUI to FALSE;
4. The SecureW2 EAP Module copies the credentials information into its own memory;
5. The SecureW2 EAP Module calls the SW2FreeCredentials function of the external resourse file providing the 
   pointer to the identity (ppwcIdentity) and the password (ppwcPassword) provided by the extension library;
6. The extension library frees the pointers;
12. The SecureW2 EAP Module returns the identity to EapHost and uses the password during the authentication fase.

Use case 2: The identity is provided by the extension library file WITH a user interface

1. EapHost will call The SecureW2 EAP Module to retrieve the users identity without 
   interaction (EapPeerGetIdentity);
2. The SecureW2 EAP Module will in turn call the SW2GetCredentials function of the extension library file 
   providing the pContext pointer;
3. The extension library does NOT return a pointer to the users identity (ppwcIdentity) and password 
   (ppwcPassword) in the SW2GetCredentials call and sets the BOOL bInvokeUI to TRUE;
4. The SecureW2 EAP Module returns the need for user interaction to EapHost;
5. EapHost will call The SecureW2 EAP Module to retrieve the users identity with interaction (EapPeerInvokeIdentityUI);
6. The SecureW2 EAP Module will in turn call the SW2InvokeCredentialsUI function of the extension library file providing 
   the pContext pointer and the window handle (hWnd) that MUST be used to show the dialog;
7. The extension library file interacts with the user;
8. The extension library returns a pointer to the users identity (ppwcIdentity) and password 
   (ppwcPassword) in the SW2InvokeCredentialsUI call;
9. The SecureW2 EAP Module copies the credentials information into its own memory;
10. The SecureW2 EAP Module calls the SW2FreeCredentials function of the external resourse file providing the 
   pointer to the identity (ppwcIdentity) and the password (ppwcPassword) provided by the extension library;
11. The extension library frees the pointers;
12. The SecureW2 EAP Module returns the identity to EapHost and uses the password during the authentication fase.

Error handling:

Handling an error without user interaction

1.	When an error occurs, the SecureW2 EAP modules will call the SW2HandleError function, providing the AuthState and the Error;
	a.	The AuthState indicates the EAP state where an error has occurred and uses the SW2_AUTH_STATE enumeration;
	b.	The Error indicates per SecureW2 EAP Method which error occurred and uses the SW2_ERROR_STATE enumeration;
2.	The extension library logs the error or if an interface to show the error it should set bInvokeUI to TRUE.

Handling an error WITH user interaction

1.	When an error occurs, the SecureW2 EAP modules will call the SW2HandleError function, providing the AuthState and the Error;
	a.	The AuthState indicates the EAP state where an error has occurred and uses the SW2_AUTH_STATE enumeration;
	b.	The Error indicates per SecureW2 EAP Method which error occurred and uses the SW2_ERROR_STATE enumeration;
2.	The extension library interacts with the user.

*/

//
// initialize generic resource, called once during DLL startup (DLLMain::DLL_PROCESS_ATTACH)
//
PVOID APIENTRY SW2Initialize(IN INT iEapType); 

//
// uninitialize generic resource, called once during DLL shutdown (DLLMain::DLL_PROCESS_DETACH)
// generic resource interface is expected to cleanup memory (pContext)
//
DWORD APIENTRY SW2Uninitialize(IN PVOID pContext); 

//
// retrieve identity without user interface. 
// If user interface is required, bInvokeUI should be set to TRUE
// If secureW2 should save the identity bSaveIdentity should be set to TRUE
//
DWORD APIENTRY SW2GetIdentity(IN PVOID		pContext,
							  OUT PWCHAR	*ppwcIdentity,
							  OUT BOOL		*bInvokeUI,
							  OUT BOOL		*bSaveIdentity); 

//
// retrieve identity with user interface
// If secureW2 should save the identity bSaveIdentity should be set to TRUE
//
DWORD APIENTRY SW2InvokeIdentityUI(IN PVOID		pContext, 
								   IN HWND		hWndParent,
								   OUT PWCHAR	*ppwcIdentity,
								   OUT BOOL		*bSaveIdentity); 

//
// free identity
//
DWORD APIENTRY SW2FreeIdentity(IN PWCHAR pwcIdentity); 

//
// retrieve response without user interface. 
// If user interface is required, bInvokeUI should be set to TRUE
//
DWORD APIENTRY SW2GetResponse(IN PVOID		pContext,
							  IN PWCHAR		pwcIdentity,
							  IN PBYTE		pbChallenge,
							  IN DWORD		cbChallenge,
							  OUT BOOL		*bInvokeUI,
							  OUT PBYTE		*ppbResponse,
							  OUT DWORD		*pcbResponse); 

//
// retrieve response using user interface
//
// cbChallenge contains the length of the pbChallenge
//
// the response should be returned using ppbResponse, the 
// length of the ppbResponse should be returned in pcbResponse
//
DWORD APIENTRY SW2InvokeResponseUI(IN PVOID		pContext,
								   IN HWND		hWndParent,
								   IN PWCHAR	pwcIdentity,
								   IN PBYTE		pbChallenge,
								   IN DWORD		cbChallenge,
								   OUT PBYTE	*ppbResponse,
								   OUT DWORD	*pcbResponse); 

//
// free reponse
//
DWORD APIENTRY SW2FreeResponse(IN PBYTE pwcResponse);

//
// retrieve response without user interface. 
// If user interface is required, bInvokeUI should be set to TRUE
// If secureW2 should save the credentials for single logon, bSaveCredentials should be set to TRUE
//
DWORD APIENTRY SW2GetCredentials(IN PVOID		pContext,
								 OUT PWCHAR		*ppwcIdentity,
								 OUT PWCHAR		*ppwcPassword,
								 OUT BOOL		*bInvokeUI,
								 OUT BOOL		*bSaveCredentials);

//
// retrieve response with user interface. 
// If secureW2 should save the credentials for single logon, bSaveCredentials should be set to TRUE
//
DWORD APIENTRY SW2InvokeCredentialsUI(IN PVOID		pContext, 
									IN HWND			hWndParent,
									OUT PWCHAR		*ppwcIdentity,
									OUT PWCHAR		*ppwcPassword,
									OUT BOOL		*bSaveCredentials);

//
// free credentials
//
DWORD APIENTRY SW2FreeCredentials(IN PWCHAR pwcIdentity,
								  IN PWCHAR pwcPassword);


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

typedef enum _SW2_EAP_RESULT
{
   SW2_EAP_RESULT_Unknown = 1,
   SW2_EAP_RESULT_Success,
   SW2_EAP_RESULT_Failure

} SW2_EAP_RESULT;

//
// Handle result
//
DWORD APIENTRY SW2HandleResult (IN PVOID			pContext, 
								 IN SW2_EAP_RESULT	eapResult);

//
// Handle error without user interaction
// If user interface is required, bInvokeUI should be set to TRUE
//
DWORD APIENTRY SW2HandleError(IN PVOID				pContext, 
								IN SW2_AUTH_STATE	AuthState, 
								IN SW2_ERROR		Error,
								OUT BOOL			*pbInvokeUI);

//
// Handle error with user interaction
//
DWORD APIENTRY SW2HandleInteractiveError(IN PVOID			pContext, 
										IN HWND				hWndParent,
										IN SW2_AUTH_STATE	AuthState, 
										IN SW2_ERROR		Error);

