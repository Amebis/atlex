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
Workflow

Initialization and Unitialization

1. At system startup the GTC module (sw2_gtc.dll) will be loaded by EapHost using the 
   DLLMain::DLL_PROCESS_ATTACH function;
2. The GTC module will then use the function LoadLibrary to load the GTC resource file (sw2_gtc_res.dll)
   which will call the function DLLMain::DLL_PROCESS_ATTACH
   (This GTC resource file implements the GTCResponder_Exports.h API);
3. The GTC module will then call the SW2Initialize() function of the GTC resource file and store the 
   returned pContext pointer (PVOID).

1. At system shutdown the GTC module (sw2_gtc.dll) will be unloaded by EapHost using the 
   DLLMain::DLL_PROCESS_DETACH function;
2. The GTC module will then call the SW2Uninitialize() function of the GTC resource file (sw2_gtc_res.dll)
   providing the pContext pointer (returned rpreviously by SW2Initialize();
3. The GTC module will then use the function FreeLibrary to unload the GTC resource file which will 
   call the function DLLMain::DLL_PROCESS_DETACH;

Retrieving the Identity:

Use case 1: The identity is provided in the configuration

1. EapHost will call the GTC Module to retrieve the users identity (EapPeerGetIdentity);
2. The GTC Method will in turn call the SW2GetIdentity function of the GTC resource file providing 
   the pContext pointer;
3. The GTC resource retrieves the configured identity;
4. The GTC module returns the identity to EapHost;

NOTE: If the GTC module is being tunneled using the SW2 TTLS module then, depending on the TTLS 
      configuration, the "outer" identity will be modified. For example tom@gtc could become 
	  anonymous@gtc (this applies to all use cases).

Use case 2: The identity is provided by the GTC resource file WITHOUT a user interface

1. EapHost will call the GTC Module to retrieve the users identity (EapPeerGetIdentity);
2. The GTC Method will in turn call the SW2GetIdentity function of the GTC resource file providing 
   the pContext pointer;
3. The GTC resource returns a pointer to the users identity (ppwcIdentity) in the SW2GetIdentity call and
   sets the BOOL pfInvokeUI to FALSE;
4. The GTC module copies the identity information into its own memory;
5. The GTC module calls the SW2FreeIdentity function of the GTC resourse file providing the pContext pointer;
6. The GTC module returns the identity to EapHost;

Use case 3: The identity is provided by the GTC resource file WITH a user interface

1. EapHost will call the GTC Module to retrieve the users identity without interaction (EapPeerGetIdentity);
2. The GTC Method will in turn call the SW2GetIdentity function of the GTC resource file providing 
   the pContext pointer;
3. The GTC resource does NOT return a pointer to the users identity (ppwcIdentity) in the SW2GetIdentity call 
   and sets the BOOL pfInvokeUI to TRUE;
4. The GTC Module returns the need for user interaction to EapHost;
5. EapHost will call the GTC Module to retrieve the users identity with interaction (EapPeerInvokeIdentityUI);
6. The GTC Method will in turn call the SW2InvokeIdentityUI function of the GTC resource file providing 
   the pContext pointer and the window handle (hWnd) that MUST be used to show the dialog;
7. The GTC resource file interacts with the user;
8. The GTC resource returns a pointer to the users identity (ppwcIdentity) in the SW2InvokeIdentityUI call;
9. The GTC module copies the identity information into its own memory;
10. The GTC module calls the SW2FreeIdentity function of the GTC resourse file providing the pContext pointer;
11. The GTC module returns the identity to EapHost;

Retrieving the Response:

Use case 1: The response is provided by the GTC resource file WITHOUT a user interface

1. EapHost will call the GTC Module to handle the GTC messages (SW2EapPeerProcessRequestPacket);
2. The GTC method receives the GTC challenge;
3. The GTC Method will call the SW2GetResponse function of the GTC resource file providing 
   the pContext pointer, the identity and the challenge string (pwcChallenge);
3. The GTC resource returns a pointer to the users response (ppwcResponse) in the SW2GetResponse call and
   sets the BOOL pfInvokeUI to FALSE;
4. The GTC module copies the response information into its own memory;
5. The GTC module calls the SW2FreeResponse function of the GTC resourse file providing the pContext pointer;
6. The GTC module handles the response accordingly (sends this via EapHost to the RADIUS server);

Use case 2: The response is provided by the GTC resource file WITH a user interface

1. EapHost will call the GTC Module to handle the GTC messages (SW2EapPeerProcessRequestPacket);
2. The GTC method receives the GTC challenge;
3. The GTC Method will call the SW2GetResponse function of the GTC resource file providing 
   the pContext pointer, the identity and the challenge string (pwcChallenge);
3. The GTC resource does NOT return a pointer to the users response (ppwcResponse) in the SW2GetResponse call 
   and sets the BOOL pfInvokeUI to TRUE;
4. The GTC Module returns the need for user interaction to EapHost;
5. EapHost will call the GTC Module to retrieve the users response with interaction (EapPeerInvokeInteractiveUI);
6. The GTC Method will in turn call the SW2InvokeResponseUI function of the GTC resource file providing 
   the pContext pointer, the identity and the challenge string and the window handle (hWnd) that MUST be 
   used to show the dialog;
7. The GTC resource file interacts with the user;
8. The GTC resource returns a pointer to the users response (ppwcResponse) in the SW2InvokeResponseUI call;
9. The GTC module copies the response information into its own memory;
10. The GTC module calls the SW2FreeResponse function of the GTC resourse file providing the pContext pointer;
11. The GTC module handles the response accordingly (sends this via EapHost to the RADIUS server);

*/
//
// initialize GTC responder, called once during DLL startup (DLLMain::DLL_PROCESS_ATTACH)
//
PVOID APIENTRY SW2Initialize(); 

//
// initialize GTC responder, called once during DLL shutdown (DLLMain::DLL_PROCESS_DETACH)
//
VOID APIENTRY SW2Uninitialize(IN PVOID pContext); 

//
// retrieve GTC identity without user interface. 
// If user interface is required, pfInvokeUI should be set to TRUE
//
DWORD APIENTRY SW2GetIdentity(IN PVOID pContext,
							  OUT BOOL *pfInvokeUI,
							  OUT PWCHAR *ppwcIdentity); 

//
// retrieve GTC identity using user interface
//
DWORD APIENTRY SW2InvokeIdentityUI(IN PVOID		pContext, 
								   IN HWND		hWndParent,
								   OUT PWCHAR	*ppwcIdentity); 

//
// free GTC identity
//
VOID APIENTRY SW2FreeIdentity(IN PVOID pContext); 

//
// retrieve GTC response without user interface. 
// If user interface is required, pfInvokeUI should be set to TRUE
//
DWORD APIENTRY SW2GetResponse(IN PVOID		pContext,
							  IN PWCHAR		pwcIdentity,
							  IN PWCHAR		pwcChallenge,
							  OUT BOOL		*pfInvokeUI,
							  OUT PWCHAR	*ppwcResponse); 

//
// retrieve GTC response using user interface
//
DWORD APIENTRY SW2InvokeResponseUI(IN PVOID		pContext,
								   IN HWND		hWndParent,
								   IN PWCHAR	pwcIdentity,
								   IN PWCHAR	pwcChallenge,
								   OUT PWCHAR	*ppwcResponse); 

//
// free GTC reponse
//
VOID APIENTRY SW2FreeResponse(IN PVOID pContext);