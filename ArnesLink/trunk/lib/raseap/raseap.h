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
#include "..\common\common.h"
#include <Raseapif.h>
#include <raserror.h>

DWORD WINAPI		RasEapInitialize(BOOL bInitialize);

DWORD WINAPI		RasEapBegin(OUT PVOID			*ppWorkBuf, 
								IN PPP_EAP_INPUT	*pInput);

DWORD WINAPI		RasEapEnd(IN PVOID pWorkBuf);

DWORD WINAPI		RasEapMakeMessage(IN PVOID				pWorkBuf, 
									  IN PPP_EAP_PACKET		*pReceiveBuf, 
									  OUT PPP_EAP_PACKET	*pSendBuf, 
									  IN DWORD				cbSendBuf, 
									  OUT PPP_EAP_OUTPUT	*pResult, 
									  IN PPP_EAP_INPUT		*pInput );

DWORD WINAPI		RasEapInvokeConfigUI(IN DWORD	dwEapTypeId, 
										 IN HWND	hwndParent, 
										 IN DWORD	dwFlags, 
										 IN PBYTE	pbConnectionDataIn, 
										 IN DWORD	dwSizeOfConnectionDataIn, 
										 OUT PBYTE	*ppbConnectionDataOut, 
										 OUT DWORD* pdwSizeOfConnectionDataOut );

DWORD WINAPI		RasEapFreeMemory(IN PBYTE pbMemory);

DWORD SW2_RegisterEapHostDLL();
DWORD SW2_UnregisterEapHostDLL();