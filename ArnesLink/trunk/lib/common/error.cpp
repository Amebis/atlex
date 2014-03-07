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
// Name: SW2_ReportEvent
// Description: Helper function for sending information to the EventViewer
// Author: Tom Rixom
// Created: 25 Februari 2007
//
DWORD
SW2_ReportEvent( WCHAR *pwcMsg, WORD wType, DWORD dwError )
{
	DWORD	dwReturnCode;
#ifndef _WIN32_WCE
	WCHAR	*pwcMsgArray[1];
    HANDLE	hHandle; 
#endif

	dwReturnCode = NO_ERROR;

#ifndef _WIN32_WCE
    if( ( hHandle = RegisterEventSource( NULL,
								 L"SecureW2" ) ) )
	{
		pwcMsgArray[0] = pwcMsg;

		if( ReportEvent( hHandle,
							wType,
							0,
							dwError,
							NULL,
							1,
							0,
							(LPCWSTR*)pwcMsgArray,
							NULL ) )
		{
			DeregisterEventSource( hHandle );
		}
	}
	else
	{
	}
#endif // _WIN32_WCE

	return dwReturnCode;
}