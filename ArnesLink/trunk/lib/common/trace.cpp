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
#pragma comment(lib, "Rtutils.lib")

VOID   
SW2Dump(
	IN DWORD dwTraceLevel,
    IN PBYTE pbData, 
	IN DWORD cbData
) 
{
#ifndef _WIN32_WCE
	/// The default level assigned to each trace message.
	TraceDumpEx(g_dwSW2TraceId, 
				dwTraceLevel |TRACE_USE_MASK | TRACE_USE_MSEC,
				pbData,
				cbData,
				4,
				FALSE,
				NULL );
#endif // _WIN32_WCE
}

VOID   
SW2Trace(
	IN DWORD	  dwTraceLevel,
    IN PWCHAR	  pwcFormat, 
    ... 
) 
{
#ifndef _WIN32_WCE
	va_list arglist;

	va_start(arglist, pwcFormat);

	/// The default level assigned to each trace message.
	TraceVprintfEx(g_dwSW2TraceId, 
	    dwTraceLevel | TRACE_USE_MASK | TRACE_USE_MSEC,
	    pwcFormat,
	    arglist);

	va_end(arglist);
#else
#ifdef SW2_TRACE_ON
	SYSTEMTIME	SystemTime;
	FILE	*f;
	va_list vlist;

	char *SW_TRACE_FILE = { "\\sw2_ttls_trace.log" };

	if( ( f = fopen( SW_TRACE_FILE, "a+" ) ) )
	{
		GetLocalTime( &SystemTime );

		_ftprintf( f, TEXT( "%d:%d:%d:%d::%s::%x::" ), SystemTime.wHour, SystemTime.wMinute, SystemTime.wSecond, SystemTime.wMilliseconds, TEXT("SW2"), GetCurrentProcessId() );

		va_start( vlist, pwcFormat );
		_vftprintf( f, pwcFormat, vlist );
		va_end( vlist );

		_ftprintf( f, TEXT( "\n" ) );

		fflush( f );

		fclose( f );
	}
#endif // SW2_TRACE_ON
#endif // _WIN32_WCE
}

#ifndef _WIN32_WCE
DWORD
SW2SetDefaultTraceLevel(IN PWCHAR pwcEapId)
{
	HKEY	hKey;
	WCHAR	pwcTemp[1024];
	DWORD	dwEnabled = 1;
	DWORD	dwDefaultMask = SW2_TRACE_DEFAULT_MASK;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	swprintf_s(pwcTemp, sizeof(pwcTemp)/sizeof(WCHAR), 
		L"Software\\Microsoft\\Tracing\\%s", pwcEapId);

	if ((dwReturnCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
										pwcTemp, 
										0, 
										KEY_ALL_ACCESS, 
										&hKey )) == NO_ERROR)
	{
		RegSetValueEx(hKey,
					L"EnableFileTracing",
					0,
					REG_DWORD,
					(PBYTE) &dwEnabled,
					sizeof(dwEnabled));

		RegSetValueEx(hKey,
					L"FileTracingMask",
					0,
					REG_DWORD,
					(PBYTE) &dwDefaultMask,
					sizeof(dwDefaultMask));

		RegCloseKey(hKey);
	}

	return dwReturnCode;
}


DWORD
SW2RemoveTraceConfiguration(IN PWCHAR pwcEapId)
{
	HKEY	hKey;
	WCHAR	pwcTemp[1024];
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	swprintf_s(pwcTemp, sizeof(pwcTemp)/sizeof(WCHAR), 
		L"Software\\Microsoft\\Tracing");

	if ((dwReturnCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
										pwcTemp, 
										0, 
										KEY_ALL_ACCESS, 
										&hKey )) == NO_ERROR)
	{
		RegDeleteKey(hKey,
					pwcEapId);

		RegCloseKey(hKey);
	}

	return dwReturnCode;
}

#endif // _WIN32_WCE