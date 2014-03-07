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
// Name: SW2_HandleExternalError
// Description: Helper function that sends errors to extension library
// Author: Tom Rixom
// Created: 3 Juni 2008
//
DWORD
SW2_HandleExternalError(IN DWORD			dwError, 
						IN SW2_EAP_FUNCTION EapFunction,
						IN SW2_GTC_STATE	GTCState)
{
	DWORD	dwReturnCode;
	BOOL	bInvokeUI;

	dwReturnCode = SW2_ERROR_NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_HandleExternalError(%ld, %ld, %ld)" ), dwError, EapFunction, GTCState );

	if (g_ResContext)
	{
		switch( EapFunction )
		{
			case SW2_EAP_FUNCTION_Initialize:

				dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
													SW2_AUTH_STATE_NONE, 
													SW2_ERROR_INTERNAL,
													&bInvokeUI);
			break;

			case SW2_EAP_FUNCTION_DeInitialize:

				dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
												SW2_AUTH_STATE_NONE, 
												SW2_ERROR_INTERNAL,
												&bInvokeUI);

			break;

			case SW2_EAP_FUNCTION_GetIdentity:
			case SW2_EAP_FUNCTION_InvokeIdentityUI:

				dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
													SW2_AUTH_STATE_IDENTITY, 
													SW2_ERROR_INTERNAL,
													&bInvokeUI);

			break;

			case SW2_EAP_FUNCTION_Begin:

				dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
												SW2_AUTH_STATE_START_SESSION, 
												SW2_ERROR_INTERNAL,
												&bInvokeUI);

			break;

			case SW2_EAP_FUNCTION_Process:

				switch( GTCState )
				{
					case SW2_GTC_STATE_None:
					case SW2_GTC_STATE_Initial:
					case SW2_GTC_STATE_Challenge:
					case SW2_GTC_STATE_InteractiveUI:
					case SW2_GTC_STATE_Done:

						dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
														SW2_AUTH_STATE_AUTHENTICATING, 
														SW2_ERROR_INTERNAL,
														&bInvokeUI);
					break;
				}
			
			break;

			case SW2_EAP_FUNCTION_InvokeConfigUI:

				// configuration errors are not interesting to extension library

			break;

			case SW2_EAP_FUNCTION_InvokeInteractiveUI:

				dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
													SW2_AUTH_STATE_UI, 
													SW2_ERROR_INTERNAL,
													&bInvokeUI);

			break;

			case SW2_EAP_FUNCTION_End:

				dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
													SW2_AUTH_STATE_END_SESSION, 
													SW2_ERROR_INTERNAL,
													&bInvokeUI);

			break;

			case SW2_EAP_FUNCTION_FreeMemory:
			
				dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
													SW2_AUTH_STATE_NONE, 
													SW2_ERROR_INTERNAL,
													&bInvokeUI);

			break;

			default:

				dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
													SW2_AUTH_STATE_NONE, 
													SW2_ERROR_INTERNAL,
													&bInvokeUI);

			break;
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_HandleExternalError:: returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_HandleError
// Description: Helper function to handle errors (Non UI)
// Author: Tom Rixom
// Created: 25 Februari 2007
//
VOID
SW2_HandleError(IN DWORD dwError, 
				IN SW2_EAP_FUNCTION EapFunction,
				IN SW2_GTC_STATE	GTCState,
				IN BOOL				*pbInvokeUI)
{
	if (dwError == NO_ERROR)
		return;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_HandleError(%ld, %ld, %ld)" ), dwError, EapFunction, GTCState );

	//
	// if extension library is available let it handle error
	//
	if (g_ResContext)
	{
		SW2_HandleExternalError(dwError, EapFunction, GTCState);
	}
	else
	{
		switch( EapFunction )
		{
			case SW2_EAP_FUNCTION_Initialize:

				SW2_ReportEvent( L"SW2_EAP_FUNCTION_Initialize Failed", EVENTLOG_ERROR_TYPE, dwError );			

			break;

			case SW2_EAP_FUNCTION_DeInitialize:

				SW2_ReportEvent( L"SW2_EAP_FUNCTION_DeInitialize Failed", EVENTLOG_ERROR_TYPE, dwError );

			break;

			case SW2_EAP_FUNCTION_Begin:

				SW2_ReportEvent( L"RasEapBegin Failed", EVENTLOG_ERROR_TYPE, dwError );

			break;

			case SW2_EAP_FUNCTION_Process:

				switch( GTCState )
				{
					case SW2_GTC_STATE_None:
					case SW2_GTC_STATE_Initial:
					case SW2_GTC_STATE_Challenge:
					case SW2_GTC_STATE_InteractiveUI:
					case SW2_GTC_STATE_Done:

						SW2_ReportEvent( L"RasEapMakeMessage Failed", EVENTLOG_ERROR_TYPE, dwError );

					break;
				}
			
			break;

			case SW2_EAP_FUNCTION_InvokeConfigUI:

				SW2_ReportEvent( L"RasEapInvokeConfigUI Failed", EVENTLOG_ERROR_TYPE, dwError );

			break;

			case SW2_EAP_FUNCTION_InvokeInteractiveUI:

				SW2_ReportEvent( L"SW2EapMethodInvokeInteractiveUI Failed", EVENTLOG_ERROR_TYPE, dwError );

			break;

			case SW2_EAP_FUNCTION_End:

				SW2_ReportEvent( L"RasEapEnd Failed", EVENTLOG_ERROR_TYPE, dwError );

			break;

			case SW2_EAP_FUNCTION_FreeMemory:

				SW2_ReportEvent( L"RasEapFreeMemory Failed", EVENTLOG_ERROR_TYPE, dwError );

			break;

			default:

				SW2_ReportEvent( L"Unknown Error", EVENTLOG_ERROR_TYPE, dwError );

			break;
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_HandleError:: returning" ) );
}