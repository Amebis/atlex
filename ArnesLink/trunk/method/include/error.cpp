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
// Name: SW2_HandleExternalInteractiveError
// Description: Helper function that sends (interactive) errors to extension library
// Author: Tom Rixom
// Created: 3 Juni 2008
//
DWORD
SW2_HandleExternalInteractiveError(IN HWND				hWnd,
								   IN DWORD				dwError, 
								   IN SW2_EAP_FUNCTION	EapFunction,
								   IN SW2_TLS_STATE		TLSState)
{
	DWORD	dwReturnCode;
	BOOL	bInvokeUI;

	dwReturnCode = NO_ERROR;

	if (dwError==NO_ERROR)
		return dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_HandleExternalInteractiveError(%ld, %ld, %ld)" ), dwError, EapFunction, TLSState );

	if (g_ResContext)
	{
		switch( EapFunction )
		{
			case SW2_EAP_FUNCTION_Initialize:

				dwReturnCode = g_ResContext->pSW2HandleInteractiveError(g_ResContext->pContext,
													hWnd,
													SW2_AUTH_STATE_NONE, 
													SW2_ERROR_INTERNAL);
			break;

			case SW2_EAP_FUNCTION_DeInitialize:

				dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
												SW2_AUTH_STATE_NONE, 
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

				switch( TLSState )
				{
					case SW2_TLS_STATE_Start:
					case SW2_TLS_STATE_Server_Hello:

						dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
															SW2_AUTH_STATE_AUTHENTICATING, 
															SW2_ERROR_TLS,
															&bInvokeUI);

					break;

					case SW2_TLS_STATE_Verify_Cert_UI:

						if (dwError==ERROR_INVALID_DOMAINNAME)
						{
							dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
															SW2_AUTH_STATE_VERIFY_CERT, 
															SW2_ERROR_CERTIFICATE_INVALID_SERVERNAME,
															&bInvokeUI);
						}
						else if (dwError==CERT_E_WRONG_USAGE)
						{
							dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
															SW2_AUTH_STATE_VERIFY_CERT, 
															SW2_ERROR_CERTIFICATE_INVALID_USAGE,
															&bInvokeUI);
						}
						else if (dwError==CERT_E_UNTRUSTEDROOT)
						{
							dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
															SW2_AUTH_STATE_VERIFY_CERT, 
															SW2_ERROR_CERTIFICATE_INVALID_TRUST,
															&bInvokeUI);
						}
						else
						{
							dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
															SW2_AUTH_STATE_VERIFY_CERT, 
															SW2_ERROR_CERTIFICATE,
															&bInvokeUI);
						}

					break;

					case SW2_TLS_STATE_Change_Cipher_Spec:
					case SW2_TLS_STATE_Resume_Session:
					case SW2_TLS_STATE_Resume_Session_Ack:
					case SW2_TLS_STATE_Inner_Authentication:
					case SW2_TLS_STATE_Error:
					case SW2_TLS_STATE_Finished:

						dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
															SW2_AUTH_STATE_AUTHENTICATING, 
															SW2_ERROR_TLS,
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

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_HandleExternalInteractiveError::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_HandleExternalError
// Description: Helper function that sends errors to extension library
// Author: Tom Rixom
// Created: 3 Juni 2008
//
DWORD
SW2_HandleExternalError(IN DWORD			dwError, 
						IN SW2_EAP_FUNCTION EapFunction,
						IN SW2_TLS_STATE	TLSState,
						IN BOOL				*pbInvokeUI)
{
	DWORD	dwReturnCode;

	dwReturnCode = SW2_ERROR_NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_HandleExternalError(%ld, %ld, %ld)" ), dwError, EapFunction, TLSState );

	if (g_ResContext)
	{
		switch( EapFunction )
		{
			case SW2_EAP_FUNCTION_Initialize:

				dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
													SW2_AUTH_STATE_NONE, 
													SW2_ERROR_INTERNAL,
													pbInvokeUI);
			break;

			case SW2_EAP_FUNCTION_DeInitialize:

				dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
												SW2_AUTH_STATE_NONE, 
												SW2_ERROR_INTERNAL,
												pbInvokeUI);

			break;

			case SW2_EAP_FUNCTION_GetIdentity:
			case SW2_EAP_FUNCTION_InvokeIdentityUI:

				dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
													SW2_AUTH_STATE_IDENTITY, 
													SW2_ERROR_INTERNAL,
													pbInvokeUI);

			break;

			case SW2_EAP_FUNCTION_Begin:

				dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
												SW2_AUTH_STATE_START_SESSION, 
												SW2_ERROR_INTERNAL,
												pbInvokeUI);

			break;

			case SW2_EAP_FUNCTION_Process:

				switch( TLSState )
				{
					case SW2_TLS_STATE_Start:
					case SW2_TLS_STATE_Server_Hello:
					case SW2_TLS_STATE_Verify_Cert_UI:

						if (dwError==ERROR_INVALID_DOMAINNAME)
						{
							dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
															SW2_AUTH_STATE_VERIFY_CERT, 
															SW2_ERROR_CERTIFICATE_INVALID_SERVERNAME,
															pbInvokeUI);
						}
						else if (dwError==CERT_E_WRONG_USAGE)
						{
							dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
															SW2_AUTH_STATE_VERIFY_CERT, 
															SW2_ERROR_CERTIFICATE_INVALID_USAGE,
															pbInvokeUI);
						}
						else if (dwError==CERT_E_UNTRUSTEDROOT)
						{
							dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
															SW2_AUTH_STATE_VERIFY_CERT, 
															SW2_ERROR_CERTIFICATE_INVALID_TRUST,
															pbInvokeUI);
						}
						else if (TLSState == SW2_TLS_STATE_Verify_Cert_UI)
						{
							dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
															SW2_AUTH_STATE_VERIFY_CERT, 
															SW2_ERROR_CERTIFICATE,
															pbInvokeUI);
						}
						else
						{
							dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
																SW2_AUTH_STATE_AUTHENTICATING, 
																SW2_ERROR_TLS,
																pbInvokeUI);
						}

					break;

					case SW2_TLS_STATE_Change_Cipher_Spec:
					case SW2_TLS_STATE_Resume_Session:
					case SW2_TLS_STATE_Resume_Session_Ack:
					case SW2_TLS_STATE_Inner_Authentication:
					case SW2_TLS_STATE_Error:
					case SW2_TLS_STATE_Finished:

						dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
															SW2_AUTH_STATE_AUTHENTICATING, 
															SW2_ERROR_TLS,
															pbInvokeUI);

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
													pbInvokeUI);

			break;

			case SW2_EAP_FUNCTION_GetResult:

				dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
													SW2_AUTH_STATE_AUTHENTICATING, 
													SW2_ERROR_AUTH_FAILED,
													pbInvokeUI);

			break;

			case SW2_EAP_FUNCTION_End:

				dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
													SW2_AUTH_STATE_END_SESSION, 
													SW2_ERROR_INTERNAL,
													pbInvokeUI);

			break;

			case SW2_EAP_FUNCTION_FreeMemory:
			
				dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
													SW2_AUTH_STATE_NONE, 
													SW2_ERROR_INTERNAL,
													pbInvokeUI);

			break;

			default:

				dwReturnCode = g_ResContext->pSW2HandleError(g_ResContext->pContext, 
													SW2_AUTH_STATE_NONE, 
													SW2_ERROR_INTERNAL,
													pbInvokeUI);

			break;
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_HandleExternalError::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_HandleInteractiveError
// Description: Helper function to handle errors that can be displayed to users
// Author: Tom Rixom
// Created: 25 Februari 2007
//
VOID
SW2_HandleInteractiveError( IN HWND				hWndParent, 
							IN DWORD			dwError,
							IN SW2_EAP_FUNCTION EapFunction,
							IN SW2_TLS_STATE	TLSState)
{
	WCHAR	pwcTemp1[1024];
	WCHAR	pwcTemp2[1024];

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_HandleInteractiveError(%ld, %ld, %ld)" ), dwError, EapFunction, TLSState );

	if (dwError == NO_ERROR)
		return;

	//
	// if extension library is available let it handle error
	//
	if (g_ResContext)
	{
		SW2_HandleExternalInteractiveError(hWndParent, 
											dwError, 
											EapFunction, 
											TLSState);
	}
	else
	{
		memset( pwcTemp1, 0, sizeof( pwcTemp1 ) );
		memset( pwcTemp2, 0, sizeof( pwcTemp2 ) );

		LoadString( g_hLanguage, IDS_ERROR_SW2_ERROR, pwcTemp1, sizeof( pwcTemp1 ) );

		switch( EapFunction )
		{
			case SW2_EAP_FUNCTION_Process:
			case SW2_EAP_FUNCTION_InvokeInteractiveUI: // error during EAP communication (MakeMessage)

				if( dwError == ERROR_PPP_INVALID_PACKET )
				{
					LoadString( g_hLanguage, IDS_ERROR_EAP_INVALID_PACKET, pwcTemp2, sizeof( pwcTemp2 ) );
				}
				else
				{
					switch( TLSState )
					{
						case SW2_TLS_STATE_Start:

							LoadString( g_hLanguage, IDS_ERROR_TLS_COMMUNICATION, pwcTemp2, sizeof( pwcTemp2 ) );

						break;

						case SW2_TLS_STATE_Server_Hello:

							LoadString( g_hLanguage, IDS_ERROR_CRYPTO_INVALID_CERTIFICATE, pwcTemp2, sizeof( pwcTemp2 ) );

						break;

						case SW2_TLS_STATE_Verify_Cert_UI:

							LoadString( g_hLanguage, IDS_ERROR_CRYPTO_INVALID_CERTIFICATE, pwcTemp2, sizeof( pwcTemp2 ) );

						break;

						case SW2_TLS_STATE_Change_Cipher_Spec:

							LoadString( g_hLanguage, IDS_ERROR_TLS_COMMUNICATION, pwcTemp2, sizeof( pwcTemp2 ) );

						break;

						case SW2_TLS_STATE_Resume_Session:

							LoadString( g_hLanguage, IDS_ERROR_TLS_COMMUNICATION, pwcTemp2, sizeof( pwcTemp2 ) );

						break;

						case SW2_TLS_STATE_Resume_Session_Ack:

							LoadString( g_hLanguage, IDS_ERROR_TLS_COMMUNICATION, pwcTemp2, sizeof( pwcTemp2 ) );

						break;

						case SW2_TLS_STATE_Inner_Authentication:

							//
							// Inner authentication is handled by showing the user dialog again
							//
							LoadString( g_hLanguage, IDS_ERROR_INNER_AUTHENTICATION, pwcTemp2, sizeof( pwcTemp2 ) );

						break;

						case SW2_TLS_STATE_Finished:

							LoadString( g_hLanguage, IDS_ERROR_TLS_COMMUNICATION, pwcTemp2, sizeof( pwcTemp2 ) );

						break;

						case SW2_TLS_STATE_Error:

						default:

							//
							// should not be possible...
							//
							LoadString( g_hLanguage, IDS_ERROR_DEFAULT, pwcTemp2, sizeof( pwcTemp2 ) );

						break;
					}
				}

			break;

			default:

				SW2Trace( SW2_TRACE_LEVEL_WARNING, TEXT( "SW2_TRACE_LEVEL_WARNING::SW2_HandleInteractiveError::Unknown EapFunction, loading DEFAULT error string: %s" ), pwcTemp2 );

				LoadString( g_hLanguage, IDS_ERROR_DEFAULT, pwcTemp2, sizeof( pwcTemp2 ) );

			break;
		}

		//
		// Do we have anything to show?
		//
		if( wcslen( pwcTemp2 ) > 0 )
		{
			MessageBox( hWndParent, 
						pwcTemp2,
						pwcTemp1,
						MB_ICONEXCLAMATION|MB_OK );
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_TRACE_LEVEL_ERROR::SW2_HandleInteractiveError::no error string" ) );
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_HandleInteractiveError::returning" ) );
}

//
// Name: SW2_HandleError
// Description: Helper function to handle errors (Non UI)
// Author: Tom Rixom
// Created: 25 Februari 2007
//
VOID
SW2_HandleError(IN DWORD			dwError, 
				IN SW2_EAP_FUNCTION EapFunction,
				IN SW2_TLS_STATE	TLSState,
				IN BOOL				*pbInvokeUI)
{

	if (dwError == NO_ERROR)
		return;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_HandleError(%ld, %ld, %ld)" ), dwError, EapFunction, TLSState );

	//
	// if extension library is available let it handle error
	//
	if (g_ResContext)
	{
		SW2_HandleExternalError(dwError, EapFunction, TLSState, pbInvokeUI);
	}
	else
	{
		switch( EapFunction )
		{
			case SW2_EAP_FUNCTION_Initialize:

				SW2_ReportEvent( L"SW2_EAP_FUNCTION_Initialize Failed", EVENTLOG_ERROR_TYPE, dwError );

				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_EAP_FUNCTION_Initialize Failed: %ld" ), dwError );

			break;

			case SW2_EAP_FUNCTION_DeInitialize:

				SW2_ReportEvent( L"SW2_EAP_FUNCTION_DeInitialize Failed", EVENTLOG_ERROR_TYPE, dwError );

				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_EAP_FUNCTION_DeInitialize Failed: %ld" ), dwError );

			break;

			case SW2_EAP_FUNCTION_GetIdentity:
			case SW2_EAP_FUNCTION_InvokeIdentityUI:
			
				if (dwError == ERROR_NO_SUCH_USER)
				{
					SW2Trace( SW2_TRACE_LEVEL_WARNING, 
						TEXT( "SW2_TRACE_LEVEL_WARNING::SW2_EAP_FUNCTION_GetIdentity Failed: ERROR_NO_SUCH_USER" ) );
				}
				else
				{
					SW2_ReportEvent( L"SW2_EAP_FUNCTION_GetIdentity Failed", EVENTLOG_ERROR_TYPE, dwError );

					SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_EAP_FUNCTION_GetIdentity Failed: %ld" ), dwError );
				}

			break;

			case SW2_EAP_FUNCTION_Begin:

				SW2_ReportEvent( L"SW2_EAP_FUNCTION_Begin Failed", EVENTLOG_ERROR_TYPE, dwError );

				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_EAP_FUNCTION_Begin Failed: %ld" ), dwError );

			break;

			case SW2_EAP_FUNCTION_Process:

				switch( TLSState )
				{
					case SW2_TLS_STATE_Start:
					case SW2_TLS_STATE_Server_Hello:
					case SW2_TLS_STATE_Verify_Cert_UI:
					case SW2_TLS_STATE_Change_Cipher_Spec:
					case SW2_TLS_STATE_Resume_Session:
					case SW2_TLS_STATE_Resume_Session_Ack:
					case SW2_TLS_STATE_Inner_Authentication:
					case SW2_TLS_STATE_Error:
					case SW2_TLS_STATE_Finished:

						SW2_ReportEvent( L"SW2_EAP_FUNCTION_Process Failed", EVENTLOG_ERROR_TYPE, dwError );

						SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_EAP_FUNCTION_Process Failed: %ld (TLSState: %ld" ), dwError, TLSState );

					break;
				}
			
			break;

			case SW2_EAP_FUNCTION_InvokeConfigUI:

				SW2_ReportEvent( L"SW2_EAP_FUNCTION_InvokeConfigUI Failed", EVENTLOG_ERROR_TYPE, dwError );
			
				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_EAP_FUNCTION_InvokeConfigUI Failed: %ld" ), dwError );

			break;

			case SW2_EAP_FUNCTION_InvokeInteractiveUI:

				SW2_ReportEvent( L"SW2_EAP_FUNCTION_InvokeInteractiveUI Failed", EVENTLOG_ERROR_TYPE, dwError );

				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_EAP_FUNCTION_InvokeInteractiveUI Failed: %ld" ), dwError );

			break;

			case SW2_EAP_FUNCTION_GetResult:

				SW2_ReportEvent( L"SW2_EAP_FUNCTION_GetResult Failed", EVENTLOG_ERROR_TYPE, dwError );
			
				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_EAP_FUNCTION_GetResult Failed: %ld" ), dwError );

			break;

			case SW2_EAP_FUNCTION_End:

				SW2_ReportEvent( L"SW2_EAP_FUNCTION_End Failed", EVENTLOG_ERROR_TYPE, dwError );
			
				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_EAP_FUNCTION_End Failed: %ld" ), dwError );

			break;

			case SW2_EAP_FUNCTION_FreeMemory:

				SW2_ReportEvent( L"SW2_EAP_FUNCTION_FreeMemory Failed", EVENTLOG_ERROR_TYPE, dwError );		

				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_EAP_FUNCTION_FreeMemory Failed: %ld" ), dwError );

			break;

			default:

				SW2_ReportEvent( L"Unknown Function Failed", EVENTLOG_ERROR_TYPE, dwError );

				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::Unknown Function Failed: %ld" ), dwError );

			break;
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_HandleError:: returning" ) );
}