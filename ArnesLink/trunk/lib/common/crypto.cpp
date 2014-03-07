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
#pragma comment(lib, "Crypt32.lib")

//
// Name: SW2_GetCertificate
// Description: Retrieve certificate from store using SHA1 fingerprint
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
SW2_GetCertificate(	PBYTE pbServerCertSHA1, 
					OUT PCCERT_CONTEXT *ppCertContext )
{
	HCRYPTPROV		hCSP;
	HCERTSTORE		hCertStore;
	WCHAR			*pwcSubjectName;
	DWORD			cwcSubjectName;
	DWORD			dwType;
	PBYTE			pbSHA1;
	DWORD			cbSHA1;
	PCCERT_CONTEXT	pCertContext = NULL;
	DWORD			dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_GetCertificate()" ) ); 

	//
	// Connect to help CSP
	//
	if ((dwReturnCode = SW2_CryptAcquireDefaultContext(&hCSP, NULL)) == NO_ERROR)
	{
		if( ( hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, 
										X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
										( HCRYPTPROV ) NULL,
										CERT_SYSTEM_STORE_LOCAL_MACHINE,
										L"MY" ) ) )
		{
			BOOL	bFoundCert = FALSE;

			while( ( pCertContext = CertEnumCertificatesInStore( hCertStore,
																pCertContext ) ) &&
					bFoundCert == FALSE )
			{
				if( ( cwcSubjectName  = CertGetNameString( pCertContext,
															CERT_NAME_SIMPLE_DISPLAY_TYPE,
															0,
															&dwType,
															NULL,
															0 ) ) > 0 )
				{
					if ((dwReturnCode=SW2AllocateMemory(cwcSubjectName, (PVOID*)&pwcSubjectName))==NO_ERROR)
					{
						if( CertGetNameString( pCertContext,
												CERT_NAME_SIMPLE_DISPLAY_TYPE,
												0,
												&dwType,
												pwcSubjectName,
												cwcSubjectName ) > 0 )
						{
							//
							// Get HASH of certificate
							//
							if( ( dwReturnCode = TLSGetSHA1( hCSP, 
														pCertContext->pbCertEncoded, 
														pCertContext->cbCertEncoded, 
														&pbSHA1, 
														&cbSHA1 ) ) == NO_ERROR )
							{
								if( memcmp( pbServerCertSHA1, pbSHA1, sizeof( pbSHA1 ) ) == 0 )
								{
									*ppCertContext = CertDuplicateCertificateContext( pCertContext );

									bFoundCert = TRUE;
								}

								SW2FreeMemory((PVOID*)&pbSHA1 );
							}
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_GetCertificate::CertGetNameString FAILED: %x" ), GetLastError() );

							dwReturnCode = ERROR_CANTOPEN;
						}

						SW2FreeMemory((PVOID*)&pwcSubjectName );
						cwcSubjectName = 0;
					}
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_GetCertificate::CertGetNameString FAILED: %x" ), GetLastError() );

					dwReturnCode = ERROR_CANTOPEN;
				}
			}

			if( !bFoundCert )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_GetCertificate::no certificates found" ) );

				dwReturnCode = ERROR_CANTOPEN;
			}

			if( dwReturnCode != NO_ERROR )
			{
				if( pCertContext )
					CertFreeCertificateContext( pCertContext );

			}
				
			CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_GetCertificate::CertOpenStore FAILED: %x" ), GetLastError() );

			dwReturnCode = ERROR_CANTOPEN;
		}

		CryptReleaseContext( hCSP, 0 );
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_GetCertificate()::returning %ld" ), dwReturnCode ); 

	return dwReturnCode;
}


//
// Name: SW2_CryptAcquireContext
// Description: Function used to acquire a connection to a CSP.
//				Also deals with the Microsoft Windows CE Bug that prevents 
//				keys from being used after an update
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
SW2_CryptAcquireContext( HCRYPTPROV *phCSP, 
						WCHAR *pwcContainer,
						WCHAR *pwcCSPName, 
						DWORD dwType )
{
	DWORD	dwErr;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CryptAcquireContext()" ) ); 

	//
	// Connect to help CSP
	//
	if( !CryptAcquireContext( phCSP,
								pwcContainer,
								pwcCSPName,
								dwType,
								0 ) )
	{
		dwErr = GetLastError();

		if( dwErr == NTE_BAD_KEYSET || NTE_BAD_KEY_STATE )
		{
			//
			// Key is invalid, try to make a new one
			//
			if( !CryptAcquireContext( phCSP,
									pwcContainer,
									pwcCSPName,
									dwType,
									CRYPT_NEWKEYSET ) )
			{
				dwErr = GetLastError();

				if( dwErr == NTE_EXISTS )
				{
					//
					// Key is corrupt, silly microsoft...
					// Let's delete it and make a new one ;)
					//
					if( CryptAcquireContext( phCSP,
											pwcContainer,
											pwcCSPName,
											dwType,
											CRYPT_DELETEKEYSET ) )
					{
						if( !CryptAcquireContext( phCSP,
													pwcContainer,
													pwcCSPName,
													dwType,
													CRYPT_NEWKEYSET ) )
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CryptAcquireContext::CryptAcquireContext(NEWKEYSET):: FAILED (%ld)" ), GetLastError() );

							dwReturnCode = ERROR_ENCRYPTION_FAILED;
						}
					}
					else if( wcscmp( pwcContainer, L"SecureW2" ) == 0 )
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CryptAcquireContext::could not create new keyset (%ld)" ), GetLastError() );

						dwReturnCode = ERROR_ENCRYPTION_FAILED;
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_WARNING, TEXT( "SW2_TRACE_LEVEL_WARNING::SW2_CryptAcquireContext::CryptAcquireContext(CRYPT_DELETEKEYSET):: FAILED (%ld), trying to create with different container" ), GetLastError() );

						//
						// Let's try one more time with a different container 
						// and then throw an error
						//

						if( !pwcContainer )
							dwReturnCode = SW2_CryptAcquireContext( phCSP, L"SecureW2", pwcCSPName, dwType );
					}
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CryptAcquireContext::CryptAcquireContext(NEWKEYSET):: FAILED (%ld)" ), dwErr );

					dwReturnCode = ERROR_ENCRYPTION_FAILED;
				}
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CryptAcquireContext::CryptAcquireContext(0):: FAILED (%ld)" ), dwErr );

			dwReturnCode = ERROR_ENCRYPTION_FAILED;
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CryptAcquireContext()::returning %ld" ), dwReturnCode ); 

	return dwReturnCode;
}

//
// Name: SW2_CryptAcquireDefaultContext
// Description: Default function used to acquire a connection the MS Enh CSP.
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
SW2_CryptAcquireDefaultContext( HCRYPTPROV *phCSP, WCHAR *pwcContainer )
{
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CryptAcquireDefaultContext()" ) ); 

	dwReturnCode = SW2_CryptAcquireContext( phCSP, pwcContainer, MS_ENHANCED_PROV, PROV_RSA_FULL );

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CryptAcquireDefaultContext()::returning %ld" ), dwReturnCode ); 

	return dwReturnCode;
}


//
// Name: TLSGetSHA1
// Description: Creates SHA1 of a message
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSGetSHA1( IN HCRYPTPROV hCSP,
			IN PBYTE pbMsg, 
			IN DWORD cbMsg, 
			OUT PBYTE *ppbSHA1, 
			OUT DWORD *pcbSHA1 )
{
	HCRYPTHASH	hSHA1;
	DWORD		dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSGetSHA1()" ) ); 

	if( CryptCreateHash( hCSP,
							CALG_SHA1,
							0,
							0,
							&hSHA1 ) )
	{
		if( CryptHashData( hSHA1,
							( PBYTE ) pbMsg,
							cbMsg,
							0 ) )
		{
			if( CryptGetHashParam( hSHA1, 
									HP_HASHVAL, 
									NULL, 
									pcbSHA1, 
									0 ) )
			{
				if ((dwReturnCode = SW2AllocateMemory(*pcbSHA1, (PVOID*)ppbSHA1))==NO_ERROR)
				{
					if( !CryptGetHashParam( hSHA1, 
											HP_HASHVAL, 
											*ppbSHA1, 
											pcbSHA1, 
											0 ) )
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSGetSHA1::CryptGetHashParam2:: FAILED (%ld)" ), GetLastError() );

						dwReturnCode = ERROR_ENCRYPTION_FAILED;

						SW2FreeMemory((PVOID*)ppbSHA1);
					}
				}
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSGetSHA1::CryptGetHashParam1:: FAILED (%ld)" ), GetLastError() );

				dwReturnCode = ERROR_ENCRYPTION_FAILED;
			}

		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSGetSHA1::CryptHashData:: FAILED (%ld)" ), GetLastError() );

			dwReturnCode = ERROR_ENCRYPTION_FAILED;
		}

		CryptDestroyHash( hSHA1 );
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSGetSHA1::CryptCreateHash(CALG_SHA1):: FAILED (%ld)" ), GetLastError() );

		dwReturnCode = ERROR_ENCRYPTION_FAILED;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSGetSHA1()::returning %ld" ), dwReturnCode ); 

	return dwReturnCode;
}

//
// Name: TLSGetMD5
// Description: Creates MD5 of a message
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSGetMD5( IN HCRYPTPROV hCSP,
			IN PBYTE pbMsg, 
			IN DWORD cbMsg, 
			OUT PBYTE *ppbMD5, 
			OUT DWORD *pcbMD5 )
{
	HCRYPTHASH	hMD5;
	DWORD		dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSGetMD5()" ) ); 

	if( CryptCreateHash( hCSP,
							CALG_MD5,
							0,
							0,
							&hMD5 ) )
	{
		if( CryptHashData( hMD5,
							( PBYTE ) pbMsg,
							cbMsg,
							0 ) )
		{
			if( CryptGetHashParam( hMD5, 
									HP_HASHVAL, 
									NULL, 
									pcbMD5, 
									0 ) )
			{
				if ((dwReturnCode = SW2AllocateMemory(*pcbMD5, (PVOID*)ppbMD5))==NO_ERROR)
				{
					if( !CryptGetHashParam( hMD5, 
											HP_HASHVAL, 
											*ppbMD5, 
											pcbMD5, 
											0 ) )
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSGetMD5::CryptGetHashParam2:: FAILED (%ld)" ), GetLastError() );

						dwReturnCode = ERROR_ENCRYPTION_FAILED;
					
						SW2FreeMemory((PVOID*)ppbMD5);
					}
				}
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSGetMD5::CryptGetHashParam1:: FAILED (%ld)" ), GetLastError() );

				dwReturnCode = ERROR_ENCRYPTION_FAILED;
			}

		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSGetMD5::CryptHashData:: FAILED (%ld)" ), GetLastError() );

			dwReturnCode = ERROR_ENCRYPTION_FAILED;
		}

		CryptDestroyHash( hMD5 );
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::TLSGetMD5::CryptCreateHash(CALG_MD5):: FAILED (%ld)" ), GetLastError() );

		dwReturnCode = ERROR_ENCRYPTION_FAILED;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::TLSGetMD5()::returning %ld" ), dwReturnCode ); 

	return dwReturnCode;
}