/*
    SecureW2, Copyright (C) SecureW2 B.V.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty off
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
// Name: SW2_VerifyCertificateChain
// Description: Verifies the certificate chain starting with pCertContext
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
SW2_VerifyCertificateChain( IN PSW2_SESSION_DATA pSessionData, IN PCCERT_CONTEXT pCertContext )
{
	HCRYPTPROV					hCSP;
	HCERTSTORE					hTempStore;
	int							i;
	CERT_CHAIN_PARA				ChainParams;
	PCCERT_CHAIN_CONTEXT		pChainContext;
	PCCERT_CONTEXT				pRootCACertContext;
	CERT_ENHKEY_USAGE			EnhkeyUsage;
	CERT_USAGE_MATCH			CertUsage;  
	PBYTE						pbSHA1;
	DWORD						cbSHA1;
	DWORD						dwFlags;
	DWORD						dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_VerifyCertificateChain()" ) );

	//
	// Create additional store to allow verification of sub ca
	//
	if( hTempStore = CertOpenStore( CERT_STORE_PROV_MEMORY, 
									X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
									( HCRYPTPROV ) NULL,
									CERT_SYSTEM_STORE_LOCAL_MACHINE,
									L"SW2" ) )
	{
		if(pSessionData->TLSSession.dwCertCount>1)
		{
			//
			// Dump all certificates, except first server (or self signed) certificate, in temp store
			//
			for(i=1;(DWORD)i<pSessionData->TLSSession.dwCertCount;i++)
			{
				CertAddEncodedCertificateToStore(hTempStore,
												X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
												pSessionData->TLSSession.pbCertificate[i],
												pSessionData->TLSSession.cbCertificate[i],
												CERT_STORE_ADD_REPLACE_EXISTING,
												NULL);

			}
		}

		//
		// Initialize the certificate chain validation
		//
		EnhkeyUsage.cUsageIdentifier = 0;
		EnhkeyUsage.rgpszUsageIdentifier = NULL;

		CertUsage.dwType = USAGE_MATCH_TYPE_AND;
		CertUsage.Usage  = EnhkeyUsage;

		// 
		// added 17 June 2003, Tom Rixom
		// Set all options to 0 but set the ChainParams.dwUrlRetrievalTimeout to 1
		// If ChainParams.dwUrlRetrievalTimeout is not set to 1 then url checking will take forever!
		// also set dwFlags to only check the cached URLS for revocation and chain checking
		//

		memset( &ChainParams, 0, sizeof( CERT_CHAIN_PARA ) );

#ifndef _WIN32_WCE
		ChainParams.dwUrlRetrievalTimeout = 1;
#endif
		
		ChainParams.cbSize = sizeof( CERT_CHAIN_PARA );
		ChainParams.RequestedUsage = CertUsage;

		dwFlags =	CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL |
					CERT_CHAIN_CACHE_END_CERT;
		//
		// Check the certificate chain
		// do not check urls as we do not have any IP connectivity
		//
		if( CertGetCertificateChain( HCCE_LOCAL_MACHINE, 
										pCertContext, 
										NULL,
										hTempStore,
										&ChainParams,
										0,
										NULL,
										&pChainContext ) )
		{
			if( pChainContext->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_VerifyCertificateChain()::chain could not be validated( %x )" ), pChainContext->TrustStatus.dwErrorStatus );

#ifdef _WIN32_WCE
			if( pChainContext->TrustStatus.dwErrorStatus != CERT_TRUST_IS_OFFLINE_REVOCATION )
				dwReturnCode = CERT_E_UNTRUSTEDROOT;
#else
				dwReturnCode = CERT_E_UNTRUSTEDROOT;
#endif // _WIN32_WCE
			}
			else
			{
				//
				// If required, verify Root CA against SecureW2 Trusted Root CA List
				//
				if(pSessionData->ProfileData.dwNrOfTrustedRootCAInList > 0)
				{
					if (pChainContext->cChain==1)
					{
						if (pChainContext->rgpChain[0]->cElement > 0)
						{
							pRootCACertContext = pChainContext->rgpChain[0]->rgpElement[pChainContext->rgpChain[0]->cElement-1]->pCertContext;

							//
							// Connect to help CSP
							//
							if ((dwReturnCode = SW2_CryptAcquireDefaultContext(&hCSP,
																			NULL)) == NO_ERROR)
							{
								if( ( dwReturnCode = TLSGetSHA1( hCSP, 
												pRootCACertContext->pbCertEncoded, 
												pRootCACertContext->cbCertEncoded, 
												&pbSHA1, &cbSHA1 ) ) == NO_ERROR )
								{
									dwReturnCode = SW2_VerifyCertificateInList(pSessionData->ProfileData, pbSHA1);

									SW2FreeMemory((PVOID*)&pbSHA1);
								}

								CryptReleaseContext( hCSP, 0 );
							}
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT("SW2_TRACE_LEVEL_ERROR::SW2_VerifyCertificateChain()::number of chain elements is zero" ) );

							dwReturnCode = ERROR_INTERNAL_ERROR;
						}
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT("SW2_TRACE_LEVEL_ERROR::SW2_VerifyCertificateChain()::more than one chain is not supported" ) );

						dwReturnCode = ERROR_NOT_SUPPORTED;
					}
				}
			}

			CertFreeCertificateChain( pChainContext );
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_VerifyCertificateChain(), CertGetCertificateChain(), FAILED: %x" ), GetLastError() );

			dwReturnCode = ERROR_INTERNAL_ERROR;
		}

		CertCloseStore(hTempStore,CERT_CLOSE_STORE_FORCE_FLAG);
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_VerifyCertificateChain(), CertOpenStore(), FAILED: %x" ), GetLastError() );

		dwReturnCode = ERROR_INTERNAL_ERROR;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_VerifyCertificateChain::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_VerifyCertificateInStore
// Description: Verifies if the certificate pCertContext is installed 
//				in the local computer store
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
SW2_VerifyCertificateInStore( IN PCCERT_CONTEXT pCertContext )
{
	HCRYPTPROV		hCSP;
	HCERTSTORE		hCertStore;
	PCCERT_CONTEXT	pCertContext2;
	WCHAR			*pwcSubjectName, *pwcSubjectName2;
	DWORD			cwcSubjectName, cwcSubjectName2;
	PBYTE			pbMD5, pbMD52;
	DWORD			cbMD5, cbMD52;
	BOOL			bFoundCert;
	DWORD			dwType;
	int				i;
	DWORD			dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_VerifyCertificateInStore()") );

	//
	// Connect to help CSP
	//
	if ((dwReturnCode = SW2_CryptAcquireDefaultContext(&hCSP,NULL))==NO_ERROR)
	{
		//
		// Retrieve Subject name of certificate
		//
		if( ( cwcSubjectName  = CertGetNameString( pCertContext,
													CERT_NAME_SIMPLE_DISPLAY_TYPE,
													0,
													&dwType,
													NULL,
													0 ) ) > 0 )
		{
			if ((dwReturnCode = SW2AllocateMemory(cwcSubjectName * sizeof( WCHAR ), (PVOID*)&pwcSubjectName))==NO_ERROR)
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
					if( ( dwReturnCode = TLSGetMD5( hCSP, 
											pCertContext->pbCertEncoded, 
											pCertContext->cbCertEncoded, 
											&pbMD5, 
											&cbMD5 ) ) == NO_ERROR )
					{
						if( hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, 
														X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
														( HCRYPTPROV ) NULL,
														CERT_SYSTEM_STORE_LOCAL_MACHINE,
														L"MY" ) )
						{
							pCertContext2 = NULL;

							bFoundCert = FALSE;

							while( !bFoundCert &&
									( pCertContext2 = CertEnumCertificatesInStore( hCertStore, pCertContext2 ) ) )
							{
								if( ( cwcSubjectName2  = CertGetNameString( pCertContext2,
																			CERT_NAME_SIMPLE_DISPLAY_TYPE,
																			0,
																			&dwType,
																			NULL,
																			0 ) ) > 0 )
								{
									if ((dwReturnCode = SW2AllocateMemory(cwcSubjectName2 * sizeof( WCHAR ), (PVOID*)&pwcSubjectName2))==NO_ERROR)
									{
										if( CertGetNameString( pCertContext2,
																CERT_NAME_SIMPLE_DISPLAY_TYPE,
																0,
																&dwType,
																pwcSubjectName2,
																cwcSubjectName2 ) > 0 )
										{
											if( wcscmp( pwcSubjectName, pwcSubjectName2 ) == 0 )
											{
												//
												// Verify HASH of certificate
												//
												if( ( dwReturnCode = TLSGetMD5( hCSP, pCertContext2->pbCertEncoded, pCertContext2->cbCertEncoded, &pbMD52, &cbMD52 ) ) == NO_ERROR )
												{
													bFoundCert = TRUE;

													for( i=0; ( DWORD ) i < cbMD5; i++ )
													{
														if( pbMD5[i] != pbMD52[i] )
														{
															bFoundCert = FALSE;
															break;
														}
													}

													SW2FreeMemory((PVOID*)&pbMD52);
												}
											}
										}
										else
										{
											SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_VerifyCertificateInStore::CertGetNameString FAILED: %x" ), GetLastError() );

											dwReturnCode = ERROR_CANTOPEN;
										}

										SW2FreeMemory((PVOID*)&pwcSubjectName2);
										cwcSubjectName2 = 0;
									}
								}
								else
								{
									SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_VerifyCertificateInStore::CertGetNameString FAILED: %x" ), GetLastError() );

									dwReturnCode = ERROR_CANTOPEN;
								}
							}

							if( pCertContext2 )
								CertFreeCertificateContext( pCertContext2 );
							//
							// Did we find anything?
							//
							if( !bFoundCert )
							{
								SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_VerifyCertificateInStore::could not find certificate" ) );

								dwReturnCode = ERROR_NO_DATA;
							}

							CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_VerifyCertificateInStore::CertOpenStore FAILED: %x" ), GetLastError() );

							dwReturnCode = ERROR_CANTOPEN;
						}

						SW2FreeMemory((PVOID*)&pbMD5);
					}
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_VerifyCertificateInStore::CertGetNameString FAILED: %x" ), GetLastError() );

					dwReturnCode = ERROR_CANTOPEN;
				}

				SW2FreeMemory((PVOID*)&pwcSubjectName);
				cwcSubjectName = 0;
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_VerifyCertificateInStore::CertGetNameString FAILED: %x" ), GetLastError() );

			dwReturnCode = ERROR_CANTOPEN;
		}

		CryptReleaseContext( hCSP, 0 );
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_VerifyCertificateInStore::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_CertGetTrustedRootCAList
// Description: Fill list box with trusted (by SecureW2) root CA list
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
SW2_CertGetTrustedRootCAList( HWND hWnd, 
							BYTE pbTrustedCAList[SW2_MAX_CA][20], 
							DWORD dwNrOfTrustedRootCAInList )
{
	HCRYPTPROV		hCSP;
	HCERTSTORE		hCertStore;
	PCCERT_CONTEXT	pCertContext = NULL;
	WCHAR			*pwcSubjectName;
	DWORD			cwcSubjectName;
	DWORD			dwType;
	DWORD			dwSelected = 0;
	PBYTE			pbSHA;
	DWORD			cbSHA;
	DWORD			dwErr;
	DWORD			i = 1;
	DWORD			j = 0;
	DWORD			dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CertGetTrustedRootCAList()" ) );

	SendMessage( hWnd, 
				LB_RESETCONTENT, 
				0, 
				0 ); 

	//
	// Nothing to display then return nothing
	//
	if( dwNrOfTrustedRootCAInList == 0 )
		return dwReturnCode;

	//
	// Connect to help CSP
	//
	if( !CryptAcquireContext( &hCSP,
								NULL,
								MS_DEF_PROV,
								PROV_RSA_FULL,
								0 ) )
	{
		dwErr = GetLastError();

		if( dwErr == NTE_BAD_KEYSET )
		{
			if( !CryptAcquireContext( &hCSP,
									NULL,
									MS_DEF_PROV,
									PROV_RSA_FULL,
									CRYPT_NEWKEYSET ) )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CertGetTrustedRootCAList::CryptAcquireContext(NEWKEYSET):: FAILED (%ld)" ), GetLastError() );

				dwReturnCode = ERROR_ENCRYPTION_FAILED;
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CertGetTrustedRootCAList::CryptAcquireContext(0):: FAILED (%ld)" ), GetLastError() );

			dwReturnCode = ERROR_ENCRYPTION_FAILED;
		}
	}

	if( dwReturnCode == NO_ERROR )
	{
		if( hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, 
										X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
										( HCRYPTPROV ) NULL,
										CERT_SYSTEM_STORE_LOCAL_MACHINE,
										L"ROOT" ) )
		{
			while( ( pCertContext = CertEnumCertificatesInStore( hCertStore,
																pCertContext ) ) )
			{
				if( ( cwcSubjectName  = CertGetNameString( pCertContext,
															CERT_NAME_SIMPLE_DISPLAY_TYPE,
															0,
															&dwType,
															NULL,
															0 ) ) > 0 )
				{
					if ((dwReturnCode = SW2AllocateMemory(cwcSubjectName * sizeof( WCHAR ), (PVOID*)&pwcSubjectName))==NO_ERROR)
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
														&pbSHA, &cbSHA ) ) == NO_ERROR )
							{
								//
								// Only add the certificates that we trust
								//
								for( j=0; j < dwNrOfTrustedRootCAInList; j++ )
								{
									if( memcmp( pbTrustedCAList[j], pbSHA, sizeof( pbSHA ) ) == 0 )
									{
										//
										// Add certificate name
										//
										dwSelected = ( DWORD ) SendMessage( 
																hWnd, 
																LB_ADDSTRING, 
																0, 
																( LPARAM ) pwcSubjectName );

										//
										// Add list number
										//
										SendMessage( hWnd,
													LB_SETITEMDATA,
													dwSelected,
													( LPARAM ) i );

										j = dwNrOfTrustedRootCAInList;
									}
								}

								SW2FreeMemory((PVOID*)&pbSHA);
							}
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CertGetTrustedRootCAList()::CertGetNameString FAILED: %x" ), GetLastError() );

							dwReturnCode = ERROR_CANTOPEN;
						}

						SW2FreeMemory((PVOID*)&pwcSubjectName);
						cwcSubjectName = 0;
					}
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CertGetTrustedRootCAList()::CertGetNameString FAILED: %x" ), GetLastError() );

					dwReturnCode = ERROR_CANTOPEN;
				}

				i++;
			}

			if( pCertContext )
				CertFreeCertificateContext( pCertContext );

			CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CertGetTrustedRootCAList()::CertOpenStore FAILED: %x" ), GetLastError() );

			dwReturnCode = ERROR_CANTOPEN;
		}

		CryptReleaseContext( hCSP, 0 );
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CertGetTrustedRootCAList::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_CertGetRootCAList
// Description: Fill list box with windows root CA list
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
SW2_CertGetRootCAList( IN HWND hWnd,
						IN BYTE pbTrustedRootCAList[SW2_MAX_CA][20],
						IN DWORD dwNrOfTrustedRootCAInList )
{
	HCRYPTPROV		hCSP;
	HCERTSTORE		hCertStore;
	PCCERT_CONTEXT	pCertContext = NULL;
	WCHAR			*pwcSubjectName;
	DWORD			cwcSubjectName;
	DWORD			dwType;
	DWORD			dwSelected;
	PBYTE			pbSHA1;
	DWORD			cbSHA1;
	BOOL			bFoundCert;
	DWORD			i = 1;
	DWORD			j = 0;
	DWORD			dwErr;
	DWORD			dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CertGetRootCAList()" ) );

	SendMessage( hWnd, 
				LB_RESETCONTENT, 
				0, 
				0 ); 

	//
	// Connect to help CSP
	//
	if( !CryptAcquireContext( &hCSP,
								NULL,
								MS_DEF_PROV,
								PROV_RSA_FULL,
								0 ) )
	{
		dwErr = GetLastError();

		if( dwErr == NTE_BAD_KEYSET )
		{
			if( !CryptAcquireContext( &hCSP,
									NULL,
									MS_DEF_PROV,
									PROV_RSA_FULL,
									CRYPT_NEWKEYSET ) )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CertGetRootCAList::CryptAcquireContext(NEWKEYSET):: FAILED (%ld)" ), GetLastError() );

				dwReturnCode = ERROR_ENCRYPTION_FAILED;
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CertGetRootCAList::CryptAcquireContext(0):: FAILED (%ld)" ), GetLastError() );

			dwReturnCode = ERROR_ENCRYPTION_FAILED;
		}
	}

	if( dwReturnCode == NO_ERROR )
	{
		if( hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, 
										X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
										( HCRYPTPROV ) NULL,
										CERT_SYSTEM_STORE_LOCAL_MACHINE,
										L"ROOT" ) )
		{
			while( ( pCertContext = CertEnumCertificatesInStore( hCertStore,
																pCertContext ) ) )
			{
				//
				// First check if we have already got this CA in our trusted list
				//
				if( ( dwReturnCode = TLSGetSHA1( hCSP, 
											pCertContext->pbCertEncoded, 
											pCertContext->cbCertEncoded, 
											&pbSHA1, 
											&cbSHA1 ) ) == NO_ERROR )
				{
					bFoundCert = FALSE;

					for( j=0; j< dwNrOfTrustedRootCAInList; j++ )
					{
						if( memcmp( pbTrustedRootCAList[j], 
									pbSHA1, 
									sizeof( pbTrustedRootCAList[j] ) ) == 0 )
						{
							bFoundCert = TRUE;

							j = dwNrOfTrustedRootCAInList;
						}
					}

					if( !bFoundCert )
					{
						if( ( cwcSubjectName  = CertGetNameString( pCertContext,
																	CERT_NAME_SIMPLE_DISPLAY_TYPE,
																	0,
																	&dwType,
																	NULL,
																	0 ) ) > 0 )
						{
							if ((dwReturnCode = SW2AllocateMemory(cwcSubjectName * sizeof( WCHAR ), (PVOID*)&pwcSubjectName))==NO_ERROR)
							{
								if( CertGetNameString( pCertContext,
														CERT_NAME_SIMPLE_DISPLAY_TYPE,
														0,
														&dwType,
														pwcSubjectName,
														cwcSubjectName ) > 0 )
								{
									//
									// Add certificate name
									//
									dwSelected = ( DWORD ) SendMessage( hWnd, 
																LB_ADDSTRING, 
																0, 
																( LPARAM ) pwcSubjectName );

									SendMessage( hWnd,
												LB_SETITEMDATA,
												dwSelected,
												( LPARAM ) i );
								}

								SW2FreeMemory((PVOID*)&pwcSubjectName);
								cwcSubjectName = 0;
							}
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CertGetRootCAList::CertGetNameString Failed (%x)" ), GetLastError() );

							dwReturnCode = ERROR_CANTOPEN;
						}
					}

					i++;
				}	
			}

			if( pCertContext )
				CertFreeCertificateContext( pCertContext );

			CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );
		}
		else
			dwReturnCode = ERROR_CANTOPEN;

		CryptReleaseContext( hCSP, 0 );
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CertGetRootCAList::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_CertGetRootCAList
// Description: Remove trusted Root CA from array
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
SW2_CertRemoveTrustedRootCA( IN DWORD dwSelected, 
						IN OUT BYTE pbTrustedRootCA[SW2_MAX_CA][20], 
						IN OUT DWORD *pdwNrOfTrustedCAInList )
{
	HCRYPTPROV		hCSP;
	HCERTSTORE		hCertStore;
	PCCERT_CONTEXT	pCertContext = NULL;
	PBYTE			pbSHA1;
	DWORD			cbSHA1;
	DWORD			dwErr;
	BOOL			bFoundCert;
	DWORD			i = 1;
	DWORD			j = 0;
	DWORD			dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CertRemoveTrustedRootCA()" ) );

	//
	// Connect to help CSP
	//
	if( !CryptAcquireContext( &hCSP,
								NULL,
								MS_DEF_PROV,
								PROV_RSA_FULL,
								0 ) )
	{
		dwErr = GetLastError();

		if( dwErr == NTE_BAD_KEYSET )
		{
			if( !CryptAcquireContext( &hCSP,
									NULL,
									MS_DEF_PROV,
									PROV_RSA_FULL,
									CRYPT_NEWKEYSET ) )
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CertRemoveTrustedRootCA::CryptAcquireContext(NEWKEYSET):: FAILED (%ld)" ), GetLastError() );

				dwReturnCode = ERROR_ENCRYPTION_FAILED;
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CertRemoveTrustedRootCA::CryptAcquireContext(0):: FAILED (%ld)" ), GetLastError() );

			dwReturnCode = ERROR_ENCRYPTION_FAILED;
		}
	}

	if( dwReturnCode == NO_ERROR )
	{
		if( hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, 
										X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
										( HCRYPTPROV ) NULL,
										CERT_SYSTEM_STORE_LOCAL_MACHINE,
										L"ROOT" ) )
		{
			while( ( pCertContext = CertEnumCertificatesInStore( hCertStore,
																pCertContext ) ) )
			{
				if( dwSelected == i )
				{
					//
					// Get HASH of certificate
					//
					if( ( dwReturnCode = TLSGetSHA1( hCSP, 
												pCertContext->pbCertEncoded, 
												pCertContext->cbCertEncoded, 
												&pbSHA1, &cbSHA1 ) ) == NO_ERROR )
					{
						//
						// Look through list remove certificate and rebuild list
						//
						bFoundCert = FALSE;

						for( j = 0; j < *pdwNrOfTrustedCAInList; j++ )
						{
							if( bFoundCert )
							{
								//
								// Rebuild rest of list if necessary
								//
								memcpy( pbTrustedRootCA[j-1], pbTrustedRootCA[j], sizeof( pbTrustedRootCA[j-1] ) );
							}
							else if( memcmp( pbTrustedRootCA[j], pbSHA1, cbSHA1 ) == 0 )
							{
								bFoundCert = TRUE;
							}
							
							if( j == *pdwNrOfTrustedCAInList )
							{
								memset( pbTrustedRootCA[j], 0, 20 );
							}
						}

						if( bFoundCert )
							*pdwNrOfTrustedCAInList = *pdwNrOfTrustedCAInList - 1;

						SW2FreeMemory((PVOID*)&pbSHA1);
					}
				}

				i++;
			}

			if( pCertContext )
				CertFreeCertificateContext( pCertContext );

			CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CertRemoveTrustedRootCA::CertOpenStore FAILED (%ld)" ), GetLastError() );

			dwReturnCode = ERROR_CANTOPEN;
		}

		CryptReleaseContext( hCSP, 0 );
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CertRemoveTrustedRootCA::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_CertGetRootCAList
// Description: Add trusted Root CA to array
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
SW2_CertAddTrustedRootCA( IN DWORD dwSelected, 
						IN OUT BYTE pbTrustedRootCA[SW2_MAX_CA][20], 
						IN OUT DWORD *pdwNrOfTrustedCAInList )
{
	HCRYPTPROV		hCSP;
	HCERTSTORE		hCertStore;
	PCCERT_CONTEXT	pCertContext = NULL;
	PBYTE			pbSHA1;
	DWORD			cbSHA1;
	DWORD			i = 1;
	DWORD			dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CertAddTrustedRootCA()" ) );

	//
	// Connect to help CSP
	//
	if ((dwReturnCode = SW2_CryptAcquireDefaultContext( &hCSP,
														NULL))==NO_ERROR)
	{
		if( hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, 
										X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
										( HCRYPTPROV ) NULL,
										CERT_SYSTEM_STORE_LOCAL_MACHINE,
										L"ROOT" ) )
		{
			while( ( pCertContext = CertEnumCertificatesInStore( hCertStore,
																pCertContext ) ) )
			{
				if( dwSelected == i )
				{
					//
					// Get HASH of certificate
					//
					if( ( dwReturnCode = TLSGetSHA1( hCSP, 
												pCertContext->pbCertEncoded, 
												pCertContext->cbCertEncoded, 
												&pbSHA1, &cbSHA1 ) ) == NO_ERROR )
					{
						memcpy( pbTrustedRootCA[*pdwNrOfTrustedCAInList ], pbSHA1, cbSHA1 );

						*pdwNrOfTrustedCAInList = *pdwNrOfTrustedCAInList + 1;

						SW2FreeMemory((PVOID*)&pbSHA1);
					}
				}

				i++;
			}

			if( pCertContext )
				CertFreeCertificateContext( pCertContext );

			CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CertAddTrustedRootCA::CertOpenStore FAILED (%ld)" ), GetLastError() );

			dwReturnCode = ERROR_CANTOPEN;
		}

		CryptReleaseContext( hCSP, 0 );
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CertAddTrustedRootCA::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_CertCheckEnhkeyUsage
// Description: Check the certificate pCertContext for the following OID:
//				EnhancedKeyUsage: ServerAuthentication("1.3.6.1.5.5.7.3.1"): szOID_PKIX_KP_SERVER_AUTH
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
SW2_CertCheckEnhkeyUsage( PCCERT_CONTEXT pCertContext )
{
	PCERT_ENHKEY_USAGE	pbEnhkeyUsage;
	DWORD				cbEnhkeyUsage;
	int					i = 0;
	DWORD				dwReturnCode;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CertCheckEnhkeyUsage()" ) );

	dwReturnCode = NO_ERROR;

	//
	// Check for the EnhancedKeyUsage: ServerAuthentication("1.3.6.1.5.5.7.3.1"): szOID_PKIX_KP_SERVER_AUTH
	//
	cbEnhkeyUsage = 0;

	if( CertGetEnhancedKeyUsage( pCertContext,
								CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG,
								NULL,
								&cbEnhkeyUsage ) )
	{
		if ((dwReturnCode = SW2AllocateMemory(cbEnhkeyUsage, (PVOID*)&pbEnhkeyUsage))==NO_ERROR)
		{
			if( CertGetEnhancedKeyUsage( pCertContext,
										CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG ,
										pbEnhkeyUsage,
										&cbEnhkeyUsage ) )
			{
				dwReturnCode = CERT_E_WRONG_USAGE;

				//
				// Found some enhanced key usages, loop through them to find the correct one
				//
				for( i = 0; i < ( int ) pbEnhkeyUsage->cUsageIdentifier; i++ )
				{
					if( strcmp( pbEnhkeyUsage->rgpszUsageIdentifier[i], szOID_PKIX_KP_SERVER_AUTH ) == 0 ) 
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CertCheckEnhkeyUsage(), certificate contains the correct Enhanced Key Usage" ) );

						dwReturnCode = NO_ERROR;
					}
				}
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CertCheckEnhkeyUsage(), CertGetEnhancedKeyUsage2(), FAILED: %x" ), GetLastError() );

				dwReturnCode = ERROR_INTERNAL_ERROR;
			}

			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CertCheckEnhkeyUsage(), freeing pbEnhkeyUsage" ) );

			SW2FreeMemory((PVOID*)&pbEnhkeyUsage);
		}
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CertCheckEnhkeyUsage(), CertGetEnhancedKeyUsage(), FAILED: %x" ), GetLastError() );

		dwReturnCode = ERROR_INTERNAL_ERROR;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CertCheckEnhkeyUsage(), returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_CertVerifyServerName
// Description: Verify if servername conforms with configured substring
// Author: Tom Rixom
// Created: 24 July 2007
//
DWORD
SW2_CertVerifyServerName(IN PSW2_SESSION_DATA pSessionData, PCCERT_CONTEXT pCertContext)
{
	PWCHAR	pwcSubjectName;
	DWORD	cwcSubjectName;
	DWORD	dwType;
	PWCHAR	pwcTemp;
	WCHAR	pwcSeperators[]= L";";
	PWCHAR  pwcToken = NULL;
	PWCHAR  pwcNextToken = NULL;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CertVerifyServerName()" ) );

	if ((cwcSubjectName  = CertGetNameString(pCertContext,
											CERT_NAME_SIMPLE_DISPLAY_TYPE,
											0,
											&dwType,
											NULL,
											0)) > 0)
	{
		if ((dwReturnCode = SW2AllocateMemory(cwcSubjectName * sizeof( WCHAR ), 
			(PVOID*) &pwcSubjectName)) == NO_ERROR)
		{
			if (CertGetNameString(pCertContext,
								CERT_NAME_SIMPLE_DISPLAY_TYPE,
								0,
								&dwType,
								pwcSubjectName,
								cwcSubjectName ) > 0 )
			{
				SW2Trace( SW2_TRACE_LEVEL_INFO, 
					TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CertVerifyServerName()::verifying servername: %s, expecting: %s" ), 
					pwcSubjectName, pSessionData->ProfileData.pwcServerName );

#ifndef _WIN32_WCE
				pwcToken = wcstok_s(pSessionData->ProfileData.pwcServerName, 
								pwcSeperators, &pwcNextToken);
#else
				pwcToken = wcstok(pSessionData->ProfileData.pwcServerName, 
								pwcSeperators);
#endif // _WIN32_WCE

				dwReturnCode = ERROR_INVALID_DOMAINNAME;

				while(pwcToken!=NULL&&
					dwReturnCode == ERROR_INVALID_DOMAINNAME)
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
						TEXT( "SW2_TRACE_LEVEL_DEBUG::SW2_CertVerifyServerName()::validating %s against %s" ),
						pwcToken, pwcSubjectName); 

					if (pwcTemp = wcsstr(pwcSubjectName, pwcToken))
					{
						SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
							TEXT( "SW2_TRACE_LEVEL_DEBUG::SW2_CertVerifyServerName()::found substring(%ld): %s" ),
							wcslen(pwcTemp), pwcTemp); 

						//
						// Check if the servername is found on the end of the Subjectname
						//
						if (wcslen(pwcTemp) == wcslen(pwcToken))
						{
							SW2Trace( SW2_TRACE_LEVEL_DEBUG, 
								TEXT( "SW2_TRACE_LEVEL_DEBUG::SW2_CertVerifyServerName()::found match" ) );

							dwReturnCode = NO_ERROR;
						}
					}
#ifndef _WIN32_WCE
					pwcToken = wcstok_s(NULL, 
						pwcSeperators, 
						&pwcNextToken);
#else
					pwcToken = wcstok(NULL, 
						pwcSeperators);
#endif // _WIN32_WCE
				}

				if (dwReturnCode != NO_ERROR)
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
						TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CertVerifyServerName()::servername mismatch" ) ); 
				}
			}

			SW2FreeMemory((PVOID*)&pwcSubjectName);
		}
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_CertVerifyServerName()::GetCertName Failed %x" ), GetLastError()); 

		dwReturnCode = ERROR_INVALID_DATA;
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CertVerifyServerName()::returning %ld" ), dwReturnCode ); 

	return dwReturnCode;
}

//
// Name: SW2_VerifyCertificateInList
// Description: Verify if HASH (SHA1) matches list of configured Root CA certificates (hashes)
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
SW2_VerifyCertificateInList( IN SW2_PROFILE_DATA ProfileData, IN PBYTE pbSHA1 )
{
	DWORD	dwReturnCode;
	DWORD	i;

	dwReturnCode = NO_ERROR;

	dwReturnCode = CERT_E_UNTRUSTEDROOT;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_VerifyCertificateInList" ) );

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_VerifyCertificateInList:: nr of ca in list: %ld" ), ProfileData.dwNrOfTrustedRootCAInList );

	for( i=0; i < ProfileData.dwNrOfTrustedRootCAInList; i++ )
	{
		if( memcmp( ProfileData.pbTrustedRootCAList[i], 
					pbSHA1, 
					sizeof( ProfileData.pbTrustedRootCAList[i] ) ) == 0 )
		{
			dwReturnCode = NO_ERROR;

			i = ProfileData.dwNrOfTrustedRootCAInList;
		}
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_VerifyCertificateInList:: returning %ld" ), dwReturnCode );

	return dwReturnCode;
}