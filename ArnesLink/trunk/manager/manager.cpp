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

DWORD
SW2RunManager()
{
	HKEY				hKey;
	DWORD				dwDisposition;
	SW2_CONFIG_DATA		ConfigData;
	LPWSTR				*pwcArglist;
	int					nArgs;
	DWORD				dwReturnCode;
	HCRYPTPROV			hCSP;
	HANDLE				hFile;
	BYTE				pbCertificate[4096];
	DWORD				cbCertificate = sizeof(pbCertificate);
	int					iCertType = -1;
	PCCERT_CONTEXT		pCertContext;
	HCERTSTORE			hCertStore;
	PBYTE				pbSHA1;
	DWORD				cbSHA1;
	HWND				hWnd;
	WCHAR				pwcProfileId[UNLEN];
	SW2_PROFILE_DATA	ProfileData;
	DWORD				dwVersion;

	dwReturnCode = NO_ERROR;

	g_dwSW2TraceId = TraceRegister(L"SECUREW2MGR");

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::ProfileManager"));

	memset(&ConfigData,  0, sizeof(ConfigData));

	if ((dwReturnCode = SW2InitializeHeap())==NO_ERROR)
	{
		dwVersion = GetVersion();

		g_dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
		g_dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

		if ((pwcArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs)) != NULL)
		{
			SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::ProfileManager::nr of arguments: %ld"), nArgs);

			if (nArgs > 2)
			{
				if ((g_hResource = LoadLibrary( L"sw2_res_default.dll")))
				{
					SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::ProfileManager::loaded resource"));

					if ((g_hLanguage = LoadLibrary( L"sw2_lang.dll")))
					{
						SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::ProfileManager::loaded language"));
					}
					else
						dwReturnCode = ERROR_INVALID_DATA;
				}
				else
					dwReturnCode = ERROR_INVALID_DATA;

				if (nArgs == 4)
				{
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, TEXT("SW2_TRACE_LEVEL_DEBUG::ProfileManager::pwcArglist[0]: %s"), pwcArglist[0]);
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, TEXT("SW2_TRACE_LEVEL_DEBUG::ProfileManager::pwcArglist[1]: %s"), pwcArglist[1]);
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, TEXT("SW2_TRACE_LEVEL_DEBUG::ProfileManager::pwcArglist[2]: %s"), pwcArglist[2]);
					SW2Trace( SW2_TRACE_LEVEL_DEBUG, TEXT("SW2_TRACE_LEVEL_DEBUG::ProfileManager::pwcArglist[3]: %s"), pwcArglist[3]);
				}

				if (dwReturnCode == NO_ERROR )
				{
					if (wcscmp( pwcArglist[1], L"profile" ) == 0 )
					{
						if (nArgs == 3)
						{
							swprintf_s(ConfigData.pwcProfileId, sizeof(ConfigData.pwcProfileId ) / sizeof (WCHAR), pwcArglist[2]);

							if (g_dwMajorVersion > 5)
								hWnd = GetForegroundWindow();
							else
								hWnd = NULL;

							if (DialogBoxParam( g_hResource,
												MAKEINTRESOURCE( IDD_CONFIG_DLG ),
												hWnd,
												ConfigDlgProc,
												(LPARAM )&(ConfigData)))
							{
								SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::ProfileManager::dialog returned"));
							}
							else
							{
								//
								// user canceled
								//
								swprintf_s( ConfigData.pwcProfileId, sizeof(ConfigData.pwcProfileId ) / sizeof (WCHAR), L"none");
							}

							SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::ProfileManager::opening manager reg key"));

							//
							// Create SecureW2 key and answer
							//
							if ((dwReturnCode = SW2_CreateSecureKey( HKEY_LOCAL_MACHINE,
															SW2_MANAGER_LOCATION,
															&hKey,
															&dwDisposition )) == NO_ERROR )
							{
								SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::ProfileManager::opened manager reg key"));

								dwReturnCode = RegSetValueEx( hKey,
														L"SelectedProfile",
														0,
														REG_SZ,
														(PBYTE)ConfigData.pwcProfileId,
														sizeof(ConfigData.pwcProfileId));

								RegCloseKey( hKey);
							}			
						}
						else
							dwReturnCode = ERROR_INVALID_DATA;
					}
					else if (wcscmp( pwcArglist[1], L"certificate" ) == 0 )
					{
						// certificate <profileid> <certificatetype> <certificatefile>

						if (nArgs == 5 )
						{
							swprintf_s( pwcProfileId, sizeof(pwcProfileId ) / sizeof (WCHAR), pwcArglist[2]);

							if (wcscmp(pwcProfileId, L"NONE")!=0)
								SW2_ReadProfile( pwcProfileId, NULL, &ProfileData);

							//
							// Check certificate type for MY (0) or ROOT (1) installation
							//
							if (wcscmp( pwcArglist[3], L"0" ) == 0 )
								iCertType = 0;
							else if (wcscmp( pwcArglist[3], L"1" ) == 0 )
								iCertType = 1;
							else if (wcscmp( pwcArglist[3], L"2" ) == 0 )
								iCertType = 2;

							if (iCertType >= 0 )
							{
								if ((hFile = CreateFile(	pwcArglist[4],
															GENERIC_READ,
															0,
															NULL,
															OPEN_EXISTING,
															FILE_ATTRIBUTE_NORMAL,
															NULL)))
								{
									if (!ReadFile( hFile,
												pbCertificate,
												cbCertificate,
												&cbCertificate,
												NULL ) )
									{
										dwReturnCode = GetLastError();

										SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::ProfileManager::ReadFile Failed (%ld)"), dwReturnCode);
									}

									CloseHandle( hFile);
								}
								else
								{
									dwReturnCode = GetLastError();
									SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::ProfileManager::CreateFile Failed (%ld)"), dwReturnCode);
								}

								if (dwReturnCode == NO_ERROR )
								{
									SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::ProfileManager::found certificate(%ld"), 
												cbCertificate);

									SW2Dump( SW2_TRACE_LEVEL_DEBUG, pbCertificate, cbCertificate);

									if ((pCertContext = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
																						pbCertificate, 
																						cbCertificate)) )
									{
										if (iCertType == 0 )
										{
											hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM,
																		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
																		( HCRYPTPROV  ) NULL, 
																		CERT_SYSTEM_STORE_LOCAL_MACHINE,
																		L"MY");
										}
										else
										{
											hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM,
																		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
																		( HCRYPTPROV  ) NULL, 
																		CERT_SYSTEM_STORE_LOCAL_MACHINE,
																		L"ROOT");
										}

										if (hCertStore )
										{
											if (!CertAddCertificateContextToStore( hCertStore, 
																					pCertContext, 
																					CERT_STORE_ADD_REPLACE_EXISTING, 
																					NULL ) )
											{
												SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::ProfileManager::CertAddCertificateContextToStore(), FAILED: %x"), GetLastError());

												dwReturnCode = CERT_E_UNTRUSTEDROOT;
											}

											CertCloseStore( hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);
										}
										else
										{
											SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::ProfileManager::CertOpenSystemStore(), FAILED: %x"), GetLastError());

											dwReturnCode = CERT_E_UNTRUSTEDROOT;
										}

										if (iCertType == 2 )
										{
											//
											// Also add root certificate to our CA list
											//
											dwReturnCode = SW2_CryptAcquireDefaultContext(&hCSP,
																			NULL);

											if (wcscmp(pwcProfileId, L"NONE")!=0)
											{
							
												//
												// Get HASH of certificate
												//
												if ((dwReturnCode = TLSGetSHA1( hCSP, 
																			pbCertificate, 
																			cbCertificate, 
																			&pbSHA1, 
																			&cbSHA1 )) == NO_ERROR )
												{
													//
													// If not in list then add
													//
													if (SW2_VerifyCertificateInList( ProfileData, pbSHA1 ) != NO_ERROR )
													{
														SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::ProfileManager::ProfileData.dwNrOfTrustedRootCAInList: %ld"), ProfileData.dwNrOfTrustedRootCAInList);

														memcpy( ProfileData.pbTrustedRootCAList[ProfileData.dwNrOfTrustedRootCAInList], 
																pbSHA1, 
																cbSHA1);

														ProfileData.dwNrOfTrustedRootCAInList++;

														dwReturnCode = SW2_WriteCertificates( ProfileData.pwcCurrentProfileId,
																						ProfileData);
													}

													SW2FreeMemory((PVOID*)&pbSHA1);
												}
												else
												{
													SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::ProfileManager::TLSGetMD5 FAILED: %ld"), dwReturnCode);
												}

												CryptReleaseContext( hCSP, 0);
											}
										}

										CertFreeCertificateContext( pCertContext);
									}
									else
									{
										SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::ProfileManager::CertCreateCertificateContext(), FAILED: %x"), GetLastError());

										dwReturnCode = CERT_E_UNTRUSTEDROOT;
									}
								}
							}
							else
								dwReturnCode = ERROR_INVALID_DATA;
						}
						else
							dwReturnCode = ERROR_INVALID_DATA;
					}
					else
						dwReturnCode = ERROR_INVALID_DATA;

					if (g_hResource)
						FreeLibrary(g_hResource);

					if (g_hLanguage)
						FreeLibrary(g_hLanguage);
				}
			}
			else
				dwReturnCode = ERROR_INVALID_DATA;

			LocalFree(pwcArglist);
		}
	}

	//
	// Report error via success or failure via registry,
	//
	//
	// Secure key creeren (value dan), antwoord in proppen en dan uit laten lezen door sw2
	//
	if ((SW2_CreateSecureKey( HKEY_LOCAL_MACHINE,
								SW2_MANAGER_LOCATION,
								&hKey,
								&dwDisposition )) == NO_ERROR )
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::ProfileManager::opened manager reg key"));

		dwReturnCode = RegSetValueEx( hKey,
								L"Error",
								0,
								REG_DWORD,
								(PBYTE)&dwReturnCode,
								sizeof(dwReturnCode));

		RegCloseKey( hKey);
	}

	//
	// Deinitialize memory heap
	//
	SW2DeInitializeHeap();

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT("SW2_TRACE_LEVEL_INFO::ProfileManager::returning: %ld"), dwReturnCode);

	TraceDeregister(g_dwSW2TraceId);

	return dwReturnCode;
}