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
#include <AccCtrl.h>
#ifndef _WIN32_WCE
#include <Aclapi.h>
#endif // _WIN32_WCE

//
// Name: SW2WireToHostFormat32
// Description: Helper function that converts a 4 binary representation
//				to a DWORD
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
SW2_WireToHostFormat32(	IN PBYTE pWireFormat )
{
    DWORD dwHostFormat = ((*((PBYTE)(pWireFormat)+0) << 24) +
				          (*((PBYTE)(pWireFormat)+1) << 16) +
						  (*((PBYTE)(pWireFormat)+2) << 8) +
						  (*((PBYTE)(pWireFormat)+3)));

    return(dwHostFormat);
}

//
// Name: SW2WireToHostFormat24
// Description: Helper function that converts a 3 binary representation
//				to a DWORD
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
SW2_WireToHostFormat24(	IN PBYTE pWireFormat )
{
    DWORD dwHostFormat = ((*((PBYTE)(pWireFormat)+0) << 16) +
						 (*((PBYTE)(pWireFormat)+1) << 8) +
                         (*((PBYTE)(pWireFormat)+2)));

    return(dwHostFormat);
}

//
// Name: SW2WireToHostFormat16
// Description: Helper function that converts a 2 binary representation
//				to a DWORD
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
SW2_WireToHostFormat16(	IN PBYTE pWireFormat )
{
    DWORD wHostFormat = ((*((PBYTE)(pWireFormat)+0) << 8) +
                        (*((PBYTE)(pWireFormat)+1)));

    return(wHostFormat);
}

//
// Name: SW2HostToWireFormat32
// Description: Helper function that converts a DWORD to a binary representation
// Author: Tom Rixom
// Created: 11 August 2004
//
VOID
SW2_HostToWireFormat32( IN     DWORD dwHostFormat,
					IN OUT PBYTE pWireFormat )
{
    *((PBYTE)(pWireFormat)+0) = (BYTE) ((DWORD)(dwHostFormat) >> 24);
    *((PBYTE)(pWireFormat)+1) = (BYTE) ((DWORD)(dwHostFormat) >> 16);
    *((PBYTE)(pWireFormat)+2) = (BYTE) ((DWORD)(dwHostFormat) >>  8);
    *((PBYTE)(pWireFormat)+3) = (BYTE) (dwHostFormat);
}

//
// Name: SW2HostToWireFormat24
// Description: Helper function that converts a 3 byte DWORD 
//				to a binary representation
// Author: Tom Rixom
// Created: 11 August 2004
//
VOID
SW2_HostToWireFormat24(	IN     DWORD  dwHostFormat,
						IN OUT PBYTE pWireFormat )
{
    *((PBYTE)(pWireFormat)+0) = (BYTE) ((DWORD)(dwHostFormat) >>  16);
    *((PBYTE)(pWireFormat)+1) = (BYTE) ((DWORD)(dwHostFormat) >>  8);
    *((PBYTE)(pWireFormat)+2) = (BYTE) (dwHostFormat);
}

//
// Name: SW2HostToWireFormat16
// Description: Helper function that converts a 2 byte DWORD 
//				to a binary representation
// Author: Tom Rixom
// Created: 11 August 2004
//
VOID
SW2_HostToWireFormat16(	IN     DWORD  wHostFormat,
					IN OUT PBYTE pWireFormat )
{
    *((PBYTE)(pWireFormat)+0) = (BYTE) ((DWORD)(wHostFormat) >>  8);
    *((PBYTE)(pWireFormat)+1) = (BYTE) (wHostFormat);
}

#ifndef _WIN32_WCE
//
// Name: SW2_GetTextualSid
// Description: Helper function retreive the string representation of a SID
// Author: Tom Rixom
// Created: 11 August 2004
//
BOOL
SW2_GetTextualSid( PSID pSid,
					LPTSTR TextualSid,
					LPDWORD lpdwBufferLen )
{
    PSID_IDENTIFIER_AUTHORITY psia;
    DWORD dwSubAuthorities;
    DWORD dwSidRev=SID_REVISION;
    DWORD dwCounter;
    DWORD dwSidSize;

    // Validate the binary SID.

    if(!IsValidSid(pSid)) return FALSE;

    // Get the identifier authority value from the SID.

    psia = GetSidIdentifierAuthority(pSid);

    // Get the number of subauthorities in the SID.

    dwSubAuthorities = *GetSidSubAuthorityCount(pSid);

    // Compute the buffer length.
    // S-SID_REVISION- + IdentifierAuthority- + subauthorities- + NULL

    dwSidSize=(15 + 12 + (12 * dwSubAuthorities) + 1) * sizeof(TCHAR);

    // Check input buffer length.
    // If too small, indicate the proper size and set last error.

    if (*lpdwBufferLen < dwSidSize)
    {
        *lpdwBufferLen = dwSidSize;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    // Add 'S' prefix and revision number to the string.

    dwSidSize=wsprintf(TextualSid, TEXT("S-%lu-"), dwSidRev );

    // Add SID identifier authority to the string.

    if ( (psia->Value[0] != 0) || (psia->Value[1] != 0) )
    {
        dwSidSize+=wsprintf(TextualSid + lstrlen(TextualSid),
                    TEXT("0x%02hx%02hx%02hx%02hx%02hx%02hx"),
                    (USHORT)psia->Value[0],
                    (USHORT)psia->Value[1],
                    (USHORT)psia->Value[2],
                    (USHORT)psia->Value[3],
                    (USHORT)psia->Value[4],
                    (USHORT)psia->Value[5]);
    }
    else
    {
        dwSidSize+=wsprintf(TextualSid + lstrlen(TextualSid),
                    TEXT("%lu"),
                    (ULONG)(psia->Value[5]      )   +
                    (ULONG)(psia->Value[4] <<  8)   +
                    (ULONG)(psia->Value[3] << 16)   +
                    (ULONG)(psia->Value[2] << 24)   );
    }

    // Add SID subauthorities to the string.
    //
    for (dwCounter=0 ; dwCounter < dwSubAuthorities ; dwCounter++)
    {
        dwSidSize+=wsprintf(TextualSid + dwSidSize, TEXT("-%lu"),
                    *GetSidSubAuthority(pSid, dwCounter) );
    }

    return TRUE;
}
#endif // _WIN32_WCE
//
// Name: SW2_IsAdmin
// Description: Helper function to determine if the logged on user has Administrator
//				priviliges
// Author: Tom Rixom
// Created: 11 August 2004
//
BOOL 
SW2_IsAdmin()
{
#ifdef _WIN32_WCE
	return TRUE;
#else
	HANDLE						hHandle;
	HANDLE						hToken;
    PTOKEN_GROUPS				pTokenGroups;
    DWORD						dwTokenGroupSize;
    PSID						psidAdministrators;
    SID_IDENTIFIER_AUTHORITY	siaNtAuthority = SECURITY_NT_AUTHORITY;
	int							i;
	DWORD						dwErr;
    BOOL						bRet;

	dwTokenGroupSize = 0;

	bRet = FALSE;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_IsAdmin()") );

	if( ( hHandle = GetCurrentProcess() ) != NULL )
	{
		if( OpenProcessToken( hHandle,
							TOKEN_QUERY, 
							&hToken ) )
		{
			GetTokenInformation( hToken,
								TokenGroups,
								NULL,
								0,
								&dwTokenGroupSize );
				
			dwErr = GetLastError();

			SetLastError( dwErr );

			if( dwErr == ERROR_INSUFFICIENT_BUFFER )
			{
				if ((SW2AllocateMemory(dwTokenGroupSize, (PVOID*)&pTokenGroups))==NO_ERROR)
				{
					if( GetTokenInformation( hToken,
											TokenGroups,
											pTokenGroups,
											dwTokenGroupSize,
											&dwTokenGroupSize ) )
					{
						if( AllocateAndInitializeSid( &siaNtAuthority,
														2,
														SECURITY_BUILTIN_DOMAIN_RID,
														DOMAIN_ALIAS_RID_ADMINS,
														0, 0, 0, 0, 0, 0,
														&psidAdministrators ) )
						{
							bRet = FALSE;

							for( i=0; i < ( int ) pTokenGroups->GroupCount; i++ )
							{
								if( EqualSid( psidAdministrators, pTokenGroups->Groups[i].Sid ) )
								{            
									bRet = TRUE;

									break;
								}
							}

							FreeSid( psidAdministrators );
						}
						else
						{
							SW2Trace( SW2_TRACE_LEVEL_ERROR, 
								TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_IsAdmin()::AllocateAndInitializeSid() FAILED %ld" ), GetLastError() );
						}
					}
					else
					{
						SW2Trace( SW2_TRACE_LEVEL_ERROR, 
							TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_IsAdmin()::GetTokenInformation2() FAILED %ld" ), GetLastError() );
					}
				
					SW2FreeMemory((PVOID*)&pTokenGroups);
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
						TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_IsAdmin()::could not allocate memory for pTokenGroups" ) );
				}
			}
			else
			{
				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_IsAdmin()::GetTokenInformation() %d FAILED %d" ), dwTokenGroupSize, GetLastError() );
			}

			CloseHandle( hToken );
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_IsAdmin:: OpenThreadToken FAILED: %d" ), GetLastError() );
		}

		CloseHandle( hHandle );
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_IsAdmin:: GetCurrentThread() FAILED: %d" ), GetLastError() );
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_IsAdmin()::returning %d" ), bRet );

    return bRet;
#endif // _WIN32_WCE
}

//
// Name: SW2_KillWindow
// Description: Helper function for closing windows
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
SW2_KillWindow( IN HANDLE hTokenImpersonateUser, LPTSTR pClass, WCHAR *pwcWindowText )
{
	HWND		hWnd;
#ifndef _WIN32_WCE
    DWORD		dwThreadId; 
    HWINSTA		hwinstaSave; 
    HDESK		hdeskSave; 
    HWINSTA		hwinstaUser; 
    HDESK		hdeskUser; 
	DWORD		dwErr;
#endif // _WIN32_WCE
	DWORD		dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_KillWindow" ) );

	//
    // Ensure connection to service window station and desktop, and 
    // save their handles. 
	//

#ifndef _WIN32_WCE
    GetDesktopWindow(); 

    hwinstaSave = GetProcessWindowStation(); 
    dwThreadId = GetCurrentThreadId(); 
    hdeskSave = GetThreadDesktop( dwThreadId ); 
 
	dwErr = ImpersonateLoggedOnUser( hTokenImpersonateUser );

	if( ( hwinstaUser = OpenWindowStation( L"WinSta0", FALSE, MAXIMUM_ALLOWED ) ) )
	{
		SetProcessWindowStation( hwinstaUser ); 

		if( ( hdeskUser = OpenDesktop( L"Default", 0, FALSE, MAXIMUM_ALLOWED ) ) )
		{
			SetThreadDesktop( hdeskUser ); 
#endif // _WIN32_WCE

			//
			// Kill any dialogs we have
			//
			if( ( hWnd = FindWindow( pClass, pwcWindowText ) ) )
				EndDialog( hWnd, FALSE );

#ifndef _WIN32_WCE
			SetThreadDesktop( hdeskSave ); 
			CloseDesktop( hdeskUser ); 
		}
		else
		{
			dwReturnCode = GetLastError();

			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_KillWindow::OpenDesktop FAILED: %x" ), dwReturnCode );
		}

		SetProcessWindowStation( hwinstaSave ); 
		CloseWindowStation( hwinstaUser );
	}
	else
	{
		dwReturnCode = GetLastError();

		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_KillWindow::OpenWindowStation FAILED: %x" ), dwReturnCode );
	}
	
	if( dwErr == NO_ERROR )
		RevertToSelf();
#endif // _WIN32_WCE


	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::SW2_KillWindow::returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_CreateAdminKey
// Description: Helper function that creates a registry key with Administrator
//				read and write priviliges
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
SW2_CreateAdminKey( IN HKEY hKey, IN WCHAR *pwcSubKey, OUT HKEY *phSubKey, OUT DWORD *pdwDisposition )
{
    DWORD						dwReturnCode;
#ifndef _WIN32_WCE
    PSID						pAdminSID = NULL;
    PSID						pEveryoneSID = NULL;
    PACL						pACL = NULL;
    PSECURITY_DESCRIPTOR		pSD = NULL;
    EXPLICIT_ACCESS				ea[1];
    SID_IDENTIFIER_AUTHORITY	SIDAuthNT = SECURITY_NT_AUTHORITY;
    SECURITY_ATTRIBUTES			sa;
#endif // _WIN32_WCE

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CreateAdminKey" ) );

	dwReturnCode = NO_ERROR;

#ifndef _WIN32_WCE

	//
	// Create a SID for the BUILTIN\Administrators group.
	//
	if( AllocateAndInitializeSid( &SIDAuthNT, 
									2,
									SECURITY_BUILTIN_DOMAIN_RID,
									DOMAIN_ALIAS_RID_ADMINS,
									0, 0, 0, 0, 0, 0,
									&pAdminSID ) ) 
	{
		memset( &ea, 0, sizeof( EXPLICIT_ACCESS ) );

		//
		// Initialize an EXPLICIT_ACCESS structure for an ACE.
		// The ACE will allow the Administrators group full access to the key.
		//
		ea[0].grfAccessPermissions = KEY_ALL_ACCESS;
		ea[0].grfAccessMode = SET_ACCESS;
		ea[0].grfInheritance= NO_INHERITANCE;
		ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
		ea[0].Trustee.ptstrName  = ( LPTSTR ) pAdminSID;

		//
		// Create a new ACL that contains the new ACEs.
		//
		if( ( dwReturnCode = SetEntriesInAcl( 1, ea, NULL, &pACL ) ) == ERROR_SUCCESS )
		{
			//
			// Initialize a security descriptor.  
			//
			if ((SW2AllocateMemory(SECURITY_DESCRIPTOR_MIN_LENGTH, (PVOID*)&pSD))==NO_ERROR)
			{
				if( InitializeSecurityDescriptor( pSD, SECURITY_DESCRIPTOR_REVISION ) )
				{
					//
					// Add the ACL to the security descriptor. 
					//
					if( SetSecurityDescriptorDacl( pSD, 
													TRUE,     // bDaclPresent flag   
													pACL, 
													FALSE))   // not a default DACL 
					{  
						//
						// Initialize a security attributes structure.
						sa.nLength = sizeof (SECURITY_ATTRIBUTES);
						sa.lpSecurityDescriptor = pSD;
						sa.bInheritHandle = FALSE;
#endif // _WIN32_WCE
						//
						// Use the security attributes to set the security descriptor 
						// when you create a key.
						//
						if( RegCreateKeyEx(	hKey, 
											pwcSubKey, 
											0, 
											NULL, 
											0, 
											KEY_ALL_ACCESS, 
#ifndef _WIN32_WCE
											&sa, 
#else
											NULL,
#endif // _WIN32_WCE
											phSubKey, 
											pdwDisposition ) != ERROR_SUCCESS )
						{
							dwReturnCode = ERROR_CANTOPEN;
						}
#ifndef _WIN32_WCE
					}
					else
						dwReturnCode = ERROR_CANTOPEN;
				}
				else
				{
					dwReturnCode = ERROR_CANTOPEN;
				}
				
				SW2FreeMemory((PVOID*)&pSD);
			}
			else
			{
				dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
			}

			LocalFree( pACL );	        
		}

		FreeSid( pAdminSID );
	}

#endif // _WIN32_WCE

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CreateAdminKey::returning %ld" ), dwReturnCode );

    return dwReturnCode;
}

//
// Name: SW2_CreateSecureKey
// Description: Helper function that creates a registry key with Administrator
//				read and write priviliges and read priviliges for normal users
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
SW2_CreateSecureKey( IN HKEY hKey, IN WCHAR *pwcSubKey, OUT HKEY *phSubKey, OUT DWORD *pdwDisposition )
{
    DWORD						dwReturnCode;
#ifndef _WIN32_WCE
    PSID						pAdminSID = NULL;
    PSID						pEveryoneSID = NULL;
    PACL						pACL = NULL;
    PSECURITY_DESCRIPTOR		pSD = NULL;
    EXPLICIT_ACCESS				ea[2];
	SID_IDENTIFIER_AUTHORITY	SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY	SIDAuthNT = SECURITY_NT_AUTHORITY;
    SECURITY_ATTRIBUTES			sa;
#endif // _WIN32_WCE

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CreateSecureKey" ) );

	dwReturnCode = NO_ERROR;

#ifndef _WIN32_WCE

	//
	// Create a well-known SID for the Everyone group.
	//
	if( AllocateAndInitializeSid( &SIDAuthWorld, 
									1,
									SECURITY_WORLD_RID,
									0, 
									0, 0, 0, 0, 0, 0,
									&pEveryoneSID ) )
	{
		//
		// Create a SID for the BUILTIN\Administrators group.
		//
		if( AllocateAndInitializeSid( &SIDAuthNT, 
										2,
										SECURITY_BUILTIN_DOMAIN_RID,
										DOMAIN_ALIAS_RID_ADMINS,
										0, 0, 0, 0, 0, 0,
										&pAdminSID ) ) 
		{
			memset( &ea, 0, 2 * sizeof( EXPLICIT_ACCESS ) );

			// Initialize an EXPLICIT_ACCESS structure for an ACE.
			// The ACE will allow Everyone read access to the key.
			ea[0].grfAccessPermissions = KEY_READ;
			ea[0].grfAccessMode = SET_ACCESS;
			ea[0].grfInheritance= NO_INHERITANCE;
			ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
			ea[0].Trustee.ptstrName  = ( LPTSTR ) pEveryoneSID;

			//
			// Initialize an EXPLICIT_ACCESS structure for an ACE.
			// The ACE will allow the Administrators group full access to the key.
			//
			ea[1].grfAccessPermissions = KEY_ALL_ACCESS;
			ea[1].grfAccessMode = SET_ACCESS;
			ea[1].grfInheritance= NO_INHERITANCE;
			ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
			ea[1].Trustee.ptstrName  = ( LPTSTR ) pAdminSID;

			//
			// Create a new ACL that contains the new ACEs.
			//
			if( ( dwReturnCode = SetEntriesInAcl( 2, ea, NULL, &pACL ) ) == ERROR_SUCCESS )
			{
				//
				// Initialize a security descriptor.  
				//
				if ((SW2AllocateMemory(SECURITY_DESCRIPTOR_MIN_LENGTH, (PVOID*)&pSD))==NO_ERROR)
				{
					if( InitializeSecurityDescriptor( pSD, SECURITY_DESCRIPTOR_REVISION ) )
					{
						//
						// Add the ACL to the security descriptor. 
						//
						if( SetSecurityDescriptorDacl( pSD, 
														TRUE,     // bDaclPresent flag   
														pACL, 
														FALSE))   // not a default DACL 
						{  
							//
							// Initialize a security attributes structure.
							sa.nLength = sizeof (SECURITY_ATTRIBUTES);
							sa.lpSecurityDescriptor = pSD;
							sa.bInheritHandle = FALSE;
#endif // _WIN32_WCE
							//
							// Use the security attributes to set the security descriptor 
							// when you create a key.
							//
							if( RegCreateKeyEx(	hKey, 
												pwcSubKey, 
												0, 
												NULL, 
												0, 
												KEY_READ | KEY_WRITE, 
#ifndef _WIN32_WCE
												&sa, 
#else
												NULL,
#endif // _WIN32_WCE
												phSubKey, 
												pdwDisposition ) != ERROR_SUCCESS )
							{
								dwReturnCode = ERROR_CANTOPEN;
							}
#ifndef _WIN32_WCE
						}
						else
							dwReturnCode = ERROR_CANTOPEN;
					}
					else
					{
						dwReturnCode = ERROR_CANTOPEN;
					}
					
					SW2FreeMemory((PVOID*)&pSD);
				}
				else
				{
					dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
				}

				LocalFree( pACL );	        
			}

			FreeSid( pAdminSID );
		}

		FreeSid( pEveryoneSID );
	}

#endif // _WIN32_WCE

	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_CreateSecureKey::returning %ld" ), dwReturnCode );

    return dwReturnCode;
}

//
// Name: SW2_RegGetDWORDValue
// Description: Helper function to retrieve a DWORD from the registry
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
SW2_RegGetDWORDValue( HKEY hKey, WCHAR *pwcValue, DWORD *pdwData )
{
	DWORD	cbdwData = sizeof( DWORD );
	DWORD	dwType;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	if( RegQueryValueEx( hKey,
						pwcValue,
						0,
						&dwType,
						( PBYTE ) pdwData,
						&cbdwData ) != ERROR_SUCCESS )
	{
		SW2Trace( SW2_TRACE_LEVEL_WARNING, 
			TEXT( "SW2_TRACE_LEVEL_WARNING::SW2_RegGetDWORDValue::RegQueryValueEx(%s) FAILED: %x" ), pwcValue, GetLastError() );

		dwReturnCode = ERROR_CANTOPEN;
	}

	return dwReturnCode;
}

//
// Name: SW2_RegGetValue
// Description: Helper function to retrieve a binary from the registry
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
SW2_RegGetValue( HKEY hKey, WCHAR *pwcValue, PBYTE *ppbData, DWORD *pcbData )
{
	DWORD	dwType = 0;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	if( RegQueryValueEx( hKey,
						pwcValue,
						0,
						&dwType,
						NULL,
						pcbData ) == ERROR_SUCCESS )
	{
		if ((SW2AllocateMemory(*pcbData, (PVOID*)ppbData))==NO_ERROR)
		{
			if( RegQueryValueEx( hKey,
								pwcValue,
								0,
								&dwType,
								*ppbData,
								pcbData ) != ERROR_SUCCESS )
			{
				SW2Trace( SW2_TRACE_LEVEL_WARNING, 
					TEXT( "SW2_TRACE_LEVEL_WARNING::SW2_RegGetValue::RegQueryValueEx2(%s) FAILED: %x" ), pwcValue, GetLastError() );

				SW2FreeMemory((PVOID*)ppbData);
				*pcbData = 0;

				dwReturnCode = ERROR_CANTOPEN;
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_RegGetValue::not enough memory for ppbData" ) );

			dwReturnCode = ERROR_NOT_ENOUGH_MEMORY;
		}
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_WARNING, 
			TEXT( "SW2_TRACE_LEVEL_WARNING::SW2_RegGetValue::RegQueryValueEx(%s) FAILED: %x" ), pwcValue, GetLastError() );

		dwReturnCode = ERROR_CANTOPEN;
	}

	return dwReturnCode;
}
/*
//
// Name: SW2_SetBinRegKey
// Description: Helper function to set a binary registry key 
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
SW2_SetBinRegKey( WCHAR *pwcKey, PBYTE pbValue, DWORD cbValue )
{
	HKEY	hKey;
	DWORD	dwDisp;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	//
	// Save information in registry:
	// license key and
	// timestamp
	//
	if( RegCreateKeyEx( HKEY_LOCAL_MACHINE,
						SW2_CLIENT_REG_LOCATION,
						0,
						NULL,
						0,
						KEY_READ | KEY_WRITE,
						NULL,
						&hKey,
						&dwDisp ) == ERROR_SUCCESS )
	{
		if( RegSetValueEx( hKey,
							pwcKey,
							0,
							REG_BINARY,
							pbValue,
							cbValue ) != ERROR_SUCCESS )
		{
			dwReturnCode = ERROR_CANTOPEN;
		}

		RegCloseKey( hKey );
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_SetBinRegKey::SW2_SetRegKeys FAILED: %x" ), GetLastError() );
	}

	return dwReturnCode;
}
*/

//
// Name: SW2_StartSVC
// Description: Helper function to start a service
// Author: Tom Rixom
// Created: 14 februari 2007
//
#ifndef _WIN32_WCE
DWORD
SW2_StartSVC(IN WCHAR *pwcService, IN BOOL bAutomatic)
{
	SC_HANDLE				hSCM;
	SC_HANDLE				hService;
	SERVICE_STATUS_PROCESS	ssStart;
	DWORD					ccData;
	DWORD					dwWaitTime;
	DWORD					dwTickTime;
	DWORD					dwTickOldTime;
	DWORD					dwReturnCode = NO_ERROR;
   
	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_StartSVC: %s" ), pwcService );

	// Open the SCM database
	if( ( hSCM = OpenSCManager( NULL, NULL, SC_MANAGER_CONNECT ) ) )
	{
		// Open the specified service
		if( ( hService = OpenService( hSCM, 
								pwcService, 
								SERVICE_QUERY_STATUS 
								| SERVICE_CHANGE_CONFIG
								| SERVICE_START 
								| SERVICE_STOP ) ) )
		{
			if( bAutomatic )
			{
				if (!ChangeServiceConfig( hService, 
										SERVICE_NO_CHANGE, // service type: no change 
										SERVICE_AUTO_START,// change service start type 
										SERVICE_NO_CHANGE, // error control: no change 
										NULL,              // binary path: no change 
										NULL,              // load order group: no change 
										NULL,              // tag ID: no change 
										NULL,              // dependencies: no change 
										NULL,              // account name: no change 
										NULL,              // password: no change 
										NULL) )            // display name: no change
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
						TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_StartSVC:: Failed to set service to auto: %ld" ), GetLastError() );
				}
			}

			if( StartService( hService,
									0,
									NULL ) )
			{
				if( QueryServiceStatusEx( hService, 
										SC_STATUS_PROCESS_INFO,
										( PBYTE ) &ssStart, 
										sizeof(SERVICE_STATUS_PROCESS),
										&ccData ) )
				{
					dwTickTime = 0;

					dwTickOldTime = GetTickCount();

					while ( ( ssStart.dwCurrentState == SERVICE_START_PENDING ) 
						&& ( dwTickTime < 5000 ) ) 
					{
						dwWaitTime = ssStart.dwWaitHint;

						if ( dwWaitTime > 500 )
							dwWaitTime = 500;

						Sleep( dwWaitTime );

						if( !QueryServiceStatusEx( hService, 
													SC_STATUS_PROCESS_INFO,
													( PBYTE ) &ssStart, 
													sizeof(SERVICE_STATUS_PROCESS),
													&ccData ) )
						{
							dwReturnCode = ERROR_OPEN_FAILED;

							break;
						}

						dwTickTime = GetTickCount() - dwTickOldTime;
					}
				}
				else
				{
					dwReturnCode = ERROR_OPEN_FAILED;
				}
			}
			else
			{
				dwReturnCode = GetLastError();

				if( dwReturnCode != ERROR_SERVICE_ALREADY_RUNNING )
				{
					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
						TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_StartSVC::StartService failed: %ld" ), dwReturnCode );

					dwReturnCode = ERROR_OPEN_FAILED;
				}
				else
				{
					SW2Trace( SW2_TRACE_LEVEL_WARNING, 
						TEXT( "SW2_TRACE_LEVEL_WARNING::SW2_StartSVC::service already running" ) );
				}
			}

			CloseServiceHandle( hService );
		}
		else
			dwReturnCode = ERROR_OPEN_FAILED;

		CloseServiceHandle( hSCM );
	}
	else
		dwReturnCode = ERROR_OPEN_FAILED;

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::SW2_StartSVC:: returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

//
// Name: SW2_StopSVC
// Description: Helper function to stop a service
// Author: Tom Rixom
// Created: 14 februari 2007
//
DWORD
SW2_StopSVC( IN WCHAR *pwcService )
{
	SC_HANDLE				hSCM;
	SC_HANDLE				hService;
	SERVICE_STATUS			ssStop1;
	SERVICE_STATUS_PROCESS	ssStop2;
	DWORD					ccData;
	DWORD					dwWaitTime;
	DWORD					dwTickTime;
	DWORD					dwTickOldTime;
	DWORD					dwReturnCode = NO_ERROR;
   
	SW2Trace( SW2_TRACE_LEVEL_INFO, TEXT( "SW2_TRACE_LEVEL_INFO::SW2_StopSVC" ) );

	// Open the SCM database
	if( ( hSCM = OpenSCManager( NULL, NULL, SC_MANAGER_CONNECT ) ) )
	{
		// Open the specified service
		if( ( hService = OpenService( hSCM, 
								pwcService, 
								SERVICE_QUERY_STATUS 
								| SERVICE_START 
								| SERVICE_STOP ) ) )
		{
			if ( !ControlService( hService, 
					SERVICE_CONTROL_STOP,
					&ssStop1 ) )
			{
				dwReturnCode = GetLastError();

				if ( dwReturnCode == ERROR_SERVICE_NOT_ACTIVE )
					dwReturnCode = NO_ERROR;
			}

			if( dwReturnCode == NO_ERROR )
			{
				dwTickTime = 0;
				
				dwTickOldTime = GetTickCount();

				if( QueryServiceStatusEx( hService, 
										SC_STATUS_PROCESS_INFO,
										( PBYTE ) &ssStop2, 
										sizeof(SERVICE_STATUS_PROCESS),
										&ccData ) )
				{
					while ( ssStop2.dwCurrentState != SERVICE_STOPPED 
						&& ( dwTickTime < 5000 ) ) 
					{
						dwWaitTime = ssStop2.dwWaitHint;

						if ( dwWaitTime > 500 )
							dwWaitTime = 500;

						Sleep( dwWaitTime );

						if( !QueryServiceStatusEx( hService, 
													SC_STATUS_PROCESS_INFO,
													( PBYTE ) &ssStop2, 
													sizeof(SERVICE_STATUS_PROCESS),
													&ccData ) )
						{
							dwReturnCode = ERROR_OPEN_FAILED;

							break;
						}

						dwTickTime = GetTickCount() - dwTickOldTime;
					}
				}
			}

			CloseServiceHandle( hService );
		}
		else
			dwReturnCode = ERROR_OPEN_FAILED;

		CloseServiceHandle( hSCM );
	}
	else
		dwReturnCode = ERROR_OPEN_FAILED;

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		TEXT( "SW2_TRACE_LEVEL_INFO::SW2_StopSVC:: returning %ld" ), dwReturnCode );

	return dwReturnCode;
}

#endif _WIN32_WCE

//
// Name: SW2_SwapArray
// Description: Helper function for swapping a byte array (big/little endian)
// Author: Tom Rixom
// Created: 11 August 2004
//
VOID
SW2_SwapArray( IN BYTE *xIn, OUT BYTE *xOut, IN int xLength )
{
    int i;
    BYTE *xOutPtr;
    BYTE *xInPtr;

    xInPtr = xIn + xLength - 1;
    xOutPtr = xOut;

    for (i = 0; i < xLength; i++)
    {
        *xOutPtr++ = *xInPtr--;
    }
}

//
// Name: SW2_XorData
// Description: Helper function that xors a message using the provided key
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
SW2_XorData( PBYTE pbDataIn, DWORD cbDataIn, PBYTE pbKey, DWORD cbKey, PBYTE *ppbDataOut )
{
	PBYTE		pbDataOut;
	int			i,j;
	DWORD		dwReturnCode;

	dwReturnCode = NO_ERROR;

	if( !pbDataIn )
		return ERROR_NOT_ENOUGH_MEMORY;
	
	if ((dwReturnCode=SW2AllocateMemory(cbDataIn, (PVOID*) ppbDataOut))==NO_ERROR)
	{
		pbDataOut = *ppbDataOut;

		for( i=0,j=0; i < ( int ) cbDataIn; j++,i++ )
		{
			pbDataOut[i] = pbDataIn[i] ^ pbKey[j];

			if( ( DWORD ) j > cbKey )
				j = 0;
		}
	}

	return dwReturnCode;
}

DWORD SW2_PutXmlElementHex(IN IXMLDOMDocument2	*pXmlDoc, 
						   IN IXMLDOMNode		*pCurrentDOMNode,
						   IN PWCHAR			pwcElementName, 
						   IN DWORD				dwSizeOfElementValue,
						   IN PBYTE				pbElementValue)
{
	PWCHAR	pwcTemp;
	DWORD	dwReturnCode;

	dwReturnCode = NO_ERROR;

	if ((dwReturnCode= SW2_ByteToHex(dwSizeOfElementValue, pbElementValue, &pwcTemp))==NO_ERROR)
	{
		dwReturnCode = SW2_PutXmlElementString(
			pXmlDoc, 
			pCurrentDOMNode,
			pwcElementName, 
			pwcTemp);

		SW2FreeMemory((PVOID*)&pwcTemp);
	}

	return dwReturnCode;
}

DWORD SW2_PutXmlElementBOOL(IN IXMLDOMDocument2	*pXmlDoc, 
							IN IXMLDOMNode		*pCurrentDOMNode,
							IN PWCHAR			pwcElementName, 
							IN BOOL				bElementValue)
{
	if (bElementValue)
		return SW2_PutXmlElementString(pXmlDoc, pCurrentDOMNode, pwcElementName, L"true");
	else
		return SW2_PutXmlElementString(pXmlDoc, pCurrentDOMNode, pwcElementName, L"false");
}

DWORD SW2_PutXmlElementDWORD(IN IXMLDOMDocument2	*pXmlDoc, 
							  IN IXMLDOMNode		*pCurrentDOMNode,
							  IN PWCHAR				pwcElementName, 
							  IN DWORD				dwElementValue)
{
	CComVariant		varNodeType = NODE_ELEMENT;
	IXMLDOMNode		*pNewDOMNode = NULL;
	HRESULT			hr;
	WCHAR			pwcTemp[256];
	DWORD			dwReturnCode;

	dwReturnCode = NO_ERROR;

#ifndef _WIN32_WCE
	swprintf_s(pwcTemp, sizeof(pwcTemp), L"%ld", dwElementValue);
#else
	swprintf(pwcTemp, L"%ld", dwElementValue);
#endif // _WIN32_WCE
	if (SUCCEEDED((hr=pXmlDoc->createNode(
		varNodeType, 
		(BSTR)pwcElementName, 
		L"http://schemas.securew2.com/eapconfig/eap-ttls/v0", 
		&pNewDOMNode))))
	{
		pNewDOMNode->put_text((BSTR)pwcTemp);

		if (FAILED((hr=pCurrentDOMNode->appendChild(pNewDOMNode,NULL))))
		{
			dwReturnCode = HRESULT_CODE(hr);
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				L"SW2_TRACE_LEVEL_ERROR::SW2_PutXmlElementValue()::appendChild failed::error: %ld", 
				dwReturnCode);
		}									

		pNewDOMNode->Release();
		pNewDOMNode = NULL;
	}
	else
	{
		dwReturnCode = HRESULT_CODE(hr);
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2_PutXmlElementValue()::createNode failed::error: %ld", 
			dwReturnCode);
	}

	return dwReturnCode;
}

DWORD SW2_PutXmlElementString(IN IXMLDOMDocument2	*pXmlDoc, 
							  IN IXMLDOMNode		*pCurrentDOMNode,
							  IN PWCHAR				pwcElementName, 
							  IN PWCHAR				pwcElementValue)
{
	CComVariant		varNodeType = NODE_ELEMENT;
	IXMLDOMNode		*pNewDOMNode = NULL;
	HRESULT			hr;
	DWORD			dwReturnCode;

	dwReturnCode = NO_ERROR;

	if (SUCCEEDED((hr=pXmlDoc->createNode(
		varNodeType, 
		(BSTR)pwcElementName, 
		L"http://schemas.securew2.com/eapconfig/eap-ttls/v0", 
		&pNewDOMNode))))
	{
		if (pwcElementValue)
			pNewDOMNode->put_text((BSTR)pwcElementValue);

		if (FAILED((hr=pCurrentDOMNode->appendChild(pNewDOMNode,NULL))))
		{
			dwReturnCode = HRESULT_CODE(hr);
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				L"SW2_TRACE_LEVEL_ERROR::SW2_PutXmlElementValue()::appendChild failed::error: %ld", 
				dwReturnCode);
		}									

		pNewDOMNode->Release();
		pNewDOMNode = NULL;
	}
	else
	{
		dwReturnCode = HRESULT_CODE(hr);
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2_PutXmlElementValue()::createNode failed::error: %ld", 
			dwReturnCode);
	}

	return dwReturnCode;
}

DWORD SW2_GetXmlElementValue(IN IXMLDOMDocument2	*pXmlDoc, 
							 IN LPWSTR				pwcElementName, 
							 OUT PWCHAR				*ppwcElementValue)
{
	WCHAR		pwcInitialNodeName[] = L"//securew2:";
	DWORD		dwSizeOfInitialNodeName;
	DWORD		dwSizeOfElementName;
	DWORD		dwSizeOfFullNodeName;
    IXMLDOMNode	*pDOMNode = NULL;
    HRESULT		hr = S_OK;
    PWCHAR		pwcFullNodeName = NULL;
    VARIANT		var = {0};
    DWORD		dwReturnCode;

	dwReturnCode = NO_ERROR;

	if ((var.bstrVal = SysAllocString(L"xmlns:securew2=\"http://schemas.securew2.com/eapconfig/eap-ttls/v0\"")))
	{
		var.vt = VT_BSTR;

		if (SUCCEEDED(hr = pXmlDoc->setProperty((BSTR)L"SelectionNamespaces", var)))
		{
			//
			// Get the size of FullNodeName.
			//
			dwSizeOfInitialNodeName = (DWORD) wcslen(pwcInitialNodeName);
			dwSizeOfElementName = (DWORD) wcslen(pwcElementName);

			dwSizeOfFullNodeName = dwSizeOfInitialNodeName + dwSizeOfElementName + 1;

			//
			// Allocate memory, will be Initial + Element + 1
			//
			if ((dwReturnCode=SW2AllocateMemory(
				dwSizeOfFullNodeName*sizeof(WCHAR),
				(PVOID*)&pwcFullNodeName))==NO_ERROR)
			{
				wsprintf(pwcFullNodeName, L"%s%s", pwcInitialNodeName, pwcElementName);

				//
				// Selecting the node we are interested in.
				//
				if (SUCCEEDED(hr = pXmlDoc->selectSingleNode((BSTR)pwcFullNodeName, &pDOMNode)))
				{
					if (pDOMNode != NULL)
					{
						// 
						// Get the content of the node as BSTR, to free string call SysFreeString(pbstrElementValue);
						//
						if (FAILED(hr = pDOMNode->get_text((BSTR*)ppwcElementValue)))
						{
							dwReturnCode = HRESULT_CODE(hr);

							SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2_GetXmlElementValue()::get_text failed for Element = %s, error: %ld", 
								pwcElementName,
								dwReturnCode);
						}

						pDOMNode->Release();
						pDOMNode = NULL;
					}
					else
					{
						dwReturnCode = ERROR_NO_DATA;

						SW2Trace( SW2_TRACE_LEVEL_WARNING, 
							L"SW2_TRACE_LEVEL_WARNING::SW2_GetXmlElementValue()::no information available for Element = %s", 
							pwcElementName);
					}
				}
				else
				{
					dwReturnCode = HRESULT_CODE(hr);

					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
						L"SW2_TRACE_LEVEL_ERROR::SW2_GetXmlElementValue()::selectSingleNode failed for Element = %s, error: %ld", 
						pwcElementName,
						dwReturnCode);
				}

				SW2FreeMemory((PVOID *)&pwcFullNodeName);
			}
		}
		else
		{
			dwReturnCode = HRESULT_CODE(hr);
		}

		SysFreeString(var.bstrVal);
	}

	return dwReturnCode;
}

DWORD SW2_GetXmlElementList(IN IXMLDOMDocument2	*pXmlDoc, 
							 IN LPWSTR				pwcElementName, 
							 OUT IXMLDOMNodeList	**ppDOMList)
{
	WCHAR			pwcInitialNodeName[] = L"//securew2:";
	DWORD			dwSizeOfInitialNodeName;
	DWORD			dwSizeOfElementName;
	DWORD			dwSizeOfFullNodeName;
    IXMLDOMNode		*pDOMNode = NULL;
    HRESULT			hr = S_OK;
    PWCHAR			pwcFullNodeName = NULL;
    VARIANT			var = {0};
    DWORD			dwReturnCode;

	dwReturnCode = NO_ERROR;

	if ((var.bstrVal = SysAllocString(L"xmlns:securew2=\"http://schemas.securew2.com/eapconfig/eap-ttls/v0\"")))
	{
		var.vt = VT_BSTR;

		if (SUCCEEDED(hr = pXmlDoc->setProperty((BSTR)L"SelectionNamespaces", var)))
		{
			//
			// Get the size of FullNodeName.
			//
			dwSizeOfInitialNodeName = (DWORD) wcslen(pwcInitialNodeName);
			dwSizeOfElementName = (DWORD) wcslen(pwcElementName);

			dwSizeOfFullNodeName = dwSizeOfInitialNodeName + dwSizeOfElementName + 1;

			//
			// Allocate memory, will be Initial + Element + 1
			//
			if ((dwReturnCode=SW2AllocateMemory(
				dwSizeOfFullNodeName*sizeof(WCHAR),
				(PVOID*)&pwcFullNodeName))==NO_ERROR)
			{
				wsprintf(pwcFullNodeName, L"%s%s", pwcInitialNodeName, pwcElementName);

				//
				// Selecting the node we are interested in.
				//
				if (FAILED(hr = pXmlDoc->selectNodes((BSTR)pwcFullNodeName, ppDOMList)))
				{
					dwReturnCode = HRESULT_CODE(hr);

					SW2Trace( SW2_TRACE_LEVEL_ERROR, 
						L"SW2_TRACE_LEVEL_ERROR::SW2_GetXmlElementValue()::selectSingleNode failed for Element = %s, error: %ld", 
						pwcElementName,
						dwReturnCode);
				}

				SW2FreeMemory((PVOID *)&pwcFullNodeName);
			}
		}
		else
		{
			dwReturnCode = HRESULT_CODE(hr);
		}

		SysFreeString(var.bstrVal);
	}

	return dwReturnCode;
}

DWORD SW2_GetXmlElementNode(IN IXMLDOMDocument2	*pXmlDoc, 
							IN LPWSTR			pwcElementName, 
							OUT IXMLDOMNode		**ppDOMNode)
{
	WCHAR		pwcInitialNodeName[] = L"//securew2:";
	DWORD		dwSizeOfInitialNodeName;
	DWORD		dwSizeOfElementName;
	DWORD		dwSizeOfFullNodeName;
    IXMLDOMNode	*pDOMNode = NULL;
    HRESULT		hr = S_OK;
    PWCHAR		pwcFullNodeName = NULL;
    VARIANT		var = {0};
    DWORD		dwReturnCode;

	dwReturnCode = NO_ERROR;

	if ((var.bstrVal = SysAllocString(L"xmlns:securew2=\"http://schemas.securew2.com/eapconfig/eap-ttls/v0\"")))
	{
		var.vt = VT_BSTR;

		if (SUCCEEDED(hr = pXmlDoc->setProperty((BSTR)L"SelectionNamespaces", var)))
		{
			//
			// Get the size of FullNodeName.
			//
			dwSizeOfInitialNodeName = (DWORD) wcslen(pwcInitialNodeName);
			dwSizeOfElementName = (DWORD) wcslen(pwcElementName);

			dwSizeOfFullNodeName = dwSizeOfInitialNodeName + dwSizeOfElementName + 1;

			//
			// Allocate memory, will be Initial + Element + 1
			//
			if ((dwReturnCode=SW2AllocateMemory(
				dwSizeOfFullNodeName*sizeof(WCHAR),
				(PVOID*)&pwcFullNodeName))==NO_ERROR)
			{
				wsprintf(pwcFullNodeName, L"%s%s", pwcInitialNodeName, pwcElementName);

				//
				// Selecting the node we are interested in.
				//
				if (SUCCEEDED(hr = pXmlDoc->selectSingleNode((BSTR)pwcFullNodeName, ppDOMNode)))
				{
					if (*ppDOMNode == NULL)
					{
						dwReturnCode = ERROR_NO_DATA;

						SW2Trace( SW2_TRACE_LEVEL_WARNING, 
							L"SW2_TRACE_LEVEL_WARNING::SW2_GetXmlElementNode()::no information available for Element = %s", pwcElementName);
					}
				}
				else
				{
					dwReturnCode = HRESULT_CODE(hr);

					SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2_GetXmlElementNode()::selectSingleNode failed for Element = %s, error: %ld", 
						pwcElementName,
						dwReturnCode);
				}

				SW2FreeMemory((PVOID *)&pwcFullNodeName);
			}
		}
		else
		{
			dwReturnCode = HRESULT_CODE(hr);
		}

		SysFreeString(var.bstrVal);
	}

	return dwReturnCode;
}

DWORD SW2_ToUpperString( IN PCHAR pcBufferIn, 
						OUT PCHAR *ppcBufferOut)
{
	DWORD	dwReturnCode;
	CHAR	c;
	int		i = 0;

	dwReturnCode = NO_ERROR;

	if ((SW2AllocateMemory((DWORD)(strlen(pcBufferIn)+1), (PVOID*)ppcBufferOut))==NO_ERROR)
	{
		while( *( pcBufferIn + i ) != '\0' )
		{
			c = *( pcBufferIn + i );

			if( c >= 'a' )
			{
				c = c - 32;
			}
		
			*( *ppcBufferOut + i ) = c;

			i++;
		}

		*( *ppcBufferOut + i ) = '\0';
	}
	
	return dwReturnCode;
}

DWORD SW2_HexToByte(IN PCHAR pcBufferIn, 
					OUT DWORD *pdwSizeOfBufferOut, 
					OUT PBYTE *ppbBufferOut)
{
	int			i;
	BYTE		hiNibble, loNibble;
	PCHAR		pcTemp;
	DWORD		dwReturnCode;

	dwReturnCode = NO_ERROR;

	*pdwSizeOfBufferOut= (DWORD) strlen(pcBufferIn) / 2;

	if ((dwReturnCode = SW2AllocateMemory(*pdwSizeOfBufferOut, (PVOID*)ppbBufferOut))==NO_ERROR)
	{
		if ((dwReturnCode=SW2_ToUpperString(pcBufferIn, &pcTemp ))==NO_ERROR)
		{
			for(i = 0; (DWORD)i < *pdwSizeOfBufferOut; i++ )
			{
				if( *( pcTemp + i*2 ) >= 'A' )
				{
					hiNibble = ( BYTE ) ( * ( pcTemp + i*2 ) - 'A' + 10 );
				}
				else
				{
					hiNibble = ( BYTE ) ( * ( pcTemp + i*2 ) - '0' );
				}

				if( * ( pcTemp + i*2 + 1 ) >= 'A' )
				{
					loNibble = ( BYTE ) ( * ( pcTemp + i*2 + 1 ) - 'A' + 10 );
				}
				else
				{
					loNibble = ( BYTE ) ( * ( pcTemp + i*2 + 1 ) - '0' );
				}
				
				*( *ppbBufferOut + i ) = ( ( hiNibble << 4 ) | loNibble );
			}
			
			SW2FreeMemory((PVOID*)&pcTemp);
		}

		if (dwReturnCode != NO_ERROR)
		{
			SW2FreeMemory((PVOID*)ppbBufferOut);

			*ppbBufferOut = NULL;
			*pdwSizeOfBufferOut = 0;
		}
	}

	return dwReturnCode;
}

DWORD SW2_ByteToHex(IN DWORD	dwSizeOfBuffer,			  
					PBYTE		pbBuffer, 
					PWCHAR		*ppwcBuffer)
{
	DWORD	dwReturnCode;
	PWCHAR	pwcPtr;
	PBYTE	pbPtr;
	int		iByte, i;

	dwReturnCode = NO_ERROR;

	if ((dwReturnCode = SW2AllocateMemory(((dwSizeOfBuffer*2) + 1)*sizeof(WCHAR), (PVOID*)ppwcBuffer))==NO_ERROR)
	{
		pwcPtr = *ppwcBuffer;
		pbPtr = pbBuffer;

		for (i = 0; (DWORD)i < dwSizeOfBuffer; i++)
		{
			iByte = (*pbPtr & 0xf0) >> 4;
			*pwcPtr++ = (iByte <= 9) ? iByte + '0' : (iByte - 10) + 'A';
			iByte = (*pbPtr & 0x0f);
			*pwcPtr++ = (iByte <= 9) ? iByte + '0' : (iByte - 10) + 'A';
			pbPtr++;
		}

		*pwcPtr++ = 0;
	}

	return dwReturnCode;
}

DWORD SW2ConvertExternalErrorCode(IN DWORD dwReturnCode)
{
	switch( dwReturnCode )
	{
		case SW2_ERROR_NO_ERROR:
			dwReturnCode = NO_ERROR;
		break;
		case SW2_ERROR_INTERNAL:
			dwReturnCode = ERROR_INTERNAL_ERROR;
		break;
		case SW2_ERROR_CRYPTO:
			dwReturnCode = ERROR_ENCRYPTION_FAILED;
		break;
		case SW2_ERROR_CERTIFICATE:
			dwReturnCode = SEC_E_CERT_EXPIRED;
		break;
		case SW2_ERROR_CERTIFICATE_INVALID_SERVERNAME:
			dwReturnCode = ERROR_INVALID_DOMAINNAME;
		break;
#ifndef _WIN32_WCE
		case SW2_ERROR_CERTIFICATE_INVALID_USAGE:
			dwReturnCode = SEC_E_CERT_WRONG_USAGE;
		break;
#endif // _WIN32_WCE
		case SW2_ERROR_CERTIFICATE_INVALID_TRUST:
			dwReturnCode = CERT_E_UNTRUSTEDROOT;
		break;
		case SW2_ERROR_TLS:
			dwReturnCode = ERROR_ENCRYPTION_FAILED;
		break;
		case SW2_ERROR_AUTH_FAILED:
			dwReturnCode = ERROR_AUTHENTICATION_FAILURE;
		break;
		case SW2_ERROR_INNER_AUTH:
			dwReturnCode = ERROR_AUTHENTICATION_FAILURE;
		break;
		case SW2_ERROR_NOT_SUPPORTED:
			dwReturnCode = ERROR_NOT_SUPPORTED;
		break;
		case SW2_ERROR_CANCELLED:
			dwReturnCode = ERROR_CANCELLED;
		break;
		case SW2_ERROR_NO_DATA:
			dwReturnCode = ERROR_NO_DATA;
		break;

		default:

			dwReturnCode = ERROR_INTERNAL_DB_ERROR;

		break;
	}

	return dwReturnCode;
}

DWORD SW2LoadExternalInterface(IN HINSTANCE hInstance,
								IN PSW2_RES_CONTEXT pResContext)
{
	DWORD dwReturnCode;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		L"SW2_TRACE_LEVEL_INFO::SW2LoadExternalInterface");

	//
	// load functions pointers for gtc external interface
	//
	if (!( pResContext->pSW2Initialize = (PSW2INITIALIZE) 
#ifdef _WIN32_WCE
		GetProcAddress(hInstance, L"SW2Initialize")))
#else
		GetProcAddress(hInstance, "SW2Initialize")))
#endif // _WIN32_WCE
		dwReturnCode = ERROR_DLL_INIT_FAILED;

	if (dwReturnCode == NO_ERROR)
	{
		if(!(pResContext->pSW2Uninitialize = (PSW2UNINITIALIZE)
#ifdef _WIN32_WCE
			GetProcAddressA(hInstance, "SW2Uninitialize")))
#else
			GetProcAddress(hInstance, "SW2Uninitialize")))
#endif // _WIN32_WCE
			dwReturnCode = ERROR_DLL_INIT_FAILED;
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2LoadExternalInterface: SW2Initialize call failed");
	}

	if (dwReturnCode == NO_ERROR)
	{
		if(!(pResContext->pSW2GetIdentity = (PSW2GETIDENTITY)
#ifdef _WIN32_WCE
			GetProcAddressA( hInstance, "SW2GetIdentity")))
#else
			GetProcAddress(hInstance, "SW2GetIdentity")))
#endif // _WIN32_WCE
			dwReturnCode = ERROR_DLL_INIT_FAILED;
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2LoadExternalInterface: SW2Uninitialize call failed");
	}

	if (dwReturnCode == NO_ERROR)
	{
		if(!(pResContext->pSW2InvokeIdentityUI = (PSW2INVOKEIDENTITYUI)
#ifdef _WIN32_WCE
			GetProcAddressA(hInstance, "SW2InvokeIdentityUI")))
#else
			GetProcAddress(hInstance, "SW2InvokeIdentityUI")))
#endif // _WIN32_WCE
			dwReturnCode = ERROR_DLL_INIT_FAILED;
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2LoadExternalInterface: SW2GetIdentity call failed");
	}

	if (dwReturnCode == NO_ERROR)
	{
		if(!(pResContext->pSW2FreeIdentity = (PSW2FREEIDENTITY)
#ifdef _WIN32_WCE
			GetProcAddressA( hInstance, "SW2FreeIdentity")))
#else
			GetProcAddress(hInstance, "SW2FreeIdentity")))
#endif // _WIN32_WCE
			dwReturnCode = ERROR_DLL_INIT_FAILED;
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2LoadExternalInterface: SW2InvokeIdentityUI call failed");
	}

	if (dwReturnCode == NO_ERROR)
	{
		if(!(pResContext->pSW2GetResponse = (PSW2GETRESPONSE)
#ifdef _WIN32_WCE
			GetProcAddressA( hInstance, "SW2GetResponse")))
#else
			GetProcAddress(hInstance, "SW2GetResponse")))
#endif // _WIN32_WCE
			dwReturnCode = ERROR_DLL_INIT_FAILED;
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2LoadExternalInterface: SW2FreeIdentity call failed");
	}

	if (dwReturnCode == NO_ERROR)
	{
		if(!(pResContext->pSW2InvokeResponseUI = (PSW2INVOKERESPONSEUI)
#ifdef _WIN32_WCE
			GetProcAddressA( hInstance, "SW2InvokeResponseUI")))
#else
			GetProcAddress(hInstance, "SW2InvokeResponseUI")))
#endif // _WIN32_WCE
			dwReturnCode = ERROR_DLL_INIT_FAILED;
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2LoadExternalInterface: SW2GetResponse call failed");
	}

	if (dwReturnCode == NO_ERROR)
	{
		if(!(pResContext->pSW2FreeResponse = (PSW2FREERESPONSE)
#ifdef _WIN32_WCE
			GetProcAddressA( hInstance, "SW2FreeResponse")))
#else
			GetProcAddress(hInstance, "SW2FreeResponse")))
#endif // _WIN32_WCE
			dwReturnCode = ERROR_DLL_INIT_FAILED;
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2LoadExternalInterface: SW2InvokeResponseUI call failed");
	}

	if (dwReturnCode == NO_ERROR)
	{
		if(!(pResContext->pSW2GetCredentials = (PSW2GETCREDENTIALS)
#ifdef _WIN32_WCE
			GetProcAddressA(hInstance, "SW2GetCredentials")))
#else
			GetProcAddress(hInstance, "SW2GetCredentials")))
#endif // _WIN32_WCE
			dwReturnCode = ERROR_DLL_INIT_FAILED;
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2LoadExternalInterface: SW2FreeResponse call failed");
	}

	if (dwReturnCode == NO_ERROR)
	{
		if(!(pResContext->pSW2InvokeCredentialsUI = (PSW2INVOKECREDENTIALSUI)
#ifdef _WIN32_WCE
			GetProcAddressA(hInstance, "SW2InvokeCredentialsUI")))
#else
			GetProcAddress(hInstance, "SW2InvokeCredentialsUI")))
#endif // _WIN32_WCE
			dwReturnCode = ERROR_DLL_INIT_FAILED;
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2LoadExternalInterface: SW2GetCredentials call failed");
	}

	if (dwReturnCode == NO_ERROR)
	{
		if(!(pResContext->pSW2FreeCredentials = (PSW2FREECREDENTIALS)
#ifdef _WIN32_WCE
			GetProcAddressA(hInstance, "SW2FreeCredentials")))
#else
			GetProcAddress(hInstance, "SW2FreeCredentials")))
#endif // _WIN32_WCE
			dwReturnCode = ERROR_DLL_INIT_FAILED;
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2LoadExternalInterface: SW2InvokeCredentialsUI call failed");
	}

	if (dwReturnCode == NO_ERROR)
	{
		if(!(pResContext->pSW2HandleResult= (PSW2HANDLERESULT)
#ifdef _WIN32_WCE
			GetProcAddressA(hInstance, "SW2HandleResult")))
#else
			GetProcAddress(hInstance, "SW2HandleResult")))
#endif // _WIN32_WCE
			dwReturnCode = ERROR_DLL_INIT_FAILED;
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2LoadExternalInterface: SW2FreeCredentials call failed");
	}

	if (dwReturnCode == NO_ERROR)
	{
		if(!(pResContext->pSW2HandleError= (PSW2HANDLEERROR)
#ifdef _WIN32_WCE
			GetProcAddressA(hInstance, "SW2HandleError")))
#else
			GetProcAddress(hInstance, "SW2HandleError")))
#endif // _WIN32_WCE
			dwReturnCode = ERROR_DLL_INIT_FAILED;
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2LoadExternalInterface: SW2HandleResult call failed");
	}

	if (dwReturnCode == NO_ERROR)
	{
		if(!(pResContext->pSW2HandleInteractiveError= (PSW2HANDLEINTERACTIVEERROR)
#ifdef _WIN32_WCE
			GetProcAddressA(hInstance, "SW2HandleInteractiveError")))
#else
			GetProcAddress(hInstance, "SW2HandleInteractiveError")))
#endif // _WIN32_WCE
			dwReturnCode = ERROR_DLL_INIT_FAILED;
	}
	else
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2LoadExternalInterface: SW2HandleError call failed");
	}

	if (dwReturnCode != NO_ERROR)
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, 
			L"SW2_TRACE_LEVEL_ERROR::SW2LoadExternalInterface: SW2HandleInteractiveError call failed");		
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2LoadExternalInterface::returning %ld", dwReturnCode);		

	return dwReturnCode;
}

DWORD SW2CopyRegistryKey(IN HKEY hDst, IN HKEY hSrc)
{
	DWORD	dwReturnCode;
	DWORD	dwErr;
	DWORD	dwI = 0;
	WCHAR	pwcValue[MAX_PATH*2];
	DWORD	cwcValue;
	BYTE	pbData[MAX_PATH*2];
	DWORD	cbData;
	DWORD	dwType;

	dwReturnCode = NO_ERROR;

	//
	// Copy information
	//
	dwErr = ERROR_SUCCESS;

	for( dwI = 0; dwErr == ERROR_SUCCESS; dwI++) 
	{ 
		cwcValue = sizeof( pwcValue );
		cbData = sizeof( pbData );

		if ( ( dwErr = RegEnumValue(hSrc, 
									dwI, 
									pwcValue,
									&cwcValue, 
									NULL, 
									&dwType, 
									pbData, 
									&cbData ) )  == ERROR_SUCCESS )
		{
			dwErr = RegSetValueEx(hDst,
								pwcValue,
								0,
								dwType,
								pbData,
								cbData);
		}
	} // for

	return dwReturnCode;
}

DWORD SW2BackupEapMethod(IN BYTE EAPTYPE)
{
	HKEY	hDstEapMethodKey;
	HKEY	hSrcEapMethodKey;
	WCHAR	pwcTemp[MAX_PATH];
	WCHAR	pwcTemp2[MAX_PATH];
	DWORD	cwcTemp2;
	DWORD	dwType;
	DWORD	dwReturnCode;
	DWORD	dwDisp = 0;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2BackupEapMethod");		

#ifndef _WIN32_WCE
	swprintf_s(pwcTemp, sizeof(pwcTemp)/sizeof(WCHAR), 
		L"System\\CurrentControlSet\\Services\\RasMan\\PPP\\EAP\\%d", EAPTYPE);
#else
	swprintf(pwcTemp, 
		L"System\\CurrentControlSet\\Services\\RasMan\\PPP\\EAP\\%d", EAPTYPE);
#endif // _WIN32_WCE

	if ((dwReturnCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
										pwcTemp, 
										0, 
										KEY_ALL_ACCESS, 
										&hSrcEapMethodKey )) == NO_ERROR)
	{
		cwcTemp2 = sizeof( pwcTemp2 );

		memset( pwcTemp2, 0, sizeof( pwcTemp2 ) );

		// read 
		if (RegQueryValueEx( hSrcEapMethodKey,
							L"Path",
							0,
							&dwType,
							(PBYTE) pwcTemp2,
							&cwcTemp2 ) == ERROR_SUCCESS )
		{
			if (wcsstr(pwcTemp2, L"sw2_") != NULL)
				dwReturnCode = ERROR_INVALID_DATA;
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_ERROR, 
				TEXT( "SW2_TRACE_LEVEL_ERROR::SW2_UnregisterRASEAPDLL::RegQueryValueEx(Path) FAILED: %ld" ), 
				dwReturnCode );

			dwReturnCode = ERROR_CANTOPEN;
		}

		if (dwReturnCode == NO_ERROR)
		{
			memset(pwcTemp, 0, sizeof(pwcTemp));

#ifndef _WIN32_WCE
			swprintf_s( pwcTemp, sizeof(pwcTemp)/sizeof(WCHAR),
				TEXT( "Software\\SecureW2\\StoredMethods\\%d"), 
				EAPTYPE );
#else
			swprintf( pwcTemp,
				TEXT( "Software\\SecureW2\\StoredMethods\\%d"), 
				EAPTYPE );
#endif // _WIN32_WCE

			if ((dwReturnCode = RegCreateKeyExW(HKEY_LOCAL_MACHINE, 
												pwcTemp, 
												0, NULL, 
												REG_OPTION_NON_VOLATILE,
												KEY_ALL_ACCESS, 
												NULL, 
												&hDstEapMethodKey, 
												&dwDisp))==NO_ERROR)
			{
				if (dwDisp == REG_CREATED_NEW_KEY)
				{
					dwReturnCode = SW2CopyRegistryKey(hDstEapMethodKey, hSrcEapMethodKey);

					RegCloseKey(hDstEapMethodKey);
				}
			}
		}
		else
		{
			SW2Trace( SW2_TRACE_LEVEL_WARNING, 
				TEXT( "SW2_TRACE_LEVEL_WARNING::SW2BackupEapMethod::Registred method is already a SecureW2 Eap Method" ) );

			// not a SecureW2 method, so discard error
			dwReturnCode = NO_ERROR;
		}

		RegCloseKey(hSrcEapMethodKey);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, 
		L"SW2_TRACE_LEVEL_INFO::SW2BackupEapMethod::returning %ld", dwReturnCode);	

	return dwReturnCode;
}

DWORD SW2RestoreEapMethod(IN BYTE EAPTYPE)
{
	HKEY	hDstEapMethodKey;
	HKEY	hSrcEapMethodKey;
	HKEY	hStoredMethodsKey;
	WCHAR	pwcTemp[MAX_PATH];
	DWORD	dwReturnCode;
	DWORD	dwDisp = 0;

	dwReturnCode = NO_ERROR;

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2RestoreEapMethod");		

#ifndef _WIN32_WCE
	swprintf_s(pwcTemp, sizeof(pwcTemp)/sizeof(WCHAR), 
		L"System\\CurrentControlSet\\Services\\RasMan\\PPP\\EAP\\%d", EAPTYPE);
#else
	swprintf(pwcTemp, 
		L"System\\CurrentControlSet\\Services\\RasMan\\PPP\\EAP\\%d", EAPTYPE);
#endif // _WIN32_WCE

	if ((dwReturnCode = RegCreateKeyExW(HKEY_LOCAL_MACHINE, 
										pwcTemp, 
										0, NULL, 
										REG_OPTION_NON_VOLATILE,
										KEY_ALL_ACCESS, 
										NULL, 
										&hDstEapMethodKey, 
										&dwDisp))==NO_ERROR)
	{
		// if we find a existing key then we skip copying
		if (dwDisp & REG_CREATED_NEW_KEY)
		{			
			// open key used to store old methods
			if ((dwReturnCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
												L"Software\\SecureW2\\StoredMethods", 
												0, 
												KEY_ALL_ACCESS, 
												&hStoredMethodsKey))==NO_ERROR)
			{
				memset(pwcTemp, 0, sizeof(pwcTemp));

#ifndef _WIN32_WCE

				swprintf_s( pwcTemp, sizeof(pwcTemp)/sizeof(WCHAR),
					TEXT( "%d"), 
					EAPTYPE );
#else
				swprintf( pwcTemp,
					TEXT( "%d"), 
					EAPTYPE );
#endif // _WIN32_WCE

				// try and find previous configuration
				if ((dwReturnCode = RegOpenKeyEx(hStoredMethodsKey, 
												pwcTemp, 
												0, 
												KEY_ALL_ACCESS, 
												&hSrcEapMethodKey))==NO_ERROR)
				{
					// copy previous configuration back
					dwReturnCode = SW2CopyRegistryKey(hDstEapMethodKey, hSrcEapMethodKey);

					RegCloseKey(hSrcEapMethodKey);
				}

				// delete the old configuration
				if (dwReturnCode == NO_ERROR)
					dwReturnCode = RegDeleteKey(hStoredMethodsKey, pwcTemp);

				RegCloseKey(hStoredMethodsKey);
			}
			else
			{
				dwReturnCode = ERROR_INVALID_DATA;

				SW2Trace( SW2_TRACE_LEVEL_ERROR, 
					L"SW2_TRACE_LEVEL_ERROR::SW2RestoreEapMethod:: EAP key already exists");		
			}
		}

		RegCloseKey(hDstEapMethodKey);
	}

	SW2Trace( SW2_TRACE_LEVEL_INFO, L"SW2_TRACE_LEVEL_INFO::SW2RestoreEapMethod::returning %ld", dwReturnCode);	

	return dwReturnCode;
}