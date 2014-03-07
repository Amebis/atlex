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
// Initialize the memory heap used throughout the SecureW2 EAP modules
//
DWORD
SW2InitializeHeap(
)
{
	DWORD dwReturnCode = ERROR_SUCCESS;

	g_localHeap = NULL;   // Make sure the global value is initialized.

	g_localHeap = HeapCreate(	0,  // Serialize access to the heap
								1,   // Create a 0-byte heap; allocations will increase it, as necessary.
								0);  // Heap is growable; limited only by available memory
	if (! g_localHeap)
	{
		dwReturnCode = GetLastError();
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2InitializeHeap()::Heap creation failed -- hit error %d!", dwReturnCode);
	}

	return dwReturnCode;
}

//
// De-Initialize the memory heap
//

DWORD
SW2DeInitializeHeap(
)
{
	DWORD dwReturnCode = ERROR_SUCCESS;
	BOOL  fOk   = TRUE;

	// Sanity check.
	if (! g_localHeap)
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2DeInitializeHeap()::Heap has not been created yet; exiting.");
		goto LDone;
	}   

	// Free the heap.
	fOk = HeapDestroy(g_localHeap);
	if (! fOk)
	{
		dwReturnCode = GetLastError();
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2DeInitializeHeap()::Heap destruction failed -- hit error %d!", dwReturnCode);
		goto LDone;
	}

	// Reinitialize the heap handle.
	g_localHeap = NULL;

LDone:

	return dwReturnCode;
}

//
// Allocate memory from the memory heap
//
DWORD
SW2AllocateMemory(
    IN     DWORD sizeInBytes,
    IN OUT PVOID *ppBuffer
)
{
	DWORD dwErr   = ERROR_SUCCESS;

	// Sanity checks.
	if (ppBuffer == NULL)
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2AllocateMemory()::Invalid buffer pointer passed in!");
		dwErr = ERROR_INVALID_PARAMETER;
		goto LDone;
	}

	if (!g_localHeap)
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2AllocateMemory()::Heap has not been created yet!");
		dwErr = ERROR_INVALID_HANDLE;
		goto LDone;
	}   

	// Allocate a new memory block on the heap.  Use HEAP_ZERO_MEMORY to
	// initialize the memory block, so callers don't have to do so.
	*ppBuffer = (PBYTE)HeapAlloc(g_localHeap, HEAP_ZERO_MEMORY, sizeInBytes);
	if (*ppBuffer == NULL)
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2AllocateMemory()::Not enough memory");
		dwErr = ERROR_OUTOFMEMORY;
		goto LDone;
	}

LDone:

	return dwErr;
}

//
// Free memory allocated by this module
//
DWORD
SW2FreeMemory(
    IN OUT PVOID *ppBuffer
)
{
	DWORD dwReturnCode = ERROR_SUCCESS;
	BOOL  fOk   = TRUE;

	// Sanity checks.
	if (ppBuffer == NULL)
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2FreeMemory()::Invalid buffer pointer passed in!");
		dwReturnCode = ERROR_INVALID_PARAMETER;
		goto LDone;
	}

	if (! g_localHeap)
	{
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2FreeMemory()::Heap has not been created yet!");
		dwReturnCode = ERROR_INVALID_HANDLE;
		goto LDone;
	}   

	// Don't try to free NULL pointers.
	if (*ppBuffer == NULL)
	{
		SW2Trace( SW2_TRACE_LEVEL_WARNING, L"SW2_TRACE_LEVEL_WARNING::SW2FreeMemory()::NULL pointer, skipping");

		// Ignore this silently.
		goto LDone;
	}

	fOk = HeapFree(g_localHeap, 0, *ppBuffer);
	if (! fOk)
	{
		dwReturnCode = GetLastError();
		SW2Trace( SW2_TRACE_LEVEL_ERROR, L"SW2_TRACE_LEVEL_ERROR::SW2FreeMemory()::Error %d while freeing memory!", dwReturnCode);
		goto LDone;
	}

	// Re-initialize the buffer pointer.
	*ppBuffer = NULL;

LDone:

	return dwReturnCode;
}