/*
    ArnesLink, Copyright 1991-2015 Amebis
    SecureW2, Copyright (C) SecureW2 B.V.

    ArnesLink is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ArnesLink is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ArnesLink. If not, see <http://www.gnu.org/licenses/>.
*/

#include "stdafx.h"

static HANDLE g_hHeap = NULL;
AL::Heap::CHeap AL::Heap::g_heap;
ATL::CParanoidHeap<AL::Heap::CHeap> AL::Heap::g_heapParanoid;
ATL::CAtlStringMgr AL::Heap::g_stringMgrParanoid(&AL::Heap::g_heapParanoid);


DWORD AL::Heap::Init()
{
    // Sanity check
    if (g_hHeap) {
        AL_TRACE_WARNING(_T("Heap is initialized already."));
        return NO_ERROR;
    }

    g_hHeap = HeapCreate(
        0,  // Serialize access to the heap
        1,   // Create a 0-byte heap; allocations will increase it, as necessary.
        0);  // Heap is growable; limited only by available memory
    if (!g_hHeap) {
        DWORD dwReturnCode = GetLastError();
        AL_TRACE_ERROR(_T("Heap creation failed (%ld)."), dwReturnCode);
        return dwReturnCode;
    }

    return NO_ERROR;
}


DWORD AL::Heap::Done()
{
    // Sanity check
    if (!g_hHeap) {
        AL_TRACE_WARNING(_T("Trying to uninitialize heap that has not been initialized."));
        return NO_ERROR;
    }

    // Free the heap.
    if (!HeapDestroy(g_hHeap)) {
        DWORD dwReturnCode = GetLastError();
        AL_TRACE_ERROR(_T("Heap destruction failed (%ld)."), dwReturnCode);
        return dwReturnCode;
    }

    // Reinitialize the heap handle.
    g_hHeap = NULL;
    return NO_ERROR;
}


DWORD AL::Heap::Alloc(_In_ SIZE_T nSize, _Out_bytecap_(nSize) LPVOID *ppBuffer)
{
    // Sanity check
    if (ppBuffer == NULL) {
        AL_TRACE_ERROR(_T("ppBuffer is NULL."));
        return ERROR_INVALID_PARAMETER;
    }

    if (!g_hHeap) {
        AL_TRACE_ERROR(_T("Uninitialized heap."));
        *ppBuffer = NULL; // Return NULL handle, to raise a NULL pointer exception in case calee won't check the return code.
        return ERROR_INVALID_HANDLE;
    }

    // Allocate a new memory block on the heap.
    // !!!IMPORTANT!!! Use HEAP_ZERO_MEMORY to initialize the memory block to zeros,
    // since a lot of code assumes this function returns zeroed memory block.
    *ppBuffer = (LPBYTE)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, nSize);
    if (*ppBuffer == NULL) {
        AL_TRACE_ERROR(_T("!!! Error allocating %ldB of memory !!!"), nSize);
        return ERROR_OUTOFMEMORY;
    }

    return NO_ERROR;
}


DWORD AL::Heap::Realloc(_In_ SIZE_T nNewSize, _Inout_bytecap_(nNewSize) LPVOID *ppBuffer)
{
    // Sanity check
    if (ppBuffer == NULL) {
        AL_TRACE_ERROR(_T("ppBuffer is NULL."));
        return ERROR_INVALID_PARAMETER;
    }

    if (!g_hHeap) {
        AL_TRACE_ERROR(_T("Uninitialized heap."));
        *ppBuffer = NULL; // Return NULL handle, to raise a NULL pointer exception in case calee won't check the return code.
        return ERROR_INVALID_HANDLE;
    }

    // Reallocate the memory block on the heap.
    // !!!IMPORTANT!!! Use HEAP_ZERO_MEMORY to initialize the new data to zeros,
    // since a lot of code assumes this function returns zeroed memory block.
    LPVOID pNewBuffer = HeapReAlloc(g_hHeap, HEAP_ZERO_MEMORY, *ppBuffer, nNewSize);
    if (pNewBuffer == NULL) {
        AL_TRACE_ERROR(_T("!!! Error reallocating %ldB of memory !!!"), nNewSize);
        return ERROR_OUTOFMEMORY;
    }

    *ppBuffer = pNewBuffer;
    return NO_ERROR;
}


DWORD AL::Heap::GetSize(_In_ LPCVOID pBuffer, _Out_ SIZE_T *pnSize)
{
    // Sanity check
    if (pBuffer == NULL) {
        AL_TRACE_ERROR(_T("pBuffer is NULL."));
        return ERROR_INVALID_PARAMETER;
    }

    if (pnSize == NULL) {
        AL_TRACE_ERROR(_T("pnSize is NULL."));
        return ERROR_INVALID_PARAMETER;
    }

    if (!g_hHeap) {
        AL_TRACE_ERROR(_T("Uninitialized heap."));
        return ERROR_INVALID_HANDLE;
    }

    *pnSize = HeapSize(g_hHeap, 0, pBuffer);
    if (*pnSize == (SIZE_T)-1) {
        *pnSize = 0;
        AL_TRACE_ERROR(_T("!!! Error getting memory size !!!"));
        return ERROR_OUTOFMEMORY;
    }

    return NO_ERROR;
}


DWORD AL::Heap::Free(_Inout_ LPVOID *ppBuffer)
{
    // Sanity check
    if (ppBuffer == NULL) {
        AL_TRACE_ERROR(_T("ppBuffer is NULL."));
        return ERROR_INVALID_PARAMETER;
    }

    if (!g_hHeap) {
        AL_TRACE_ERROR(_T("Uninitialized heap."));
        return ERROR_INVALID_HANDLE;
    }

    if (*ppBuffer == NULL) {
        // Don't try to free NULL pointers. Ignore this silently.
        AL_TRACE_WARNING(_T("Ignoring NULL pointer free attempt."));
        return NO_ERROR;
    }

    if (!HeapFree(g_hHeap, 0, *ppBuffer)) {
        DWORD dwReturnCode = GetLastError();
        AL_TRACE_ERROR(_T("Error freeing memory (%ld)."), dwReturnCode);
        return dwReturnCode;
    }

    // Re-initialize the buffer pointer.
    *ppBuffer = NULL;
    return NO_ERROR;
}


_Ret_opt_bytecap_(nBytes) void* AL::Heap::CHeap::Allocate(_In_ size_t nBytes) throw()
{
    return HeapAlloc(g_hHeap, 0, nBytes);
}


void AL::Heap::CHeap::Free(_In_opt_ void* p) throw()
{
    HeapFree(g_hHeap, 0, p);
}


_Ret_opt_bytecap_(nBytes) void* AL::Heap::CHeap::Reallocate(_In_opt_ void* p, _In_ size_t nBytes) throw()
{
    return HeapReAlloc(g_hHeap, 0, p, nBytes);
}


size_t AL::Heap::CHeap::GetSize(_In_ void* p) throw()
{
    return HeapSize(g_hHeap, 0, p);
}
