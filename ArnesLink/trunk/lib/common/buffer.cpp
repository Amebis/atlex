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


#define BASE64_PADDING  ((CHAR)'=')


//
// Local data
//

static LPCSTR s_pszBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const BYTE s_aUnBase64[] = {
/*           0    1    2    3    4    5    6    7    8    9    A    B    C    D    E    F  */
/* 0 */    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
/* 1 */    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
/* 2 */    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  62, 255, 255, 255,  63,
/* 3 */     52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255, 255,  64, 255, 255,
/* 4 */    255,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
/* 5 */     15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,
/* 6 */    255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
/* 7 */     41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51, 255, 255, 255, 255, 255,
/* 8 */    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
/* 9 */    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
/* A */    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
/* B */    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
/* C */    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
/* D */    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
/* E */    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
/* F */    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
};


//
// Local function declaration
//

template <class T> inline static VOID _Base64Encode(_In_count_c_(3) LPCBYTE pDataIn, _Out_cap_c_(4) T *pDataOut);
template <class T> inline static VOID _Base64Encode(_In_count_(nDataInLen) LPCBYTE pDataIn, _In_ SIZE_T nDataInLen, _Out_cap_c_(4) T *pDataOut);
inline static SIZE_T _Base64Decode(_In_count_c_(4) LPCBYTE pDataIn, _Out_cap_c_(3) LPBYTE pDataOut);


VOID AL::Buffer::Swap(_In_bytecount_(nSize) LPCVOID pDataIn, _Out_bytecap_(nSize) LPVOID pDataOut, _In_ SIZE_T nSize)
{
    LPCBYTE pbIn = (LPCBYTE)pDataIn + nSize;
    LPBYTE pbOut = (LPBYTE)pDataOut;

    while (pDataIn < pbIn)
        *(pbOut++) = *(--pbIn);
}


VOID AL::Buffer::Swap(_Inout_bytecount_(nSize) LPVOID pData, _In_ SIZE_T nSize)
{
    for (LPBYTE pbLeft = (LPBYTE)pData, pbRight = (LPBYTE)pData + nSize; pbLeft < --pbRight; pbLeft++) {
        BYTE b = *pbLeft;
        *pbLeft = *pbRight;
        *pbRight = b;
    }
}


VOID AL::Buffer::XORData(_In_bytecount_(nSize) LPCVOID pDataIn, _Out_bytecap_(nSize) LPVOID pDataOut, _In_ SIZE_T nSize, _In_bytecount_(nKeySize) LPCVOID pKey, _In_ SIZE_T nKeySize)
{
    LPCBYTE
        pbIn     = (LPCBYTE)pDataIn,
        pbInEnd  = (LPCBYTE)pDataIn + nSize,
        pbKey    = (LPCBYTE)pKey,
        pbKeyEnd = (LPCBYTE)pKey + nKeySize;
    LPBYTE
        pbOut = (LPBYTE)pDataOut;

    while (pbIn < pbInEnd) {
        *(pbOut++) = *(pbIn++) ^ *(pbKey++);
        if (pbKey > pbKeyEnd) pbKey = (LPCBYTE)pKey;
    }
}


VOID AL::Buffer::XORData(_Inout_bytecount_(nSize) LPVOID pData, _In_ SIZE_T nSize, _In_bytecount_(nKeySize) LPCVOID pKey, _In_ SIZE_T nKeySize)
{
    LPBYTE
        pbData    = (LPBYTE)pData;
    LPCBYTE
        pbDataEnd = (LPCBYTE)pData + nSize,
        pbKey     = (LPCBYTE)pKey,
        pbKeyEnd  = (LPCBYTE)pKey + nKeySize;

    while (pbData < pbDataEnd) {
        *(pbData++) ^= *(pbKey++);
        if (pbKey > pbKeyEnd) pbKey = (LPCBYTE)pKey;
    }
}


VOID AL::Buffer::CommandLine::Encode(_In_z_ LPCWSTR pszBufferIn, _Out_ ATL::CAtlStringW &sValue)
{
    int nLen = 0;

    //
    // Count the number of output characters required to store encoded string.
    //
    for (SIZE_T i = 0; pszBufferIn[i]; i++) {
        WORD c = (WORD)(pszBufferIn[i]);
        nLen += c < L' ' || c == L'%' || c == L'"' ? 3 : 1;
    }

    //
    // Allocate memory for output string.
    //
    LPWSTR pszBufferOut = sValue.GetBuffer(nLen);
    if (!pszBufferOut) AtlThrow(E_OUTOFMEMORY);

    //
    // Encode input string.
    //
    for (SIZE_T i = 0, j = 0; pszBufferIn[i]; i++) {
        WORD c = (WORD)(pszBufferIn[i]);
        if (c < L' ' || c == L'%' || c == L'"') {
            WORD x;
                                 pszBufferOut[j++] = L'%';
            x = (c >> 4) & 0x0f; pszBufferOut[j++] = x < 10 ? L'0' + x : L'a' + x - 10;
            x = (c     ) & 0x0f; pszBufferOut[j++] = x < 10 ? L'0' + x : L'a' + x - 10;
        } else
            pszBufferOut[j++] = c;
    }

    sValue.ReleaseBuffer(nLen);
}


VOID AL::Buffer::CommandLine::Decode(_In_z_ LPCWSTR pszBufferIn, _Out_ ATL::CAtlStringW &sValue)
{
    //
    // Allocate memory for output string.
    //
    LPWSTR pszBufferOut = sValue.GetBuffer((int)wcslen(pszBufferIn));
    if (!pszBufferOut) AtlThrow(E_OUTOFMEMORY);

    //
    // Decode input string.
    //
    int j = 0;
    for (SIZE_T i = 0; pszBufferIn[i];) {
        if (pszBufferIn[i] == L'%') {
            //
            // Skip the "%" character.
            //
            i++;

            //
            // Parse hexadecimal stored ASCII code.
            //
            WORD x;
                 if (L'0' <= pszBufferIn[i] && pszBufferIn[i] <= L'9') x =            (pszBufferIn[i++] - L'0'     );
            else if (L'a' <= pszBufferIn[i] && pszBufferIn[i] <= L'f') x =            (pszBufferIn[i++] - L'a' + 10);
            else if (L'A' <= pszBufferIn[i] && pszBufferIn[i] <= L'F') x =            (pszBufferIn[i++] - L'A' + 10);
            else break;
                 if (L'0' <= pszBufferIn[i] && pszBufferIn[i] <= L'9') x = (x << 4) | (pszBufferIn[i++] - L'0'     );
            else if (L'a' <= pszBufferIn[i] && pszBufferIn[i] <= L'f') x = (x << 4) | (pszBufferIn[i++] - L'a' + 10);
            else if (L'A' <= pszBufferIn[i] && pszBufferIn[i] <= L'F') x = (x << 4) | (pszBufferIn[i++] - L'A' + 10);
            else break;

            //
            // Store the character.
            //
            pszBufferOut[j++] = x;
        } else
            pszBufferOut[j++] = pszBufferIn[i++];
    }
    sValue.ReleaseBuffer(j);
}


AL::Buffer::Base64::CEncoder::CEncoder() : m_nCount(0)
{
}


VOID AL::Buffer::Base64::CEncoder::Encode(_In_bytecount_(nDataInSize) LPCVOID pDataIn, _In_ SIZE_T nDataInSize, _Out_ ATL::CAtlString &sValue, _In_opt_ BOOL bLast)
{
    //
    // Estimate maximum output size and allocate memory for output string.
    //
    LPTSTR pszDataOut = sValue.GetBuffer((int)((m_nCount + nDataInSize + 2)/3) * 4);
    if (!pszDataOut) AtlThrow(E_OUTOFMEMORY);

    SIZE_T i = 0;
    int j = 0;
    for (;;) {
        if (m_nCount >= 3) {
            // Internal state is full enough.
            _Base64Encode(m_pbData, pszDataOut + j);
            m_nCount = 0;
            j += 4;
        }

        if (i >= nDataInSize) {
            // Out of input data.
            break;
        }

        m_pbData[m_nCount++] = ((LPCBYTE)pDataIn)[i++];
    }

    if (bLast && m_nCount) {
        // This is the last block => flush internal state.
        _Base64Encode(m_pbData, m_nCount, pszDataOut + j);
        m_nCount = 0;
        j += 4;
    }

    sValue.ReleaseBuffer(j);
    sValue.FreeExtra();
}


AL::Buffer::Base64::CDecoder::CDecoder() : m_nCount(0)
{
}


VOID AL::Buffer::Base64::CDecoder::Decode(_In_z_ LPCSTR pszDataIn, _Out_ ATL::CAtlArray<BYTE> &aValue, _Out_opt_ BOOL *pbLast)
{
    //
    // Estimate maximum output size and allocate buffer.
    //
    if (!aValue.SetCount(((m_nCount + strlen(pszDataIn) + 3)/4)*3)) AtlThrow(E_OUTOFMEMORY);
    LPBYTE pDataOut = aValue.GetData();

    SIZE_T i = 0, j = 0;
    for (;;) {
        if (m_nCount >= 4) {
            // Internal state is full enough.
            SIZE_T nLen = _Base64Decode(m_pbData, pDataOut + j);
            j += nLen;
            m_nCount = 0;
            if (nLen < 3) {
                if (pbLast) *pbLast = TRUE;
                break;
            }
        }

        if (!pszDataIn[i]) {
            // Out of input data.
            if (pbLast) *pbLast = FALSE;
            break;
        }

        if ((UINT)pszDataIn[i] < 0x100 && (m_pbData[m_nCount] = s_aUnBase64[(UINT)pszDataIn[i]]) != 255) {
            // Input was a valid Base64 char.
            m_nCount++;
        }
        i++;
    }

    //
    // Update final length.
    //
    aValue.SetCount(j);
}


VOID AL::Buffer::Base64::CDecoder::Decode(_In_z_ LPCWSTR pszDataIn, _Out_ ATL::CAtlArray<BYTE> &aValue, _Out_opt_ BOOL *pbLast)
{
    //
    // Estimate maximum output size and allocate buffer.
    //
    if (!aValue.SetCount(((m_nCount + wcslen(pszDataIn) + 3)/4)*3)) AtlThrow(E_OUTOFMEMORY);
    LPBYTE pDataOut = aValue.GetData();

    SIZE_T i = 0, j = 0;
    for (;;) {
        if (m_nCount >= 4) {
            // Internal state is full enough.
            SIZE_T nLen = _Base64Decode(m_pbData, pDataOut + j);
            j += nLen;
            m_nCount = 0;
            if (nLen < 3) {
                if (pbLast) *pbLast = TRUE;
                break;
            }
        }

        if (!pszDataIn[i]) {
            // Out of input data.
            if (pbLast) *pbLast = FALSE;
            break;
        }

        if ((UINT)pszDataIn[i] < 0x100 && (m_pbData[m_nCount] = s_aUnBase64[(UINT)pszDataIn[i]]) != 255) {
            // Input was a valid Base64 char.
            m_nCount++;
        }
        i++;
    }

    //
    // Update final length.
    //
    aValue.SetCount(j);
}


//
// Local functions
//
template <class T> inline static VOID _Base64Encode(_In_count_c_(3) LPCBYTE pDataIn, _Out_cap_c_(4) T *pDataOut)
{
    pDataOut[0] = s_pszBase64[                      pDataIn[0] >> 2         ];
    pDataOut[1] = s_pszBase64[((pDataIn[0] << 4) | (pDataIn[1] >> 4)) & 0x3f];
    pDataOut[2] = s_pszBase64[((pDataIn[1] << 2) | (pDataIn[2] >> 6)) & 0x3f];
    pDataOut[3] = s_pszBase64[                      pDataIn[2]        & 0x3f];
}


template <class T> inline static VOID _Base64Encode(_In_count_(nDataInLen) LPCBYTE pDataIn, _In_ SIZE_T nDataInLen, _Out_cap_c_(4) T *pDataOut)
{
    if (nDataInLen > 0) {
        pDataOut[0] = s_pszBase64[pDataIn[0] >> 2];
        if (nDataInLen>1) {
            pDataOut[1] = s_pszBase64[((pDataIn[0] << 4) | (pDataIn[1] >> 4)) & 0x3f];
            if (nDataInLen > 2) {
                pDataOut[2] = s_pszBase64[((pDataIn[1] << 2) | (pDataIn[2] >> 6)) & 0x3f];
                pDataOut[3] = s_pszBase64[pDataIn[2] & 0x3f];
            } else {
                pDataOut[2] = s_pszBase64[(pDataIn[1] << 2) & 0x3f];
                pDataOut[3] = BASE64_PADDING;
            }
        } else {
            pDataOut[1] = s_pszBase64[(pDataIn[0] << 4) & 0x3f];
            pDataOut[2] = BASE64_PADDING;
            pDataOut[3] = BASE64_PADDING;
        }
    } else {
        pDataOut[0] = BASE64_PADDING;
        pDataOut[1] = BASE64_PADDING;
        pDataOut[2] = BASE64_PADDING;
        pDataOut[3] = BASE64_PADDING;
    }
}


inline static SIZE_T _Base64Decode(_In_count_c_(4) LPCBYTE pDataIn, _Out_cap_c_(3) LPBYTE pDataOut)
{
    pDataOut[0] = ((pDataIn[0] << 2) | (pDataIn[1] >> 4)) & 0xff;
    if (pDataIn[2] < 64) {
        pDataOut[1]  = ((pDataIn[1] << 4) | (pDataIn[2] >> 2)) & 0xff;
        if (pDataIn[3] < 64) {
            pDataOut[2]  = ((pDataIn[2] << 6) | pDataIn[3]) & 0xff;
            return 3;
        } else
            return 2;
    } else
        return 1;
}
