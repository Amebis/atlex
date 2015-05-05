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

#ifndef __AL_COMMON__
#define __AL_COMMON__

#include "..\..\include\version.h"


//
// Resource codes
//

//
// Dialogs
//
#define IDD_AL_CONFIG                                100
#define IDC_AL_CONFIG_TAB                            8

#define IDD_AL_CONFIGCFG                             101
#define IDC_AL_CONFIGCFG_AUTH_ICO                    8
#define IDC_AL_CONFIGCFG_AUTH_PAP                    9
#define IDC_AL_CONFIGCFG_AUTH_PAP_CRED_NOTE          10
#define IDC_AL_CONFIGCFG_AUTH_PAP_INNER_ID_LBL       11
#define IDC_AL_CONFIGCFG_AUTH_PAP_INNER_ID           12
#define IDC_AL_CONFIGCFG_AUTH_PAP_PASSWORD_LBL       13
#define IDC_AL_CONFIGCFG_AUTH_PAP_PASSWORD           14
#define IDC_AL_CONFIGCFG_AUTH_PAP_CRED_NOTE2         15
#define IDC_AL_CONFIGCFG_AUTH_MSCHAPV2               16
#define IDC_AL_CONFIGCFG_AUTH_MSCHAPV2_CFG           17
#define IDC_AL_CONFIGCFG_AUTH_MSCHAPV2_CRED_SET      18
#define IDC_AL_CONFIGCFG_AUTH_MSCHAPV2_CRED_CLR      19
#define IDC_AL_CONFIGCFG_OUTERID_ICO                 20
#define IDC_AL_CONFIGCFG_OUTER_ID_SAME               21
#define IDC_AL_CONFIGCFG_OUTER_ID_EMPTY              22
#define IDC_AL_CONFIGCFG_OUTER_ID_CUSTOM             23
#define IDC_AL_CONFIGCFG_OUTER_ID_CUSTOM_LBL         24
#define IDC_AL_CONFIGCFG_OUTER_ID_CUSTOM_VAL         25
#define IDC_AL_CONFIGCFG_VERIFY_CERT_ICO             26
#define IDC_AL_CONFIGCFG_CA_LIST_LBL                 27
#define IDC_AL_CONFIGCFG_CA_LIST                     28
#define IDC_AL_CONFIGCFG_CA_ADD                      29
#define IDC_AL_CONFIGCFG_CA_REMOVE                   30
#define IDC_AL_CONFIGCFG_VERIFY_NAME_LBL             31
#define IDC_AL_CONFIGCFG_VERIFY_NAME_VAL             32
#define IDC_AL_CONFIGCFG_VERIFY_NAME_NOTE            33
#define IDC_AL_CONFIGCFG_CONNECTION_ICO              34
#define IDC_AL_CONFIGCFG_ENABLE_RESUME               35

#define IDD_AL_CREDENTIALS                           102
#define IDC_AL_CREDENTIALS_WARNING_ICO               8
#define IDC_AL_CREDENTIALS_ICON                      9
#define IDC_AL_CREDENTIALS_DESCRIPTION               10
#define IDC_AL_CREDENTIALS_USERNAME_LBL              11
#define IDC_AL_CREDENTIALS_USERNAME                  12
#define IDC_AL_CREDENTIALS_PASSWORD_LBL              13
#define IDC_AL_CREDENTIALS_PASSWORD                  14
#define IDC_AL_CREDENTIALS_SAVE                      15

#define IDD_AL_UNTRUSTEDCERT                         103
#define IDC_AL_UNTRUSTEDCERT_TXT                     8
#define IDC_AL_UNTRUSTEDCERT_TREE                    9
#define IDC_AL_UNTRUSTEDCERT_VIEW                    10
#define IDC_AL_UNTRUSTEDCERT_TRUST                   11

#define IDD_AL_MONITOR                               104
#define IDC_AL_MONITOR_TREE                          8
#define IDC_AL_MONITOR_COPY                          9
#define IDC_AL_MONITOR_FOOTER                        10

#define IDD_AL_IMPORT_FILE                           105
#define IDC_AL_IMPORT_FILE_NAME                      8
#define IDC_AL_IMPORT_FILE_BROWSE                    9

#define IDD_AL_IMPORT_PROVIDER                       106
#define IDD_AL_IMPORT_PROVIDER_LIST                  8

#define IDD_AL_IMPORT_CREDENTIALS_EAP                107
#define IDC_AL_IMPORT_CREDENTIALS_EAP_SET            8
#define IDC_AL_IMPORT_CREDENTIALS_EAP_CLR            9

#define IDD_AL_IMPORT_CREDENTIALS_PAP                108
#define IDC_AL_IMPORT_CREDENTIALS_PAP_DESCRIPTION    8
#define IDC_AL_IMPORT_CREDENTIALS_PAP_USERNAME_LBL   9
#define IDC_AL_IMPORT_CREDENTIALS_PAP_USERNAME       10
#define IDC_AL_IMPORT_CREDENTIALS_PAP_PASSWORD_LBL   11
#define IDC_AL_IMPORT_CREDENTIALS_PAP_PASSWORD       12

#define IDD_AL_IMPORT_COMMIT                         109
#define IDC_AL_IMPORT_COMMIT_PROGRESS                8

#define IDD_AL_IMPORT_FINISH_SUCCESS                 110

#define IDD_AL_IMPORT_FINISH_FAILURE                 111
#define IDC_AL_IMPORT_FINISH_FAILURE_MSG             8

//
// Strings
//
#define IDS_AL_ERROR_ERROR                           100
#define IDS_AL_ERROR_ALERT                           101
#define IDS_AL_ERROR_CERTIFICATE_FILE_READ           102
#define IDS_AL_ERROR_PROFILE_NOROOTCA                103
#define IDS_AL_ERROR_IMPORT_ROOT                     104
#define IDS_AL_ERROR_IMPORT_WIZARD_READ              105
#define IDS_AL_ERROR_IMPORT_WIZARD_CONTENT           106
#define IDS_AL_ERROR_IMPORT_WIZARD_PROFILE           107
#define IDS_AL_ERROR_IMPORT_WIZARD_PROFILE_NAME      108
#define IDS_AL_ERROR_IMPORT_WIZARD_PROFILE_XML       109
#define IDS_AL_ERROR_IMPORT_WIZARD_PROFILE_DELETE    110
#define IDS_AL_ERROR_IMPORT_WIZARD_PROFILE_ADD       111

#define IDS_AL_MSG_OUTER_AUTH                        112
#define IDS_AL_MSG_SERVER_NAME                       114
#define IDS_AL_MSG_CA_TRUSTED                        115
#define IDS_AL_MSG_CERTIFICATE_CONFIRMED             116
#define IDS_AL_MSG_INNER_AUTH                        117
#define IDS_AL_MSG_AUTH_SUCCEEDED                    118

#define IDS_AL_MSGERR_GENERIC_INSTRUCTION            120
#define IDS_AL_MSGERR_TLS_UNKNOWN_STATE              121
#define IDS_AL_MSGERR_PACKET_RESPONSE_INIT           122
#define IDS_AL_MSGERR_PACKET_RESPONSE_BUILD          123
#define IDS_AL_MSGERR_PACKET_UNEXPECTED              124
#define IDS_AL_MSGERR_PACKET_REQUEST_UNEXPECTED      125
#define IDS_AL_MSGERR_PACKET_INVALID                 126
#define IDS_AL_MSGERR_PACKET_NO_CHIPHER              127
#define IDS_AL_MSGERR_MESSAGE_READ                   128
#define IDS_AL_MSGERR_SRV_UNEXCPECTED_VERSION        129
#define IDS_AL_MSGERR_SERVER_NAME_INACCEPTABLE       133
#define IDS_AL_MSGERR_SERVER_NAME_INACCEPTABLE_DESC  134
#define IDS_AL_MSGERR_SERVER_NAME                    135
#define IDS_AL_MSGERR_SERVER_CERT_UNTRUSTED          136
#define IDS_AL_MSGERR_SERVER_CERT_UNTRUSTED_DESC     137
#define IDS_AL_MSGERR_SERVER_CERT_INACCEPTABLE       138
#define IDS_AL_MSGERR_SERVER_CERT_INACCEPTABLE_DESC  139
#define IDS_AL_MSGERR_SERVER_CERT_CHAIN              140
#define IDS_AL_MSGERR_SERVER_CERT_MISSING            141
#define IDS_AL_MSGERR_HANDLE_INNER_AUTH              142
#define IDS_AL_MSGERR_AUTH_FAILED                    143
#define IDS_AL_MSGERR_AUTH_FAILED_DESC               144
#define IDS_AL_MSGERR_CRED_MISSING                   145
#define IDS_AL_MSGERR_CRED_MISSING_DESC              146

#define IDS_AL_MSG_MONITOR_SESSION_BEGIN             147
#define IDS_AL_MSG_MONITOR_SESSION_END               148

#define IDS_AL_FILE_ALL                              149
#define IDS_AL_FILE_ARNESLINK_CONFIG                 150
#define IDS_AL_FILE_CERTIFICATE                      151
#define IDS_AL_FILE_CERTIFICATEX509                  152
#define IDS_AL_FILE_CERTIFICATEPKCS7                 153
#define IDS_AL_FILE_SELECT                           154

#define IDS_AL_IDENTITY_LBL                          155
#define IDS_AL_PASSWORD_LBL                          156
#define IDS_AL_ADD_CERTIFICATE_TITLE                 157

#define IDS_AL_IMPORT_TITLE                          158
#define IDS_AL_IMPORT_WIZARD                         159
#define IDS_AL_IMPORT_FILE_TITLE                     160
#define IDS_AL_IMPORT_PROVIDER_TITLE                 161
#define IDS_AL_IMPORT_CREDENTIALS_TITLE_EAP          162
#define IDS_AL_IMPORT_CREDENTIALS_SET_NOTE           163
#define IDS_AL_IMPORT_CREDENTIALS_CLR_NOTE           164
#define IDS_AL_IMPORT_CREDENTIALS_TITLE_PAP          165
#define IDS_AL_IMPORT_COMMIT_TITLE                   166
#define IDS_AL_IMPORT_FINISH_SUCCESS_TITLE           167
#define IDS_AL_IMPORT_FINISH_FAILURE_TITLE           168

#define IDS_AL_PS_BACK                               169
#define IDS_AL_PS_NEXT                               170
#define IDS_AL_PS_FINISH                             171
#define IDS_AL_PS_CANCEL                             172

#define IDS_AL_LANGUAGE_IANA_SUBTAG                  173

//
// Bitmaps
//
#define IDB_AL_HEADER                       100
#define IDB_AL_HEADER_WIDE                  101

//
// Icons
//
#define IDI_AL_LOGO                         100
#define IDI_AL_IMPORT                       101

//
// Menus
//
#define IDM_AL_MONITOR                      100
#define ID_AL_MONITOR_SHOW_LOG              1


#if !defined(RC_INVOKED) && !defined(MIDL_PASS)


//
// Includes
//

#include <Windows.h>

#include <eaptypes.h>
#include <eapmethodtypes.h>
#include <eapmethodauthenticatorapis.h>
#include <eapmethodpeerapis.h>

#include <LMCons.h>
#include <MsXml2.h>
#include <Raseapif.h>

#include "..\atl\atlcrypt.h"
#include "..\atl\atleap.h"
#include "..\atl\atlwin.h"
#include <atlcoll.h>
#include <atlstr.h>


#pragma comment(lib, "comctl32.lib")
#ifdef _M_AMD64
#pragma comment(linker, "/MANIFESTDEPENDENCY:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker, "/MANIFESTDEPENDENCY:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif


//
// Global constants
//

#define AL_EAP_VENDOR               "ARNES"
#define AL_EAP_AUTHOR_ID            17236
#define AL_EAP_TYPE_TTLS            21
#define AL_EAP_TYPE_PEAP            25
#define AL_EAP_TYPE_MSCHAPV2        26
#define AL_EAP_CREDENTIAL_VERSION   1

// EAP method-version mask
#define AL_EAP_METHOD_VERSION       0x07

#define AL_EAP_TTLS_V0              0
#define AL_EAP_TTLS_V1              1

#define AL_EAP_PEAP_V0              0
#define AL_EAP_PEAP_V1              1
#define AL_EAP_PEAP_V2              2

#define AL_EAP_KEYING_MATERIAL_LABEL_TTLS_V0 "ttls keying material"
#define AL_EAP_KEYING_MATERIAL_LABEL_TTLS_V1 "ttls v1 keying material"
#define AL_EAP_KEYING_MATERIAL_LABEL_PEAP_V0 "client EAP encryption"
#define AL_EAP_KEYING_MATERIAL_LABEL_PEAP_V1 "client EAP encryption"

#define AL_TLS_SESSION_ID_SIZE      32

#define AL_TLS_FINISH_SIZE          12

#define AL_TLS_MAX_FRAG_SIZE        1024

#define AL_TLS_MAX_MAC              24

#define AL_TLS_REQUEST_LENGTH_INC   0x80
#define AL_TLS_REQUEST_MORE_FRAG    0x40
#define AL_TLS_REQUEST_START        0x20

#define AL_TLS_CLIENT_FINISHED_LABEL "client finished"
#define AL_TLS_SERVER_FINISHED_LABEL "server finished"
#define AL_TLS_KEY_EXPANSION_LABEL   "key expansion"

#define AL_TLS_RANDOM_SIZE          32

#define AL_TLS_PMS_SIZE             48
#define AL_TLS_MS_SIZE              48

#define AL_SECUREW2_XORPATTERN      "8FC8E6CF371C2D049BBC243E84F2A3766ED907EF09601139284E83C268B032C6" \
                                    "3EE448A7BCE76F64149AC82AC2DE5613E76F190FF2DC41E31CBF5610BEAEC079" \
                                    "F64AE45A884C74CFDC61A19D5C1C1CA44BD28A73D51DF25A9D5147B63164A604" \
                                    "59670224BB0F42376D7E1551632AE72F0FF44CBED3C5F313ED6C408D641931BB"

#define AL_DUMP_ERROR(d, c)         AL::Trace::Dump                         (AL::Trace::LEVEL_ERROR  , d, c, _T("  ") _T(__FUNCTION__) _T(" "))
#define AL_DUMP_WARNING(d, c)       AL::Trace::Dump                         (AL::Trace::LEVEL_WARNING, d, c, _T("  ") _T(__FUNCTION__) _T(" "))
#define AL_DUMP_INFO(d, c)          AL::Trace::Dump                         (AL::Trace::LEVEL_INFO   , d, c, _T("  ") _T(__FUNCTION__) _T(" "))
#define AL_DUMP_DEBUG(d, c)         AL::Trace::Dump                         (AL::Trace::LEVEL_DEBUG  , d, c, _T("  ") _T(__FUNCTION__) _T(" "))
#define AL_TRACE_ERROR(f, ...)      AL::Trace::Output                       (AL::Trace::LEVEL_ERROR  ,       _T("  ") _T(__FUNCTION__) _T(" ") f, ##__VA_ARGS__)
#define AL_TRACE_WARNING(f, ...)    AL::Trace::Output                       (AL::Trace::LEVEL_WARNING,       _T("  ") _T(__FUNCTION__) _T(" ") f, ##__VA_ARGS__)
#define AL_TRACE_INFO(f, ...)       AL::Trace::Output                       (AL::Trace::LEVEL_INFO   ,       _T("  ") _T(__FUNCTION__) _T(" ") f, ##__VA_ARGS__)
#define AL_TRACE_DEBUG(f, ...)      AL::Trace::Output                       (AL::Trace::LEVEL_DEBUG  ,       _T("  ") _T(__FUNCTION__) _T(" ") f, ##__VA_ARGS__)
#define AL_TRACEFN_VOID_WARNING     AL::Trace::CAutoTrace           _traceAL(AL::Trace::LEVEL_WARNING,       _T("->") _T(__FUNCTION__), _T("<-") _T(__FUNCTION__))
#define AL_TRACEFN_VOID_INFO        AL::Trace::CAutoTrace           _traceAL(AL::Trace::LEVEL_INFO   ,       _T("->") _T(__FUNCTION__), _T("<-") _T(__FUNCTION__))
#define AL_TRACEFN_VOID_DEBUG       AL::Trace::CAutoTrace           _traceAL(AL::Trace::LEVEL_DEBUG  ,       _T("->") _T(__FUNCTION__), _T("<-") _T(__FUNCTION__))
#define AL_TRACEFN_WARNING(res)     AL::Trace::CAutoTraceRes<DWORD> _traceAL(AL::Trace::LEVEL_WARNING,       _T("->") _T(__FUNCTION__), _T("<-") _T(__FUNCTION__) _T(" (%ld)"), res)
#define AL_TRACEFN_INFO(res)        AL::Trace::CAutoTraceRes<DWORD> _traceAL(AL::Trace::LEVEL_INFO   ,       _T("->") _T(__FUNCTION__), _T("<-") _T(__FUNCTION__) _T(" (%ld)"), res)
#define AL_TRACEFN_DEBUG(res)       AL::Trace::CAutoTraceRes<DWORD> _traceAL(AL::Trace::LEVEL_DEBUG  ,       _T("->") _T(__FUNCTION__), _T("<-") _T(__FUNCTION__) _T(" (%ld)"), res)


//
// Global data types
//

#ifndef _LPCBYTE_DEFINED
#define _LPCBYTE_DEFINED
typedef const BYTE *LPCBYTE;
#endif


//
// AL namespace
//

namespace AL {
    //
    // Tracing
    //
    namespace Trace {
        enum LEVEL_T {
            LEVEL_ERROR   = 0x00010000,
            LEVEL_WARNING = 0x00020000,
            LEVEL_INFO    = 0x00040000,
            LEVEL_DEBUG   = 0x00080000,
        };

        DWORD Init(_In_z_ LPCTSTR pszTraceId);
        DWORD Done();
        VOID Dump(_In_ LEVEL_T level, _In_bytecount_(cbData) LPCVOID pData, _In_ DWORD cbData, _In_opt_z_ LPCTSTR pszPrefix = NULL);
        VOID Output(_In_ LEVEL_T level, _In_z_ LPCTSTR pszFormat, ...);
        DWORD GetFilePath(_In_z_ LPCTSTR pszTraceId, _Out_ ATL::CAtlString &sFilePath);
        DWORD RemoveConfiguration(_In_z_ LPCTSTR pszTraceId);

        class CAutoTrace {
        public:
            inline CAutoTrace(_In_ LEVEL_T level, _In_z_ LPCTSTR pszFormatEntry, _In_z_ LPCTSTR pszFormatExit) :
                m_level(level),
                m_pszFormatExit(pszFormatExit)
            {
                Output(level, pszFormatEntry);
            }

            inline ~CAutoTrace()
            {
                Output(m_level, m_pszFormatExit);
            }

        protected:
            LEVEL_T m_level;
            LPCTSTR m_pszFormatExit;
        };

        template <class T>
        class CAutoTraceRes {
        public:
            inline CAutoTraceRes(_In_ LEVEL_T level, _In_z_ LPCTSTR pszFormatEntry, _In_z_ LPCTSTR pszFormatExit, _In_ T &tResult) :
                m_level(level),
                m_pszFormatExit(pszFormatExit),
                m_tResult(tResult)
            {
                Output(level, pszFormatEntry);
            }

            inline ~CAutoTraceRes()
            {
                Output(m_level, m_pszFormatExit, m_tResult);
            }

        protected:
            LEVEL_T m_level;
            LPCTSTR m_pszFormatExit;
            T       &m_tResult;
        };

        extern LPTSTR g_pszID;
    }

    //
    // Heap management
    //
    namespace Heap {
        DWORD Init();
        DWORD Done();
        DWORD Alloc(_In_ SIZE_T nSize, _Inout_bytecap_(nSize) LPVOID *ppBuffer);
        DWORD Realloc(_In_ SIZE_T nNewSize, _Inout_bytecap_(nNewSize) LPVOID *ppBuffer);
        DWORD GetSize(_In_ LPCVOID pBuffer, _Out_ SIZE_T *pnSize);
        DWORD Free(_Inout_ LPVOID *pBuffer);

        class CHeap : public IAtlMemMgr
        {
        public:
            _Ret_opt_bytecap_(nBytes) virtual void* Allocate(_In_ size_t nBytes) throw();
            virtual void Free(_In_opt_ void* p) throw();
            _Ret_opt_bytecap_(nBytes) virtual void* Reallocate(_In_opt_ void* p, _In_ size_t nBytes) throw();
            virtual size_t GetSize(_In_ void* p) throw();
        };

        extern CHeap g_heap;
        extern CParanoidHeap<CHeap> g_heapParanoid;
        extern ATL::CAtlStringMgr g_stringMgrParanoid;
    }

    //
    // Conversions
    //
    namespace Convert {
        inline DWORD N2H32(_In_count_c_(4) LPCBYTE pbNetworkFormat);
        inline DWORD N2H24(_In_count_c_(3) LPCBYTE pbNetworkFormat);
        inline  WORD N2H16(_In_count_c_(2) LPCBYTE pbNetworkFormat);

        inline VOID H2N32(_In_ DWORD dwHostFormat, _Out_cap_c_(4) LPBYTE pbNetworkFormat);
        inline VOID H2N24(_In_ DWORD dwHostFormat, _Out_cap_c_(3) LPBYTE pbNetworkFormat);
        inline VOID H2N16(_In_  WORD  wHostFormat, _Out_cap_c_(2) LPBYTE pbNetworkFormat);
    }

    //
    // Buffer operations
    //
    namespace Buffer {
        VOID Swap(_In_bytecount_(nSize) LPCVOID pDataIn, _Out_bytecap_(nSize) LPVOID pDataOut, _In_ SIZE_T nSize);
        VOID Swap(_Inout_bytecount_(nSize) LPVOID pData, _In_ SIZE_T nSize);

        VOID XORData(_In_bytecount_(nSize) LPCVOID pDataIn, _Out_bytecap_(nSize) LPVOID pDataOut, _In_ SIZE_T nSize, _In_bytecount_(nKeySize) LPCVOID pKey, _In_ SIZE_T nKeySize);
        VOID XORData(_Inout_bytecount_(nSize) LPVOID pData, _In_ SIZE_T nSize, _In_bytecount_(nKeySize) LPCVOID pKey, _In_ SIZE_T nKeySize);

        namespace CommandLine {
            VOID Encode(_In_z_ LPCWSTR pszBufferIn, _Out_ ATL::CAtlStringW &sValue);
            VOID Decode(_In_z_ LPCWSTR pszBufferIn, _Out_ ATL::CAtlStringW &sValue);
        }

        namespace Base64 {
            //
            // CEncoder
            //
            class CEncoder {
            public:
                CEncoder();
                VOID Encode(_In_bytecount_(nDataInSize) LPCVOID pDataIn, _In_ SIZE_T nDataInSize, _Out_ ATL::CAtlString &sValue, _In_opt_ BOOL bLast = TRUE);

            protected:
                SIZE_T m_nCount;
                BYTE   m_pbData[3];
            };

            //
            // CDecoder
            //
            class CDecoder {
            public:
                CDecoder();
                VOID Decode(_In_z_ LPCSTR  pszDataIn, _Out_ ATL::CAtlArray<BYTE> &aValue, _Out_opt_ BOOL *pbLast = NULL);
                VOID Decode(_In_z_ LPCWSTR pszDataIn, _Out_ ATL::CAtlArray<BYTE> &aValue, _Out_opt_ BOOL *pbLast = NULL);

            protected:
                SIZE_T m_nCount;
                BYTE   m_pbData[4];
            };
        };
    }

    //
    // OS specific operations
    //
    namespace System {
        DWORD GetModulePath(_In_ HMODULE hInstance, _In_z_ LPCTSTR pszLibraryFilename, _Out_ ATL::CAtlString &sModulePath);
        HMODULE LoadLibrary(_In_ HMODULE hInstance, _In_z_ LPCTSTR pszLibraryFilename, _In_ DWORD dwFlags = 0);
        DWORD FormatMsg(_In_ DWORD dwMessageId, _Out_z_cap_(dwBufferLen) LPTSTR pszBuffer, _In_ DWORD dwBufferLen, ...);

        //
        // Global data
        //
        extern HINSTANCE g_hInstance;
        extern HINSTANCE g_hResource;
        extern ULARGE_INTEGER g_uliVerEap3Host;
    }

    //
    // XML
    //
    namespace XML {
        DWORD SelectNode(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrNodeName, _Out_ IXMLDOMNode **ppXmlNode);
        DWORD SelectNodes(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrNodeName, _Out_ IXMLDOMNodeList **ppXmlNodes);
        DWORD SelectElement(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ IXMLDOMElement **ppXmlElement);
        DWORD GetElementValue(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ BSTR *pbstrValue);
        DWORD GetElementValue(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ ATL::CAtlString &sValue);
        DWORD GetElementValue(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ DWORD *pdwValue);
        DWORD GetElementValue(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ BOOL *pbValue);
        DWORD GetElementBase64(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ ATL::CAtlArray<BYTE> &aValue);
        DWORD GetElementEncrypted(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _Out_ ATL::CAtlString &sValue);
        DWORD GetElementLocalized(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _In_z_ LPCTSTR pszLang, _Out_ BSTR *pbstrValue);
        DWORD GetElementLocalized(_In_ IXMLDOMNode *pXmlParent, _In_z_ const BSTR bstrElementName, _In_z_ LPCTSTR pszLang, _Out_ ATL::CAtlString &sValue);
        DWORD PutElement(_In_ IXMLDOMDocument2 *pXmlDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _Out_ IXMLDOMElement **ppXmlElement);
        DWORD PutElementValue(_In_ IXMLDOMDocument2 *pXmlDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_z_ const BSTR bstrValue);
        DWORD PutElementValue(_In_ IXMLDOMDocument2 *pXmlDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_ DWORD dwValue);
        DWORD PutElementValue(_In_ IXMLDOMDocument2 *pXmlDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_ BOOL bValue);
        DWORD PutElementBase64(_In_ IXMLDOMDocument2 *pXmlDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_count_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen);
        DWORD PutElementEncrypted(_In_ IXMLDOMDocument2 *pXmlDoc, _In_ IXMLDOMNode *pCurrentDOMNode, _In_z_ const BSTR bstrElementName, _In_opt_z_ const BSTR bstrNamespace, _In_count_(nValueLen) LPCVOID pValue, _In_ SIZE_T nValueLen);
    }

    //
    // Cryptography
    //
    namespace Crypto {
        DWORD AcquireContext(_Out_ HCRYPTPROV *phCSP, _In_z_ LPCTSTR pszContainer, _In_opt_z_ LPCTSTR pszCSPName = MS_ENHANCED_PROV, _In_opt_ DWORD dwType = PROV_RSA_FULL);
        DWORD GetCertificate(_In_count_c_(20) LPCBYTE pbServerCertSHA1, _Out_ PCCERT_CONTEXT *ppCertContext);
        DWORD GetHash(_In_ HCRYPTPROV hCSP, _In_ ALG_ID algid, _In_bytecount_(dwMsgSize) LPCVOID pMsg, _In_ DWORD dwMsgSize, _Out_ ATL::CAtlArray<BYTE> &aHash);
        DWORD GenSecureRandom(_Inout_bytecount_(dwRandomSize) LPVOID pRandom, IN DWORD dwRandomSize);
        DWORD CreatePrivateExponentOneKey(_In_ HCRYPTPROV hProv, _In_ DWORD dwKeySpec, _Out_ HCRYPTKEY *phPrivateKey);
        BOOL ExportPlainSessionBlob(_In_ HCRYPTKEY hPublicKey, _In_ HCRYPTKEY hSessionKey, _Out_bytecap_(*dwKeyMaterial) LPBYTE *pbKeyMaterial, _Out_ DWORD *pdwKeyMaterial);
        BOOL ImportPlainSessionBlob(_In_ HCRYPTPROV hProv, _In_ HCRYPTKEY hPrivateKey, _In_ ALG_ID dwAlgId, _In_bytecount_(dwKeyMaterialSize) LPBYTE pbKeyMaterial, _In_ DWORD dwKeyMaterialSize, _Out_ ATL::Crypt::CKey &keySession);
    }

    //
    // Monitor
    //
    class CMonitor {
    public:
        CMonitor();
        virtual ~CMonitor();

        DWORD Init(_In_ HANDLE hTokenImpersonateUser, _In_ HANDLE hSession);
        void Done();

        DWORD Send(_In_z_ LPCTSTR pszParameters, _In_ BOOL bSynchronous = TRUE) const;
        DWORD SendMsg(_In_z_ LPCWSTR pszMessage, _In_z_ LPCWSTR pszTitle, _In_z_ LPCWSTR pszDetails, _In_ BOOL bSynchronous = TRUE) const;
        DWORD SendError(_In_ const EAP_ERROR* pEapError, _In_ BOOL bSynchronous = TRUE) const;

    protected:
        virtual VOID InternalDone();

    public:
        HANDLE m_hSession;
        HANDLE m_hTokenImpersonateUser;
        HANDLE m_hProfileUser;
        ATL::CAtlString m_sMonitorFile;
    };

    //
    // EAP
    //
    namespace EAP {
        enum INNERSTATE_T {
            INNERSTATE_Unknown = 0,
            INNERSTATE_Start,
            INNERSTATE_Identity,
            INNERSTATE_EAPType,
            INNERSTATE_InteractiveUI,
            INNERSTATE_MakeMessage,
            INNERSTATE_Finished
        };

        //
        // EAP BLOB Base
        //
        class CBlobBase {
        public:
            CBlobBase();
            virtual ~CBlobBase();
            virtual DWORD Create(_In_ SIZE_T nSize) = 0;
            virtual VOID Free() = 0;
            virtual DWORD Attach(_In_ LPVOID p) = 0;
            virtual LPVOID Detach() = 0;

            inline LPVOID  GetData()       { return m_pData; }
            inline LPCVOID GetData() const { return m_pData; }
            inline SIZE_T  GetSize() const { return m_nSize; }

        protected:
            LPVOID m_pData;
            SIZE_T m_nSize;
        };

        //
        // EAP BLOB Flat
        //
        class CBlobFlat : public CBlobBase {
        public:
            CBlobFlat();
            virtual ~CBlobFlat();
            virtual DWORD Create(_In_ SIZE_T nSize);
            virtual VOID Free();
            virtual DWORD Attach(_In_ LPVOID p);
            virtual LPVOID Detach();
        };

        //
        // EAP BLOB Cookie Header
        //
        struct BLOBCOOKIEHDR {
            enum BLOBTYPE_T {
                BLOBTYPE_Heap = 0x50414548,
                BLOBTYPE_File = 0x454C4946,
            } type;
        };

        //
        // EAP BLOB
        //
        class CBlob : public CBlobBase {
        public:
            CBlob();
            virtual ~CBlob();
            virtual DWORD Create(_In_ SIZE_T nSize);
            virtual VOID Free();
            virtual DWORD Attach(_In_ LPVOID p);
            virtual LPVOID Detach();
            inline LPCVOID GetCookieData() const { return m_pCookie; }
            inline SIZE_T GetCookieSize() const
            {
                if (m_pCookie) {
                    SIZE_T nSize;
                    return AL::Heap::GetSize(m_pCookie, &nSize) == NO_ERROR ? nSize : 0;
                } else
                    return 0;
            }

        protected:
            BLOBCOOKIEHDR *m_pCookie;
            union {
                struct {
                    HANDLE m_hFile;
                    HANDLE m_hMapping;
                };
            };
        };

        //
        // EAP BLOB Reader
        //
        class CBlobReader {
        public:
            CBlobReader();
            virtual ~CBlobReader();
            DWORD Mount(_In_ LPCVOID p, _In_ SIZE_T nSize, _In_opt_ BOOL bIsLastConsumer = FALSE);

            inline LPCVOID GetData() const { return m_pData; }
            inline SIZE_T  GetSize() const { return m_nSize; }

        protected:
            LPCVOID m_pData;
            SIZE_T m_nSize;
            BLOBCOOKIEHDR *m_pCookie;
            union {
                struct {
                    HANDLE m_hFile;
                    HANDLE m_hMapping;
                };
            };
            BOOL m_bIsLastConsumer;
        };

        //
        // EAP Packet
        //
        class CPacket : public ATL::CObjectWithHandleDuplT<EapPacket*>
        {
        public:
            virtual ~CPacket() throw();
            DWORD Create(_In_ EapCode Code, _In_ BYTE bId, _In_ WORD wLength) throw();
            DWORD CreateRequest(_In_ BYTE bId, _In_ BYTE bProtocolId, _In_ BYTE bFlags, _In_opt_ WORD wLength = 6);
            DWORD CreateResponse(_In_ BYTE bId, _In_ BYTE bProtocolId, _In_ BYTE bFlags, _In_opt_ WORD wLength = 6);
            inline DWORD CreateAccept(_In_ BYTE bId) { return Create(EapCodeSuccess, bId + 1, 4); }
            inline DWORD CreateReject(_In_ BYTE bId) { return Create(EapCodeFailure, bId + 1, 4); }
            inline WORD GetSize() const { return AL::Convert::N2H16(m_h->Length); }
            DWORD Append(_In_bytecount_(nSize) LPCVOID pBuf, _In_ SIZE_T nSize, _In_ SIZE_T nSizeTotal);

        protected:
            virtual void InternalFree();
            virtual HANDLE InternalDuplicate(HANDLE h) const;
        };

        //
        // EAP identification
        //
        extern BYTE g_bType;

        //
        // EAP hooks
        //
        DWORD Init(_Out_ EAP_ERROR **ppEapError);
        DWORD Done(_Out_ EAP_ERROR **ppEapError);
        DWORD ConfigXml2Blob(_In_ DWORD dwFlags, _In_ IXMLDOMDocument2 *pXMLConfigDoc, _Out_ CBlob &blobConnectionOut, _Out_ EAP_ERROR **ppEapError);
        DWORD ConfigBlob2Xml(_In_ DWORD dwFlags, _In_ SIZE_T nConnectionSize, _In_bytecount_(nConnectionSize) LPCVOID pConnection, _Out_ IXMLDOMDocument2 **ppXMLConfigDoc, _Out_ EAP_ERROR **ppEapError);
        DWORD GetMethodProperties(_In_ DWORD dwVersion, _In_ DWORD dwFlags, _In_ EAP_METHOD_TYPE eapMethodType, _In_ HANDLE hTokenImpersonateUser, _In_ SIZE_T nConnectionDataSize, _In_bytecount_(nConnectionDataSize) LPCVOID pConnectionData, _In_ SIZE_T nUserDataSize, _In_bytecount_(nUserDataSize) LPCVOID pUserData, _Out_ EAP_METHOD_PROPERTY_ARRAY *pMethodPropertyArray, _Out_ EAP_ERROR **ppEapError);
        DWORD InvokeConfigUI(_In_ HWND hWndParent, _In_ DWORD dwFlags, _In_ SIZE_T nConnectionDataInSize, _In_bytecount_(nConnectionDataInSize) LPCVOID pConnectionDataIn, _Out_ CBlob &blobConnectionDataOut, _Out_ EAP_ERROR **ppEapError);
        DWORD CredentialsXml2Blob(_In_ DWORD dwFlags, _In_ IXMLDOMDocument2 *pXMLCredentialsDoc, _In_ SIZE_T nConnectionInSize, _In_bytecount_(nConnectionInSize) LPCVOID pConnectionIn, _Out_ CBlob &blobCredentialsOut, _Out_ EAP_ERROR **ppEapError);
        DWORD QueryCredentialInputFields(_In_ HANDLE hUserToken, _In_ DWORD dwFlags, _In_ SIZE_T nConnectionDataSize, _In_bytecount_(nConnectionDataSize) LPCVOID pConnectionData, _Out_ EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldArray, _Out_ EAP_ERROR **ppEapError);
        DWORD QueryUserBlobFromCredentialInputFields(_In_ HANDLE hUserToken, _In_ DWORD dwFlags, _In_ SIZE_T nEapConnDataSize, _In_bytecount_(nEapConnDataSize) LPCVOID pEapConnData, _In_ const EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldArray, _Out_ CBlob &blobUserOut, _Out_ EAP_ERROR **ppEapError);
#ifndef AL_GENERIC_CREDENTIAL_UI
        DWORD GetIdentity(_In_ DWORD dwFlags, _In_ SIZE_T nConnectionDataSize, _In_bytecount_(nConnectionDataSize) LPCVOID pConnectionData, _In_ SIZE_T nUserDataInSize, _In_bytecount_(nUserDataInSize) LPCVOID pUserDataIn, _In_ HANDLE hTokenImpersonateUser, _Out_ BOOL *pfInvokeUI, _Out_ CBlob &blobUserOut, _Out_ CBlobFlat &blobIdentity, _Out_ EAP_ERROR **ppEapError);
#endif
        DWORD InvokeIdentityUI(_In_ HWND hWndParent, _In_ DWORD dwFlags, _In_ SIZE_T nConnectionDataSize, _In_bytecount_(nConnectionDataSize) LPCVOID pConnectionData, _In_ SIZE_T nUserDataInSize, _In_bytecount_(nUserDataInSize) LPCVOID pUserDataIn, _Out_ CBlob &blobUserOut, _Out_ CBlobFlat &blobIdentity, _Out_ EAP_ERROR **ppEapError);
        DWORD BeginSession(_In_ DWORD dwFlags, _In_ HANDLE hTokenImpersonateUser, _In_ SIZE_T nConnectionDataSize, _In_bytecount_(nConnectionDataSize) LPCVOID pConnectionData, _In_ SIZE_T nUserDataSize, _In_bytecount_(nUserDataSize) LPCVOID pUserData, _In_ const AL::CMonitor *pMonitor, _Out_ LPVOID *ppWorkBuffer, _Out_ EAP_ERROR **ppEapError);
        DWORD EndSession(_In_ LPVOID pWorkBuffer, _Out_ EAP_ERROR **ppEapError);
#ifdef AL_GENERIC_CREDENTIAL_UI
        DWORD SetCredentials(_Inout_ LPVOID pWorkBuffer, _In_z_ LPCWSTR pszIdentity, _In_z_ LPCWSTR pszPassword, _Out_ EAP_ERROR **ppEapError);
#endif
        DWORD Process(_Inout_ LPVOID pWorkBuffer, _In_ EapPacket *pReceivePacket, _Out_ CPacket &pktSend, _Out_ EapPeerMethodOutput* pEapPeerMethodOutput, _Out_ EAP_ERROR **ppEapError);
        DWORD GetResult(_Inout_ LPVOID pWorkBuffer, _In_ EapPeerMethodResultReason eapReason, _Inout_ EapPeerMethodResult *pEapPeerMethodResult, _Out_ EAP_ERROR **ppEapError);
        DWORD GetUIContext(_Inout_ LPVOID pWorkBuffer, _Out_ DWORD *pdwUIContextDataSize, _Out_bytecap_(*pdwUIContextDataSize) LPBYTE *ppbUIContextData, _Out_ EAP_ERROR **ppEapError);
        DWORD InvokeInteractiveUI(_In_ HWND hWndParent, _In_ SIZE_T nUIContextDataSize, _In_bytecount_(nUIContextDataSize) LPCVOID pUIContextData, _Out_ AL::EAP::CBlob &blobDataFromInteractiveUI, _Out_ EAP_ERROR **ppEapError);
        DWORD SetUIContext(_Inout_ LPVOID pWorkBuffer, _In_ SIZE_T nUIContextDataSize, _In_bytecount_(nUIContextDataSize) LPCVOID pUIContextData, _Out_ EAP_ERROR **ppEapError);

        //
        // Helper functions
        //
        DWORD RecordError(_Out_ EAP_ERROR **ppEapError, _In_ DWORD dwErrorCode, _In_ DWORD dwReasonCode, _In_ LPCGUID pRootCauseGuid, _In_ LPCGUID pRepairGuid, _In_ LPCGUID pHelpLinkGuid, _In_z_ LPCWSTR pszRootCauseString, _In_z_ LPCWSTR pszRepairString);
        DWORD FreeError(_Inout_ EAP_ERROR **ppEapError);
        BOOL DllMainImpl(_In_ HINSTANCE hInstance, _In_ DWORD dwReason, _In_ LPVOID pReserved);
    }

    //
    // RASEAP
    //
    namespace RASEAP {
        //
        // RASEAP Function API
        //
        typedef DWORD (APIENTRY *PINNERFREEMEMORY)(IN BYTE *pMemory);
        typedef DWORD (APIENTRY *PINNERGETINFO)(IN DWORD dwEapTypeId, IN PPP_EAP_INFO *pEapInfo);
        typedef DWORD (APIENTRY *PINNERGETIDENTITY)(IN DWORD dwEapTypeId, IN HWND hwndParent, IN DWORD dwFlags, IN LPCWSTR pwszPhonebook, IN LPCWSTR pwszEntry, IN const BYTE *pConnectionDataIn, IN DWORD dwSizeOfConnectionDataIn, IN const BYTE *pUserDataIn, IN DWORD dwSizeOfUserDataIn, OUT BYTE **ppbUserDataOut, OUT DWORD * pdwSizeOfUserDataOut, OUT WCHAR ** ppwszIdentity);
        typedef DWORD (APIENTRY *PINNERINVOKECONFIGUI)(IN DWORD dwEapTypeId, IN HWND hwndParent, IN DWORD dwFlags, IN BYTE *pConnectionDataIn, IN DWORD dwSizeOfConnectionDataIn, OUT BYTE **ppConnectionDataOut, OUT DWORD* pdwSizeOfConnectionDataOut);
        typedef DWORD (APIENTRY *PINNERINVOKEINTERACTIVEUI)(IN DWORD dwEapTypeId, IN HWND hWndParent, IN LPCBYTE pUIContextData, IN DWORD dwSizeofUIContextData, OUT LPBYTE* ppDataFromInteractiveUI, OUT DWORD* lpdwSizeOfDataFromInteractiveUI);

        //
        // RASEAP Peer Configuration
        //
        class CPeerData {
        public:
            CPeerData();
            DWORD Load(_In_ DWORD dwType);

        public:
            DWORD m_dwType;

            ATL::CAtlString m_sFriendlyName;
            ATL::CAtlString m_sPath;
            ATL::CAtlString m_sPathConfigUI;
            ATL::CAtlString m_sPathIdentity;
            ATL::CAtlString m_sPathInteractiveUI;

            DWORD m_dwInvokeUsernameDlg;
            DWORD m_dwInvokePasswordDlg;
        };

        //
        // RASEAP Peer Instance Base Class
        //
        class CPeerInstanceBase : public ATL::CAtlLibrary
        {
        public:
            CPeerInstanceBase();
            DWORD Load(_In_ LPCTSTR lpFileName);

        public:
            PINNERFREEMEMORY RasEapFreeMemory;
        };

        //
        // RASEAP Peer Instance
        //
        class CPeerInstance : public CPeerInstanceBase
        {
        public:
            CPeerInstance();
            DWORD Load(_In_ const CPeerData *pCfg);

        public:
            PINNERGETINFO RasEapGetInfo;
            PPP_EAP_INFO  m_info;
        };

        //
        // RASEAP Config UI Peer
        //
        class CPeerConfigUI : public CPeerInstanceBase
        {
        public:
            CPeerConfigUI();
            DWORD Load(_In_ const CPeerData *pCfg);

        public:
            PINNERINVOKECONFIGUI RasEapInvokeConfigUI;
        };

        //
        // RASEAP Interactive UI Peer
        //
        class CPeerInteractiveUI : public CPeerInstanceBase
        {
        public:
            CPeerInteractiveUI();
            DWORD Load(_In_ const CPeerData *pCfg);

        public:
            PINNERINVOKEINTERACTIVEUI RasEapInvokeInteractiveUI;
        };

        //
        // RASEAP Identity Peer
        //
        class CPeerIdentity : public CPeerInstanceBase
        {
        public:
            CPeerIdentity();
            DWORD Load(_In_ const CPeerData *pCfg);

        public:
            PINNERGETIDENTITY RasEapGetIdentity;
        };
    }

    //
    // TLS
    //
    namespace TLS {
        //
        // TLS state
        //
        enum STATE_T {
            STATE_START = 0,
            STATE_SERVER_HELLO,
            STATE_VERIFY_CERT_UI,
            STATE_CHANGE_CIPHER_SPEC,
            STATE_RESUME_SESSION,
            STATE_RESUME_SESSION_ACK,
            STATE_INNER_AUTHENTICATION,
            STATE_FINISHED
        };

        //
        // TLS UI type
        //
        enum UITYPE_T {
            UITYPE_Unknown = 0,
            UITYPE_VERIFY_CERT,
            UITYPE_INNER_EAP,
#ifdef AL_EAPHOST
            UITYPE_INNER_EAPHOST,
#endif
        };

        //
        // TLS inner authentication method
        //
        enum INNERMETHOD_T {
            INNERMETHOD_Unknown = 0,
            INNERMETHOD_PAP,
            INNERMETHOD_EAP,
#ifdef AL_EAPHOST
            INNERMETHOD_EAPHOST,
#endif
        };

        //
        // Certificate list
        //
        class CCertList : public ATL::CAtlList<ATL::Crypt::CCertContext>
        {
        public:
            BOOL AddCertificate(_In_  DWORD dwCertEncodingType, _In_  const BYTE *pbCertEncoded, _In_  DWORD cbCertEncoded);
        };

        //
        // TLS config data
        //
        class CConfigData {
        public:
            CConfigData();
            DWORD Save(_Inout_ IXMLDOMDocument2 *pXMLConfigDoc) const;
            DWORD Load(_In_ IXMLDOMDocument2 *pXMLConfigDoc);

        public:
            ATL::CAtlString m_sProviderID;

            //
            // Outer identity
            //
            ATL::CAtlStringW m_sOuterIdentity;

            //
            // Server certificate validation
            //
            CCertList m_lTrustedRootCAs;
            ATL::CAtlStringA m_sServerName;

            //
            // Inner authentication
            //
            INNERMETHOD_T m_InnerAuth;

            //
            // Alternative credential labels
            //
            ATL::CAtlString m_sAltCredentialLbl;
            ATL::CAtlString m_sAltIdentityLbl;
            ATL::CAtlString m_sAltPasswordLbl;

            //
            // Inner Credentials
            //
            ATL::CAtlStringW m_sIdentity;
            ATL::CAtlStringW m_sPassword;

            //
            // EAP Data
            // TODO: Split this class for PAP and RASEAP specific implementation.
            //
            ATL::CAtlArray<BYTE> m_aEAPConnectionData;
            ATL::CAtlArray<BYTE> m_aEAPUserData;

            //
            // Miscelaneous settings
            //
            BOOL m_fUseSessionResumption;
        };

        //
        // TLS session data
        //
        class CTLSSession {
        public:
            CTLSSession();
            void Reset();
            void ResetReceiveMsg();
            DWORD AddHandshakeMessage(_In_bytecount_(dwMessageSize) LPCBYTE pbMessage, _In_ SIZE_T nMessageSize);

        public:
            ATL::Crypt::CContext m_hCSP;

            STATE_T m_TLSState;

            BYTE m_pbPMS[AL_TLS_PMS_SIZE];

            ALG_ID m_algEncKey;
            DWORD m_dwEncKeySize; // 20 for SHA1, 24 for 3DES

            ALG_ID m_algMacKey;
            DWORD m_dwMacKeySize; // 20 for SHA1, 24 for 3DES
            BYTE m_pbMacWrite[AL_TLS_MAX_MAC];
            BYTE m_pbMacRead[AL_TLS_MAX_MAC];

            ATL::Crypt::CKey m_keyRead;
            ATL::Crypt::CKey m_keyWrite;

            ATL::CAtlList<ATL::Crypt::CCertContext> m_lCertificateChain;

            BYTE m_pbRandomClient[AL_TLS_RANDOM_SIZE];
            BYTE m_pbRandomServer[AL_TLS_RANDOM_SIZE];

            BYTE m_pbCipher[2];

            BYTE m_bCompression;

            ATL::CAtlList<ATL::CAtlArray<BYTE> > m_lHandshakeMsgs;

            ATL::CAtlArray<BYTE> m_aReceiveMsg;
            SIZE_T m_nReceiveCursor;

            DWORD m_dwSeqNum;

            BOOL m_fCipherSpec;
            BOOL m_fServerFinished;
            BOOL m_fFoundAlert;     // sent if something was wrong
            BOOL m_fSentFinished;   // we have sent our finished message
            BOOL m_fCertRequest;    // server requested certificate

            ATL::CAtlArray<BYTE> m_aState;

            ATL::CAtlArray<BYTE> m_aTLSSessionID;
            time_t m_tTLSSessionID; // the time this TTLS session ID was set
            BYTE m_pbMS[AL_TLS_MS_SIZE];

            AL::EAP::CPacket m_pktInnerEAPMsg;
        };


        //
        // TLS user data
        //
        class CUserData {
        public:
            CUserData();

        public:
            BOOL m_fPromptForCredentials;

            //
            // General user information
            //
            ATL::CAtlStringW m_sIdentity;
            ATL::CAtlStringW m_sPassword;
            BOOL m_fSaveCredentials;

            //
            // Stuff needed for session resumption
            //
            ATL::CAtlArray<BYTE> m_aTLSSessionID;
            time_t m_tTLSSessionID; // the time this TTLS session ID was set
            BYTE m_pbMS[AL_TLS_MS_SIZE];

            //
            // To see what happened in a previous session
            //
            EapPeerMethodResultReason m_EapReasonLast;

            //
            // Stuff needed for inner EAP authentication
            // TODO: Split this class for PAP and RASEAP specific implementation.
            //
            ATL::CAtlArray<BYTE> m_aEAPUserData;
        };

        //
        // TLS work buffer
        //
        class CSessionData {
        public:
            CSessionData(_In_opt_ HANDLE hTokenImpersonateUser = NULL, _In_opt_ LPCBYTE pbConnectionData = NULL, _In_opt_ LPCBYTE pbUserData = NULL, _In_opt_ const AL::CMonitor *pMonitor = NULL);
            virtual ~CSessionData();

        public:
            BYTE m_bCurrentMethodVersion;
            BYTE m_bNewMethodVersion;

            DWORD m_fFlags;

            HANDLE m_hTokenImpersonateUser;

            CTLSSession m_TLSSession;

            BYTE m_bPacketId;

            AL::EAP::CBlob m_blobDataForInteractiveUI;
            ATL::CAtlArray<BYTE> m_aDataFromInteractiveUI;

            CUserData m_user;

            BOOL m_fSaveConfigData;
            CConfigData m_cfg;

            struct INNERSESSIONDATA {
                //
                // Stuff needed for inner EAP authentication
                // TODO: Split this class for PAP and RASEAP specific implementation.
                //
                AL::RASEAP::CPeerData m_eapcfg;
                AL::RASEAP::CPeerInstance m_eap;

                LPBYTE m_pbSessionData;
#ifdef AL_EAPHOST
                EAP_SESSIONID m_eapSessionId;
#endif

                BOOL m_fHandledAccessReject;

                PPP_EAP_INPUT m_EapInput;

                AL::EAP::INNERSTATE_T m_EapState;
            } m_Inner;

            const AL::CMonitor *m_pMonitor;

            BOOL m_fSentEapExtensionSuccess;
        };

        DWORD EncBlock(_Inout_ CTLSSession *pTLSSession, _In_bytecount_(dwDataSize) LPCBYTE pbData, _In_ DWORD dwDataSize, _Out_bytecap_(*pdwEncBlockSize) LPBYTE *ppbEncBlock, _Out_ DWORD *pdwEncBlockSize);
        DWORD DecBlock(_In_ const CTLSSession *pTLSSession, _In_bytecount_(dwEncBlockSize) LPCBYTE pbEncBlock, _In_ DWORD dwEncBlockSize, _Out_bytecap_(*pdwRecordSize) LPBYTE *ppbRecord, _Out_ DWORD *pdwRecordSize);
        DWORD PRF(_In_ HCRYPTPROV hCSP, _In_bytecount_(dwSecretSize) LPCBYTE pbSecret, _In_ DWORD dwSecretSize, _In_bytecount_(dwLabelSize) LPCBYTE pbLabel, _In_ DWORD dwLabelSize, _In_bytecount_(dwSeedSize) LPCBYTE pbSeed, _In_ DWORD dwSeedSize, _Out_bytecap_(dwDataSize) LPBYTE pbData, _In_ DWORD dwDataSize);
        DWORD DeriveKeys(_Inout_ CTLSSession *pTLSSession);

        DWORD ParseServerPacket(_Inout_ CSessionData *pSessionData);
        DWORD ParseApplicationDataRecord(_Inout_ CSessionData *pSessionData, _In_bytecount_(dwRecordSize) LPCBYTE pbRecord, _In_ DWORD dwRecordSize);
        DWORD AddEAPMessage(_Inout_ CSessionData *pSessionData, _In_bytecount_(dwEAPAttributeSize) LPCBYTE pbEAPAttribute, _In_ DWORD dwEAPAttributeSize, _Inout_ AL::EAP::CPacket &pktSend, _Out_ EapPeerMethodOutput* pEapPeerMethodOutput);

        DWORD AuthMakeEAPResponseAttribute(IN BYTE bType, IN BYTE bPacketId, IN BYTE bFlags, IN LPCBYTE pbData, IN DWORD cbData, OUT LPBYTE *ppbEAPAttribute, OUT DWORD *pcbEAPAttribute);
        DWORD AuthMakeDiameterAttribute(DWORD dwType, LPCBYTE pbData, DWORD cbData, LPBYTE *ppbDiameter, DWORD *pcbDiameter);
        DWORD AuthHandleInnerAuthentication(_Inout_ CSessionData *pSessionData, _Out_ AL::EAP::CPacket &pktSend, _Out_ EapPeerMethodOutput* pEapPeerMethodOutput);

        namespace Record {
            DWORD MakeApplication(_Inout_ CTLSSession *pTLSSession, _In_bytecount_(dwMessageSize) LPCBYTE pbMessage, _In_ DWORD dwMessageSize, _Out_bytecap_(*pdwRecordSize) LPBYTE *ppbRecord, _Out_ DWORD *pdwRecordSize, _In_ BOOL bEncrypt);
            DWORD MakeHandshake(_Inout_ CTLSSession *pTLSSession, _In_bytecount_(dwMessageSize) LPCBYTE pbMessage, _In_ DWORD dwMessageSize, _Out_bytecap_(*pdwRecordSize) LPBYTE *ppbRecord, _Out_ DWORD *pdwRecordSize, _In_ BOOL bEncrypt);
            DWORD MakeChangeCipherSpec(_Out_bytecap_(*pdwRecordSize) LPBYTE *ppbRecord, _Out_ DWORD *pdwRecordSize);
        }

        namespace Msg {
            DWORD MakeClientHello(_Out_ BYTE pbRandomClient[AL_TLS_RANDOM_SIZE], _In_bytecount_(dwTLSSessionIDSize) LPCBYTE pbTLSSessionID, _In_ DWORD dwTLSSessionIDSize, _Out_bytecap_(*pdwTLSMessageSize) LPBYTE *ppbTLSMessage, _Out_ DWORD *pdwTLSMessageSize, _Out_ ALG_ID *palgEncKey, _Out_ DWORD *pdwEncKeySize, _Out_ ALG_ID *palgMacKey, _Out_ DWORD *pdwMacKeySize);
            DWORD MakeServerHello(_Out_ BYTE pbRandomServer[AL_TLS_RANDOM_SIZE], _In_bytecount_(dwTLSSessionIDSize) LPCBYTE pbTLSSessionID, _In_ DWORD dwTLSSessionIDSize, _Out_bytecap_(*pdwTLSMessageSize) LPBYTE *ppbTLSMessage, _Out_ DWORD *pdwTLSMessageSize, _Out_ ALG_ID *palgEncKey, _Out_ DWORD *pdwEncKeySize, _Out_ ALG_ID *palgMacKey, _Out_ DWORD *pdwMacKeySize);
            DWORD MakeCertificateRequest(_Out_bytecap_(*pdwTLSMessageSize) LPBYTE *ppbTLSMessage, _Out_ DWORD *pdwTLSMessageSize);
            DWORD MakeServerHelloDone(_Out_bytecap_(*pdwTLSMessageSize) LPBYTE *ppbTLSMessage, _Out_ DWORD *pdwTLSMessageSize);
            DWORD MakeClientCertificate(_Out_bytecap_(*pdwTLSMessageSize) LPBYTE *ppbTLSMessage, _Out_ DWORD *pdwTLSMessageSize);
            DWORD MakeServerCertificate(_In_ LPCBYTE pbServerCertSHA1, _Out_bytecap_(*pdwTLSMessageSize) LPBYTE *ppbTLSMessage, _Out_ DWORD *pdwTLSMessageSize);
            DWORD MakeClientKeyExchange(_In_bytecount_(dwEncPMSSize) LPCBYTE pbEncPMS, _In_ DWORD dwEncPMSSize, _Out_bytecap_(*pdwTLSMessageSize) LPBYTE *ppbTLSMessage, _Out_ DWORD *pdwTLSMessageSize);
            DWORD MakeFinished(_In_ const CTLSSession *pTLSSession, _In_bytecount_(dwLabelSize) LPCBYTE pbLabel, _In_ DWORD dwLabelSize, _In_bytecount_(dwMSSize) LPCBYTE pbMS, _In_ DWORD dwMSSize, _Out_bytecap_(*pdwTLSMessageSize) LPBYTE *ppbTLSMessage, _Out_ DWORD *pdwTLSMessageSize);
            DWORD VerifyFinished(_In_ const CTLSSession *pTLSSession, _In_bytecount_(dwLabelSize) LPCBYTE pbLabel, _In_ DWORD dwLabelSize, _In_bytecount_(dwMSSize) LPCBYTE pbMS, _In_ DWORD dwMSSize, _In_bytecount_(dwVerifyFinishedSize) LPCBYTE pbVerifyFinished, _In_ DWORD dwVerifyFinishedSize);
        }

        //
        // TLS dialogs
        //
        namespace DlgProc {
            INT_PTR CALLBACK Config(IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam);
            INT_PTR CALLBACK Credentials(IN  HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam);
            INT_PTR CALLBACK ServerUntrusted(IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam);
        }

        //
        // Certificate management
        //
        namespace Cert {
            DWORD VerifyChain(_In_ const ATL::CAtlList<ATL::Crypt::CCertContext> *plTrustedRootCAs, _In_ const ATL::CAtlList<ATL::Crypt::CCertContext> *plCertificateChain, _In_ POSITION posStart);
            DWORD VerifyInStore(_In_ PCCERT_CONTEXT pCertContext);
            DWORD VerifyServerName(_In_ const CConfigData *pConfigData, _In_ PCCERT_CONTEXT pCertContext);
        }
    }

    //
    // TTLS
    //
    namespace TTLS {
        DWORD ReadMessage(_Inout_ AL::TLS::CTLSSession *pTLSSession, _In_ BYTE bPacketId, _In_ const EapPacket *pReceivePacket, _Out_ AL::EAP::CPacket &pktSend, _Inout_ EapPeerMethodOutput *pEapPeerMethodOutput, _Out_ BYTE *pbMethodVersion, _In_ DWORD dwEAPPacketLength, _In_ BYTE bEapProtocolId, _In_ BYTE bVersion);
        DWORD SendMessage(_In_bytecount_(dwSendMsgSize) LPCBYTE pbSendMsg, _In_ DWORD dwSendMsgSize, _Inout_ DWORD *pdwSendCursor, _In_ BYTE bPacketId, _Inout_ AL::EAP::CPacket &pktSend, _Inout_ EapPeerMethodOutput *pEapPeerMethodOutput);
        DWORD BuildResponsePacket(_Inout_ AL::TLS::CTLSSession *pTLSSession, _In_ BYTE bPacketId, _Out_ AL::EAP::CPacket &pktSend, _Inout_ EapPeerMethodOutput *pEapPeerMethodOutput, _In_ BYTE bEapProtocolId, _In_ BYTE bFlags);
        DWORD ParseHandshakeRecord(_Inout_ AL::TLS::CTLSSession *pTLSSession, _In_bytecount_(dwRecordSize) LPCBYTE pbRecord, _In_ DWORD dwRecordSize);
        DWORD ParseInnerApplicationDataRecord(_Inout_ AL::TLS::CTLSSession *pTLSSession, _In_bytecount_(dwRecordSize) LPCBYTE pbRecord, _In_ DWORD dwRecordSize);
    }
}


//
// Inline functions
//

inline DWORD AL::Convert::N2H32(_In_count_c_(4) LPCBYTE pbNetworkFormat)
{
    return
        ((DWORD)(pbNetworkFormat[0]) << 24) |
        ((DWORD)(pbNetworkFormat[1]) << 16) |
        ((DWORD)(pbNetworkFormat[2]) <<  8) |
        ((DWORD)(pbNetworkFormat[3])      );
}


inline DWORD AL::Convert::N2H24(_In_count_c_(3) LPCBYTE pbNetworkFormat)
{
    return
        ((DWORD)(pbNetworkFormat[0]) << 16) |
        ((DWORD)(pbNetworkFormat[1]) <<  8) |
        ((DWORD)(pbNetworkFormat[2])      );
}


inline WORD AL::Convert::N2H16(_In_count_c_(2) LPCBYTE pbNetworkFormat)
{
    return
        ((WORD)(pbNetworkFormat[0]) << 8) |
        ((WORD)(pbNetworkFormat[1])     );
}


inline VOID AL::Convert::H2N32(_In_ DWORD dwHostFormat, _Out_cap_c_(4) LPBYTE pbNetworkFormat)
{
    pbNetworkFormat[0] = (BYTE)((dwHostFormat >> 24) & 0xff);
    pbNetworkFormat[1] = (BYTE)((dwHostFormat >> 16) & 0xff);
    pbNetworkFormat[2] = (BYTE)((dwHostFormat >>  8) & 0xff);
    pbNetworkFormat[3] = (BYTE)((dwHostFormat      ) & 0xff);
}


inline VOID AL::Convert::H2N24(_In_ DWORD dwHostFormat, _Out_cap_c_(3) LPBYTE pbNetworkFormat)
{
    pbNetworkFormat[0] = (BYTE)((dwHostFormat >> 16) & 0xff);
    pbNetworkFormat[1] = (BYTE)((dwHostFormat >>  8) & 0xff);
    pbNetworkFormat[2] = (BYTE)((dwHostFormat      ) & 0xff);
}


inline VOID AL::Convert::H2N16(_In_ WORD wHostFormat, _Out_cap_c_(2) LPBYTE pbNetworkFormat)
{
    pbNetworkFormat[0] = (BYTE)((wHostFormat >>  8) & 0xff);
    pbNetworkFormat[1] = (BYTE)((wHostFormat      ) & 0xff);
}


//
// Memory pack functions
//

// Primitive Data Types
template <class T>
inline VOID MemPack(_Inout_ BYTE **ppbCursor, _In_ const T &val)
{
    memcpy(*ppbCursor, &val, sizeof(T));
    *ppbCursor += sizeof(T);
}

template <class T>
inline SIZE_T MemGetPackedSize(_In_ const T &val)
{
    return sizeof(T);
}

template <class T>
inline VOID MemUnpack(_Inout_ const BYTE **ppbCursor, _Out_ T &val)
{
    memcpy(&val, *ppbCursor, sizeof(T));
    *ppbCursor += sizeof(T);
}


// Strings
template <class T>
inline VOID MemPack(_Inout_ BYTE **ppbCursor, _In_ const ATL::CStringT<T, StrTraitATL<T, ChTraitsCRT<T> > > &str)
{
    int nCount = str.GetLength();
    *(int*)*ppbCursor = nCount;
    *ppbCursor += sizeof(int);

    size_t nSize = sizeof(T)*nCount;
    memcpy(*ppbCursor, (const T*)str, nSize);
    *ppbCursor += nSize;
}

template <class T>
inline SIZE_T MemGetPackedSize(const ATL::CStringT<T, StrTraitATL<T, ChTraitsCRT<T> > > &str)
{
    return sizeof(int) + sizeof(T)*str.GetLength();
}

template <class T>
inline VOID MemUnpack(_Inout_ const BYTE **ppbCursor, _Out_ ATL::CStringT<T, StrTraitATL<T, ChTraitsCRT<T> > > &str)
{
    int nCount = *(int*)*ppbCursor;
    *ppbCursor += sizeof(int);

    T* szBuffer = str.GetBuffer(nCount);
    if (!szBuffer) AtlThrow(E_OUTOFMEMORY);
    size_t nSize = sizeof(T)*nCount;
    memcpy(szBuffer, *ppbCursor, nSize);
    *ppbCursor += nSize;
    str.ReleaseBuffer(nCount);
}


// Certificates
inline VOID MemPack(_Inout_ BYTE **ppbCursor, _In_ const ATL::Crypt::CCertContext &cc)
{
    *(DWORD*)*ppbCursor = cc->dwCertEncodingType;
    *ppbCursor += sizeof(DWORD);

    *(DWORD*)*ppbCursor = cc->cbCertEncoded;
    *ppbCursor += sizeof(DWORD);

    memcpy(*ppbCursor, cc->pbCertEncoded, cc->cbCertEncoded);
    *ppbCursor += cc->cbCertEncoded;
}

inline SIZE_T MemGetPackedSize(_In_ const ATL::Crypt::CCertContext &cc)
{
    return sizeof(DWORD) + sizeof(DWORD) + cc->cbCertEncoded;
}

inline VOID MemUnpack(_Inout_ const BYTE **ppbCursor, _Out_ ATL::Crypt::CCertContext &cc)
{
    DWORD dwCertEncodingType = *(DWORD*)*ppbCursor;
    *ppbCursor += sizeof(DWORD);

    DWORD dwCertEncodedSize = *(DWORD*)*ppbCursor;
    *ppbCursor += sizeof(DWORD);

    ATL::CTempBuffer<BYTE> pbCertEncoded(dwCertEncodedSize);
    memcpy(pbCertEncoded, *ppbCursor, dwCertEncodedSize);
    *ppbCursor += dwCertEncodedSize;
    cc.Create(dwCertEncodingType, pbCertEncoded, dwCertEncodedSize);
}


// Arrays of objects
template <class T>
inline VOID MemPack(_Inout_ BYTE **ppbCursor, _In_ const ATL::CAtlArray<T> &a)
{
    size_t nCount = a.GetCount();
    *(size_t*)*ppbCursor = nCount;
    *ppbCursor += sizeof(size_t);

    for (size_t i = 0; i < nCount; i++)
        MemPack(ppbCursor, a[i]);
}

template <class T>
inline SIZE_T MemGetPackedSize(_In_ const ATL::CAtlArray<T> &a)
{
    size_t nCount = a.GetCount();
    SIZE_T nSize = sizeof(size_t);

    for (size_t i = 0; i < nCount; i++)
        nSize += MemGetPackedSize(a[i]);

    return nSize;
}

template <class T>
inline VOID MemUnpack(_Inout_ const BYTE **ppbCursor, _Out_ ATL::CAtlArray<T> &a)
{
    size_t nCount = *(size_t*)*ppbCursor;
    *ppbCursor += sizeof(size_t);

    if (!a.SetCount(nCount)) AtlThrow(E_OUTOFMEMORY);
    for (size_t i = 0; i < nCount; i++)
        MemUnpack(ppbCursor, a[i]);
}


// Arrays of BYTEs
inline VOID MemPack(_Inout_ BYTE **ppbCursor, _In_ const ATL::CAtlArray<BYTE> &a)
{
    size_t nSize = a.GetCount();
    *(size_t*)*ppbCursor = nSize;
    *ppbCursor += sizeof(size_t);

    memcpy(*ppbCursor, a.GetData(), nSize);
    *ppbCursor += nSize;
}

inline SIZE_T MemGetPackedSize(_In_ const ATL::CAtlArray<BYTE> &a)
{
    return sizeof(size_t) + a.GetCount();
}

inline VOID MemUnpack(_Inout_ const BYTE **ppbCursor, _Out_ ATL::CAtlArray<BYTE> &a)
{
    size_t nSize = *(size_t*)*ppbCursor;
    *ppbCursor += sizeof(size_t);

    if (!a.SetCount(nSize)) AtlThrow(E_OUTOFMEMORY);
    memcpy(a.GetData(), *ppbCursor, nSize);
    *ppbCursor += nSize;
}


// Lists
template <class T>
inline VOID MemPack(_Inout_ BYTE **ppbCursor, _In_ const ATL::CAtlList<T> &list)
{
    size_t nCount = list.GetCount();
    *(size_t*)*ppbCursor = nCount;
    *ppbCursor += sizeof(size_t);

    for (POSITION pos = list.GetHeadPosition(); pos; list.GetNext(pos))
        MemPack(ppbCursor, list.GetAt(pos));
}

template <class T>
inline SIZE_T MemGetPackedSize(_In_ const ATL::CAtlList<T> &list)
{
    SIZE_T nSize = sizeof(size_t);

    for (POSITION pos = list.GetHeadPosition(); pos; list.GetNext(pos))
        nSize += MemGetPackedSize(list.GetAt(pos));

    return nSize;
}

template <class T>
inline VOID MemUnpack(_Inout_ const BYTE **ppbCursor, _Out_ ATL::CAtlList<T> &list)
{
    list.RemoveAll();

    size_t nCount = *(size_t*)*ppbCursor;
    *ppbCursor += sizeof(size_t);

    for (size_t i = 0; i < nCount; i++)
        MemUnpack(ppbCursor, list.GetAt(list.AddTail()));
}

// AL::TLS::CCertList
inline VOID MemPack(_Inout_ BYTE **ppbCursor, _In_ const AL::TLS::CCertList &cfg)
{
    MemPack(ppbCursor, (const ATL::CAtlList<ATL::Crypt::CCertContext>&)cfg);
}

inline SIZE_T MemGetPackedSize(_In_ const AL::TLS::CCertList &cfg)
{
    return MemGetPackedSize((const ATL::CAtlList<ATL::Crypt::CCertContext>&)cfg);
}

inline VOID MemUnpack(_Inout_ const BYTE **ppbCursor, _Out_ AL::TLS::CCertList &cfg)
{
    MemUnpack(ppbCursor, (ATL::CAtlList<ATL::Crypt::CCertContext>&)cfg);
}

// AL::TLS::CConfigData
VOID MemPack(_Inout_ BYTE **ppbCursor, _In_ const AL::TLS::CConfigData &cfg);
SIZE_T MemGetPackedSize(_In_ const AL::TLS::CConfigData &cfg);
VOID MemUnpack(_Inout_ const BYTE **ppbCursor, _Out_ AL::TLS::CConfigData &cfg);

// AL::TLS::CUserData
VOID MemPack(_Inout_ BYTE **ppbCursor, _In_ const AL::TLS::CUserData &user);
SIZE_T MemGetPackedSize(_In_ const AL::TLS::CUserData &user);
VOID MemUnpack(_Inout_ const BYTE **ppbCursor, _Out_ AL::TLS::CUserData &user);


#endif // !defined(RC_INVOKED) && !defined(MIDL_PASS)
#endif // __AL_COMMON__
