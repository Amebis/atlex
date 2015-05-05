/*
    Copyright 1991-2015 Amebis

    This file is part of ArnesLink.

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


BOOL AL::TLS::CCertList::AddCertificate(_In_  DWORD dwCertEncodingType, _In_  const BYTE *pbCertEncoded, _In_  DWORD cbCertEncoded)
{
    ATL::Crypt::CCertContext cc;
    if (cc.Create(dwCertEncodingType, pbCertEncoded, cbCertEncoded)) {
        for (POSITION pos = GetHeadPosition(); ; GetNext(pos)) {
            if (pos) {
                const ATL::Crypt::CCertContext &cc2 = GetAt(pos);
                if (cc->cbCertEncoded == cc2->cbCertEncoded &&
                    memcmp(cc->pbCertEncoded, cc2->pbCertEncoded, cc->cbCertEncoded) == 0)
                {
                    // This certificate is already on the list.
                    return FALSE;
                }
            } else {
                ATL::Crypt::CCertContext &cc2 = GetAt(AddTail());
                cc2.Attach(cc.Detach());
                return TRUE;
            }
        }
    } else {
        AL_TRACE_WARNING(_T("CertCreateCertificateContext failed (%ld)."), GetLastError());
        return FALSE;
    }
}


