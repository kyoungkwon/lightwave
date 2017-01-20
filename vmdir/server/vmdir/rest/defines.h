/*
 * Copyright © 2012-2015 VMware, Inc.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the “License”); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS, without
 * warranties or conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#define MAX_HTTP_PAYLOAD_LENGTH                 4086
#define HTTP_PORT_NUMBER                        "7477"

#define BAIL_ON_VMDIR_REST_ERROR(dwError, pOperation, pHttp) \
    if (dwError) \
    { \
        if (pHttp && !pHttp->bIsResponseCreated) \
        { \
            PCSTR pszErrorMsg = ""; \
            PCSTR pszResult = "[]"; \
            PCSTR pszAdditionalInfo = ""; \
            DWORD dwLdapErrorCode = 0; \
            \
            if (pOperation && ((PVDIR_OPERATION)pOperation)->ldapResult.pszErrMsg) \
            { \
                pszErrorMsg = ((PVDIR_OPERATION)pOperation)->ldapResult.pszErrMsg; \
                dwLdapErrorCode = ((PVDIR_OPERATION)pOperation)->ldapResult.errCode; \
            } \
            else \
            { \
                dwLdapErrorCode = VmDirToLDAPError(dwError); \
            } \
            \
            VmDirHttpCreateRESTResponsePayload( \
                                    dwLdapErrorCode, \
                                    pszErrorMsg, \
                                    pszAdditionalInfo, \
                                    pszResult, \
                                    pHttp \
                                    ); \
        } \
        goto error; \
    }

//FIXME Appropriate VMDIR Error?
#define BAIL_ON_CURL_REQUEST_SEND_ERROR(curlResultCode) \
    if (curlResultCode != CURLE_OK) \
    { \
        dwError = VMDIR_ERROR_GENERIC; \
        BAIL_ON_VMDIR_ERROR(dwError); \
    }
