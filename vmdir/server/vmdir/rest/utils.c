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


#include "../includes.h"
#include <sasl/saslutil.h>      /* base64 decode */

DWORD
VmDirHttpGetAllAttributeValues(
    PVDIR_ATTRIBUTE pAttr,
    PSTR*           ppszAttrVals
    )
{
    DWORD dwError = 0;
    unsigned int iVal = 0;
    PSTR pszEncodedData = NULL;
    PSTR pszAttrVals = NULL;
    int len = 0;

    if (pAttr == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    for (iVal = 0; iVal < pAttr->numVals; iVal++)
    {
        PCSTR pszValComma = ",";
        if (!(iVal + 1 < pAttr->numVals))
        {
            pszValComma = "";
        }
        /* Need to encode Octet String */
        //FIXME Add Method to check for Security Descriptor
        if (VmDirSchemaAttrIsOctetString(pAttr->pATDesc) ||
                VmDirStringCompareA(pAttr->pATDesc->pszName, ATTR_OBJECT_SECURITY_DESCRIPTOR, FALSE) == 0)
        {
            dwError = VmDirAllocateMemory(pAttr->vals[iVal].lberbv_len * 2 + 1, (PVOID*)&pszEncodedData);
            BAIL_ON_VMDIR_ERROR(dwError);

            sasl_encode64(
                    pAttr->vals[iVal].lberbv_val,
                    pAttr->vals[iVal].lberbv_len,
                    pszEncodedData,
                    pAttr->vals[iVal].lberbv_len * 2 + 1,
                    &len
                    );

            pszEncodedData[len] = '\0';

            dwError = VmDirCatStringPrintf(&pszAttrVals, "\"%s\"%s", pszEncodedData, pszValComma);
            BAIL_ON_VMDIR_ERROR(dwError);

            VMDIR_SAFE_FREE_STRINGA(pszEncodedData);
        }
        else
        {
            dwError = VmDirCatStringPrintf(&pszAttrVals, "\"%s\"%s", pAttr->vals[iVal].lberbv_val, pszValComma);
            BAIL_ON_VMDIR_ERROR(dwError);
        }
    }

    *ppszAttrVals = pszAttrVals;
    pszAttrVals = NULL;

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszAttrVals);
    VMDIR_SAFE_FREE_STRINGA(pszEncodedData);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Callback write function for server initiated REST Request
 * It will store data from curl response
 */
size_t
VmDirHttpRESTWriteCallBack(
    PVOID  pContents,
    size_t size,
    size_t nmemb,
    PVOID  pResponse
    )
{
    DWORD dwError = 0;
    PVMDIR_REST_RECEIVED_RESPONSE pRESTReceivedResponse = NULL;
    size_t responseSize = size * nmemb;

    pRESTReceivedResponse = (PVMDIR_REST_RECEIVED_RESPONSE)pResponse;

    dwError = VmDirReallocateMemory(
                        (PVOID) pRESTReceivedResponse->pszResponse,
                        (PVOID) &(pRESTReceivedResponse->pszResponse),
                        pRESTReceivedResponse->size + responseSize + 1
                        );
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirCopyMemory(
                        pRESTReceivedResponse->pszResponse + pRESTReceivedResponse->size,
                        responseSize,
                        pContents,
                        responseSize
                        );
    BAIL_ON_VMDIR_ERROR(dwError);

    pRESTReceivedResponse->size = pRESTReceivedResponse->size + responseSize;
    pRESTReceivedResponse->pszResponse[pRESTReceivedResponse->size] = 0;

cleanup:
    return responseSize;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Check response status in received REST response
 */
DWORD
VmDirHttpIsRESTRequestSucceeded(
    PVMDIR_HTTP pHttp,
    PSTR        pszResponse,
    BOOLEAN*    pbIsRESTRequestSucceeded
    )
{
    DWORD dwError = 0;
    BOOLEAN bIsRESTRequestSucceeded = FALSE;
    json_t *pjRoot = NULL;
    json_error_t jError;
    json_t *pjLdapStatus = NULL;
    json_t *pjErrorMessage = NULL;
    json_t *pjAdditionalInfo = NULL;
    PCSTR pszLdapStatus = NULL;
    PCSTR pszErrorMeesage = NULL;
    PCSTR pszAdditionalInfo = NULL;
    int iLdapStatusCode = 0;

    if (pszResponse == NULL || pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    pjRoot = json_loads(pszResponse, 0, &jError);
    if (!pjRoot)
    {
        //FIXME Check this error type
        dwError = VMDIR_ERROR_INVALID_RESULT;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    if (!json_is_object(pjRoot))
    {
        //FIXME Check this error type
        dwError = VMDIR_ERROR_INVALID_RESULT;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    pjLdapStatus = json_object_get(pjRoot, "ldap-status");
    if (!json_is_string(pjLdapStatus))
    {
        //FIXME Check this error type
        dwError = VMDIR_ERROR_INVALID_RESULT;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }
    pszLdapStatus = json_string_value(pjLdapStatus);

    pjErrorMessage = json_object_get(pjRoot, "error-message");
    if (!json_is_string(pjErrorMessage))
    {
        //FIXME Check this error type
        dwError = VMDIR_ERROR_INVALID_RESULT;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }
    pszErrorMeesage = json_string_value(pjErrorMessage);

    pjAdditionalInfo = json_object_get(pjRoot, "additional-info");
    if (!json_is_string(pjAdditionalInfo))
    {
        //FIXME Check this error type
        dwError = VMDIR_ERROR_INVALID_RESULT;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }
    pszAdditionalInfo = json_string_value(pjAdditionalInfo);

    if (strcmp(pszLdapStatus, "0") == 0)
    {
        dwError = VmDirCatStringPrintf(
                            &(pHttp->pRESTResponseToSend->pszAdditionalInfo),
                            " %s ",
                            pszAdditionalInfo
                            );
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

        bIsRESTRequestSucceeded = TRUE;
    }
    else
    {
        iLdapStatusCode = VmDirStringToIA(pszLdapStatus);

        dwError = VmDirHttpCreateRESTResponsePayload(
                                    (DWORD)iLdapStatusCode,
                                    pszErrorMeesage,
                                    pszAdditionalInfo,
                                    "[]",
                                    pHttp
                                    );
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

        bIsRESTRequestSucceeded = FALSE;
    }

    *pbIsRESTRequestSucceeded = bIsRESTRequestSucceeded;

cleanup:
    if (pjRoot)
    {
        json_decref(pjRoot);
        pjRoot = NULL;
    }
    return dwError;

error:
    goto cleanup;
}

/*
 * This function builds up an enormous string to return to the client as
 * there is not yet an HTTP 'write' function available.
 */
ULONG
VmDirCatStringPrintf(
    OUT PSTR*   ppszString,
    IN PCSTR    pszFormat,
    IN ...
    )
{
    DWORD dwError = 0;
    va_list args;
    PSTR pszString = NULL;

    va_start(args, pszFormat);
    dwError = VmDirAllocateStringPrintfV(&pszString, pszFormat, args);
    va_end(args);
    BAIL_ON_VMDIR_ERROR(dwError);

    size_t len = *ppszString ? strlen(*ppszString) : 0;
    dwError = VmDirReallocateMemory((PVOID) *ppszString, (PVOID) ppszString, len + strlen(pszString) + 1);
    BAIL_ON_VMDIR_ERROR(dwError);

    strcpy(*ppszString + len, pszString);

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszString);
    return dwError;
error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
        "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Allocates tokens based on a delimeter.
*/
DWORD
VmDirGetComponent(
    PCSTR*  ppszString,
    int     delim,
    PSTR*   ppszComponent
    )
{
    DWORD dwError = 0;
    PCSTR pszStart = NULL;
    PCSTR pszEnd = NULL;
    PCSTR pszString = NULL;
    PSTR pszComponent = NULL;

    assert(ppszComponent != NULL);

    pszStart = ppszString ? *ppszString : NULL;
    pszEnd = pszStart ? strchr(pszStart, delim) : NULL;
    if (pszEnd)
    {
        dwError = VmDirAllocateStringOfLenA(
                    pszStart,
                    pszEnd - pszStart,
                    &pszComponent);
        BAIL_ON_VMDIR_ERROR(dwError);

        pszString = pszEnd + 1;
    }
    else if (pszStart && *pszStart)
    {
        dwError = VmDirAllocateStringA(pszStart, &pszComponent);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    if (ppszString)
    {
        *ppszString = pszString;
    }
    *ppszComponent = pszComponent;

cleanup:
    return dwError;
error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
        "%s failed, error (%d)", __FUNCTION__, dwError );
    VmDirFreeStringA(pszComponent);
    goto cleanup;
}

static
DWORD
_VmDirParseUriManage(
    PCSTR       pszUri,
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;
    PCSTR pUriHaystack = NULL;
    PSTR pszOperation = NULL;
    PSTR pszDomainDN = NULL;

    if (pHttp == NULL || pszUri == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    pUriHaystack = pszUri;

    dwError = VmDirGetComponent(&pUriHaystack, '\0', &pszOperation);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    if (!strcmp(pszOperation, "topology"))
    {
        pszDomainDN = gVmdirServerGlobals.systemDomainDN.lberbv.bv_val;
        if (pszDomainDN == NULL)
        {
            dwError = ERROR_INVALID_STATE;
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
        }
        if (!strcmp(pHttp->pszMethod, "GET"))
        {
            pHttp->restOp = VDIR_REST_OPERATION_GET_TOPOLOGY;
        }
        else
        {
            dwError = VMDIR_ERROR_INVALID_REQUEST;
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
        }
    }
    else if (!strcmp(pszOperation, "computers"))
    {
        pszDomainDN = gVmdirServerGlobals.systemDomainDN.lberbv.bv_val;
        if (pszDomainDN == NULL)
        {
            dwError = ERROR_INVALID_STATE;
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
        }
        if (!strcmp(pHttp->pszMethod, "GET"))
        {
            pHttp->restOp = VDIR_REST_OPERATION_GET_COMPUTERS;
        }
        else
        {
            dwError = VMDIR_ERROR_INVALID_REQUEST;
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
        }
    }
    else if (!strcmp(pszOperation, "dc"))
    {
        pszDomainDN = gVmdirServerGlobals.systemDomainDN.lberbv.bv_val;
        if (pszDomainDN == NULL)
        {
            dwError = ERROR_INVALID_STATE;
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
        }
        if (!strcmp(pHttp->pszMethod, "GET"))
        {
            pHttp->restOp = VDIR_REST_OPERATION_GET_DCINFO;
        }
        else
        {
            dwError = VMDIR_ERROR_INVALID_REQUEST;
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
        }
    }
    else if (!strcmp(pszOperation, "replication"))
    {
        // FIXME verify method type of this
        if (!strcmp(pHttp->pszMethod, "POST"))
        {
            pHttp->restOp = VDIR_REST_OPERATION_REPLNOW;
        }
        else if (!strcmp(pHttp->pszMethod, "PUT"))
        {
            pHttp->restOp = VDIR_REST_OPERATION_ADD_REPL_PARTNER;
            dwError = VmDirHttpGetRequestPayload(pHttp->pRestReq, pHttp);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
        }
        else if (!strcmp(pHttp->pszMethod, "DELETE"))
        {
            pHttp->restOp = VDIR_REST_OPERATION_REMOVE_REPL_PARTNER;
            dwError = VmDirHttpGetRequestPayload(pHttp->pRestReq, pHttp);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
        }
        else
        {
            dwError = VMDIR_ERROR_INVALID_REQUEST;
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
        }
    }
    else
    {
        dwError = VMDIR_ERROR_INVALID_REQUEST;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    if (pszDomainDN != NULL)
    {
        /* Need to allocate memory as we can't refer global variable directly */
        dwError = VmDirAllocateStringPrintf(&(pHttp->pszDn), "%s", pszDomainDN);
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    pszDomainDN = NULL;

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszOperation);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
        "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Expects input like
 * cn=Users,dc=vsphere,dc=local/subtree/(objectclass=*)/cn,telephoneNumber/308
 * where we have the dn, the scope, the filter, the attributes to return, and
 * a cookie for paged results.
*/
static
DWORD
_VmDirParseUriLdap(
    PCSTR       pszUri,
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;
    PCSTR pUriHaystack = NULL;
    PCSTR pPathHaystack = NULL;
    PCSTR pQueryHaystack = NULL;
    PSTR pszPath = NULL;
    PSTR pszQuery = NULL;
    PSTR pszDn = NULL;
    PSTR pszScope = NULL;
    ber_int_t scope = LDAP_SCOPE_DEFAULT;
    PSTR pszFilter = NULL;
    PSTR pszAttrs = NULL;
    PSTR pszAttrVal = NULL;
    PSTR pAttr = NULL;
    PSTR pVal = NULL;
    PSTR pszPageCookie = NULL;
    PSTR pszPageSize = NULL;

    if (pHttp == NULL || pszUri == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    pUriHaystack = pszUri;

    /* URI will have the form  /path/to/resource?query1=val1&query2=val2 */
    dwError = VmDirGetComponent(&pUriHaystack, '?', &pszPath);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = VmDirGetComponent(&pUriHaystack, '\0', &pszQuery);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    pPathHaystack = pszPath;
    dwError = VmDirGetComponent(&pPathHaystack, '/', &pszDn);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = VmDirGetComponent(&pPathHaystack, '/', &pszScope);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    if (!pszScope)
    {
        scope = LDAP_SCOPE_BASE;
    }
    else if (!strcmp(pszScope, "subtree") ||
             !strcmp(pszScope, "sub"))
    {
        scope = LDAP_SCOPE_SUBTREE;
    }
    else if (!strcmp(pszScope, "base"))
    {
        scope = LDAP_SCOPE_BASE;
    }
    else if (!strcmp(pszScope, "one") ||
             !strcmp(pszScope, "onelevel"))
    {
        scope = LDAP_SCOPE_ONE;
    }
    if (scope == LDAP_SCOPE_DEFAULT)
    {
        // FIXME Log here or else where?
        scope = LDAP_SCOPE_BASE;
    }

    dwError = VmDirGetComponent(&pPathHaystack, '/', &pszFilter);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    if (!pszFilter || !*pszFilter)
    {
        VMDIR_SAFE_FREE_STRINGA(pszFilter);

        dwError = VmDirAllocateStringA("(objectclass=*)", &pszFilter);
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = VmDirGetComponent(&pPathHaystack, '/', &pszAttrs);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    if (!pszAttrs || !*pszAttrs)
    {
        VMDIR_SAFE_FREE_STRINGA(pszAttrs);
    }

    pQueryHaystack = pszQuery;
    while (pQueryHaystack && *pQueryHaystack)
    {
        PSTR pEqual = NULL;

        dwError = VmDirGetComponent(&pQueryHaystack, '&', &pszAttrVal);
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

        pEqual = strchr(pszAttrVal, '=');
        if (pEqual)
        {
            *pEqual = '\0';
            pVal = pEqual + 1;
            pAttr = pszAttrVal;
            if (!strcmp(pAttr, "pageCookie"))
            {
                VMDIR_SAFE_FREE_STRINGA(pszPageCookie);

                dwError = VmDirAllocateStringA(pVal, &pszPageCookie);
                BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
            }
            if (!strcmp(pAttr, "pageSize"))
            {
                VMDIR_SAFE_FREE_STRINGA(pszPageSize);
                dwError = VmDirAllocateStringA(pVal, &pszPageSize);
                BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
            }
        }
        VMDIR_SAFE_FREE_STRINGA(pszAttrVal);
    }

    pHttp->pszDn = pszDn; pszDn = NULL;
    pHttp->pszScope = pszScope; pszScope = NULL;
    pHttp->scope = scope;
    pHttp->pszFilter = pszFilter; pszFilter = NULL;
    pHttp->pszAttrs = pszAttrs; pszAttrs = NULL;
    pHttp->pszPageCookie = pszPageCookie; pszPageCookie = NULL;
    if (pszPageSize)
    {
        pHttp->uiPageSize = atoi(pszPageSize);
    }

    /* Determine REST operation type */
    if (!strcmp(pHttp->pszMethod, "PUT"))
    {
        pHttp->restOp = VDIR_REST_OPERATION_ADD;
        dwError = VmDirHttpGetRequestPayload(pHttp->pRestReq, pHttp);
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }
    else if (!strcmp(pHttp->pszMethod, "PATCH"))
    {
        pHttp->restOp = VDIR_REST_OPERATION_PATCH;
        dwError = VmDirHttpGetRequestPayload(pHttp->pRestReq, pHttp);
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }
    else if (!strcmp(pHttp->pszMethod, "GET"))
    {
        pHttp->restOp = VDIR_REST_OPERATION_SEARCH;
    }
    else if (!strcmp(pHttp->pszMethod, "DELETE"))
    {
        pHttp->restOp = VDIR_REST_OPERATION_DELETE;
    }

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszPath);
    return dwError;

error:
    VMDIR_SAFE_FREE_STRINGA(pszDn);
    VMDIR_SAFE_FREE_STRINGA(pszScope);
    VMDIR_SAFE_FREE_STRINGA(pszFilter);
    VMDIR_SAFE_FREE_STRINGA(pszAttrs);
    VMDIR_SAFE_FREE_STRINGA(pszPageCookie);
    VMDIR_SAFE_FREE_STRINGA(pszPageSize);
    goto cleanup;
}

DWORD
VmDirParseUri(
    PCSTR           pszFullUri,
    PVMDIR_HTTP     pHttp
    )
{
    DWORD dwError = 0;
    const char szLdap[] = "/vmdir/ldap/";
    const char szManage[] = "/vmdir/manage/";

    if (pszFullUri == NULL || pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    if (!strncmp(pszFullUri, szLdap, sizeof(szLdap) - 1))
    {
        dwError = _VmDirParseUriLdap(pszFullUri + (sizeof(szLdap) - 1), pHttp);
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }
    else if (!strncmp(pszFullUri, szManage, sizeof(szManage) - 1))
    {
        dwError = _VmDirParseUriManage(pszFullUri + (sizeof(szManage) - 1), pHttp);
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }
    else
    {
        dwError = VMDIR_ERROR_INVALID_REQUEST;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    /* Ensure that it is a valid request */
    if (pHttp->restOp == 0)
    {
        dwError = VMDIR_ERROR_INVALID_REQUEST;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
        "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * This will create Access Info for REST operations.
 */
DWORD
VmDirHttpCreateAccessInfo(
    PVMDIR_HTTP         pHttp,
    PVDIR_CONNECTION    pConn
    )
{
    DWORD dwError = 0;

    if (pHttp == NULL || pConn == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    pConn->bIsAnonymousBind = FALSE;
    pConn->AccessInfo.pAccessToken = pHttp->pToken;
    pHttp->pToken = NULL;
    pConn->AccessInfo.pszBindedObjectSid = pHttp->pszBindedObjectSid;
    pHttp->pszBindedObjectSid = NULL;

    dwError = VmDirAllocateStringA(pHttp->pEntry->dn.lberbv.bv_val,
                                            &(pConn->AccessInfo.pszBindedDn));
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = VmDirAllocateStringA(BERVAL_NORM_VAL(pHttp->pEntry->dn),
                                            &(pConn->AccessInfo.pszNormBindedDn));
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
        "%s failed, error (%d)", __FUNCTION__, dwError);
    if (pHttp->pToken)
    {
        VmDirReleaseAccessToken(&pHttp->pToken);
    }
    if (pConn != NULL)
    {
        VMDIR_SAFE_FREE_MEMORY(pConn->AccessInfo.pszBindedDn);
        VMDIR_SAFE_FREE_MEMORY(pConn->AccessInfo.pszNormBindedDn);
        VMDIR_SAFE_FREE_MEMORY(pConn->AccessInfo.pszBindedObjectSid);
    }
    goto cleanup;
}
