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

/*
 * Performs Add operation. Input JSON data should be there in
 * pHttp->pszInputJson before calling this.
 * Only one entry is allowed to add per call.
 */
DWORD
VmDirHttpAddRequestHandler(
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;
    VDIR_OPERATION op = {0};
    VDIR_BERVALUE bvDN = VDIR_BERVALUE_INIT;

    if (pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);
    }

    dwError = VmDirInitStackOperation(&op, VDIR_OPERATION_TYPE_INTERNAL, LDAP_REQ_ADD, NULL);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    bvDN.lberbv.bv_val = pHttp->pszDn;
    bvDN.lberbv.bv_len = VmDirStringLenA(bvDN.lberbv.bv_val);

    dwError = VmDirBervalContentDup(&bvDN, &op.reqDn);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    op.pBEIF = VmDirBackendSelect(NULL);

    dwError = VmDirHttpParseJSONToAdd(pHttp, &op);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpCreateAccessInfo(pHttp, op.conn);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirInternalAddEntry(&op);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpCreateRESTResponsePayload(
                                    op.ldapResult.errCode,
                                   "",
                                   "",
                                   "[]",
                                   pHttp
                                   );
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

cleanup:
    VmDirFreeBervalContent(&bvDN);
    VmDirFreeOperationContent(&op);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
        "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Performs Search operation.
 * Only entries for which user has access right will be returned.
 */
DWORD
VmDirHttpSearchRequestHandler(
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;
    VDIR_ENTRY_ARRAY  entryArray = {0};
    PSTR pszAnswer = NULL;
    PSTR pszPageCookie = NULL;
    VDIR_OPERATION op = {0};

    if (pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);
    }

    if (pHttp->pszPageCookie)
    {
        pszPageCookie = pHttp->pszPageCookie;
    }

    if (pHttp->pszWWWAuthenticateToken)
    {
        dwError = VmRESTSetHttpHeader(pHttp->ppRestRes, "WWW-Authenticate", pHttp->pszWWWAuthenticateToken);
        BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);
    }

    dwError = VmDirInitStackOperation(&op, VDIR_OPERATION_TYPE_INTERNAL, LDAP_REQ_SEARCH, NULL);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpCreateAccessInfo(pHttp, op.conn);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirFilterInternalSearch(
                    pHttp->pszDn,
                    pHttp->scope,
                    pHttp->pszFilter,
                    pHttp->uiPageSize,
                    &pszPageCookie,
                    &entryArray);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpBuildJSONSearchResponse(pHttp, &entryArray, pszPageCookie, &op, &pszAnswer);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpCreateRESTResponsePayload(
                                       op.ldapResult.errCode,
                                       "",
                                       "",
                                       pszAnswer,
                                       pHttp
                                       );
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

cleanup:
    if (pszPageCookie != pHttp->pszPageCookie)
    {
        VMDIR_SAFE_FREE_STRINGA(pszPageCookie);
    }
    VMDIR_SAFE_FREE_STRINGA(pszAnswer);
    VmDirFreeEntryArrayContent(&entryArray);
    VmDirFreeOperationContent(&op);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Performs PATCH operation
 */
DWORD
VmDirHttpModifyRequestHandler(
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;
    VDIR_OPERATION op = {0};
    VDIR_BERVALUE bvDN = VDIR_BERVALUE_INIT;

    if (pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);
    }

    dwError = VmDirInitStackOperation(&op, VDIR_OPERATION_TYPE_INTERNAL, LDAP_REQ_MODIFY, NULL);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    bvDN.lberbv.bv_val = pHttp->pszDn;
    bvDN.lberbv.bv_len = VmDirStringLenA(bvDN.lberbv.bv_val);

    dwError = VmDirBervalContentDup( &bvDN, &op.reqDn );
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirBervalContentDup( &op.reqDn, &op.request.modifyReq.dn );
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    op.pBEIF = VmDirBackendSelect(op.reqDn.lberbv.bv_val);

    dwError = VmDirHttpParseJSONToModify(pHttp, &op);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpCreateAccessInfo(pHttp, op.conn);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirInternalModifyEntry(&op);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpCreateRESTResponsePayload(
                                    op.ldapResult.errCode,
                                    "",
                                    "",
                                    "[]",
                                    pHttp
                                    );
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

cleanup:
    VmDirFreeBervalContent(&bvDN);
    VmDirFreeOperationContent(&op);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Performs Delete operation
 */
DWORD
VmDirHttpDeleteRequestHandler(
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;

    if (pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = VmDirHttpDelete(pHttp);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = VmDirHttpCreateRESTResponsePayload(
                                        LDAP_SUCCESS,
                                        "",
                                        "",
                                        "[]",
                                        pHttp
                                        );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
        "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

DWORD
VmDirHttpGetDCInfoRequestHandler(
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;
    PSTR pszAnswer = NULL;
    VDIR_OPERATION op = {0};
    PVMDIR_DC_INFO* ppDCInfo = NULL;
    PSTR pszDCInfo = NULL;
    DWORD dwNumDC = 0;

    if (pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);
    }

    dwError = VmDirInitStackOperation(&op, VDIR_OPERATION_TYPE_INTERNAL, LDAP_REQ_SEARCH, NULL);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpCreateAccessInfo(pHttp, op.conn);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpGetDCInfo(pHttp, &op, &ppDCInfo, &dwNumDC);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirCatStringPrintf(&pszAnswer, "{\n");
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpBuildJSONGetDCInfo(ppDCInfo, dwNumDC, &pszDCInfo);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirCatStringPrintf(&pszAnswer, pszDCInfo);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirCatStringPrintf(&pszAnswer, "\n}");
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpCreateRESTResponsePayload(
                                        op.ldapResult.errCode,
                                        "",
                                        "",
                                        pszAnswer,
                                        pHttp
                                        );
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszAnswer);
    VMDIR_SAFE_FREE_STRINGA(pszDCInfo);
    VmDirFreeDCInfoArray(ppDCInfo, dwNumDC);
    VmDirFreeOperationContent(&op);
    return dwError;
error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
        "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

DWORD
VmDirHttpGetComputersRequestHandler(
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;
    PSTR pszAnswer = NULL;
    VDIR_OPERATION op = {0};
    DWORD dwNumComputers = 0;
    PSTR pszComputers = NULL;
    PSTR* ppszComputers = NULL;

    if (pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);
    }

    dwError = VmDirInitStackOperation(&op, VDIR_OPERATION_TYPE_INTERNAL, LDAP_REQ_SEARCH, NULL);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpCreateAccessInfo(pHttp, op.conn);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpGetComputers(pHttp, &op, &ppszComputers, &dwNumComputers);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirCatStringPrintf(&pszAnswer, "{\n");
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpBuildJSONGetComputers(ppszComputers, dwNumComputers, &pszComputers);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirCatStringPrintf(&pszAnswer, pszComputers);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirCatStringPrintf(&pszAnswer, "\n}");
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpCreateRESTResponsePayload(
                                        op.ldapResult.errCode,
                                        "",
                                        "",
                                        pszAnswer,
                                        pHttp
                                        );
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszAnswer);
    VMDIR_SAFE_FREE_STRINGA(pszComputers);
    VmDirFreeStringArray(ppszComputers, dwNumComputers);
    VmDirFreeOperationContent(&op);
    return dwError;
error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
        "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Return info related to DCs and their replication partners
 * Also return all computers info along with DCs
 */
DWORD
VmDirHttpGetTopologyRequestHandler(
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;
    PSTR pszAnswer = NULL;
    VDIR_OPERATION op = {0};
    PVMDIR_DC_INFO* ppDCInfo = NULL;
    PSTR* ppszComputers = NULL;
    PSTR pszComputers = NULL;
    PSTR pszDCInfo = NULL;
    DWORD dwNumDC = 0;
    DWORD dwNumComputers = 0;

    if (pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);
    }

    dwError = VmDirInitStackOperation(&op, VDIR_OPERATION_TYPE_INTERNAL, LDAP_REQ_SEARCH, NULL);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpCreateAccessInfo(pHttp, op.conn);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpGetDCInfo(pHttp, &op, &ppDCInfo, &dwNumDC);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpGetComputers(pHttp, &op, &ppszComputers, &dwNumComputers);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirCatStringPrintf(&pszAnswer, "{\n");
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpBuildJSONGetDCInfo(ppDCInfo, dwNumDC, &pszDCInfo);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirCatStringPrintf(&pszAnswer, pszDCInfo);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirCatStringPrintf(&pszAnswer, ",\n");
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpBuildJSONGetComputers(ppszComputers, dwNumComputers, &pszComputers);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirCatStringPrintf(&pszAnswer, pszComputers);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirCatStringPrintf(&pszAnswer, "\n}");
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirHttpCreateRESTResponsePayload(
                                      op.ldapResult.errCode,
                                      "",
                                      "",
                                      pszAnswer,
                                      pHttp
                                      );
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

cleanup:
    VmDirFreeStringArray(ppszComputers, dwNumComputers);
    VmDirFreeDCInfoArray(ppDCInfo, dwNumDC);
    VMDIR_SAFE_FREE_STRINGA(pszAnswer);
    VMDIR_SAFE_FREE_STRINGA(pszComputers);
    VMDIR_SAFE_FREE_STRINGA(pszDCInfo);
    VmDirFreeOperationContent(&op);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Start replication on current node
 */
DWORD
VmDirHttpReplNowRequestHandler(
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;

    if (pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    PVDIR_ATTRIBUTE  pAttrUPN = VmDirFindAttrByName(pHttp->pEntry, ATTR_KRB_UPN);
    if (pAttrUPN == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_ENTRY;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    /* Only Admin is allowed to do force replication */
    dwError = VmDirAdministratorAccessCheck(pAttrUPN->vals->lberbv.bv_val);
    if (dwError == ERROR_ACCESS_DENIED)
    {
        dwError = VMDIR_ERROR_INSUFFICIENT_ACCESS;
    }
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    VmDirdSetReplNow(TRUE);
    VmDirUrgentReplSignal();

    dwError = VmDirHttpCreateRESTResponsePayload(
                                         LDAP_SUCCESS,
                                         "",
                                         "",
                                         "[]",
                                         pHttp
                                         );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Add RA between two nodes
 * Replication Agreement will be added two way by default
 */
DWORD
VmDirHttpAddRARequestHandler(
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;
    PVMDIR_REST_RA_OPERATION_INFO pRESTRAOperationInfo = NULL;

    if (pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = VmDirHttpParseJSONToRAOperationInfo(pHttp, &pRESTRAOperationInfo);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    if (pRESTRAOperationInfo->bIsTwoWayRepl)
    {
        dwError = VmDirHttpAddRATwoWay(pHttp, pRESTRAOperationInfo);
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }
    else
    {
        dwError = VmDirHttpAddRAOneWay(pHttp, pRESTRAOperationInfo);
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = VmDirHttpCreateRESTResponsePayload(
                                        LDAP_SUCCESS,
                                        "",
                                        "",
                                        "[]",
                                        pHttp
                                        );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

cleanup:
    VmDirHttpFreeRESTRAOperationInfo(pRESTRAOperationInfo);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Remove RAs between two nodes
 * Replication Agreement will be removed two way by default
 */
DWORD
VmDirHttpRemoveRARequestHandler(
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;
    PVMDIR_REST_RA_OPERATION_INFO pRESTRAOperationInfo = NULL;

    if (pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = VmDirHttpParseJSONToRAOperationInfo(pHttp, &pRESTRAOperationInfo);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    if (pRESTRAOperationInfo->bIsTwoWayRepl)
    {
        dwError = VmDirHttpRemoveRATwoWay(pHttp, pRESTRAOperationInfo);
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }
    else
    {
        dwError = VmDirHttpRemoveRAOneWay(pHttp, pRESTRAOperationInfo);
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = VmDirHttpCreateRESTResponsePayload(
                                        LDAP_SUCCESS,
                                        "",
                                        "",
                                        "[]",
                                        pHttp
                                        );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

cleanup:
    VmDirHttpFreeRESTRAOperationInfo(pRESTRAOperationInfo);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

