/*
 * Copyright © 2017 VMware, Inc.  All Rights Reserved.
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

#include "includes.h"

REST_MODULE _ldap_rest_module[] =
{
    {
        "/vmca/ldap",
        {VmDirRESTLdapSearch, VmDirRESTLdapAdd, NULL, VmDirRESTLdapDelete, VmDirRESTLdapModify}
    },
    {0}
};

DWORD
VmDirRESTGetLdapModule(
    PREST_MODULE*   ppRestModule
    )
{
    *ppRestModule = _ldap_rest_module;
    return 0;
}

/*
 * Performs Add operation. Input JSON data should be there in
 * pHttp->pszInputJson before calling this.
 * Only one entry is allowed to add per call.
 */
DWORD
VmDirRESTLdapAdd(
    const char* pszInputJson,
    char**      ppszOutputJson
    )
{
    DWORD	dwError = 0;
    PVDIR_ENTRY pEntry = NULL;
    PVDIR_REST_OPERATION    pRestOp = NULL;
    PVDIR_OPERATION         pAddOp = NULL;

    if (!pszInputJson)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    pRestOp = (PVDIR_REST_OPERATION)pszInputJson;   // FIXME hack

    dwError = VmDirExternalOperationCreate(
            NULL, -1, LDAP_REQ_ADD, pRestOp->pConn, &pAddOp);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirRESTDecodeEntry(pRestOp->pjInput, &pEntry);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirResetAddRequestEntry(pAddOp, pEntry);
    BAIL_ON_VMDIR_ERROR(dwError);
    pEntry = NULL;

    dwError = VmDirMLAdd(pAddOp);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    VMDIR_SET_REST_RESULT(pRestOp, pAddOp, dwError);
    VmDirFreeOperation(pAddOp);
    VmDirFreeEntry(pEntry);
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
VmDirRESTLdapSearch(
    const char* pszInputJson,
    char**      ppszOutputJson
    )
{
    DWORD   dwError = 0;
    PSTR    pszDN = NULL;
    PSTR    pszResultCount = NULL;
    PVDIR_LDAP_CONTROL  pPagedResultsCtrl = NULL;
    PVDIR_REST_OPERATION    pRestOp = NULL;
    PVDIR_OPERATION         pSearchOp = NULL;

    if (!pszInputJson)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    pRestOp = (PVDIR_REST_OPERATION)pszInputJson;   // FIXME hack

    dwError = VmDirExternalOperationCreate(
            NULL, -1, LDAP_REQ_SEARCH, pRestOp->pConn, &pSearchOp);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirRESTGetLdapSearchParams(
            pRestOp,
            &pszDN,
            &pSearchOp->request.searchReq.scope,
            &pSearchOp->request.searchReq.filter,
            &pSearchOp->request.searchReq.attrs,
            &pPagedResultsCtrl);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirStringToBervalContent(pszDN, &pSearchOp->reqDn);
    BAIL_ON_VMDIR_ERROR(dwError);

    pSearchOp->showPagedResultsCtrl = pPagedResultsCtrl;
    pSearchOp->request.searchReq.bStoreRsltInMem = TRUE;

    dwError = VmDirMLSearch(pSearchOp);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirRESTEncodeEntryArray(
            &pSearchOp->internalSearchEntryArray,
            pSearchOp->request.searchReq.attrs,
            &pRestOp->pResult->pjOutput);
    BAIL_ON_VMDIR_ERROR(dwError);

    // set additional info
    if (pPagedResultsCtrl)
    {
        dwError = VmDirRESTResultSetAddlInfo(
                pRestOp->pResult,
                "paged_results_cookie",
                pPagedResultsCtrl->value.pagedResultCtrlVal.cookie);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirAllocateStringPrintf(
            &pszResultCount, "%ld", pSearchOp->internalSearchEntryArray.iSize);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirRESTResultSetAddlInfo(
            pRestOp->pResult, "result_count", pszResultCount);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    VMDIR_SET_REST_RESULT(pRestOp, pSearchOp, dwError);
    VMDIR_SAFE_FREE_MEMORY(pszDN);
    VMDIR_SAFE_FREE_MEMORY(pszResultCount);
    VMDIR_SAFE_FREE_MEMORY(pPagedResultsCtrl);
    VmDirFreeOperation(pSearchOp);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Performs Modify operation
 */
DWORD
VmDirRESTLdapModify(
    const char* pszInputJson,
    char**      ppszOutputJson
    )
{
    DWORD   dwError = 0;
    PSTR    pszDN = NULL;
    PVDIR_REST_OPERATION    pRestOp = NULL;
    PVDIR_OPERATION         pModifyOp = NULL;

    if (!pszInputJson)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    pRestOp = (PVDIR_REST_OPERATION)pszInputJson;   // FIXME hack

    dwError = VmDirExternalOperationCreate(
            NULL, -1, LDAP_REQ_MODIFY, pRestOp->pConn, &pModifyOp);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirRESTGetStrParam(pRestOp, "dn", &pszDN, TRUE);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirStringToBervalContent(pszDN, &pModifyOp->reqDn);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirStringToBervalContent(pszDN, &pModifyOp->request.modifyReq.dn);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirRESTDecodeMods(
            pRestOp->pjInput,
            &pModifyOp->request.modifyReq.mods,
            &pModifyOp->request.modifyReq.numMods);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirMLModify(pModifyOp);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    VMDIR_SET_REST_RESULT(pRestOp, pModifyOp, dwError);
    VMDIR_SAFE_FREE_MEMORY(pszDN);
    VmDirFreeOperation(pModifyOp);
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
VmDirRESTLdapDelete(
    const char* pszInputJson,
    char**      ppszOutputJson
    )
{
    DWORD   dwError = 0;
    PSTR    pszDN = NULL;
    PVDIR_REST_OPERATION    pRestOp = NULL;
    PVDIR_OPERATION         pDeleteOp = NULL;

    if (!pszInputJson)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    pRestOp = (PVDIR_REST_OPERATION)pszInputJson;   // FIXME hack

    dwError = VmDirExternalOperationCreate(
            NULL, -1, LDAP_REQ_DELETE, pRestOp->pConn, &pDeleteOp);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirRESTGetStrParam(pRestOp, "dn", &pszDN, TRUE);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirStringToBervalContent(pszDN, &pDeleteOp->reqDn);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirStringToBervalContent(pszDN, &pDeleteOp->request.deleteReq.dn);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirMLDelete(pDeleteOp);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    VMDIR_SET_REST_RESULT(pRestOp, pDeleteOp, dwError);
    VMDIR_SAFE_FREE_MEMORY(pszDN);
    VmDirFreeOperation(pDeleteOp);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

