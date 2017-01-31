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

    dwError = VmDirParseJSONToEntry(pRestOp->pszInputJson, &pEntry);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirResetAddRequestEntry(pAddOp, pEntry);
    BAIL_ON_VMDIR_ERROR(dwError);
    pEntry = NULL;

    dwError = VmDirMLAdd(pAddOp);
    BAIL_ON_VMDIR_ERROR(dwError);

    // TODO create result

cleanup:
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
    PSTR    pszScope = NULL;
    PSTR    pszFilter = NULL;
    PSTR    pszAttrs = NULL;
    PSTR    pszPageSize = NULL;
    PSTR    pszPageResultsCookie = NULL;
    int                 scope = LDAP_SCOPE_BASE;
    PVDIR_FILTER        pFilter = NULL;
    PVDIR_BERVALUE      pbvAttrs = NULL;    // TODO maybe should be a map
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

    // get dn
    dwError = VmDirRESTGetParam(pRestOp, "dn", &pszDN, TRUE);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirStringToBervalContent(pszDN, &pSearchOp->reqDn);
    BAIL_ON_VMDIR_ERROR(dwError);

    // get scope
    dwError = VmDirRESTGetParam(pRestOp, "scope", &pszScope, FALSE);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (!IsNullOrEmptyString(pszScope))
    {
        if (VmDirStringCompareA("base", pszScope, FALSE) == 0)
        {
            scope = LDAP_SCOPE_BASE;
        }
        else if (VmDirStringCompareA("one", pszScope, FALSE) == 0 ||
                 VmDirStringCompareA("onelevel", pszScope, FALSE) == 0)
        {
            scope = LDAP_SCOPE_ONELEVEL;
        }
        else if (VmDirStringCompareA("sub", pszScope, FALSE) == 0 ||
                 VmDirStringCompareA("subtree", pszScope, FALSE) == 0)
        {
            scope = LDAP_SCOPE_SUBTREE;
        }
        else
        {
            dwError = VMDIR_ERROR_INVALID_REQUEST;
            BAIL_ON_VMDIR_ERROR(dwError);
        }
    }
    pSearchOp->request.searchReq.scope = scope;

    // get filter
    dwError = VmDirRESTGetParam(pRestOp, "filter", &pszFilter, FALSE);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (IsNullOrEmptyString(pszFilter))
    {
        dwError = VmDirAllocateStringA("(objectclass=*)", &pszFilter);
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = StrFilterToFilter(pszFilter, &pFilter);
    BAIL_ON_VMDIR_ERROR(dwError);

    pSearchOp->request.searchReq.filter = pFilter;
    pFilter = NULL;

    // get attributes
    dwError = VmDirRESTGetParam(pRestOp, "attrs", &pszAttrs, FALSE);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (!IsNullOrEmptyString(pszAttrs))
    {

    }

    // get paged results control
    dwError = VmDirRESTGetParam(pRestOp, "page_size", &pszPageSize, FALSE);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirRESTGetParam(
            pRestOp, "page_results_cookie", &pszPageResultsCookie, FALSE);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (!IsNullOrEmptyString(pszPageSize))
    {
        dwError = VmDirAllocateMemory(
                sizeof(VDIR_LDAP_CONTROL), (PVOID*)&pPagedResultsCtrl);
        BAIL_ON_VMDIR_ERROR(dwError);

        pPagedResultsCtrl->value.pagedResultCtrlVal.pageSize =
                (DWORD)VmDirStringToIA(pszPageSize);

        pPagedResultsCtrl->value.pagedResultCtrlVal.cookie[0] = '\0';
        if (!IsNullOrEmptyString(pszPageResultsCookie))
        {
            dwError = VmDirStringNCpyA(
                    pPagedResultsCtrl->value.pagedResultCtrlVal.cookie,
                    VMDIR_PS_COOKIE_LEN,
                    pszPageResultsCookie,
                    VMDIR_PS_COOKIE_LEN - 1);
            BAIL_ON_VMDIR_ERROR(dwError);
        }
    }

    pSearchOp->showPagedResultsCtrl = pPagedResultsCtrl;

    // run search
    dwError = VmDirMLSearch(pSearchOp);
    BAIL_ON_VMDIR_ERROR(dwError);

    // TODO create result

    if (pPagedResultsCtrl)
    {
        // additional info - new cookie (maybe always?)
    }

    // additional info - result count
    // additional info - result

cleanup:
    VMDIR_SAFE_FREE_MEMORY(pszDN);
    VMDIR_SAFE_FREE_MEMORY(pszScope);
    VMDIR_SAFE_FREE_MEMORY(pszFilter);
    VMDIR_SAFE_FREE_MEMORY(pszAttrs);
    VMDIR_SAFE_FREE_MEMORY(pszPageSize);
    VMDIR_SAFE_FREE_MEMORY(pszPageResultsCookie);
    DeleteFilter(pFilter);

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

    dwError = VmDirRESTGetParam(pRestOp, "dn", &pszDN, TRUE);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirStringToBervalContent(pszDN, &pModifyOp->reqDn);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirStringToBervalContent(pszDN, &pModifyOp->request.modifyReq.dn);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirParseJSONToMods(
            pRestOp->pszInputJson,
            &pModifyOp->request.modifyReq.mods,
            &pModifyOp->request.modifyReq.numMods);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirMLModify(pModifyOp);
    BAIL_ON_VMDIR_ERROR(dwError);

    // TODO create result

cleanup:
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

    dwError = VmDirRESTGetParam(pRestOp, "dn", &pszDN, TRUE);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirStringToBervalContent(pszDN, &pDeleteOp->reqDn);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirStringToBervalContent(pszDN, &pDeleteOp->request.deleteReq.dn);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirMLDelete(pDeleteOp);
    BAIL_ON_VMDIR_ERROR(dwError);

    // TODO create result

cleanup:
    VMDIR_SAFE_FREE_MEMORY(pszDN);
    VmDirFreeOperation(pDeleteOp);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

