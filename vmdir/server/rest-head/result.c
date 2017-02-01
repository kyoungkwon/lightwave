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

DWORD
VmDirRESTResultInit(
    PVDIR_REST_RESULT*  ppRestRslt
    )
{
    DWORD   dwError = 0;
    PVDIR_REST_RESULT   pRestRslt = NULL;

    if (!ppRestRslt)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirAllocateMemory(
            sizeof(VDIR_REST_RESULT), (PVOID*)&pRestRslt);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = LwRtlCreateHashMap(
            &pRestRslt->pAddlInfo,
            LwRtlHashDigestPstrCaseless,
            LwRtlHashEqualPstrCaseless,
            NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

    *ppRestRslt = pRestRslt;

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError );

    VmDirFreeRESTResult(pRestRslt);
    goto cleanup;
}

DWORD
VmDirRESTResultSetError(
    PVDIR_REST_RESULT   pRestRslt,
    DWORD               dwErrCode,
    PSTR                pszErrMsg
    )
{
    DWORD   dwError = 0;

    if (!pRestRslt)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    pRestRslt->dwErrCode = dwErrCode;

    if (IsNullOrEmptyString(pRestRslt->pszErrMsg) &&
        !IsNullOrEmptyString(pszErrMsg))
    {
        dwError = VmDirAllocateStringA(pszErrMsg, &pRestRslt->pszErrMsg);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError );

    goto cleanup;
}

DWORD
VmDirRESTResultSetAddlInfo(
    PVDIR_REST_RESULT   pRestRslt,
    PSTR                pszKey,
    PSTR                pszVal
    )
{
    DWORD   dwError = 0;
    PSTR    pszKeyCp = NULL;
    PSTR    pszValCp = NULL;

    if (!pRestRslt || IsNullOrEmptyString(pszKey) || IsNullOrEmptyString(pszVal))
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirAllocateStringA(pszKey, &pszKeyCp);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirAllocateStringA(pszVal, &pszValCp);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = LwRtlHashMapInsert(pRestRslt->pAddlInfo, pszKeyCp, pszValCp, NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError );

    VMDIR_SAFE_FREE_MEMORY(pszKeyCp);
    VMDIR_SAFE_FREE_MEMORY(pszValCp);
    goto cleanup;
}

DWORD
VmDirRESTResultToResponseBody(
    PVDIR_REST_RESULT   pRestRslt,
    PSTR*               ppszBody
    )
{
    DWORD   dwError = 0;
    json_t* pjBody = NULL;
    json_t* pjErrCode = NULL;
    json_t* pjErrMsg = NULL;
    json_t* pjAddl = NULL;
    json_t* pjRslt = NULL;
    LW_HASHMAP_ITER iter = LW_HASHMAP_ITER_INIT;
    LW_HASHMAP_PAIR pair = {NULL, NULL};
    PSTR    pszBody = NULL;

    if (!pRestRslt || !ppszBody)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    pjBody = json_object();

    pjErrCode = json_integer(pRestRslt->dwErrCode);
    dwError = json_object_set_new(pjBody, "error_code", pjErrCode);
    BAIL_ON_VMDIR_ERROR(dwError);

    pjErrMsg = json_string(VDIR_SAFE_STRING(pRestRslt->pszErrMsg));
    dwError = json_object_set_new(pjBody, "error_message", pjErrMsg);
    BAIL_ON_VMDIR_ERROR(dwError);

    while (LwRtlHashMapIterate(pRestRslt->pAddlInfo, &iter, &pair))
    {
        pjAddl = json_string((PSTR)pair.pValue);
        dwError = json_object_set_new(pjBody, (PSTR)pair.pKey, pjAddl);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    if (!IsNullOrEmptyString(pRestRslt->pszOutputJson))
    {
        pjRslt = json_string(pRestRslt->pszOutputJson);
        dwError = json_object_set_new(pjBody, "result", pjRslt);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    pszBody = json_dumps(pjBody, JSON_INDENT(4));
    if (IsNullOrEmptyString(pszBody))
    {
        dwError = VMDIR_ERROR_INVALID_RESULT;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    *ppszBody = pszBody;

cleanup:
    if (pjBody)
    {
        json_decref(pjBody);
    }
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError );

    VMDIR_SAFE_FREE_MEMORY(pszBody);
    goto cleanup;
}

VOID
VmDirFreeRESTResult(
    PVDIR_REST_RESULT	pRestRslt
    )
{
	if (pRestRslt)
	{
        VMDIR_SAFE_FREE_MEMORY(pRestRslt->pszErrMsg);
        VMDIR_SAFE_FREE_MEMORY(pRestRslt->pszOutputJson);
        LwRtlHashMapClear(pRestRslt->pAddlInfo, VmDirSimpleHashMapPairFree, NULL);
        LwRtlFreeHashMap(&pRestRslt->pAddlInfo);
	}
}
