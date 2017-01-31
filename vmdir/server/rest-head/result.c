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
    PVDIR_REST_RESULT*  ppRestResult
    )
{
    DWORD   dwError = 0;
    PVDIR_REST_RESULT   pRestResult = NULL;

    if (!ppRestResult)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirAllocateMemory(
            sizeof(VDIR_REST_RESULT), (PVOID*)&pRestResult);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = LwRtlCreateHashMap(
            &pRestResult->pAdditionalInfo,
            LwRtlHashDigestPstrCaseless,
            LwRtlHashEqualPstrCaseless,
            NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

    *ppRestResult = pRestResult;

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError );

    VmDirFreeRESTResult(pRestResult);
    goto cleanup;
}

VOID
VmDirFreeRESTResult(
    PVDIR_REST_RESULT	pRestResult
    )
{
	if (pRestResult)
	{
        VMDIR_SAFE_FREE_MEMORY(pRestResult->pszErrorCode);
        VMDIR_SAFE_FREE_MEMORY(pRestResult->pszErrorMessage);
        VMDIR_SAFE_FREE_MEMORY(pRestResult->pszOutputJson);
        LwRtlHashMapClear(pRestResult->pAdditionalInfo, VmDirSimpleHashMapPairFree, NULL);
        LwRtlFreeHashMap(&pRestResult->pAdditionalInfo);
	}
}
