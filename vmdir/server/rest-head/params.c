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
VmDirRESTGetParam(
    PVDIR_REST_OPERATION    pRestOp,
    PSTR                    pszParam,
    PSTR*                   ppszValue,
    BOOLEAN                 bRequired
    )
{
    DWORD   dwError = 0;
    PSTR    pszValue = NULL;

    if (!pRestOp || IsNullOrEmptyString(pszParam) || !ppszValue)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    if (LwRtlHashMapFindKey(pRestOp->pParamMap, (PVOID*)&pszValue, pszParam))
    {
        dwError = bRequired ? VMDIR_ERROR_INVALID_REQUEST : 0;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirAllocateStringA(pszValue, ppszValue);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d) (pszParam=%s)",
            __FUNCTION__, dwError, VDIR_SAFE_STRING(pszParam));

    goto cleanup;
}
