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
VmDirRESTOperationInit(
    PVDIR_REST_OPERATION*   ppRestOp
    )
{
    DWORD   dwError = 0;
    PVDIR_REST_OPERATION    pRestOp = NULL;

    if (!ppRestOp)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirAllocateMemory(
    		sizeof(VDIR_REST_OPERATION), (PVOID*)&pRestOp);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = LwRtlCreateHashMap(
            &pRestOp->pParamMap,
            LwRtlHashDigestPstrCaseless,
            LwRtlHashEqualPstrCaseless,
            NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirAllocateMemory(
            sizeof(VDIR_CONNECTION), (PVOID*)&pRestOp->pConn);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirRESTResultInit(&pRestOp->pResult);
    BAIL_ON_VMDIR_ERROR(dwError);

    *ppRestOp = pRestOp;

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError );

    VmDirFreeRESTOperation(pRestOp);
    goto cleanup;
}

DWORD
VmDirRESTOperationReadRequest(
    PVDIR_REST_OPERATION    pRestOp,
    PREST_REQUEST           pRestReq,
    DWORD                   dwParamCount
    )
{
    DWORD   dwError = 0;
    DWORD   i = 0, done = 0;
    PSTR    pszTmp = NULL;
    PSTR    pszKey = NULL;
    PSTR    pszVal = NULL;
    size_t  len = 0;

    if (!pRestOp || !pRestReq)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    // read request methods
    dwError = VmRESTGetHttpMethod(pRestReq, &pRestOp->pszMethod);
    BAIL_ON_VMDIR_ERROR(dwError);

    // read request URI
    dwError = VmRESTGetHttpURI(pRestReq, &pRestOp->pszEndpoint);
    BAIL_ON_VMDIR_ERROR(dwError);

    pszTmp = VmDirStringChrA(pRestOp->pszEndpoint, '?');
    if (pszTmp)
    {
        *pszTmp = '\0';
    }

    // read request authorization info
    dwError = VmRESTGetHttpHeader(pRestReq, "Authorization", &pRestOp->pszAuth);
    BAIL_ON_VMDIR_ERROR(dwError);

    // read request params
    for (i = 1; i <= dwParamCount; i++)
    {
        dwError = VmRESTGetParamsByIndex(pRestReq, dwParamCount, i, &pszKey, &pszVal);
        BAIL_ON_VMDIR_ERROR(dwError);

        dwError = LwRtlHashMapInsert(pRestOp->pParamMap, pszKey, pszVal, NULL);
        BAIL_ON_VMDIR_ERROR(dwError);

        pszKey = NULL;
        pszVal = NULL;
    }

    // read request input json
    while (!done)
    {
        dwError = VmDirReallocateMemory(
                (PVOID)pRestOp->pszInputJson,
                (PVOID*)&pRestOp->pszInputJson,
                len + MAX_REST_PAYLOAD_LENGTH);
        BAIL_ON_VMDIR_ERROR(dwError);

        dwError = VmRESTGetHttpPayload(pRestReq, pRestOp->pszInputJson + len, &done);
        BAIL_ON_VMDIR_ERROR(dwError);

        len = strlen(pRestOp->pszInputJson);
    }

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Set HTTP headers as well as payload
 */
DWORD
VmDirRESTOperationWriteResponse(
    PVDIR_REST_OPERATION    pRestOp,
    PREST_RESPONSE*         ppResponse
    )
{
    DWORD   dwError = 0;
    DWORD   done = 0;
    PSTR    pszData = NULL;
    PSTR    pszDataLen = NULL;
    size_t  dataLen = 0;
    size_t  sentLen = 0;

    if (!pRestOp || !ppResponse)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmRESTSetHttpStatusVersion(ppResponse, "HTTP/1.1");
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmRESTSetHttpStatusCode(ppResponse, "200");
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmRESTSetHttpReasonPhrase(ppResponse, "OK");
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmRESTSetHttpHeader(ppResponse, "Connection", "close");
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmRESTSetHttpHeader(ppResponse, "Content-Type", "application/json");
    BAIL_ON_VMDIR_ERROR(dwError);

//    TODO use pRestOp->pResult

    dataLen = VmDirStringLenA(pszData);

    dwError = VmDirAllocateStringPrintf(&pszDataLen, "%ld", dataLen);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmRESTSetDataLength(ppResponse, pszDataLen);
    BAIL_ON_VMDIR_ERROR(dwError);

    while (!done)
    {
        size_t chunkLen = dataLen > MAX_REST_PAYLOAD_LENGTH ?
                MAX_REST_PAYLOAD_LENGTH : dataLen;

        dwError = VmRESTSetHttpPayload(ppResponse, pszData + sentLen, chunkLen, &done);
        BAIL_ON_VMDIR_ERROR(dwError);

        sentLen += chunkLen;
        dataLen -= chunkLen;
    }

    dwError = VmRESTSetHttpPayload(ppResponse, "", 0, &done);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszData);
    VMDIR_SAFE_FREE_STRINGA(pszDataLen);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

VOID
VmDirFreeRESTOperation(
    PVDIR_REST_OPERATION    pRestOp
    )
{
    if (pRestOp)
    {
        VMDIR_SAFE_FREE_MEMORY(pRestOp->pszMethod);
        VMDIR_SAFE_FREE_MEMORY(pRestOp->pszEndpoint);
        VMDIR_SAFE_FREE_MEMORY(pRestOp->pszInputJson);
        LwRtlHashMapClear(pRestOp->pParamMap, VmDirSimpleHashMapPairFree, NULL);
        LwRtlFreeHashMap(&pRestOp->pParamMap);
        VmDirDeleteConnection(&pRestOp->pConn);
        VmDirFreeRESTResult(pRestOp->pResult);
    }
}