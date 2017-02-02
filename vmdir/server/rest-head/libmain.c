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

REST_PROCESSOR sVmDirRESTHandlers =
{
    .pfnHandleCreate = &VmDirRESTRequestHandler,
    .pfnHandleRead = &VmDirRESTRequestHandler,
    .pfnHandleUpdate = &VmDirRESTRequestHandler,
    .pfnHandleDelete = &VmDirRESTRequestHandler,
};

DWORD
VmDirRESTServiceStartup(
    VOID
    )
{
    DWORD   dwError = 0;
    REST_CONF   config = {0};
    PREST_PROCESSOR     pHandlers = &sVmDirRESTHandlers;
    PREST_API_MODULE    pModule = NULL;

    MODULE_REG_MAP stRegMap[] =
    {
        {"ldap", VmDirRESTGetLdapModule},
        {NULL, NULL}
    };

    config.pSSLCertificate = VMDIR_REST_SSLCERT;
    config.pSSLKey = VMDIR_REST_SSLKEY;
    config.pServerPort = VMDIR_REST_PORT;
    config.pDebugLogFile = VMDIR_REST_DEBUGLOGFILE;
    config.pClientCount = VMDIR_REST_CLIENTCNT;
    config.pMaxWorkerThread = VMDIR_REST_WORKERTHCNT;

    dwError = VmRESTInit(&config, NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = coapi_load_from_file(REST_API_SPEC, &gpVdirRestApiDef);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = coapi_map_api_impl(gpVdirRestApiDef, stRegMap);
    BAIL_ON_VMDIR_ERROR(dwError);

    for (pModule = gpVdirRestApiDef->pModules; pModule; pModule = pModule->pNext)
    {
        PREST_API_ENDPOINT pEndPoint = pModule->pEndPoints;
        for (; pEndPoint; pEndPoint = pEndPoint->pNext)
        {
            dwError = VmRESTRegisterHandler(pEndPoint->pszName, pHandlers, NULL);
            BAIL_ON_VMDIR_ERROR(dwError);
        }
    }

    dwError = VmRESTStart();
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                    "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

VOID
VmDirRESTServiceShutdown(
    VOID
    )
{
    VMDIR_SAFE_FREE_MEMORY(gpVdirRestApiDef);
    VmRESTStop();
    VmRESTShutdown();
}

DWORD
VmDirRESTRequestHandler(
    PREST_REQUEST   pRequest,
    PREST_RESPONSE* ppResponse,
    uint32_t        paramsCount
    )
{
    DWORD   dwError = 0;
    PVDIR_REST_OPERATION    pRestOp = NULL;
    PREST_API_METHOD    pMethod = NULL;

    if (!pRequest || !ppResponse)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirRESTOperationInit(&pRestOp);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirRESTOperationReadRequest(pRestOp, pRequest, paramsCount);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirRESTAuth(pRestOp);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = coapi_find_handler(
            gpVdirRestApiDef,
            pRestOp->pszEndpoint,
            pRestOp->pszMethod,
            &pMethod);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = pMethod->pFnImpl((char*)pRestOp, NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

response:
    // TODO what about http return code and msg?
    VMDIR_SET_REST_RESULT(pRestOp, NULL, dwError);
    // Nothing can be done if failed to send response
    dwError = VmDirRESTOperationWriteResponse(pRestOp, ppResponse);
    goto cleanup;

cleanup:
    VmDirFreeRESTOperation(pRestOp);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError );
    goto response;
}
