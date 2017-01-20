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
 * Validate received HTTP method
 */
static
DWORD
_VmDirValidateHTTPMethod(
    PREST_REQUEST   pRequest,
    PVMDIR_HTTP     pHttp
    )
{
    DWORD dwError = 0;
    PSTR pszMethod = NULL;

    if (pRequest == NULL || pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = VmRESTGetHttpMethod(pRequest, &pszMethod);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    if (!(strcmp(pszMethod, "PUT")    == 0 ||
          strcmp(pszMethod, "PATCH")  == 0 ||
          strcmp(pszMethod, "GET")    == 0 ||
          strcmp(pszMethod, "DELETE") == 0 ||
          strcmp(pszMethod, "POST")   == 0)
       )
    {
        dwError = VMDIR_ERROR_INVALID_REQUEST;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    pHttp->pszMethod = pszMethod;
    pszMethod = NULL;

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszMethod);
    return dwError;
error:
    goto cleanup;
}

/*
 * Get HTTP Payload from request and store it in HTTP struct
 */
DWORD
VmDirHttpGetRequestPayload(
    PREST_REQUEST   pRequest,
    PVMDIR_HTTP     pHttp
    )
{
    DWORD dwError = 0;
    DWORD done = 0;

    if (pRequest == NULL || pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    /* Iterate till we read entire payload */
    while (done != 1)
    {
        size_t len = pHttp->pszInputJson ? strlen(pHttp->pszInputJson) : 0;
        dwError = VmDirReallocateMemory((PVOID) pHttp->pszInputJson,
                          (PVOID) &(pHttp->pszInputJson), len + MAX_HTTP_PAYLOAD_LENGTH);
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

        // FIXME Add number of retry?
        dwError = VmRESTGetHttpPayload(pRequest, pHttp->pszInputJson + len, &done);
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
 * Parse JSON payload for Add operation
 */
DWORD
VmDirHttpParseJSONToAdd(
    PVMDIR_HTTP     pHttp,
    PVDIR_OPERATION pOp
    )
{
    DWORD dwError = 0;
    PCSTR pDN = NULL;
    PVDIR_ATTRIBUTE pAttribute = NULL;
    json_t *pjRoot = NULL;
    json_error_t jError;
    json_t *pjDn = NULL;
    json_t *pjValuesArray = NULL;
    json_t *pjAttrs = NULL;
    void *j = NULL;
    int k = 0;

    if (pHttp == NULL || pOp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    if (!pHttp->pszInputJson)
    {
        dwError = VMDIR_ERROR_GENERIC;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    pjRoot = json_loads(pHttp->pszInputJson, 0, &jError);
    if (!pjRoot)
    {
        dwError = VMDIR_ERROR_INVALID_REQUEST;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    if (!json_is_object(pjRoot))
    {
        dwError = VMDIR_ERROR_INVALID_REQUEST;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    pjDn = json_object_get(pjRoot, "dn");
    if (!json_is_string(pjDn))
    {
        dwError = VMDIR_ERROR_INVALID_REQUEST;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }
    pDN = json_string_value(pjDn);

    pjAttrs = json_object_get(pjRoot, "attrs");
    if (pjAttrs == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_REQUEST;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = VmDirInitializeEntryFromDN(pOp->request.addReq.pEntry, pDN);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    for (j = json_object_iter(pjAttrs); j != NULL; j = json_object_iter_next(pjAttrs, j))
    {
        PCSTR pszAttr = json_object_iter_key(j);

        pjValuesArray = json_object_iter_value(j);
        if (!json_is_array(pjValuesArray))
        {
            dwError = VMDIR_ERROR_INVALID_REQUEST;
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
        }

        for (k = 0; k < json_array_size(pjValuesArray); k++)
        {
            json_t *pjValue = json_array_get(pjValuesArray, k);
            PCSTR pValue = json_string_value(pjValue);

            dwError = VmDirAttributeAllocate(
                        pszAttr,
                        1,
                        pOp->request.addReq.pEntry->pSchemaCtx,
                        &pAttribute);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

            dwError = VmDirAllocateStringA(pValue, &(pAttribute->vals[0].lberbv.bv_val));
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

            pAttribute->vals[0].lberbv.bv_len = strlen(pValue);
            pAttribute->vals[0].bOwnBvVal = TRUE;

            dwError = VmDirEntryAddAttribute(pOp->request.addReq.pEntry, pAttribute);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
            pAttribute = NULL;
        }
    }

cleanup:
    if (pjRoot)
    {
        json_decref(pjRoot);
    }
    VmDirFreeAttribute(pAttribute);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Parse JSON payload for PATCH operation
 */
DWORD
VmDirHttpParseJSONToModify(
    PVMDIR_HTTP     pHttp,
    PVDIR_OPERATION pOp
    )
{
    DWORD dwError = 0;
    json_t *pjRoot = NULL;
    json_error_t jError;
    int i;
    PVDIR_BERVALUE pBerv = NULL;

    if (pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    if (!pHttp->pszInputJson)
    {
        dwError = VMDIR_ERROR_GENERIC;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    pjRoot = json_loads(pHttp->pszInputJson, 0, &jError);
    if (!pjRoot)
    {
        dwError = VMDIR_ERROR_INVALID_REQUEST;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    if (!json_is_array(pjRoot))
    {
        dwError = VMDIR_ERROR_INVALID_REQUEST;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    for(i = 0; i < json_array_size(pjRoot); i++)
    {
        json_t *pjData = NULL;
        json_t *pjOp = NULL;
        json_t *pjPath = NULL;
        json_t *pjValArr = NULL;
        json_t *pjVal = NULL;

        int iCntAttr = 0;
        PCSTR pszOp = NULL;
        int operation = 0;
        PCSTR pszAttrName = NULL;
        int lenAttrName = 0;
        PCSTR pszAttrValue = NULL;
        int lenAttrValue = 0;
        size_t numAttrs = 0;

        pjData = json_array_get(pjRoot, i);
        if (!json_is_object(pjData))
        {
            dwError = VMDIR_ERROR_INVALID_REQUEST;
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
        }

        pjOp = json_object_get(pjData, "op");
        if (!json_is_string(pjOp))
        {
            dwError = VMDIR_ERROR_INVALID_REQUEST;
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
        }
        pszOp = json_string_value(pjOp);

        pjPath = json_object_get(pjData, "path");
        if (!json_is_string(pjPath))
        {
            dwError = VMDIR_ERROR_INVALID_REQUEST;
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
        }
        pszAttrName = json_string_value(pjPath);

        if (!strcmp("add", pszOp))
        {
            operation = MOD_OP_ADD;
        }
        else if (!strcmp("remove", pszOp))
        {
            operation = MOD_OP_DELETE;
        }
        else if (!strcmp("replace", pszOp))
        {
            operation = MOD_OP_REPLACE;
        }
        else
        {
            dwError = VMDIR_ERROR_INVALID_PARAMETER;
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
        }

        if (operation == MOD_OP_ADD || operation == MOD_OP_REPLACE)
        {
            pjValArr = json_object_get(pjData, "value");
            if (!json_is_array(pjValArr))
            {
                dwError = VMDIR_ERROR_INVALID_REQUEST;
                BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
            }

            numAttrs = json_array_size(pjValArr);

            dwError = VmDirAllocateMemory(sizeof(VDIR_BERVALUE) * numAttrs, (PVOID*)&pBerv);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

            for (iCntAttr = 0; iCntAttr < numAttrs; iCntAttr++)
            {
                pjVal = json_array_get(pjValArr, iCntAttr);
                if (!json_is_string(pjVal))
                {
                    dwError = VMDIR_ERROR_INVALID_REQUEST;
                    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
                }
                pszAttrValue = json_string_value(pjVal);

                pBerv[iCntAttr].lberbv_val = (PSTR)pszAttrValue;
                pBerv[iCntAttr].lberbv_len = VmDirStringLenA(pszAttrValue);
            }

            dwError = VmDirOperationAddModReq(pOp, operation, (PSTR)pszAttrName, pBerv, numAttrs);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

            VMDIR_SAFE_FREE_MEMORY(pBerv);
            pBerv = NULL;
        }
        else
        {
            dwError = VmDirAppendAMod(pOp, operation, (PSTR)pszAttrName, lenAttrName, (PSTR)pszAttrValue, lenAttrValue);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
        }
    }

cleanup:
    VMDIR_SAFE_FREE_MEMORY(pBerv);
    if (pjRoot)
    {
        json_decref(pjRoot);
    }
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;

}

/*
 * Get Replication related Info from JSON payload for Add/Remove RAs
 */
DWORD
VmDirHttpParseJSONToRAOperationInfo(
    PVMDIR_HTTP                     pHttp,
    PVMDIR_REST_RA_OPERATION_INFO*  ppRESTRAOperationInfo
    )
{
    DWORD dwError = 0;
    PVMDIR_REST_RA_OPERATION_INFO pRESTRAOperationInfo = NULL;
    BOOLEAN bIsTwoWayReplication = TRUE;
    PCSTR pszSrcHostName = NULL;
    PCSTR pszTgtHostName = NULL;
    PSTR pszSrcServerName = NULL;
    PSTR pszTgtServerName = NULL;
    PCSTR pReplicationType = NULL;
    json_t *pjRoot = NULL;
    json_error_t jError;
    json_t *pjSrcHost = NULL;
    json_t *pjTgtHost = NULL;
    json_t *pjReplicationType = NULL;

    if (pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    if (!pHttp->pszInputJson)
    {
        //FIXME Appropriate Error?
        dwError = VMDIR_ERROR_GENERIC;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    pjRoot = json_loads(pHttp->pszInputJson, 0, &jError);
    if (!pjRoot)
    {
        dwError = VMDIR_ERROR_INVALID_REQUEST;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    if (!json_is_object(pjRoot))
    {
        dwError = VMDIR_ERROR_INVALID_REQUEST;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    pjReplicationType = json_object_get(pjRoot, "replication-type");
    if (!json_is_string(pjReplicationType))
    {
        /* Default is Two Way Replication */
        bIsTwoWayReplication = TRUE;
    }
    else
    {
        pReplicationType = json_string_value(pjReplicationType);

        if (!strcmp(pReplicationType, "one-way"))
        {
            bIsTwoWayReplication = FALSE;
        }
        else if (!strcmp(pReplicationType, "two-way"))
        {
            bIsTwoWayReplication = TRUE;
        }
        else
        {
            dwError = VMDIR_ERROR_INVALID_REQUEST;
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
        }
    }

    pjSrcHost = json_object_get(pjRoot, "source");
    if (pjSrcHost == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_REQUEST;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }
    pszSrcHostName = json_string_value(pjSrcHost);

    pjTgtHost = json_object_get(pjRoot, "target");
    if (pjTgtHost == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_REQUEST;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }
    pszTgtHostName = json_string_value(pjTgtHost);

    /* Check if src and dest is same */
    if (!strcmp(pszSrcHostName, pszTgtHostName))
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = VmDirAllocateMemory(
                  sizeof(VMDIR_REST_RA_OPERATION_INFO),
                  (PVOID*)&pRESTRAOperationInfo
                  );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    pRESTRAOperationInfo->bIsTwoWayRepl = bIsTwoWayReplication;

    dwError = VmDirGetServerName(
                           pszSrcHostName,
                           &pszSrcServerName
                           );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = VmDirGetServerName(
                           pszTgtHostName,
                           &pszTgtServerName
                           );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = VmDirAllocateStringA(pszSrcServerName, &(pRESTRAOperationInfo->pszSrcServerName));
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = VmDirAllocateStringA(pszTgtServerName, &(pRESTRAOperationInfo->pszTgtServerName));
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    *ppRESTRAOperationInfo = pRESTRAOperationInfo;
    pRESTRAOperationInfo = NULL;

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszSrcServerName);
    VMDIR_SAFE_FREE_STRINGA(pszTgtServerName);
    json_decref(pjRoot);
    VmDirHttpFreeRESTRAOperationInfo(pRESTRAOperationInfo);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Register Http Request Handler
 */
PREST_PROCESSOR
VmDirHttpGetRequestHandler(
    VOID
    )
{
    static REST_PROCESSOR sVmDirHttpHandlers = {
            VMDIR_SF_INIT(.pfnHandleRequest, &VmDirHttpRequestHandler),
    };
    return &sVmDirHttpHandlers;
}

DWORD
VmDirHttpRequestHandler(
    PREST_REQUEST    pRequest,
    PREST_RESPONSE*  ppResponse
    )
{
    DWORD dwError = 0;
    PSTR pszUri = NULL;
    PVMDIR_HTTP pHttp = NULL;

    if (pRequest == NULL || ppResponse == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirAllocateMemory(sizeof(VMDIR_HTTP), (PVOID*)&pHttp);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirAllocateMemory(sizeof(VMDIR_REST_RESPONSE_TO_SEND), (PVOID*)&pHttp->pRESTResponseToSend);
    BAIL_ON_VMDIR_ERROR(dwError);

    pHttp->pRestReq = pRequest;
    pHttp->ppRestRes = ppResponse;

    dwError =  _VmDirValidateHTTPMethod(pRequest, pHttp);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = VmRESTGetHttpURI(pRequest, &pszUri);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = VmDirParseUri(pszUri, pHttp);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = VmDirHttpAuth(pHttp);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    // FIXME Enable Authentication
    /* Authentication based on Token */
    //uiError = VmDirHttpAuthToken(pHttp);
    //BAIL_ON_HTTP_ERROR(uiError);

    switch(pHttp->restOp)
    {
        case VDIR_REST_OPERATION_ADD:
            dwError = VmDirHttpAddRequestHandler(pHttp);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
            break;

        case VDIR_REST_OPERATION_DELETE:
            dwError = VmDirHttpDeleteRequestHandler(pHttp);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
            break;

        case VDIR_REST_OPERATION_SEARCH:
            dwError = VmDirHttpSearchRequestHandler(pHttp);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
            break;

        case VDIR_REST_OPERATION_PATCH:
            dwError = VmDirHttpModifyRequestHandler(pHttp);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
            break;

        case VDIR_REST_OPERATION_GET_TOPOLOGY:
            dwError = VmDirHttpGetTopologyRequestHandler(pHttp);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
            break;

        case VDIR_REST_OPERATION_GET_DCINFO:
            dwError = VmDirHttpGetDCInfoRequestHandler(pHttp);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
            break;

        case VDIR_REST_OPERATION_GET_COMPUTERS:
            dwError = VmDirHttpGetComputersRequestHandler(pHttp);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
            break;

        case VDIR_REST_OPERATION_REPLNOW:
            dwError = VmDirHttpReplNowRequestHandler(pHttp);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
            break;

        case VDIR_REST_OPERATION_ADD_REPL_PARTNER:
            dwError = VmDirHttpAddRARequestHandler(pHttp);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
            break;

        case VDIR_REST_OPERATION_REMOVE_REPL_PARTNER:
            dwError = VmDirHttpRemoveRARequestHandler(pHttp);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
            break;

        default:
            dwError = VMDIR_ERROR_INVALID_REQUEST;
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
            break;
    }

response:
    dwError = VmDirHttpSendResponse(pHttp);
    if (dwError)
    {
        VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                         "%s failed, error (%d)", __FUNCTION__, dwError);
    }
    goto cleanup;

cleanup:
    VmDirFreeHttp(pHttp);
    pHttp = NULL;
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                    "%s failed, error (%d)", __FUNCTION__, dwError);
    goto response;
}

VOID
VmDirFreeHttp(
    PVMDIR_HTTP pHttp
    )
{
    if (pHttp)
    {
        VMDIR_SAFE_FREE_STRINGA(pHttp->pszDn);
        VMDIR_SAFE_FREE_STRINGA(pHttp->pszScope);
        VMDIR_SAFE_FREE_STRINGA(pHttp->pszMethod);
        VMDIR_SAFE_FREE_STRINGA(pHttp->pszFilter);
        VMDIR_SAFE_FREE_STRINGA(pHttp->pszAttrs);
        VMDIR_SAFE_FREE_STRINGA(pHttp->pszPageCookie);
        VMDIR_SAFE_FREE_STRINGA(pHttp->pszWWWAuthenticateToken);
        VMDIR_SAFE_FREE_STRINGA(pHttp->pszUser);
        VMDIR_SAFE_FREE_STRINGA(pHttp->pszInputJson);
        VMDIR_SAFE_FREE_STRINGA(pHttp->pszOutputJson);
        if (pHttp->pToken)
        {
            VmDirReleaseAccessToken(&pHttp->pToken);
        }
        VMDIR_SAFE_FREE_MEMORY(pHttp->pszBindedObjectSid);
        VMDIR_SAFE_FREE_STRINGA(pHttp->pszPasswd);
        VmDirFreeEntry(pHttp->pEntry);
        VmDirFreeRESTResponseToSend(pHttp->pRESTResponseToSend);
        VMDIR_SAFE_FREE_MEMORY(pHttp);
    }
}
