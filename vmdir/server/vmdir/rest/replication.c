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

static
DWORD
_VmDirHttpBuildRAEntry(
    PVDIR_ENTRY pEntry,
    PSTR        pszReplURI,
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;
    PVDIR_ATTRIBUTE pAttribute = NULL;
    int iAttrNameCnt = 0;
    int iAttrValsCnt = 0;
    PSTR pszLastLocalUsn = NULL;
    USN lastLocalUsn = 0;

    if (pEntry           == NULL ||
        pszReplURI       == NULL ||
        pHttp            == NULL
        )
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = VmDirAllocateStringPrintf(
                                    &pszLastLocalUsn,
                                    "%u",
                                    lastLocalUsn
                                    );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    PCSTR attrNameList[] = {ATTR_OBJECT_CLASS, ATTR_LABELED_URI, ATTR_LAST_LOCAL_USN_PROCESSED, NULL};
    PCSTR objectClassVals[] = {OC_REPLICATION_AGREEMENT, OC_TOP, NULL};
    PCSTR labeledURIVals[] = {pszReplURI, NULL};
    PCSTR usnVals[] = {pszLastLocalUsn, NULL};
    PCSTR* attrVals[] = {objectClassVals, labeledURIVals, usnVals, NULL};

    for (iAttrNameCnt = 0; attrNameList[iAttrNameCnt] != NULL; iAttrNameCnt++)
    {
        PCSTR* vals = attrVals[iAttrNameCnt];
        for (iAttrValsCnt = 0; vals[iAttrValsCnt] != NULL; iAttrValsCnt++)
        {
            dwError = VmDirAttributeAllocate(
                                    attrNameList[iAttrNameCnt],
                                    1,
                                    pEntry->pSchemaCtx,
                                    &pAttribute
                                    );
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

            dwError = VmDirAllocateStringA(vals[iAttrValsCnt], &(pAttribute->vals[0].lberbv.bv_val));
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

            pAttribute->vals[0].lberbv.bv_len = strlen(vals[iAttrValsCnt]);
            pAttribute->vals[0].bOwnBvVal = TRUE;

            dwError = VmDirEntryAddAttribute(pEntry, pAttribute);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
            pAttribute = NULL;
        }
    }

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszLastLocalUsn);
    VmDirFreeAttribute(pAttribute);
    return dwError;

error:
    goto cleanup;
}

/*
 * Send REST request to other node
 */
static
DWORD
_VmDirHttpSendRARESTRequest(
    PVMDIR_HTTP                     pHttp,
    PSTR                            pszSrcHostName,
    PSTR                            pszTgtHostName,
    PVMDIR_REST_RECEIVED_RESPONSE*  ppRESTReceivedResponse
    )
{
    DWORD dwError = 0;
    PSTR pszPayload = NULL;
    PSTR pszCurlURL = NULL;
    PSTR pszUserNamePasswd = NULL;
    PVMDIR_REST_RECEIVED_RESPONSE pRESTReceivedResponse = NULL;
    CURL* pCurlHandler = NULL;
    CURLcode curlResultCode = 0;

    if (pHttp             == NULL ||
        pszSrcHostName   == NULL ||
        pszTgtHostName    == NULL ||
        pHttp->pEntry     == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = VmDirAllocateMemory(
                            sizeof(VMDIR_REST_RECEIVED_RESPONSE),
                            (PVOID*)&pRESTReceivedResponse
                            );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = VmDirAllocateStringPrintf(
                                        &pszPayload,
                                        "{\n"
                                        "  \"replication-type\": \"one-way\",\n"
                                        "  \"source\": \"%s\",\n"
                                        "  \"target\": \"%s\"\n"
                                        "}",
                                        pszSrcHostName,
                                        pszTgtHostName);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    /* initialize curl session */
    pCurlHandler = curl_easy_init();
    if (pCurlHandler == NULL)
    {
        dwError = VMDIR_ERROR_GENERIC;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = VmDirAllocateStringPrintf(
                                        &pszCurlURL,
                                        "http://%s:%s/vmdir/manage/replication",
                                        pszTgtHostName,
                                        HTTP_PORT_NUMBER
                                        );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = VmDirAllocateStringPrintf(
                                        &pszUserNamePasswd,
                                        "%s:%s",
                                        pHttp->pEntry->dn.lberbv.bv_val,
                                        pHttp->pszPasswd
                                        );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    /* Set curl URL */
    curlResultCode = curl_easy_setopt(pCurlHandler, CURLOPT_URL, pszCurlURL);
    BAIL_ON_CURL_REQUEST_SEND_ERROR(curlResultCode);

    /* Enable data sending as we want to pass payload for REST request */
    curlResultCode = curl_easy_setopt(pCurlHandler, CURLOPT_POST, 1L);
    BAIL_ON_CURL_REQUEST_SEND_ERROR(curlResultCode);

    curlResultCode = curl_easy_setopt(pCurlHandler, CURLOPT_POSTFIELDS, pszPayload);
    BAIL_ON_CURL_REQUEST_SEND_ERROR(curlResultCode);

    /* Set payload data size */
    curlResultCode = curl_easy_setopt(pCurlHandler, CURLOPT_POSTFIELDSIZE, (curl_off_t)(strlen(pszPayload)));
    BAIL_ON_CURL_REQUEST_SEND_ERROR(curlResultCode);

    /* Set callback function to receive response */
    curlResultCode = curl_easy_setopt(pCurlHandler, CURLOPT_WRITEFUNCTION, VmDirHttpRESTWriteCallBack);
    BAIL_ON_CURL_REQUEST_SEND_ERROR(curlResultCode);

    /* Write response to given struct */
    curlResultCode = curl_easy_setopt(pCurlHandler, CURLOPT_WRITEDATA, (PVOID) pRESTReceivedResponse);
    BAIL_ON_CURL_REQUEST_SEND_ERROR(curlResultCode);

    //FIXME Assuming basic authentication as of now
    curlResultCode = curl_easy_setopt(pCurlHandler, CURLOPT_HTTPAUTH, (LONG) CURLAUTH_BASIC);
    BAIL_ON_CURL_REQUEST_SEND_ERROR(curlResultCode);

    /* Send UserName and Password */
    curlResultCode = curl_easy_setopt(pCurlHandler, CURLOPT_USERPWD, pszUserNamePasswd);
    BAIL_ON_CURL_REQUEST_SEND_ERROR(curlResultCode);

    curlResultCode = curl_easy_setopt(pCurlHandler, CURLOPT_CUSTOMREQUEST, pHttp->pszMethod);
    BAIL_ON_CURL_REQUEST_SEND_ERROR(curlResultCode);

    /* Perform curl request */
    curlResultCode = curl_easy_perform(pCurlHandler);
    BAIL_ON_CURL_REQUEST_SEND_ERROR(curlResultCode);

    *ppRESTReceivedResponse = pRESTReceivedResponse;
    pRESTReceivedResponse = NULL;

cleanup:
    if (pCurlHandler != NULL)
    {
        curl_easy_cleanup(pCurlHandler);
    }
    VMDIR_SAFE_FREE_STRINGA(pszPayload);
    VMDIR_SAFE_FREE_STRINGA(pszCurlURL);
    VMDIR_SAFE_FREE_STRINGA(pszUserNamePasswd);
    VmDirHttpFreeRESTReceivedResponse(pRESTReceivedResponse);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
        "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Add Replication Agreement between current node
 * and other specified node in federation
 */
static
DWORD
_VmDirHttpAddRALocal(
    PVMDIR_HTTP pHttp,
    PSTR        pszSrcServerName
    )
{
    DWORD dwError = 0;
    PSTR pszReplAgrDN = NULL;
    PSTR pszReplURI = NULL;
    VDIR_OPERATION op = {0};
    VDIR_BERVALUE bvDN = VDIR_BERVALUE_INIT;

    if (pHttp == NULL || IsNullOrEmptyString(pszSrcServerName))
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    if (VmDirIsIPV6AddrFormat(pszSrcServerName))
    {
        dwError = VmDirAllocateStringPrintf(&pszReplURI, "%s://[%s]", VMDIR_LDAP_PROTOCOL, pszSrcServerName);
    }
    else
    {
        dwError = VmDirAllocateStringPrintf(&pszReplURI, "%s://%s", VMDIR_LDAP_PROTOCOL, pszSrcServerName);
    }
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = VmDirInitStackOperation(&op, VDIR_OPERATION_TYPE_INTERNAL, LDAP_REQ_ADD, NULL);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    /* Create Replication Agreement DN */
    dwError = VmDirAllocateStringPrintf(
                                &pszReplAgrDN,
                                "labeledURI=%s,cn=%s,cn=%s,cn=%s,cn=%s,cn=%s,cn=%s,%s",
                                pszReplURI,
                                VMDIR_REPL_AGRS_CONTAINER_NAME,
                                gVmdirServerGlobals.bvServerObjName.lberbv.bv_val,
                                VMDIR_SERVERS_CONTAINER_NAME,
                                gVmdirServerGlobals.pszSiteName,
                                VMDIR_SITES_RDN_VAL,
                                VMDIR_CONFIGURATION_CONTAINER_NAME,
                                gVmdirServerGlobals.systemDomainDN.lberbv.bv_val
                                );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    bvDN.lberbv.bv_val = pszReplAgrDN;
    bvDN.lberbv.bv_len = VmDirStringLenA(bvDN.lberbv.bv_val);

    dwError = VmDirBervalContentDup(&bvDN, &op.reqDn);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    op.pBEIF = VmDirBackendSelect(NULL);

    dwError = VmDirInitializeEntryFromDN(op.request.addReq.pEntry, pszReplAgrDN);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = _VmDirHttpBuildRAEntry(op.request.addReq.pEntry, pszReplURI, pHttp);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = VmDirHttpCreateAccessInfo(pHttp, op.conn);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = VmDirInternalAddEntry(&op);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    /*
     * Log success into additional info field of response payload
     * Useful when one of the two operations is failed
     */
    dwError = VmDirCatStringPrintf(
                &(pHttp->pRESTResponseToSend->pszAdditionalInfo),
                "Replication Agreement between source %s and target %s is added ",
                pszSrcServerName,
                gVmdirServerGlobals.bvServerObjName.lberbv.bv_val
                );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszReplURI);
    VMDIR_SAFE_FREE_STRINGA(pszReplAgrDN);
    VmDirFreeBervalContent(&bvDN);
    VmDirFreeOperationContent(&op);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError);
    /* Log failure of this operation in additional info field of response payload, Ignore return value */
    VmDirCatStringPrintf(
                    &(pHttp->pRESTResponseToSend->pszAdditionalInfo),
                    "Replication Agreement between source %s and target %s is not added ",
                    pszSrcServerName,
                    gVmdirServerGlobals.bvServerObjName.lberbv.bv_val
                    );
    goto cleanup;
}

/*
 * Remove Replication Agreement between current node
 * and other specified node in federation
 */
DWORD
_VmDirHttpRemoveRALocal(
    PVMDIR_HTTP pHttp,
    PSTR        pszSrcHostName
    )
{
    DWORD dwError = 0;
    PSTR pszReplURI = NULL;
    PSTR pszReplAgrDN = NULL;
    PSTR pszSrcServerName = NULL;

    if (pHttp == NULL || pszSrcHostName == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = VmDirGetServerName(
                            pszSrcHostName,
                            &pszSrcServerName
                            );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    if (VmDirIsIPV6AddrFormat(pszSrcServerName))
    {
        dwError = VmDirAllocateStringPrintf(&pszReplURI, "%s://[%s]", VMDIR_LDAP_PROTOCOL, pszSrcServerName);
    }
    else
    {
        dwError = VmDirAllocateStringPrintf(&pszReplURI, "%s://%s", VMDIR_LDAP_PROTOCOL, pszSrcServerName);
    }
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    /* Create Replication Agreement DN */
    dwError = VmDirAllocateStringPrintf(
                                &pszReplAgrDN,
                                "labeledURI=%s,cn=%s,cn=%s,cn=%s,cn=%s,cn=%s,cn=%s,%s",
                                pszReplURI,
                                VMDIR_REPL_AGRS_CONTAINER_NAME,
                                gVmdirServerGlobals.bvServerObjName.lberbv.bv_val,
                                VMDIR_SERVERS_CONTAINER_NAME,
                                gVmdirServerGlobals.pszSiteName,
                                VMDIR_SITES_RDN_VAL,
                                VMDIR_CONFIGURATION_CONTAINER_NAME,
                                gVmdirServerGlobals.systemDomainDN.lberbv.bv_val
                                );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    pHttp->pszDn = pszReplAgrDN;
    pszReplAgrDN = NULL;

    dwError = VmDirHttpDelete(pHttp);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    /*
     * Log success into additional info field of response payload
     * Useful when one of the two operations is failed
     */
    dwError = VmDirCatStringPrintf(
            &(pHttp->pRESTResponseToSend->pszAdditionalInfo),
            "Replication Agreement between source %s and target %s is removed ",
            pszSrcServerName,
            gVmdirServerGlobals.bvServerObjName.lberbv.bv_val
            );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszReplURI);
    VMDIR_SAFE_FREE_STRINGA(pszReplAgrDN);
    VMDIR_SAFE_FREE_STRINGA(pszSrcServerName);
    return dwError;

error:
    /* Log failure of this operation in additional info field of response payload, Ignore return value */
    VmDirCatStringPrintf(
                    &(pHttp->pRESTResponseToSend->pszAdditionalInfo),
                    "Replication Agreement between source %s and target %s is not removed ",
                    pszSrcServerName,
                    gVmdirServerGlobals.bvServerObjName.lberbv.bv_val
                    );
    goto cleanup;
}

static
DWORD
_VmDirHttpPerformRemoteRAOperation(
    PVMDIR_HTTP pHttp,
    PSTR        pszSrcHostName,
    PSTR        pszTgtHostName
    )
{
    DWORD dwError = 0;
    PVMDIR_REST_RECEIVED_RESPONSE pRESTReceivedResponse = NULL;
    BOOLEAN bIsRESTRequestSucceeded = FALSE;

    if (pHttp == NULL || pszSrcHostName == NULL || pszTgtHostName == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = _VmDirHttpSendRARESTRequest(
                                    pHttp,
                                    pszSrcHostName,
                                    pszTgtHostName,
                                    &pRESTReceivedResponse
                                    );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = VmDirHttpIsRESTRequestSucceeded(
                            pHttp,
                            pRESTReceivedResponse->pszResponse,
                            &bIsRESTRequestSucceeded
                            );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    if (!bIsRESTRequestSucceeded)
    {
        //FIXME Error type?
        dwError = VMDIR_ERROR_GENERIC;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

cleanup:
    VmDirHttpFreeRESTReceivedResponse(pRESTReceivedResponse);
    return dwError;
error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

DWORD
VmDirHttpAddRAOneWay(
    PVMDIR_HTTP                     pHttp,
    PVMDIR_REST_RA_OPERATION_INFO   pRESTRAOperationInfo
    )
{
    DWORD dwError = 0;
    PSTR pszLocalServerName = gVmdirServerGlobals.bvServerObjName.lberbv.bv_val;

    if (pHttp == NULL || pRESTRAOperationInfo == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    if (VmDirStringCompareA(pRESTRAOperationInfo->pszTgtServerName, pszLocalServerName, FALSE) == 0)
    {
        dwError = _VmDirHttpAddRALocal(pHttp, pRESTRAOperationInfo->pszSrcServerName);
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }
    else
    {
        dwError = _VmDirHttpPerformRemoteRAOperation(
                                    pHttp,
                                    pRESTRAOperationInfo->pszSrcServerName,
                                    pRESTRAOperationInfo->pszTgtServerName
                                    );
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

cleanup:
    return dwError;
error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

DWORD
VmDirHttpAddRATwoWay(
    PVMDIR_HTTP                     pHttp,
    PVMDIR_REST_RA_OPERATION_INFO   pRESTRAOperationInfo
    )
{
    DWORD dwError = 0;
    PSTR pszTempSrcServerName = NULL;

    if (pHttp == NULL || pRESTRAOperationInfo == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = VmDirHttpAddRAOneWay(pHttp, pRESTRAOperationInfo);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    /* Swap Src and Tgt */
    pszTempSrcServerName = pRESTRAOperationInfo->pszSrcServerName;
    pRESTRAOperationInfo->pszSrcServerName = pRESTRAOperationInfo->pszTgtServerName;
    pRESTRAOperationInfo->pszTgtServerName = pszTempSrcServerName;

    dwError = VmDirHttpAddRAOneWay(pHttp, pRESTRAOperationInfo);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

cleanup:
    return dwError;
error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

DWORD
VmDirHttpRemoveRAOneWay(
    PVMDIR_HTTP                     pHttp,
    PVMDIR_REST_RA_OPERATION_INFO   pRESTRAOperationInfo
    )
{
    DWORD dwError = 0;
    PSTR pszLocalServerName = gVmdirServerGlobals.bvServerObjName.lberbv.bv_val;

    if (pHttp == NULL || pRESTRAOperationInfo == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    if (VmDirStringCompareA(pRESTRAOperationInfo->pszTgtServerName, pszLocalServerName, FALSE) == 0)
    {
        dwError = _VmDirHttpRemoveRALocal(pHttp, pRESTRAOperationInfo->pszSrcServerName);
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }
    else
    {
        dwError = _VmDirHttpPerformRemoteRAOperation(
                                    pHttp,
                                    pRESTRAOperationInfo->pszSrcServerName,
                                    pRESTRAOperationInfo->pszTgtServerName
                                    );
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

cleanup:
    return dwError;
error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

DWORD
VmDirHttpRemoveRATwoWay(
    PVMDIR_HTTP                     pHttp,
    PVMDIR_REST_RA_OPERATION_INFO   pRESTRAOperationInfo
    )
{
    DWORD dwError = 0;
    PSTR pszTempSrcServerName = NULL;

    if (pHttp == NULL || pRESTRAOperationInfo == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = VmDirHttpRemoveRAOneWay(pHttp, pRESTRAOperationInfo);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    /* Swap Src and Tgt */
    pszTempSrcServerName = pRESTRAOperationInfo->pszSrcServerName;
    pRESTRAOperationInfo->pszSrcServerName = pRESTRAOperationInfo->pszTgtServerName;
    pRESTRAOperationInfo->pszTgtServerName = pszTempSrcServerName;

    dwError = VmDirHttpRemoveRAOneWay(pHttp, pRESTRAOperationInfo);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

cleanup:
    return dwError;
error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

VOID
VmDirHttpFreeRESTRAOperationInfo(
    PVMDIR_REST_RA_OPERATION_INFO pRESTRAOperationInfo
    )
{
    if (pRESTRAOperationInfo)
    {
        VMDIR_SAFE_FREE_STRINGA(pRESTRAOperationInfo->pszSrcServerName);
        VMDIR_SAFE_FREE_STRINGA(pRESTRAOperationInfo->pszTgtServerName);
        VMDIR_SAFE_FREE_MEMORY(pRESTRAOperationInfo);
    }
}
