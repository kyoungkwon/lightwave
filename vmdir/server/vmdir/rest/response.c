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
 * Assign values for REST response payload
 */
DWORD
VmDirHttpCreateRESTResponsePayload(
    DWORD         dwLdapStatusCode,
    PCSTR         pszErrorMsg,
    PCSTR         pszAdditionalInfo,
    PCSTR         pszOperationResult,
    PVMDIR_HTTP   pHttp
    )
{

    DWORD dwError = 0;
    PSTR pszLdapStatusCode = NULL;
    PSTR pszErrorMessage = NULL;
    PSTR pszResult = NULL;

    if (pHttp                == NULL ||
        pszErrorMsg          == NULL ||
        pszAdditionalInfo    == NULL ||
        pszOperationResult   == NULL
        )
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirAllocateStringPrintf(&pszLdapStatusCode, "%d", dwLdapStatusCode);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirAllocateStringA(pszErrorMsg, &pszErrorMessage);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirAllocateStringA(pszOperationResult, &pszResult);
    BAIL_ON_VMDIR_ERROR(dwError);

    /*
     * Preserve whatever is there in additional info
     * Useful when we want to combine messages from different operations initiated due to one operation
     * i.e. Add/Remove ReplicationAgreements
     */
    dwError = VmDirCatStringPrintf(
                &(pHttp->pRESTResponseToSend->pszAdditionalInfo),
                "%s",
                pszAdditionalInfo
                );
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    pHttp->pRESTResponseToSend->pszLdapStatusCode = pszLdapStatusCode;
    pszLdapStatusCode = NULL;
    pHttp->pRESTResponseToSend->pszErrorMessage = pszErrorMessage;
    pszErrorMessage = NULL;
    pHttp->pRESTResponseToSend->pszResult = pszResult;
    pszResult = NULL;

    pHttp->bIsResponseCreated = TRUE;

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszLdapStatusCode);
    VMDIR_SAFE_FREE_STRINGA(pszErrorMessage);
    VMDIR_SAFE_FREE_STRINGA(pszResult);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Build JSON response for GetDCInfo
 */
DWORD
VmDirHttpBuildJSONGetDCInfo(
    PVMDIR_DC_INFO* ppDCInfo,
    DWORD           dwNumDC,
    PSTR*           ppszAnswer
    )
{
    DWORD dwError = 0;
    PSTR pszPartnerEntryComma = ",";
    PSTR pszDCEntryComma = ",";
    PSTR pszAnswer = NULL;
    size_t idxDC = 0;
    size_t idxPartner = 0;

    if (dwNumDC > 0 && ppDCInfo == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirCatStringPrintf(&pszAnswer, "  \"DCs\": [\n");
    BAIL_ON_VMDIR_ERROR(dwError);

    for (idxDC=0; idxDC < dwNumDC; idxDC++)
    {
        if (idxDC + 1 == dwNumDC)
        {
            pszDCEntryComma = "";
        }

        dwError = VmDirCatStringPrintf(&pszAnswer, "    {\n      \"%s\": \"%s\",\n      \"site\": \"%s\",\n"
                                        "      \"replication-partners\": [\n",
                                        ATTR_CN, ppDCInfo[idxDC]->pszHostName, ppDCInfo[idxDC]->pszSiteName);
        BAIL_ON_VMDIR_ERROR(dwError);

        for (idxPartner = 0; idxPartner < ppDCInfo[idxDC]->dwPartnerCount; idxPartner++)
        {
            if (idxPartner + 1 == ppDCInfo[idxDC]->dwPartnerCount)
            {
                pszPartnerEntryComma = "";
            }

            /* Skip protocol name in URI */
            dwError = VmDirCatStringPrintf(&pszAnswer, "        {\n          \"%s\": \"%s\"\n        }%s\n",
                            ATTR_LABELED_URI, ppDCInfo[idxDC]->ppPartners[idxPartner] + strlen("ldap://"),
                            pszPartnerEntryComma);
            BAIL_ON_VMDIR_ERROR(dwError);
        }

        dwError = VmDirCatStringPrintf(&pszAnswer, "      ]\n    }%s\n", pszDCEntryComma);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirCatStringPrintf(&pszAnswer, "  ]");
    BAIL_ON_VMDIR_ERROR(dwError);

    *ppszAnswer = pszAnswer;
    pszAnswer = NULL;

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszAnswer);
    return dwError;

error:
    goto cleanup;
}

/*
 * Build JSON response for GetComputers
 */
DWORD
VmDirHttpBuildJSONGetComputers(
    PSTR*   ppszComputers,
    DWORD   dwNumComputers,
    PSTR*   ppszAnswer
    )
{
    DWORD dwError = 0;
    size_t idxComputer = 0;
    PSTR pszAnswer = NULL;
    PSTR pszComputerEntryComma = ",";

    if (dwNumComputers > 0 && ppszComputers == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirCatStringPrintf(&pszAnswer, "  \"Computers\": [\n");
    BAIL_ON_VMDIR_ERROR(dwError);

    for (idxComputer=0; idxComputer < dwNumComputers; idxComputer++)
    {
        if (idxComputer + 1 == dwNumComputers)
        {
            pszComputerEntryComma = "";
        }

        dwError = VmDirCatStringPrintf(&pszAnswer, "    {\n      \"%s\": \"%s\"\n    }%s\n",
                            ATTR_CN, ppszComputers[idxComputer], pszComputerEntryComma);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirCatStringPrintf(&pszAnswer, "  ]");
    BAIL_ON_VMDIR_ERROR(dwError);

    *ppszAnswer = pszAnswer;
    pszAnswer = NULL;

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszAnswer);
    return dwError;
error:
    goto cleanup;

}

/*
 * Build JSON response for SEARCH operation
 */
DWORD
VmDirHttpBuildJSONSearchResponse(
    PVMDIR_HTTP         pHttp,
    PVDIR_ENTRY_ARRAY   pEntryArray,
    PSTR                pszPageCookie,
    PVDIR_OPERATION     pOp,
    PSTR*               ppszAnswer
    )
{
    DWORD dwError = 0;
    size_t i = 0;
    PSTR pszAttr = NULL;
    PSTR pszAnswer = NULL;
    PSTR pszAttrVals = NULL;

    if (pHttp == NULL || pEntryArray == NULL || pOp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = VmDirCatStringPrintf(&pszAnswer, "[\n");
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    if (pszPageCookie)
    {
        dwError = VmDirCatStringPrintf(&pszAnswer, "  \"pageNum\" : \"%s\",\n", pszPageCookie);
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    if (pEntryArray->iSize > 0)
    {
        for ( i = 0; i < pEntryArray->iSize; i++ )
        {
            PCSTR pszEntryComma = ",";
            PVDIR_ENTRY pEntry = &(pEntryArray->pEntry[i]);

            dwError = VmDirSrvAccessCheck(pOp, &(pOp->conn->AccessInfo), pEntry, VMDIR_RIGHT_DS_READ_PROP);
            if (dwError == VMDIR_ERROR_INSUFFICIENT_ACCESS)
            {
                /* skip this entry as user is unauthorized */
                VMDIR_LOG_WARNING( VMDIR_LOG_MASK_ALL,
                                   "Access deny on search entry result [%s,%d] (bindedDN-%s) (targetDn-%s)\n",
                                   __FILE__, __LINE__, pOp->conn->AccessInfo.pszBindedDn, pEntry->dn.lberbv.bv_val);
                dwError = 0;
                continue;
            }

            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

            if (!(i + 1 < pEntryArray->iSize))
            {
                pszEntryComma = "";
            }

            dwError = VmDirCatStringPrintf(&pszAnswer, "  {\n"
                                             "     \"dn\": \"%s\",\n"
                                             "     \"attrs\": {\n", pEntry->dn.lberbv.bv_val);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

            if (pHttp->pszAttrs)
            {
                PCSTR pszHaystack = pHttp->pszAttrs;
                while (pszHaystack)
                {
                    dwError = VmDirGetComponent(&pszHaystack, ',', &pszAttr);
                    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

                    PCSTR pszAttrComma = ",";
                    if (!pszHaystack)
                    {
                        pszAttrComma = "";
                    }

                    if (pszAttr)
                    {
                        PVDIR_ATTRIBUTE pAttr = VmDirFindAttrByName(pEntry, pszAttr);
                        if (pAttr)
                        {
                            dwError = VmDirCatStringPrintf(&pszAnswer, "       \"%s\": [", pAttr->type.lberbv.bv_val);
                            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

                            dwError = VmDirHttpGetAllAttributeValues(pAttr, &pszAttrVals);
                            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

                            dwError = VmDirCatStringPrintf(&pszAnswer, "%s", pszAttrVals);
                            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

                            dwError = VmDirCatStringPrintf(&pszAnswer, "]%s\n", pszAttrComma);
                            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
                        }
                        VMDIR_SAFE_FREE_STRINGA(pszAttrVals);
                        pszAttrVals = NULL;
                        VMDIR_SAFE_FREE_MEMORY(pszAttr);
                        pszAttr = NULL;
                    }
                }
            }
            else
            {
                PVDIR_ATTRIBUTE  pAttr = NULL;
                for (pAttr = pEntry->attrs; pAttr; pAttr = pAttr->next)
                {

                    PCSTR pszAttrComma = ",";
                    if (!pAttr->next)
                    {
                       pszAttrComma = "";
                    }
                    dwError = VmDirCatStringPrintf(&pszAnswer, "       \"%s\": [", pAttr->type.lberbv.bv_val);
                    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

                    dwError = VmDirHttpGetAllAttributeValues(pAttr, &pszAttrVals);
                    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

                    dwError = VmDirCatStringPrintf(&pszAnswer, "%s", pszAttrVals);
                    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

                    dwError = VmDirCatStringPrintf(&pszAnswer, "]%s\n", pszAttrComma);
                    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

                    VMDIR_SAFE_FREE_STRINGA(pszAttrVals);
                    pszAttrVals = NULL;
                }
            }
            dwError = VmDirCatStringPrintf(&pszAnswer, "    }\n"
                                             "  }%s\n", pszEntryComma);
            BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
        }
    }
    dwError = VmDirCatStringPrintf(&pszAnswer, "]");
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    *ppszAnswer = pszAnswer;
    pszAnswer = NULL;

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszAnswer);
    VMDIR_SAFE_FREE_MEMORY(pszAttr);
    VMDIR_SAFE_FREE_STRINGA(pszAttrVals);
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
VmDirHttpSendResponse(
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;
    uint32_t done = 0;
    int byteSent = 0;
    int bytesToSend = 0;
    PSTR pszResponsePayload = NULL;
    size_t length = 0;
    char payloadLength[128] = {0};

    if (pHttp == NULL || pHttp->pRESTResponseToSend == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmRESTSetHttpStatusVersion(pHttp->ppRestRes, "HTTP/1.1");
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmRESTSetHttpStatusCode(pHttp->ppRestRes, "200");
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmRESTSetHttpReasonPhrase(pHttp->ppRestRes, "OK");
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmRESTSetHttpHeader(pHttp->ppRestRes, "Connection", "close");
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmRESTSetHttpHeader(pHttp->ppRestRes, "Content-Type", "application/json");
    BAIL_ON_VMDIR_ERROR(dwError);

    if (pHttp->pszWWWAuthenticateToken)
    {
        dwError = VmRESTSetHttpHeader(pHttp->ppRestRes, "WWW-Authenticate", pHttp->pszWWWAuthenticateToken);
        BAIL_ON_VMDIR_ERROR(dwError);
    }
    else
    {
        dwError = VmRESTSetHttpHeader(pHttp->ppRestRes, "WWW-Authenticate", "Negotiate");
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmDirAllocateStringPrintf(&pszResponsePayload,
                                            "{\n"
                                            "  \"ldap-status\": \"%s\",\n"
                                            "  \"error-message\": \"%s\",\n"
                                            "  \"additional-info\": \"%s\",\n"
                                            "  \"result\": %s\n"
                                            "}\n",
                                            pHttp->pRESTResponseToSend->pszLdapStatusCode,
                                            pHttp->pRESTResponseToSend->pszErrorMessage,
                                            pHttp->pRESTResponseToSend->pszAdditionalInfo,
                                            pHttp->pRESTResponseToSend->pszResult
                                            );
    BAIL_ON_VMDIR_ERROR(dwError);

    length = strlen(pszResponsePayload);
    sprintf(payloadLength, "%ld", length);

    if (length < MAX_HTTP_PAYLOAD_LENGTH)
    {
        dwError = VmRESTSetHttpHeader(pHttp->ppRestRes, "Content-Length", payloadLength);
        BAIL_ON_VMDIR_ERROR(dwError);

        dwError = VmRESTSetHttpPayload(pHttp->ppRestRes, pszResponsePayload, length, &done);
        BAIL_ON_VMDIR_ERROR(dwError);
    }
    else
    {
        dwError = VmRESTSetHttpHeader(pHttp->ppRestRes, "Transfer-Encoding", "chunked");
        BAIL_ON_VMDIR_ERROR(dwError);

        while (byteSent < length)
        {
            bytesToSend = (length - byteSent) > MAX_HTTP_PAYLOAD_LENGTH ?
                                            MAX_HTTP_PAYLOAD_LENGTH : (length - byteSent);

            dwError = VmRESTSetHttpPayload(pHttp->ppRestRes, pszResponsePayload + byteSent, bytesToSend, &done);
            BAIL_ON_VMDIR_ERROR(dwError);

            byteSent += bytesToSend;
        }

        dwError = VmRESTSetHttpPayload(pHttp->ppRestRes, "", 0, &done);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    /* Ensure that response is sent, done will be 1 on success */
    if (!done)
    {
        dwError = VMDIR_ERROR_GENERIC;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszResponsePayload);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
        "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

VOID
VmDirFreeRESTResponseToSend(
    PVMDIR_REST_RESPONSE_TO_SEND pRESTResponseToSend
    )
{
    if (pRESTResponseToSend)
    {
        VMDIR_SAFE_FREE_STRINGA(pRESTResponseToSend->pszLdapStatusCode);
        VMDIR_SAFE_FREE_STRINGA(pRESTResponseToSend->pszErrorMessage);
        VMDIR_SAFE_FREE_STRINGA(pRESTResponseToSend->pszAdditionalInfo);
        VMDIR_SAFE_FREE_STRINGA(pRESTResponseToSend->pszResult);
        VMDIR_SAFE_FREE_MEMORY(pRESTResponseToSend);
    }
}

/*
 * Free Received REST Response for server initiated REST Request
 */
VOID
VmDirHttpFreeRESTReceivedResponse(
    PVMDIR_REST_RECEIVED_RESPONSE pRESTReceivedResponse
    )
{
    if (pRESTReceivedResponse)
    {
        VMDIR_SAFE_FREE_STRINGA(pRESTReceivedResponse->pszResponse);
        VMDIR_SAFE_FREE_MEMORY(pRESTReceivedResponse);
        pRESTReceivedResponse = NULL;
    }
}
