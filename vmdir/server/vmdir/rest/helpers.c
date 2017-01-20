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
 * Perform Internal Delete operation
 * on entry specified in 'pszDn' of HTTP struct
 */
DWORD
VmDirHttpDelete(
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;
    VDIR_OPERATION op = {0};
    VDIR_BERVALUE bvDN = VDIR_BERVALUE_INIT;

    if (pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);
    }

    dwError = VmDirInitStackOperation(&op, VDIR_OPERATION_TYPE_INTERNAL, LDAP_REQ_DELETE, NULL);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    bvDN.lberbv.bv_val = pHttp->pszDn;
    bvDN.lberbv.bv_len = VmDirStringLenA(bvDN.lberbv.bv_val);

    dwError = VmDirBervalContentDup( &bvDN, &op.reqDn );
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirBervalContentDup(&op.reqDn, &op.request.deleteReq.dn);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    op.pBEIF = VmDirBackendSelect(op.reqDn.lberbv.bv_val);

    dwError = VmDirHttpCreateAccessInfo(pHttp, op.conn);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

    dwError = VmDirInternalDeleteEntry(&op);
    BAIL_ON_VMDIR_REST_ERROR(dwError, &op, pHttp);

cleanup:
    VmDirFreeBervalContent(&bvDN);
    VmDirFreeOperationContent(&op);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
        "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Get All computers and their count
 */
DWORD
VmDirHttpGetComputers(
    PVMDIR_HTTP     pHttp,
    PVDIR_OPERATION pOp,
    PSTR**          pppszComputers,
    DWORD*          pdwNumComputers
    )
{
    DWORD dwError = 0;
    PSTR* ppszComputers = NULL;
    DWORD dwNumComputers = 0;

    dwError = VmDirHttpGetObjectAttribute(
                    pHttp,
                    pOp,
                    "ou=Computers",
                    OC_COMPUTER,
                    ATTR_CN,
                    LDAP_SCOPE_ONELEVEL,
                    &ppszComputers,
                    &dwNumComputers);
    BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);

    *pppszComputers = ppszComputers;
    ppszComputers = NULL;
    *pdwNumComputers = dwNumComputers;

cleanup:
    VmDirFreeStringArray(ppszComputers, dwNumComputers);
    return dwError;

error:
    goto cleanup;
}

DWORD
VmDirHttpGetDCInfo(
    PVMDIR_HTTP         pHttp,
    PVDIR_OPERATION     pOp,
    PVMDIR_DC_INFO**    pppDCInfo,
    DWORD*              pdwNumDC
    )
{
    DWORD dwError = 0;
    PVMDIR_DC_INFO* ppDCInfo = NULL;
    PSTR* ppszServers = NULL;
    PSTR* ppszSites = NULL;
    DWORD dwNumDC = 0;
    DWORD idxDC = 0;
    DWORD dwNumSites = 0;
    size_t idxSite = 0;

    if (pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);
    }

    dwError = VmDirHttpGetObjectAttribute(
                        pHttp,
                        pOp,
                        "cn=Sites,cn=Configuration",
                        OC_DIR_SERVER,
                        ATTR_CN,
                        LDAP_SCOPE_SUBTREE,
                        &ppszServers,
                        &dwNumDC);
    BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);

    if (dwNumDC > 0 )
    {
        dwError = VmDirAllocateMemory(
                        dwNumDC*sizeof(VMDIR_DC_INFO),
                        (PVOID*)&ppDCInfo
                        );
        BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);

        dwError = VmDirHttpGetObjectAttribute(
                        pHttp,
                        pOp,
                        "cn=Sites,cn=Configuration",
                        OC_CONTAINER,
                        ATTR_CN,
                        LDAP_SCOPE_ONELEVEL,
                        &ppszSites,
                        &dwNumSites);
        BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);

        for (idxSite=0; idxSite < dwNumSites; idxSite++)
        {
            dwError = VmDirHttpGetSiteDCInfo(pHttp, pOp, ppszSites[idxSite], &idxDC, ppDCInfo);
            BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);
        }
    }

    *pppDCInfo = ppDCInfo;
    ppDCInfo = NULL;
    *pdwNumDC = dwNumDC;

cleanup:
    VmDirFreeStringArray(ppszSites, dwNumSites);
    VmDirFreeStringArray(ppszServers, dwNumDC);
    VmDirFreeDCInfoArray(ppDCInfo, dwNumDC);
    return dwError;
error:
    goto cleanup;
}

/*
 * Return info related to DCs and their replication partners
 * Also return all computers info along with DCs
 */
DWORD
VmDirHttpGetSiteDCInfo(
    PVMDIR_HTTP         pHttp,
    PVDIR_OPERATION     pOp,
    PSTR                pszSiteName,
    DWORD*              pdwIdxDC,
    PVMDIR_DC_INFO*     ppDCInfo
    )
{
    DWORD dwError = 0;
    PSTR pszSiteServersDNPrefix = NULL;
    PSTR pszServerDNPrefix = NULL;
    PSTR* ppszServers = NULL;
    PSTR* ppszPartners = NULL;
    DWORD dwNumPartners = 0;
    DWORD dwNumServers = 0;
    size_t idxServer = 0;

    if (pHttp == NULL || pOp == NULL || pszSiteName == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);
    }

    dwError = VmDirAllocateStringPrintf(
                    &pszSiteServersDNPrefix,
                    "cn=Servers,cn=%s,cn=Sites,cn=Configuration",
                    pszSiteName);
    BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);

    dwError = VmDirHttpGetObjectAttribute(
                    pHttp,
                    pOp,
                    pszSiteServersDNPrefix,
                    OC_DIR_SERVER,
                    ATTR_CN,
                    LDAP_SCOPE_ONELEVEL,
                    &ppszServers,
                    &dwNumServers);
    BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);

    for (idxServer=0; idxServer < dwNumServers; idxServer++, (*pdwIdxDC)++)
    {
        dwError = VmDirAllocateMemory(
                        sizeof(VMDIR_DC_INFO),
                        (PVOID*)&ppDCInfo[*pdwIdxDC]
                        );
        BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);

        dwError = VmDirAllocateStringA(
                        ppszServers[idxServer],
                        &ppDCInfo[*pdwIdxDC]->pszHostName);
        BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);

        dwError = VmDirAllocateStringA(
                        pszSiteName,
                        &ppDCInfo[*pdwIdxDC]->pszSiteName);
        BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);

        dwError = VmDirAllocateStringPrintf(
                        &pszServerDNPrefix,
                        "cn=%s,%s",
                        ppszServers[idxServer],
                        pszSiteServersDNPrefix);
        BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);

        dwError = VmDirHttpGetObjectAttribute(
                        pHttp,
                        pOp,
                        pszServerDNPrefix,
                        OC_REPLICATION_AGREEMENT,
                        ATTR_LABELED_URI,
                        LDAP_SCOPE_SUBTREE,
                        &ppszPartners,
                        &dwNumPartners);
        BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);

        VMDIR_SAFE_FREE_STRINGA(pszServerDNPrefix);

        if (dwNumPartners > 0)
        {
            DWORD idxPartner = 0;
            dwError = VmDirAllocateMemory(
                            sizeof(PSTR)*dwNumPartners,
                            (PVOID)&ppDCInfo[*pdwIdxDC]->ppPartners);
            BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);
            for (idxPartner = 0; idxPartner < dwNumPartners; ++idxPartner)
            {
                dwError = VmDirAllocateStringA(
                                ppszPartners[idxPartner],
                                &ppDCInfo[*pdwIdxDC]->ppPartners[idxPartner]);
                BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);
            }

            ppDCInfo[*pdwIdxDC]->dwPartnerCount = dwNumPartners;
        }

        VmDirFreeStringArray(ppszPartners, dwNumPartners);
        ppszPartners = NULL;
    }

cleanup:
    VmDirFreeStringArray(ppszPartners, dwNumPartners);
    VmDirFreeStringArray(ppszServers, dwNumServers);
    VMDIR_SAFE_FREE_STRINGA(pszServerDNPrefix);
    VMDIR_SAFE_FREE_MEMORY(pszSiteServersDNPrefix);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                "%s failed, error (%d)", __FUNCTION__, dwError);
     goto cleanup;
}

DWORD
VmDirHttpGetObjectAttribute(
    PVMDIR_HTTP     pHttp,
    PVDIR_OPERATION pOp,
    PSTR            pszSearchDNPrefix,
    PSTR            pszObjectClass,
    PSTR            pszAttribute,
    int             scope,
    PSTR**          pppszValues,
    DWORD*          pdwNumValues
    )
{
    DWORD dwError = 0;
    DWORD dwValuesCount = 0;
    PSTR* ppszValues = NULL;
    PSTR pszFilter = NULL;
    PSTR pszSearchBaseDNPrefix = NULL;
    VDIR_ENTRY_ARRAY  entryArray = {0};
    size_t i = 0;

    if (pHttp == NULL || pOp == NULL ||
                pszSearchDNPrefix == NULL || pszObjectClass == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);
    }

    dwError = VmDirAllocateStringPrintf(
                    &pszSearchBaseDNPrefix,
                    "%s,%s",
                    pszSearchDNPrefix,
                    pHttp->pszDn);
    BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);

    dwError = VmDirAllocateStringPrintf(
                        &pszFilter,
                        "(objectclass=%s)",
                        pszObjectClass
                        );
    BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);

    dwError = VmDirFilterInternalSearch(
                    pszSearchBaseDNPrefix,
                    scope,
                    pszFilter,
                    0,
                    NULL,
                    &entryArray);
    BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);

    if (entryArray.iSize > 0)
    {
        dwError = VmDirAllocateMemory(sizeof(PSTR) * entryArray.iSize, (VOID*)&ppszValues);
        BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);

        for (i = 0; i < entryArray.iSize; i++)
        {
            PVDIR_ENTRY pEntry = &(entryArray.pEntry[i]);

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
            BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);

            PVDIR_ATTRIBUTE pAttr = VmDirFindAttrByName(pEntry, pszAttribute);
            if (pAttr)
            {
                dwError = VmDirAllocateMemory(
                                    sizeof(CHAR) * pAttr->vals[0].lberbv_len + 1,
                                    (PVOID)&ppszValues[dwValuesCount]);
                BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);

                dwError = VmDirStringNCpyA(
                                    ppszValues[dwValuesCount],
                                    pAttr->vals[0].lberbv_len + 1,
                                    pAttr->vals[0].lberbv_val,
                                    pAttr->vals[0].lberbv_len);
                BAIL_ON_VMDIR_REST_ERROR(dwError, pOp, pHttp);

                dwValuesCount = dwValuesCount + 1;
            }
        }
    }

    *pppszValues = ppszValues;
    ppszValues = NULL;
    *pdwNumValues = dwValuesCount;
    dwValuesCount = 0;

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszSearchBaseDNPrefix);
    VMDIR_SAFE_FREE_STRINGA(pszFilter);
    VmDirFreeEntryArrayContent(&entryArray);
    return dwError;

error:
    if (ppszValues != NULL)
    {
        for (i=0; i<entryArray.iSize; i++)
        {
            VMDIR_SAFE_FREE_STRINGA(ppszValues[i]);
        }
    }
    VMDIR_SAFE_FREE_MEMORY(ppszValues);
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                "%s failed, error (%d)", __FUNCTION__, dwError);
     goto cleanup;
}
