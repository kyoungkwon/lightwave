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
VmDirRESTAuth(
    PVDIR_REST_OPERATION    pRestOp
    )
{
    DWORD   dwError = 0;
    PVDIR_OPERATION pBindOp = NULL;

    if (!pRestOp)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    if (IsNullOrEmptyString(pRestOp->pszAuth))
    {
        dwError = VmDirMLSetupAnonymousAccessInfo(&pRestOp->pConn->AccessInfo);
        BAIL_ON_VMDIR_ERROR(dwError);

        pRestOp->pConn->bIsAnonymousBind = TRUE;
        goto cleanup;
    }

    dwError = VmDirExternalOperationCreate(
            NULL, -1, LDAP_REQ_BIND, pRestOp->pConn, &pBindOp);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirRESTAuthBasic(pRestOp, pBindOp);
    dwError = dwError ? VmDirRESTAuthToken(pRestOp, pBindOp) : 0;
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirInternalBindEntry(pBindOp);
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    VmDirFreeOperation(pBindOp);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

DWORD
VmDirRESTAuthBasic(
    PVDIR_REST_OPERATION    pRestOp,
    PVDIR_OPERATION         pBindOp
    )
{
    DWORD   dwError = 0;
    int     sts = 0;
    int     len = 0;
    PSTR    pszBasic = NULL;
    PSTR    pszData = NULL;
    PSTR    pszDecode = NULL;
    PSTR    pszPass = NULL;

    if (!pRestOp || IsNullOrEmptyString(pRestOp->pszAuth) || !pBindOp)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    pszBasic = strstr(pRestOp->pszAuth, "Basic ");
    if (IsNullOrEmptyString(pszBasic))
    {
        dwError = VMDIR_ERROR_AUTH_METHOD_NOT_SUPPORTED;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    pszData = pszBasic + strlen("Basic ");

    dwError = VmDirAllocateMemory(VmDirStringLenA(pszData) + 1, (PVOID*)&pszDecode);
    BAIL_ON_VMDIR_ERROR(dwError);

    sts = sasl_decode64(pszData, strlen(pszData), pszDecode, strlen(pszData), &len);
    if (sts != SASL_OK)
    {
        dwError = VMDIR_ERROR_AUTH_METHOD_NOT_SUPPORTED;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    pszPass = strchr(pszDecode, ':');
    if (IsNullOrEmptyString(pszPass))
    {
        dwError = VMDIR_ERROR_AUTH_METHOD_NOT_SUPPORTED;
        BAIL_ON_VMDIR_ERROR(dwError);
    }
    *pszPass = '\0';
    pszPass++;

    dwError = VmDirStringToBervalContent(pszDecode, &pBindOp->reqDn);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirStringToBervalContent(pszPass, &pBindOp->request.bindReq.cred);
    BAIL_ON_VMDIR_ERROR(dwError);

    pBindOp->request.bindReq.method = LDAP_AUTH_SIMPLE;

cleanup:
    VMDIR_SECURE_FREE_STRINGA(pszDecode);
    return dwError;

error:
    goto cleanup;
}

/*
 * Do Authentication based on received Token
 */
DWORD
VmDirRESTAuthToken(
    PVDIR_REST_OPERATION    pRestOp,
    PVDIR_OPERATION         pBindOp
    )
{
    DWORD   dwError = 0;
    PSTR    pszUPN = NULL;
    PSTR    pszDN = NULL;

    if (!pRestOp || IsNullOrEmptyString(pRestOp->pszAuth) || !pBindOp)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    // TODO use access token from rest request
    dwError = VmDirAllocateStringA("Administrator@vsphere.local", &pszUPN);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirUPNToDN(pszUPN, &pszDN);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmDirStringToBervalContent(pszDN, &pBindOp->reqDn);
    BAIL_ON_VMDIR_ERROR(dwError);

    pBindOp->request.bindReq.method = LDAP_AUTH_NONE;

cleanup:
    VMDIR_SAFE_FREE_STRINGA(pszUPN);
    VMDIR_SAFE_FREE_STRINGA(pszDN);
    return dwError;

error:
    goto cleanup;
}
