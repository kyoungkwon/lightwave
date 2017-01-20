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

#include <sasl/saslutil.h>      /* base64 decode */

DWORD
VmDirHttpGenerateWWWAuthenticateNegotiateGSS(
    gss_buffer_desc*    pBuffer,
    PSTR*               ppszNegotiate
    )
{
    DWORD dwError = 0;
    PSTR pszEncodedData = NULL;
    PSTR pszNegotiate = NULL;
    int len = 0;

    if (pBuffer)
    {
        dwError = VmDirAllocateMemory(pBuffer->length * 2 + 1, (PVOID*)&pszEncodedData);
        BAIL_ON_VMDIR_ERROR(dwError);

        pszEncodedData[0] = ' ';
        sasl_encode64(pBuffer->value, pBuffer->length, pszEncodedData + 1, pBuffer->length * 2, &len);
    }

    dwError =  VmDirAllocateStringPrintf(&pszNegotiate, "Negotiate%s", pszEncodedData ? pszEncodedData : "");
    BAIL_ON_VMDIR_ERROR(dwError);

    *ppszNegotiate = pszNegotiate;

cleanup:
    VMDIR_SAFE_FREE_MEMORY(pszEncodedData);
    return dwError;
error:
    VMDIR_SAFE_FREE_STRINGA(pszNegotiate);
    goto cleanup;
}

DWORD
VmDirHttpAuthNegotiate(
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;
    PSTR pAuthorization = NULL;
    PSTR pNegotiate = NULL;
    PSTR pszDecode = NULL;
    int len = 0;
    PSTR pData = NULL;
    PVDIR_ENTRY pEntry = NULL;
    OM_uint32 major_status, minor_status;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc display_name = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;
    gss_name_t client_name = GSS_C_NO_NAME;
    static gss_OID_desc gss_spnego_mech_oid_desc =
                                  {6, (void *)"\x2b\x06\x01\x05\x05\x02"};
    static gss_OID gss_spnego_mech_oid = &gss_spnego_mech_oid_desc;

    if (pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    dwError = VmRESTGetHttpHeader(pHttp->pRestReq, "Authorization", &pAuthorization);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (!pAuthorization)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER; // FIXME
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    pNegotiate = strstr(pAuthorization, "Negotiate ");
    if (!pNegotiate || !*pNegotiate)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER; // FIXME
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    len = 0;
    pData = pNegotiate + strlen("Negotiate ");

    dwError = VmDirAllocateStringA(pData, &pszDecode);
    BAIL_ON_VMDIR_ERROR(dwError);

    sasl_decode64(pData, strlen(pData), pszDecode, strlen(pData), &len);

    input_token.length = len;
    input_token.value = pszDecode;

    major_status = gss_accept_sec_context(&minor_status,
                               &gss_context,
                               NULL,
                               &input_token,
                               NULL,
                               &client_name,
                               &gss_spnego_mech_oid,
                               &output_token,
                               NULL,
                               NULL,
                               NULL);

    if (output_token.length)
    {
        dwError = VmDirHttpGenerateWWWAuthenticateNegotiateGSS(&output_token, &pHttp->pszWWWAuthenticateToken);
        BAIL_ON_VMDIR_ERROR(dwError);
    }

    if (major_status == GSS_S_CONTINUE_NEEDED)
    {
        OM_uint32 min2;
        gss_buffer_desc mech_msg = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc gss_msg = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc minor_msg = GSS_C_EMPTY_BUFFER;
        OM_uint32 msg_ctx = 0;
        PSTR pszError = NULL;

        gss_oid_to_str(&min2, gss_spnego_mech_oid, &mech_msg);
        gss_display_status(&min2, major_status, GSS_C_GSS_CODE, gss_spnego_mech_oid, &msg_ctx, &gss_msg);
        gss_display_status(&min2, minor_status, GSS_C_MECH_CODE, gss_spnego_mech_oid, &msg_ctx, &minor_msg);

        dwError = VmDirAllocateStringPrintf(&pszError, "gss_rc[%d:%*s] mech[%*s] minor[%u:%*s]",
            major_status, (int)gss_msg.length,
            (const char *)(gss_msg.value?gss_msg.value:""),
            (int)mech_msg.length,
            (const char *)(mech_msg.value?mech_msg.value:""),
            minor_status, (int)minor_msg.length,
            (const char *)(minor_msg.value?minor_msg.value:""));
        BAIL_ON_VMDIR_ERROR(dwError);

        gss_release_buffer(&min2, &mech_msg);
        gss_release_buffer(&min2, &gss_msg);
        gss_release_buffer(&min2, &minor_msg);

        dwError = VMDIR_ERROR_INSUFFICIENT_ACCESS;
        BAIL_ON_VMDIR_ERROR(dwError);
    }
    if (major_status == GSS_S_COMPLETE)
    {
        gss_display_name(&minor_status, client_name, &display_name, NULL);

        dwError = VmDirAllocateStringA(display_name.value, &(pHttp->pszUser));
        BAIL_ON_VMDIR_ERROR(dwError);
    }

cleanup:
    gss_release_buffer(&minor_status, &display_name);
    gss_release_name(&minor_status, &client_name);
    gss_delete_sec_context(&minor_status, &gss_context, GSS_C_NO_BUFFER);
    gss_release_buffer(&minor_status, &output_token);
    VmDirFreeEntry(pEntry);
    VMDIR_SECURE_FREE_STRINGA(pszDecode);
    return dwError;
error:
    goto cleanup;
}

DWORD
VmDirHttpAuthBasic(
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;
    PSTR pAuthorization = NULL;
    PSTR pBasic = NULL;
    int len = 0;
    PSTR pData = NULL;
    PSTR pszDecode = NULL;
    PSTR pszPass = NULL;
    PVDIR_ENTRY pEntry = NULL;

    if (pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    dwError = VmRESTGetHttpHeader(pHttp->pRestReq, "Authorization", &pAuthorization);
    BAIL_ON_VMDIR_ERROR(dwError);

    if (!pAuthorization)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    pBasic = strstr(pAuthorization, "Basic ");
    if (!pBasic || !*pBasic)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    pData = pBasic + strlen("Basic ");

    dwError = VmDirAllocateStringA(pData, &pszDecode);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    sasl_decode64(pData, strlen(pData), pszDecode, strlen(pData), &len);

    pszPass = strchr(pszDecode, ':');
    if (pszPass)
    {
        VDIR_BERVALUE passwd = VDIR_BERVALUE_INIT;
        PACCESS_TOKEN pToken = NULL;

        *pszPass = '\0';
        pszPass++;

        dwError = VmDirSimpleDNToEntry(pszDecode, &pEntry);
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

        passwd.lberbv.bv_val = pszPass;
        passwd.lberbv.bv_len = strlen(passwd.lberbv.bv_val);
        dwError = VdirPasswordCheck(&passwd, pEntry);
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

        dwError = VmDirSrvCreateAccessTokenWithEntry(pEntry, &pToken, &(pHttp->pszBindedObjectSid));
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

        dwError = VmDirAllocateStringOfLenA(
                            passwd.lberbv.bv_val,
                            passwd.lberbv.bv_len,
                            &(pHttp->pszPasswd)
                            );
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

        pHttp->pEntry = pEntry;
        pEntry = NULL;
        pHttp->pToken = pToken;
    }

cleanup:
    VmDirFreeEntry(pEntry);
    VMDIR_SECURE_FREE_STRINGA(pszDecode);
    return dwError;
error:
    goto cleanup;
}

DWORD
VmDirHttpAuth(
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;

    if (pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    if (getenv("VMDIR_NO_AUTH")) // hack FIXME
    {
        goto cleanup;
    }

    dwError = VmDirHttpAuthBasic(pHttp);
    if (dwError != VMDIR_ERROR_INVALID_PARAMETER)
    {
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }
/*
    uiError = VmDirHttpAuthNegotiate(pHttp);
    if (uiError != VMDIR_ERROR_INVALID_PARAMETER)
    {
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }
*/
cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

/*
 * Do Authentication based on received Token
 */
DWORD
VmDirHttpAuthToken(
    PVMDIR_HTTP pHttp
    )
{
    DWORD dwError = 0;
    PSTR pszUPN = NULL;
    PSTR pszDn = NULL;
    PVDIR_ENTRY pEntry = NULL;
    PACCESS_TOKEN pToken = NULL;
    PSTR pszBindedObjectSid = NULL;

    if (pHttp == NULL)
    {
        dwError = VMDIR_ERROR_INVALID_PARAMETER;
        BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);
    }

    //FIXME Take access token from pHttp and pass it to third party lib
    pszUPN = strdup("Administrator@vsphere.local");

    dwError = VmDirUPNToDN(pszUPN, &pszDn);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = VmDirSimpleDNToEntry(pszDn, &pEntry);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    dwError = VmDirSrvCreateAccessTokenWithEntry(pEntry, &pToken, &pszBindedObjectSid);
    BAIL_ON_VMDIR_REST_ERROR(dwError, NULL, pHttp);

    pHttp->pToken = pToken;
    pToken = NULL;
    pHttp->pEntry = pEntry;
    pEntry = NULL;
    pHttp->pszBindedObjectSid = pszBindedObjectSid;
    pszBindedObjectSid = NULL;

cleanup:
    VmDirFreeEntry(pEntry);
    VmDirReleaseAccessToken(&pToken);
    VMDIR_SAFE_FREE_STRINGA(pszBindedObjectSid);
    VMDIR_SAFE_FREE_STRINGA(pszUPN);
    VMDIR_SECURE_FREE_STRINGA(pszDn);
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
            "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}
