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

// auth.c
DWORD
VmDirRESTAuth(
    PVDIR_REST_OPERATION    pRestOp
    );

DWORD
VmDirRESTAuthBasic(
    PVDIR_REST_OPERATION    pRestOp,
    PVDIR_OPERATION         pBindOp
    );

DWORD
VmDirRESTAuthToken(
    PVDIR_REST_OPERATION    pRestOp,
    PVDIR_OPERATION         pBindOp
    );

// decode.c
DWORD
VmDirRESTDecodeEntry(
    json_t*         pjInput,
    PVDIR_ENTRY*    ppEntry
    );

DWORD
VmDirRESTDecodeMods(
    json_t*             pjInput,
    PVDIR_MODIFICATION* ppMods,
    DWORD*              pdwNumMods
    );

// encode.c
DWORD
VmDirRESTEncodeAttribute(
    PVDIR_ATTRIBUTE pAttr,
    json_t**        ppjOutput
    );

DWORD
VmDirRESTEncodeEntry(
    PVDIR_ENTRY     pEntry,
    PVDIR_BERVALUE  pbvAttrs,
    json_t**        ppjOutput
    );

DWORD
VmDirRESTEncodeEntryArray(
    PVDIR_ENTRY_ARRAY   pEntryArray,
    PVDIR_BERVALUE      pbvAttrs,
    json_t**            ppjOutput
    );

// ldapapi.c
DWORD
VmDirRESTGetLdapModule(
    PREST_MODULE*   ppRestModule
    );

DWORD
VmDirRESTLdapAdd(
    const char* pszInputJson,
    char**      ppszOutputJson
    );

DWORD
VmDirRESTLdapSearch(
    const char* pszInputJson,
    char**      ppszOutputJson
    );

DWORD
VmDirRESTLdapModify(
    const char* pszInputJson,
    char**      ppszOutputJson
    );

DWORD
VmDirRESTLdapDelete(
    const char* pszInputJson,
    char**      ppszOutputJson
    );

// libmain.c
DWORD
VmDirRESTRequestHandler(
    PREST_REQUEST   pRequest,
    PREST_RESPONSE* ppResponse,
    uint32_t        paramsCount
    );

// operation.c
DWORD
VmDirRESTOperationInit(
    PVDIR_REST_OPERATION*   ppRestOp
    );

DWORD
VmDirRESTOperationReadRequest(
    PVDIR_REST_OPERATION    pRestOp,
    PREST_REQUEST           pRestReq,
    DWORD                   dwParamCount
    );

DWORD
VmDirRESTOperationWriteResponse(
    PVDIR_REST_OPERATION    pRestOp,
    PREST_RESPONSE*         ppResponse
    );

VOID
VmDirFreeRESTOperation(
    PVDIR_REST_OPERATION    pRestOp
    );

// param.c
DWORD
VmDirRESTGetStrParam(
    PVDIR_REST_OPERATION    pRestOp,
    PSTR                    pszKey,
    PSTR*                   ppszVal,
    BOOLEAN                 bRequired
    );

DWORD
VmDirRESTGetIntParam(
    PVDIR_REST_OPERATION    pRestOp,
    PSTR                    pszKey,
    int*                    piVal,
    BOOLEAN                 bRequired
    );

DWORD
VmDirRESTGetStrListParam(
    PVDIR_REST_OPERATION    pRestOp,
    PSTR                    pszKey,
    PVMDIR_STRING_LIST*     ppValList,
    BOOLEAN                 bRequired
    );

DWORD
VmDirRESTGetLdapSearchParams(
    PVDIR_REST_OPERATION    pRestOp,
    PSTR*                   ppszDN,
    int*                    piScope,
    PVDIR_FILTER*           ppFilter,
    PVDIR_BERVALUE*         ppbvAttrs,
    PVDIR_LDAP_CONTROL*     ppPagedResultsCtrl
    );

// result.c
DWORD
VmDirRESTResultInit(
    PVDIR_REST_RESULT*  ppRestRslt
    );

DWORD
VmDirRESTResultSetError(
    PVDIR_REST_RESULT   pRestRslt,
    DWORD               dwErrCode,
    PSTR                pszErrMsg
    );

DWORD
VmDirRESTResultSetAddlInfo(
    PVDIR_REST_RESULT   pRestRslt,
    PSTR                pszKey,
    PSTR                pszVal
    );

DWORD
VmDirRESTResultToResponseBody(
    PVDIR_REST_RESULT   pRestRslt,
    PSTR*               ppszBody
    );

VOID
VmDirFreeRESTResult(
    PVDIR_REST_RESULT   pRestRslt
    );
