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

// jsonbuild.c

// jsonparse.c
DWORD
VmDirParseJSONToEntry(
    const char*     pszInputJson,
    PVDIR_ENTRY*    ppEntry
    );

DWORD
VmDirParseJSONToMods(
    const char*         pszInputJson,
    PVDIR_MODIFICATION* ppMods,
    DWORD*              pdwNumMods
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
    PSTR*                   ppszValue,
    BOOLEAN                 bRequired
    );

DWORD
VmDirRESTGetIntParam(
    PVDIR_REST_OPERATION    pRestOp,
    PSTR                    pszKey,
    int*                    piValue,
    BOOLEAN                 bRequired
    );

DWORD
VmDirRESTGetStrArrayParam(
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
    PVDIR_REST_RESULT*  ppRestResult
    );

VOID
VmDirFreeRESTResult(
    PVDIR_REST_RESULT   pRestResult
    );
