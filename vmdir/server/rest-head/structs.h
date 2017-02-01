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

typedef struct _VDIR_REST_RESULT
{
    DWORD       dwErrCode;
    PSTR        pszErrMsg;
    PSTR        pszOutputJson;
    PLW_HASHMAP pAddlInfo;

} VDIR_REST_RESULT, *PVDIR_REST_RESULT;

typedef struct _VDIR_REST_OPERATION
{
    PSTR                pszMethod;
    PSTR                pszEndpoint;
    PSTR                pszInputJson;
    PSTR				pszAuth;
    PLW_HASHMAP         pParamMap;
    PVDIR_CONNECTION	pConn;
    PVDIR_REST_RESULT   pResult;

} VDIR_REST_OPERATION, *PVDIR_REST_OPERATION;
