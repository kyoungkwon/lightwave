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

/* Supported REST operation */
typedef enum
{
    VDIR_REST_OPERATION_SEARCH = 1,
    VDIR_REST_OPERATION_ADD = 2,
    VDIR_REST_OPERATION_PATCH = 3,
    VDIR_REST_OPERATION_DELETE = 4,
    VDIR_REST_OPERATION_GET_TOPOLOGY = 5,
    VDIR_REST_OPERATION_GET_COMPUTERS = 6,
    VDIR_REST_OPERATION_GET_DCINFO = 7,
    VDIR_REST_OPERATION_REPLNOW = 8,
    VDIR_REST_OPERATION_ADD_REPL_PARTNER = 9,
    VDIR_REST_OPERATION_REMOVE_REPL_PARTNER = 10,
} VDIR_REST_OPERATION;

typedef struct _VMDIR_REST_RA_OPERATION_INFO
{
    BOOLEAN bIsTwoWayRepl;
    PSTR pszSrcServerName;
    PSTR pszTgtServerName;
} VMDIR_REST_RA_OPERATION_INFO, *PVMDIR_REST_RA_OPERATION_INFO;

/*
 * Structure to store response received from REST
 * request explicitly made by server to partner node
 * i.e. for Add/Remove Replication Agreement
 */
typedef struct _VMDIR_REST_RECEIVED_RESPONSE
{
    PSTR pszResponse;
    size_t size;
} VMDIR_REST_RECEIVED_RESPONSE, *PVMDIR_REST_RECEIVED_RESPONSE;

/* This structure is used to store REST response related info */
typedef struct _VMDIR_REST_RESPONSE_TO_SEND
{
    PSTR pszLdapStatusCode;
    PSTR pszErrorMessage;
    PSTR pszAdditionalInfo;
    PSTR pszResult;
} VMDIR_REST_RESPONSE_TO_SEND, *PVMDIR_REST_RESPONSE_TO_SEND;

typedef struct __VMDIR_HTTP__
{
    PREST_REQUEST    pRestReq;
    PREST_RESPONSE*  ppRestRes;

    PSTR pszDn;                         /* DN parsed from request */

    VDIR_REST_OPERATION restOp;         /* Requested REST operation */

    PSTR pszMethod;                     /* Requested Method, Required to differentiate operations */

    /* Search related */
    PSTR pszScope;
    ber_int_t scope;
    PSTR pszFilter;
    PSTR pszAttrs;
    PSTR pszPageCookie;
    UINT uiPageSize;

    /* Auth */
    PSTR pszWWWAuthenticateToken;
    PSTR pszUser;                                           /* Authenticated user or NULL for anonymous */
    PVDIR_ENTRY pEntry;                                     /* Entry of authenticated user */
    PACCESS_TOKEN pToken;                                   /* Token of authenticated user */
    PSTR pszBindedObjectSid;                                /* ObjectSid of authenticated user */
    PSTR pszPasswd;                                         /* Password used in basic authentication */

    PVMDIR_REST_RESPONSE_TO_SEND pRESTResponseToSend;       /* Pointer to response payload structure */
    BOOLEAN bIsResponseCreated;
    PSTR pszInputJson;
    PSTR pszOutputJson;

} VMDIR_HTTP, *PVMDIR_HTTP;
