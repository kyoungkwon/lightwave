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


// auth.c

DWORD
VmDirHttpGenerateWWWAuthenticateNegotiateGSS(
    gss_buffer_desc*    pBuffer,
    PSTR*               ppszNegotiate
    );

DWORD
VmDirHttpAuthNegotiate(
    PVMDIR_HTTP pHttp
    );

DWORD
VmDirHttpAuthBasic(
    PVMDIR_HTTP pHttp
    );

DWORD
VmDirHttpAuth(
    PVMDIR_HTTP pHttp
    );

DWORD
VmDirHttpAuthToken(
    PVMDIR_HTTP pHttp
    );

// api.c

DWORD
VmDirHttpAddRequestHandler(
    PVMDIR_HTTP pHttp
    );

DWORD
VmDirHttpSearchRequestHandler(
    PVMDIR_HTTP pHttp
    );

DWORD
VmDirHttpModifyRequestHandler(
    PVMDIR_HTTP pHttp
    );

DWORD
VmDirHttpDeleteRequestHandler(
    PVMDIR_HTTP pHttp
    );

DWORD
VmDirHttpGetDCInfoRequestHandler(
    PVMDIR_HTTP pHttp
    );

DWORD
VmDirHttpGetComputersRequestHandler(
    PVMDIR_HTTP pHttp
    );

DWORD
VmDirHttpGetTopologyRequestHandler(
    PVMDIR_HTTP pHttp
    );

DWORD
VmDirHttpReplNowRequestHandler(
    PVMDIR_HTTP pHttp
    );

DWORD
VmDirHttpAddRARequestHandler(
    PVMDIR_HTTP pHttp
    );

DWORD
VmDirHttpRemoveRARequestHandler(
    PVMDIR_HTTP pHttp
    );

// helpers.c

DWORD
VmDirHttpDelete(
    PVMDIR_HTTP pHttp
    );

DWORD
VmDirHttpGetComputers(
    PVMDIR_HTTP     pHttp,
    PVDIR_OPERATION pOp,
    PSTR**          pppszComputers,
    DWORD*          pdwNumComputers
    );

DWORD
VmDirHttpGetDCInfo(
    PVMDIR_HTTP         pHttp,
    PVDIR_OPERATION     pOp,
    PVMDIR_DC_INFO**    pppDCInfo,
    DWORD*              pdwNumDC
    );

DWORD
VmDirHttpGetSiteDCInfo(
    PVMDIR_HTTP         pHttp,
    PVDIR_OPERATION     pOp,
    PSTR                pszSiteName,
    DWORD*              pdwIdxDC,
    PVMDIR_DC_INFO*     ppDCInfo
    );

DWORD
VmDirHttpGetObjectAttribute(
    PVMDIR_HTTP     pHttp,
    PVDIR_OPERATION pOp,
    PSTR            pszSearchDNPrefiix,
    PSTR            pszFilter,
    PSTR            pszAttribute,
    int             scope,
    PSTR**          pppszValues,
    DWORD*          pdwNumValues
    );

// http.c

DWORD
VmDirHttpServiceStartup(
    VOID
    );

DWORD
VmDirHttpServiceShutdown(
    VOID
    );

// utils.c

DWORD
VmDirHttpGetAllAttributeValues(
    PVDIR_ATTRIBUTE pAttr,
    PSTR*           ppszAttrVals
    );

size_t
VmDirHttpRESTWriteCallBack(
    PVOID  pContents,
    size_t size,
    size_t nmemb,
    PVOID  pResponse
    );

DWORD
VmDirHttpIsRESTRequestSucceeded(
    PVMDIR_HTTP pHttp,
    PSTR        pszResponse,
    BOOLEAN*    pbIsRESTRequestSucceeded
    );

ULONG
VmDirCatStringPrintf(
    OUT PSTR*   ppszString,
    IN PCSTR    pszFormat,
    IN ...
    );

DWORD
VmDirGetComponent(
    PCSTR*  ppszString,
    int     delim,
    PSTR*   ppszComponent
    );

DWORD
VmDirParseUri(
    PCSTR           pszFullUri,
    PVMDIR_HTTP     pHttp
    );

DWORD
VmDirHttpCreateAccessInfo(
    PVMDIR_HTTP         pHttp,
    PVDIR_CONNECTION    pConn
    );

// replication.c

DWORD
VmDirHttpAddRAOneWay(
    PVMDIR_HTTP                     pHttp,
    PVMDIR_REST_RA_OPERATION_INFO   pRESTRAOperationInfo
    );

DWORD
VmDirHttpAddRATwoWay(
    PVMDIR_HTTP                     pHttp,
    PVMDIR_REST_RA_OPERATION_INFO   pRESTRAOperationInfo
    );

DWORD
VmDirHttpRemoveRAOneWay(
    PVMDIR_HTTP                     pHttp,
    PVMDIR_REST_RA_OPERATION_INFO   pRESTRAOperationInfo
    );

DWORD
VmDirHttpRemoveRATwoWay(
    PVMDIR_HTTP                     pHttp,
    PVMDIR_REST_RA_OPERATION_INFO   pRESTRAOperationInfo
    );

VOID
VmDirHttpFreeRESTRAOperationInfo(
    PVMDIR_REST_RA_OPERATION_INFO pRESTRAOperationInfo
    );

// response.c

DWORD
VmDirHttpCreateRESTResponsePayload(
    DWORD         dwLdapStatusCode,
    PCSTR         pszErrorMsg,
    PCSTR         pszAdditionalInfo,
    PCSTR         pszOperationResult,
    PVMDIR_HTTP   pHttp
    );

DWORD
VmDirHttpBuildJSONGetDCInfo(
    PVMDIR_DC_INFO* ppDCInfo,
    DWORD           dwNumDC,
    PSTR*           ppszAnswer
    );

DWORD
VmDirHttpBuildJSONGetComputers(
    PSTR*   ppszComputers,
    DWORD   dwNumComputers,
    PSTR*   ppszAnswer
    );

DWORD
VmDirHttpBuildJSONSearchResponse(
    PVMDIR_HTTP         pHttp,
    PVDIR_ENTRY_ARRAY   pEntryArray,
    PSTR                pszPageCookie,
    PVDIR_OPERATION     pOp,
    PSTR*               ppszAnswer
    );

DWORD
VmDirHttpSendResponse(
    PVMDIR_HTTP pHttp
    );

VOID
VmDirFreeRESTResponseToSend(
    PVMDIR_REST_RESPONSE_TO_SEND pRESTResponseToSend
    );

VOID
VmDirHttpFreeRESTReceivedResponse(
    PVMDIR_REST_RECEIVED_RESPONSE pRESTReceivedResponse
    );

// request.c


DWORD
VmDirHttpGetRequestPayload(
    PREST_REQUEST   pRequest,
    PVMDIR_HTTP     pHttp
    );

DWORD
VmDirHttpParseJSONToAdd(
    PVMDIR_HTTP     pHttp,
    PVDIR_OPERATION pOp
    );

DWORD
VmDirHttpParseJSONToModify(
    PVMDIR_HTTP     pHttp,
    PVDIR_OPERATION pOp
    );

DWORD
VmDirHttpParseJSONToRAOperationInfo(
    PVMDIR_HTTP                     pHttp,
    PVMDIR_REST_RA_OPERATION_INFO*  ppRESTRAOperationInfo
    );

PREST_PROCESSOR
VmDirHttpGetRequestHandler(
    VOID
    );

DWORD
VmDirHttpRequestHandler(
    PREST_REQUEST    pRequest,
    PREST_RESPONSE*  ppResponse
    );

VOID
VmDirFreeHttp(
    PVMDIR_HTTP pHttp
    );
