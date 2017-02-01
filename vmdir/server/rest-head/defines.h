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

// REST ENGINE CONFIG VALUES
// TRIDENT
#define VMDIR_REST_SSLCERT      "/root/mycert.pem"
#define VMDIR_REST_SSLKEY       "/root/mycert.pem"
#define REST_API_SPEC           "/root/vmdir.json"
#define VMDIR_REST_PORT         "7477"
#define VMDIR_REST_DEBUGLOGFILE "/tmp/vmdirrest.log"
#define VMDIR_REST_CLIENTCNT    "5"
#define VMDIR_REST_WORKERTHCNT  "5"

// VMDIR REST ENDPOINT URI VALUES
#define VMDIR_LDAP_URI  "vmdir/ldap"
#define VMDIR_USER_URI  "vmdir/user"

#define MAX_REST_PAYLOAD_LENGTH 4096

#define VMDIR_SET_REST_RESULT(pRestOp, pMLOp, dwError)                  \
    do                                                                  \
    {                                                                   \
       if (pRestOp)                                                     \
       {                                                                \
           if (pMLOp)                                                   \
           {                                                            \
               int err = ((pMLOp)->ldapResult).errCode;                 \
               char* msg = ((pMLOp)->ldapResult).pszErrMsg;             \
               VmDirRESTResultSetError((pRestOp)->pResult, err, msg);   \
           }                                                            \
           if (!((pRestOp)->pResult)->dwErrCode)                        \
           {                                                            \
               int err = VmDirToLDAPError(dwError);                     \
               char* msg = ldap_err2string(err);                        \
               VmDirRESTResultSetError((pRestOp)->pResult, err, msg);   \
           }                                                            \
       }                                                                \
    } while (0)
