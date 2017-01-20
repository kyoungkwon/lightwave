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

DWORD
VmDirHttpServiceStartup(
    VOID
    )
{
    DWORD dwError = 0;
    REST_CONF restConfig = {0};

    PREST_PROCESSOR pHandlers = VmDirHttpGetRequestHandler();

    //FIXME Follow restConfig
    restConfig.pSSLCertificate = "";
    restConfig.pSSLKey = "";
    restConfig.pServerPort = HTTP_PORT_NUMBER;
    restConfig.pDebugLogFile = "/tmp/restServer.log";
    restConfig.pClientCount = "10";
    restConfig.pMaxWorkerThread = "10";

    dwError = VmRESTInit(&restConfig, NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmRESTRegisterHandler(NULL, pHandlers, NULL);
    BAIL_ON_VMDIR_ERROR(dwError);

    dwError = VmRESTStart();
    BAIL_ON_VMDIR_ERROR(dwError);

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                    "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}

DWORD
VmDirHttpServiceShutdown(
    VOID
    )
{
    DWORD dwError = 0;

    dwError = VmRESTStop();
    BAIL_ON_VMDIR_ERROR(dwError);

    VmRESTShutdown();

cleanup:
    return dwError;

error:
    VMDIR_LOG_ERROR( VMDIR_LOG_MASK_ALL,
                    "%s failed, error (%d)", __FUNCTION__, dwError);
    goto cleanup;
}
