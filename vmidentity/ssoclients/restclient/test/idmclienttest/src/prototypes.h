/*
 * Copyright © 2012-2016 VMware, Inc.  All Rights Reserved.
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

#ifndef PROTOTYPES_H_
#define PROTOTYPES_H_

PCSTRING IdmTenantCreateTest();
PCSTRING IdmTenantGetTest();
PCSTRING IdmTenantDeleteTest();
PCSTRING IdmTenantGetConfigTest();
PCSTRING IdmTenantUpdateConfigTest();
PCSTRING IdmTenantSearchTest();

PCSTRING IdmDiagnosticsClearEventLogTest();
PCSTRING IdmDiagnosticsGetEventLogTest();
PCSTRING IdmDiagnosticsGetEventLogStatusTest();
PCSTRING IdmDiagnosticsStartEventLogTest();
PCSTRING IdmDiagnosticsStopEventLogTest();

PCSTRING IdmIdentityProviderCreateTest();
PCSTRING IdmIdentityProviderProbeTest();
PCSTRING IdmIdentityProviderGetAllTest();
PCSTRING IdmIdentityProviderGetTest();
PCSTRING IdmIdentityProviderUpdateTest();
PCSTRING IdmIdentityProviderDeleteTest();

PCSTRING IdmCertificateGetTest();
PCSTRING IdmCertificateDeleteTest();
PCSTRING IdmCertificateGetPrivateKeyTest();
PCSTRING IdmCertificateSetCredentialsTest();

PCSTRING IdmExternalIdpRegisterTest();
PCSTRING IdmExternalIdpRegisterByMetadataTest();    // this does not work since metadata is not set yet.
PCSTRING IdmExternalIdpGetAllTest();
PCSTRING IdmExternalIdpGetTest();
PCSTRING IdmExternalIdpDeleteTest();

PCSTRING IdmGroupCreateTest();
PCSTRING IdmGroupGetTest();
PCSTRING IdmGroupUpdateTest();
PCSTRING IdmGroupDeleteTest();
PCSTRING IdmGroupAddMembersTest();
PCSTRING IdmGroupGetMembersTest();
PCSTRING IdmGroupRemoveMembersTest();
PCSTRING IdmGroupGetParentsTest();

PCSTRING IdmOidcClientRegisterTest();
PCSTRING IdmOidcClientGetAllTest();
PCSTRING IdmOidcClientGetTest();
PCSTRING IdmOidcClientUpdateTest();
PCSTRING IdmOidcClientDeleteTest();

PCSTRING IdmRelyingPartyRegisterTest();
PCSTRING IdmRelyingPartyGetAllTest();
PCSTRING IdmRelyingPartyGetTest();
PCSTRING IdmRelyingPartyUpdateTest();
PCSTRING IdmRelyingPartyDeleteTest();

PCSTRING IdmResourceServerRegisterTest();
PCSTRING IdmResourceServerGetAllTest();
PCSTRING IdmResourceServerGetTest();
PCSTRING IdmResourceServerUpdateTest();
PCSTRING IdmResourceServerDeleteTest();

PCSTRING IdmServerGetComputersTest();

PCSTRING IdmSolutionUserCreateTest();
PCSTRING IdmSolutionUserGetTest();
PCSTRING IdmSolutionUserUpdateTest();
PCSTRING IdmSolutionUserDeleteTest();

PCSTRING IdmUserCreateTest();
PCSTRING IdmUserGetTest();
PCSTRING IdmUserGetGroupsTest();
PCSTRING IdmUserUpdateTest();
PCSTRING IdmUserDeleteTest();

PCSTRING IdmUserCreateTestByHOKToken();
PCSTRING IdmUserGetTestByHOKToken();
PCSTRING IdmUserDeleteTestByHOKToken();

PCSTRING IdmUserGetTestHA();

SSOERROR
RestTestSetup(
    PCSTRING testConfigureFile,
    PCSTRING hokPrivateKeyFile);

void
RestTestCleanup();

PCSTRING
RestTestGenerateErrorMessage(
    PCSTRING testName,
    const SSOERROR testError,
    const REST_SERVER_ERROR* pTestServerError);

#endif /* PROTOTYPES_H_ */
