/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.services.clientpolicy.executor;

import org.keycloak.events.Errors;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.PreAuthorizationRequestContext;

import java.util.Set;

public class CheckExactStringMatchingOfRedirectUrisExecutor implements ClientPolicyExecutorProvider<ClientPolicyExecutorConfigurationRepresentation> {

    private final KeycloakSession session;

    public CheckExactStringMatchingOfRedirectUrisExecutor(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getProviderId() {
        return CheckExactStringMatchingOfRedirectUrisExecutorFactory.PROVIDER_ID;
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        ClientPolicyEvent event = context.getEvent();
        switch (event) {
            case PRE_AUTHORIZATION_REQUEST:
                RealmModel realm = session.getContext().getRealm();
                String clientId = ((PreAuthorizationRequestContext) context).getClientId();
                if (clientId == null) {
                    return;
                }
                ClientModel client  = realm.getClientByClientId(clientId);
                checkRedirectUris(session.getContext().getHttpRequest().getUri().getQueryParameters().getFirst(OIDCLoginProtocol.REDIRECT_URI_PARAM),
                        client.getRedirectUris());
            break;
       }
    }

    private void checkRedirectUris(String redirectUri, Set<String> validRedirects) throws ClientPolicyException {
        if (redirectUri == null) {
            return;
        }
        if (!validRedirects.contains(redirectUri)) {
            throw new ClientPolicyException(Errors.INVALID_REQUEST, "The redirect_uri did not exactly match the string to Valid redirect URIs.");
        }
    }
}
