/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.authentication.authenticators.broker;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;

import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * @author <a href="mailto:Ryan.Slominski@gmail.com">Ryan Slominski</a>
 */
public class IdpAutoLinkAuthenticator extends AbstractIdpAuthenticator {

    private static Logger logger = Logger.getLogger(IdpAutoLinkAuthenticator.class);

    @Override
    protected void authenticateImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        if (!isExistingUserInfoRegistered(authSession)) {
            String username = getUsername(context, serializedCtx, brokerContext);
            if (username != null) {
                ExistingUserInfo duplication = checkExistingUser(context,username, serializedCtx, brokerContext);

                if (duplication != null) {
                    logger.debugf("Duplication detected. There is already existing user with %s '%s' .",
                        duplication.getDuplicateAttributeName(), duplication.getDuplicateAttributeValue());

                    // Set duplicated user, so next authenticators can deal with it
                    context.getAuthenticationSession().setAuthNote(EXISTING_USER_INFO, duplication.serialize());
                }
            }
        }
        UserModel existingUser = getExistingUser(session, realm, authSession);

        logger.debugf("User '%s' will auto link with identity provider '%s' . Identity provider username is '%s' ", existingUser.getUsername(),
                brokerContext.getIdpConfig().getAlias(), brokerContext.getUsername());

        context.setUser(existingUser);
        context.success();
    }

    private boolean isExistingUserInfoRegistered(AuthenticationSessionModel authSession) {
        String existingUserId = authSession.getAuthNote(EXISTING_USER_INFO);
        return existingUserId != null;
    }

    @Override
    protected void actionImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {
        authenticateImpl(context, serializedCtx, brokerContext);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

}
