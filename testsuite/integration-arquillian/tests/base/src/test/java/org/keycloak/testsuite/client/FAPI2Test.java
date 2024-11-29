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
 *
 */
package org.keycloak.testsuite.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Collections;

import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.authentication.authenticators.client.JWTClientAuthenticator;
import org.keycloak.authentication.authenticators.client.X509ClientAuthenticator;
import org.keycloak.crypto.Algorithm;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.utils.OIDCResponseMode;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.client.resources.TestApplicationResourceUrls;
import org.keycloak.testsuite.rest.resource.TestingOIDCEndpointsApplicationResource;
import org.keycloak.testsuite.util.MutualTLSUtils;
import org.keycloak.testsuite.util.OAuthClient;
import org.keycloak.testsuite.util.OAuthClient.ParResponse;

public class FAPI2Test extends AbstractFAPI2Test {

    @Test
    public void testFAPI2SecurityProfileClientRegistration() throws Exception {
        testFAPI2ClientRegistration(FAPI2_SECURITY_PROFILE_NAME);
    }

    @Test
    public void testFAPI2SecurityProfileOIDCClientRegistration() throws Exception {
        testFAPI2OIDCClientRegistration(FAPI2_SECURITY_PROFILE_NAME);
    }

    @Test
    public void testFAPI2SecurityProfileSignatureAlgorithms() throws Exception {
        testFAPI2SignatureAlgorithms(FAPI2_SECURITY_PROFILE_NAME);
    }

    @Test
    public void testFAPI2SecurityProfileLoginWithPrivateKeyJWT() throws Exception {
        // setup client policy
        setupPolicyFAPI2ForAllClient(FAPI2_SECURITY_PROFILE_NAME);

        // Register client with private-key-jwt
        String clientUUID = createClientByAdmin(clientId, (ClientRepresentation clientRep) -> {
            clientRep.setClientAuthenticatorType(JWTClientAuthenticator.PROVIDER_ID);
            OIDCAdvancedConfigWrapper.fromClientRepresentation(clientRep).setRequestUris(Collections.singletonList(TestApplicationResourceUrls.clientRequestUri()));
        });
        ClientResource clientResource = adminClient.realm(REALM_NAME).clients().get(clientUUID);
        ClientRepresentation client = clientResource.toRepresentation();
        OIDCAdvancedConfigWrapper clientConfig = OIDCAdvancedConfigWrapper.fromClientRepresentation(client);
        assertEquals(JWTClientAuthenticator.PROVIDER_ID, client.getClientAuthenticatorType());
        assertEquals(Algorithm.PS256, clientConfig.getTokenEndpointAuthSigningAlg());
        assertEquals(OAuth2Constants.PKCE_METHOD_S256, clientConfig.getPkceCodeChallengeMethod());
        assertFalse(client.isImplicitFlowEnabled());
        assertFalse(client.isFullScopeAllowed());
        assertFalse(clientConfig.isUseDPoP());
        assertTrue(clientConfig.isUseMtlsHokToken());
        assertTrue(client.isConsentRequired());

        // send a pushed authorization request
        oauth.clientId(clientId);
        String codeVerifier = "1234567890123456789012345678901234567890123"; // 43
        String codeChallenge = generateS256CodeChallenge(codeVerifier);

        TestingOIDCEndpointsApplicationResource.AuthorizationEndpointRequestObject requestObject = createValidRequestObjectForSecureRequestObjectExecutor(clientId);
        requestObject.setNonce("123456");
        requestObject.setCodeChallenge(codeChallenge);
        requestObject.setCodeChallengeMethod(OAuth2Constants.PKCE_METHOD_S256);
        registerRequestObject(requestObject, clientId, Algorithm.PS256, false);

        String signedJwt = createSignedRequestToken(clientId, Algorithm.PS256);
        ParResponse pResp = oauth.doPushedAuthorizationRequest(clientId, null, signedJwt);
        assertEquals(201, pResp.getStatusCode());
        String requestUri = pResp.getRequestUri();
        oauth.requestUri(requestUri);
        oauth.request(null);

        // send an authorization request
        String code = loginUserAndGetCode(clientId, false);

        // send a token request
        signedJwt = createSignedRequestToken(clientId, Algorithm.PS256);
        OAuthClient.AccessTokenResponse tokenResponse = doAccessTokenRequestWithClientSignedJWT(code, signedJwt, codeVerifier, MutualTLSUtils::newCloseableHttpClientWithDefaultKeyStoreAndTrustStore);
        assertSuccessfulTokenResponse(tokenResponse);

        // check HoK required
        AccessToken accessToken = oauth.verifyToken(tokenResponse.getAccessToken());
        Assert.assertNotNull(accessToken.getConfirmation().getCertThumbprint());

        // Logout and remove consent of the user for next logins
        logoutUserAndRevokeConsent(clientId, TEST_USERNAME);
    }

    @Test
    public void testFAPI2SecurityProfileLoginWithMTLS() throws Exception {
        // setup client policy
        setupPolicyFAPI2ForAllClient(FAPI2_SECURITY_PROFILE_NAME);

        // create client with MTLS authentication
        // Register client with X509
        String clientUUID = createClientByAdmin(clientId, (ClientRepresentation clientRep) -> {
            clientRep.setClientAuthenticatorType(X509ClientAuthenticator.PROVIDER_ID);
            OIDCAdvancedConfigWrapper clientConfig = OIDCAdvancedConfigWrapper.fromClientRepresentation(clientRep);
            clientConfig.setRequestUris(Collections.singletonList(TestApplicationResourceUrls.clientRequestUri()));
            clientConfig.setTlsClientAuthSubjectDn(MutualTLSUtils.DEFAULT_KEYSTORE_SUBJECT_DN);
            clientConfig.setAllowRegexPatternComparison(false);
        });
        ClientResource clientResource = adminClient.realm(REALM_NAME).clients().get(clientUUID);
        ClientRepresentation client = clientResource.toRepresentation();
        OIDCAdvancedConfigWrapper clientConfig = OIDCAdvancedConfigWrapper.fromClientRepresentation(client);
        assertEquals(X509ClientAuthenticator.PROVIDER_ID, client.getClientAuthenticatorType());
        assertEquals(Algorithm.PS256, clientConfig.getTokenEndpointAuthSigningAlg());
        assertEquals(OAuth2Constants.PKCE_METHOD_S256, clientConfig.getPkceCodeChallengeMethod());
        assertFalse(client.isImplicitFlowEnabled());
        assertFalse(client.isFullScopeAllowed());
        assertFalse(clientConfig.isUseDPoP());
        assertTrue(clientConfig.isUseMtlsHokToken());
        assertTrue(client.isConsentRequired());

        oauth.clientId(clientId);

        // without PAR request - should fail
        oauth.openLoginForm();
        assertBrowserWithError("request_uri not included.");

        String codeVerifier = "1234567890123456789012345678901234567890123"; // 43
        String codeChallenge = generateS256CodeChallenge(codeVerifier);
        oauth.codeChallenge(codeChallenge);
        oauth.codeChallengeMethod(OAuth2Constants.PKCE_METHOD_S256);
        oauth.stateParamHardcoded(null);
        oauth.nonce("123456");

        // requiring hybrid request - should fail
        oauth.responseType(OIDCResponseType.CODE + " " + OIDCResponseType.ID_TOKEN + " " + OIDCResponseType.TOKEN);
        ParResponse pResp = oauth.doPushedAuthorizationRequest(clientId, null);
        assertEquals(401, pResp.getStatusCode());
        assertEquals(OAuthErrorException.UNAUTHORIZED_CLIENT, pResp.getError());

        // authorization request does not match PAR request - should fail
        oauth.responseType(OIDCResponseType.CODE);
        pResp = oauth.doPushedAuthorizationRequest(clientId, null);
        assertEquals(201, pResp.getStatusCode());
        String requestUri = pResp.getRequestUri();
        oauth.responseType(OIDCResponseType.CODE + " " + OIDCResponseType.ID_TOKEN + " " + OIDCResponseType.TOKEN);
        oauth.requestUri(requestUri);
        oauth.openLoginForm();
        assertRedirectedToClientWithError(OAuthErrorException.INVALID_REQUEST, false, "Parameter response_type does not match");

        oauth.responseType(OIDCResponseType.CODE);

        // an additional parameter in an authorization request that does not exist in a PAR request - should fail
        oauth.requestUri(null);
        pResp = oauth.doPushedAuthorizationRequest(clientId, null);
        assertEquals(201, pResp.getStatusCode());
        requestUri = pResp.getRequestUri();
        oauth.stateParamRandom();
        oauth.requestUri(requestUri);
        oauth.openLoginForm();
        assertBrowserWithError("PAR request did not include necessary parameters");

        // duplicated usage of a PAR request - should fail
        oauth.openLoginForm();
        assertBrowserWithError("PAR not found. not issued or used multiple times.");

        // send a pushed authorization request
        oauth.stateParamHardcoded(null);
        oauth.requestUri(null);
        pResp = oauth.doPushedAuthorizationRequest(clientId, null);
        assertEquals(201, pResp.getStatusCode());
        requestUri = pResp.getRequestUri();

        // send an authorization request
        oauth.requestUri(requestUri);
        String code = loginUserAndGetCode(clientId, false);

        // send a token request
        oauth.codeVerifier(codeVerifier);
        OAuthClient.AccessTokenResponse tokenResponse = oauth.doAccessTokenRequest(code, null);

        // check HoK required
        assertSuccessfulTokenResponse(tokenResponse);
        AccessToken accessToken = oauth.verifyToken(tokenResponse.getAccessToken());
        Assert.assertNotNull(accessToken.getConfirmation().getCertThumbprint());

        // Logout and remove consent of the user for next logins
        logoutUserAndRevokeConsent(clientId, TEST_USERNAME);
    }

    @Test
    public void testFAPI2MessageSigningClientRegistration() throws Exception {
        testFAPI2ClientRegistration(FAPI2_MESSAGE_SIGNING_PROFILE_NAME);
    }

    @Test
    public void testFAPI2MessageSigningOIDCClientRegistration() throws Exception {
        testFAPI2OIDCClientRegistration(FAPI2_MESSAGE_SIGNING_PROFILE_NAME);
    }

    @Test
    public void testFAPI2MessageSigningSignatureAlgorithms() throws Exception {
        testFAPI2SignatureAlgorithms(FAPI2_MESSAGE_SIGNING_PROFILE_NAME);
    }

    @Test
    public void testFAPI2MessageSigningLoginWithMTLS() throws Exception {
        // setup client policy
        setupPolicyFAPI2ForAllClient(FAPI2_MESSAGE_SIGNING_PROFILE_NAME);

        // create client with MTLS authentication
        // Register client with X509
        String clientUUID = createClientByAdmin(clientId, (ClientRepresentation clientRep) -> {
            clientRep.setClientAuthenticatorType(X509ClientAuthenticator.PROVIDER_ID);
            OIDCAdvancedConfigWrapper clientConfig = OIDCAdvancedConfigWrapper.fromClientRepresentation(clientRep);
            clientConfig.setRequestUris(Collections.singletonList(TestApplicationResourceUrls.clientRequestUri()));
            clientConfig.setTlsClientAuthSubjectDn(MutualTLSUtils.DEFAULT_KEYSTORE_SUBJECT_DN);
            clientConfig.setAllowRegexPatternComparison(false);
            clientConfig.setRequestObjectRequired("request or request_uri");
            clientConfig.setAuthorizationSignedResponseAlg(Algorithm.PS256);
        });
        ClientResource clientResource = adminClient.realm(REALM_NAME).clients().get(clientUUID);
        ClientRepresentation client = clientResource.toRepresentation();
        OIDCAdvancedConfigWrapper clientConfig = OIDCAdvancedConfigWrapper.fromClientRepresentation(client);
        assertEquals(X509ClientAuthenticator.PROVIDER_ID, client.getClientAuthenticatorType());
        assertEquals(Algorithm.PS256, clientConfig.getTokenEndpointAuthSigningAlg());
        assertEquals(OAuth2Constants.PKCE_METHOD_S256, clientConfig.getPkceCodeChallengeMethod());
        assertEquals(Algorithm.PS256, clientConfig.getRequestObjectSignatureAlg());
        assertFalse(client.isImplicitFlowEnabled());
        assertFalse(client.isFullScopeAllowed());
        assertFalse(clientConfig.isUseDPoP());
        assertTrue(clientConfig.isUseMtlsHokToken());
        assertTrue(client.isConsentRequired());

        // Set request object and correct responseType
        oauth.clientId(clientId);
        oauth.stateParamHardcoded(null);
        String codeVerifier = "1234567890123456789012345678901234567890123"; // 43
        String codeChallenge = generateS256CodeChallenge(codeVerifier);
        TestingOIDCEndpointsApplicationResource.AuthorizationEndpointRequestObject requestObject = createValidRequestObjectForSecureRequestObjectExecutor(clientId);
        requestObject.setNonce("123456");
        requestObject.setResponseType(OIDCResponseType.CODE);
        requestObject.setResponseMode(OIDCResponseMode.QUERY_JWT.value());
        requestObject.setCodeChallenge(codeChallenge);
        requestObject.setCodeChallengeMethod(OAuth2Constants.PKCE_METHOD_S256);
        registerRequestObject(requestObject, clientId, Algorithm.PS256, false);

        // send a pushed authorization request
        ParResponse pResp = oauth.doPushedAuthorizationRequest(clientId, null);
        assertEquals(201, pResp.getStatusCode());
        String requestUri = pResp.getRequestUri();

        // send an authorization request
        oauth.codeChallenge(codeChallenge);
        oauth.codeChallengeMethod(OAuth2Constants.PKCE_METHOD_S256);
        oauth.nonce("123456");
        oauth.responseType(OIDCResponseType.CODE);
        oauth.responseMode(OIDCResponseMode.QUERY_JWT.value());
        oauth.requestUri(requestUri);
        oauth.request(null);
        String code = loginUserAndGetCodeInJwtQueryResponseMode(clientId);

        // send a token request
        oauth.codeVerifier(codeVerifier);
        OAuthClient.AccessTokenResponse tokenResponse = oauth.doAccessTokenRequest(code, null);

        // check HoK required
        assertSuccessfulTokenResponse(tokenResponse);
        AccessToken accessToken = oauth.verifyToken(tokenResponse.getAccessToken());
        Assert.assertNotNull(accessToken.getConfirmation().getCertThumbprint());

        // Logout and remove consent of the user for next logins
        logoutUserAndRevokeConsent(clientId, TEST_USERNAME);
    }

    @Test
    public void testFAPI2MessageSigningLoginWithPrivateKeyJWT() throws Exception {
        // setup client policy
        setupPolicyFAPI2ForAllClient(FAPI2_MESSAGE_SIGNING_PROFILE_NAME);

        // create client with MTLS authentication
        // Register client with X509
        String clientUUID = createClientByAdmin(clientId, (ClientRepresentation clientRep) -> {
            clientRep.setClientAuthenticatorType(JWTClientAuthenticator.PROVIDER_ID);
            OIDCAdvancedConfigWrapper clientConfig = OIDCAdvancedConfigWrapper.fromClientRepresentation(clientRep);
            clientConfig.setRequestUris(Collections.singletonList(TestApplicationResourceUrls.clientRequestUri()));
            clientConfig.setRequestObjectRequired("request or request_uri");
            OIDCAdvancedConfigWrapper.fromClientRepresentation(clientRep).setAuthorizationSignedResponseAlg(Algorithm.PS256);
        });
        ClientResource clientResource = adminClient.realm(REALM_NAME).clients().get(clientUUID);
        ClientRepresentation client = clientResource.toRepresentation();
        OIDCAdvancedConfigWrapper clientConfig = OIDCAdvancedConfigWrapper.fromClientRepresentation(client);
        assertEquals(JWTClientAuthenticator.PROVIDER_ID, client.getClientAuthenticatorType());
        assertEquals(Algorithm.PS256, clientConfig.getTokenEndpointAuthSigningAlg());
        assertEquals(Algorithm.PS256, clientConfig.getRequestObjectSignatureAlg());
        assertEquals(OAuth2Constants.PKCE_METHOD_S256, clientConfig.getPkceCodeChallengeMethod());
        assertFalse(client.isImplicitFlowEnabled());
        assertFalse(client.isFullScopeAllowed());
        assertFalse(clientConfig.isUseDPoP());
        assertTrue(clientConfig.isUseMtlsHokToken());
        assertTrue(client.isConsentRequired());

        oauth.clientId(clientId);
        oauth.stateParamHardcoded(null);
        String codeVerifier = "1234567890123456789012345678901234567890123"; // 43
        String codeChallenge = generateS256CodeChallenge(codeVerifier);

        // without a request object - should fail
        oauth.codeChallenge(codeChallenge);
        oauth.codeChallengeMethod(OAuth2Constants.PKCE_METHOD_S256);
        oauth.stateParamHardcoded(null);
        oauth.nonce("123456");
        oauth.responseType(OIDCResponseType.CODE);
        TestingOIDCEndpointsApplicationResource.AuthorizationEndpointRequestObject requestObject = createValidRequestObjectForSecureRequestObjectExecutor(clientId);
        registerRequestObject(requestObject, clientId, Algorithm.PS256, true);
        oauth.requestUri(null);
        oauth.request(null);
        String signedJwt = createSignedRequestToken(clientId, Algorithm.PS256);
        ParResponse pResp = oauth.doPushedAuthorizationRequest(clientId, null, signedJwt);
        assertEquals(400, pResp.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST_OBJECT, pResp.getError());

        // Set request object and correct responseType
        requestObject = createValidRequestObjectForSecureRequestObjectExecutor(clientId);
        requestObject.setNonce("123456");
        requestObject.setResponseType(OIDCResponseType.CODE);
        requestObject.setResponseMode(OIDCResponseMode.QUERY_JWT.value());
        requestObject.setCodeChallenge(codeChallenge);
        requestObject.setCodeChallengeMethod(OAuth2Constants.PKCE_METHOD_S256);
        registerRequestObject(requestObject, clientId, Algorithm.PS256, false);

        // send a pushed authorization request
        signedJwt = createSignedRequestToken(clientId, Algorithm.PS256);
        pResp = oauth.doPushedAuthorizationRequest(clientId, null, signedJwt);
        assertEquals(201, pResp.getStatusCode());
        String requestUri = pResp.getRequestUri();

        // send an authorization request
        oauth.requestUri(requestUri);
        oauth.request(null);
        String code = loginUserAndGetCodeInJwtQueryResponseMode(clientId);

        // send a token request
        signedJwt = createSignedRequestToken(clientId, Algorithm.PS256);
        OAuthClient.AccessTokenResponse tokenResponse = doAccessTokenRequestWithClientSignedJWT(code, signedJwt, codeVerifier, MutualTLSUtils::newCloseableHttpClientWithDefaultKeyStoreAndTrustStore);
        assertSuccessfulTokenResponse(tokenResponse);
 
        // check HoK required
        assertSuccessfulTokenResponse(tokenResponse);
        AccessToken accessToken = oauth.verifyToken(tokenResponse.getAccessToken());
        Assert.assertNotNull(accessToken.getConfirmation().getCertThumbprint());

        // Logout and remove consent of the user for next logins
        logoutUserAndRevokeConsent(clientId, TEST_USERNAME);
    }

}
