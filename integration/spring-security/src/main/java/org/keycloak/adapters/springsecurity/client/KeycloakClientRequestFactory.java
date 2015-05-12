package org.keycloak.adapters.springsecurity.client;

import org.apache.http.HttpHost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.HttpClients;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * Factory for {@link ClientHttpRequest} objects created for server to server secured
 * communication using OAuth2 bearer tokens issued by Keycloak.
 *
 * @author <a href="mailto:srossillo@smartling.com">Scott Rossillo</a>
 * @version $Revision: 1 $
 */
@Component
@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
public class KeycloakClientRequestFactory extends HttpComponentsClientHttpRequestFactory implements ClientHttpRequestFactory {

    public static final String AUTHORIZATION_HEADER = "Authorization";

    public KeycloakClientRequestFactory() {
        super(HttpClients.custom()
                .disableCookieManagement()
                .build()
        );
    }

    @Override
    protected void postProcessHttpRequest(HttpUriRequest request) {
        KeycloakSecurityContext context = this.getKeycloakSecurityContext();
        request.setHeader(AUTHORIZATION_HEADER, "Bearer " + context.getTokenString());
    }

    /**
     * Returns the {@link KeycloakSecurityContext} from the Spring {@link SecurityContextHolder}'s {@link Authentication}.
     *
     * @return the current <code>KeycloakSecurityContext</code>
     */
    protected KeycloakSecurityContext getKeycloakSecurityContext() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        KeycloakAuthenticationToken token;
        KeycloakSecurityContext context;

        if (authentication == null) {
            throw new IllegalStateException("Cannot set authorization header because there is no authenticated principal");
        }

        if (!KeycloakAuthenticationToken.class.isAssignableFrom(authentication.getClass())) {
            throw new IllegalStateException(
                    String.format(
                            "Cannot set authorization header because Authentication is of type %s but %s is required",
                            authentication.getClass(), KeycloakAuthenticationToken.class)
            );
        }

        token = (KeycloakAuthenticationToken) authentication;
        context = token.getAccount().getKeycloakSecurityContext();

        return context;
    }
}
