package org.keycloak.authentication.authenticators;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticatorModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class LoginFormUsernameAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "auth-login-form-username";

    @Override
    public Authenticator create(AuthenticatorModel model) {
        return new LoginFormUsernameAuthenticator(model);
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        throw new IllegalStateException("illegal call");
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayCategory() {
        return "User Validation";
    }

    @Override
    public String getDisplayType() {
        return "Login Form Username";
    }

    @Override
    public String getHelpText() {
        return "Validates a username that is specified on the login page.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }
}
