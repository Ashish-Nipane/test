package org.keycloak.model.test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;

import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.keycloak.models.AuthenticationLinkModel;
import org.keycloak.models.AuthenticationProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.authentication.AuthProviderConstants;
import org.keycloak.authentication.AuthenticationProviderException;
import org.keycloak.authentication.AuthenticationProviderManager;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AuthProvidersExternalModelTest extends AbstractModelTest {

    private RealmModel realm1;
    private RealmModel realm2;
    private AuthenticationManager am;

    @Before
    @Override
    public void  before() throws Exception {
        super.before();

        // Create 2 realms and user in realm1
        realm1 = realmManager.createRealm("realm1");
        realm2 = realmManager.createRealm("realm2");
        realm1.addRequiredCredential(CredentialRepresentation.PASSWORD);
        realm2.addRequiredCredential(CredentialRepresentation.PASSWORD);
        realm1.setAuthenticationProviders(Arrays.asList(AuthenticationProviderModel.DEFAULT_PROVIDER));
        realm2.setAuthenticationProviders(Arrays.asList(AuthenticationProviderModel.DEFAULT_PROVIDER));

        UserModel john = realm1.addUser("john");
        john.setEnabled(true);
        john.setFirstName("John");
        john.setLastName("Doe");
        john.setEmail("john@email.org");

        UserCredentialModel credential = new UserCredentialModel();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue("password");
        realm1.updateCredential(john, credential);

        am = new AuthenticationManager(providerSession);
    }


    @Test
    public void testExternalModelAuthentication() {
        MultivaluedMap<String, String> formData = createFormData("john", "password");

        // Authenticate user with realm1
        Assert.assertEquals(AuthenticationManager.AuthenticationStatus.SUCCESS, am.authenticateForm(null, realm1, formData));

        // Verify that user doesn't exists in realm2 and can't authenticate here
        Assert.assertEquals(AuthenticationManager.AuthenticationStatus.INVALID_USER, am.authenticateForm(null, realm2, formData));
        Assert.assertNull(realm2.getUser("john"));

        // Add externalModel authenticationProvider into realm2 and point to realm1
        setupAuthenticationProviders();

        try {
            // this is needed for externalModel provider
            ResteasyProviderFactory.pushContext(KeycloakSession.class, identitySession);

            // Authenticate john in realm2 and verify that now he exists here.
            Assert.assertEquals(AuthenticationManager.AuthenticationStatus.SUCCESS, am.authenticateForm(null, realm2, formData));
            UserModel john2 = realm2.getUser("john");
            Assert.assertNotNull(john2);
            Assert.assertEquals("john", john2.getLoginName());
            Assert.assertEquals("John", john2.getFirstName());
            Assert.assertEquals("Doe", john2.getLastName());
            Assert.assertEquals("john@email.org", john2.getEmail());

            // Verify link exists
            AuthenticationLinkModel authLink = realm2.getAuthenticationLink(john2);
            Assert.assertNotNull(authLink);
            Assert.assertEquals(authLink.getAuthProvider(), AuthProviderConstants.PROVIDER_NAME_EXTERNAL_MODEL);
            Assert.assertEquals(authLink.getAuthUserId(), realm1.getUser("john").getId());
        } finally {
            ResteasyProviderFactory.clearContextData();
        }

    }

    @Test
    public void testExternalModelPasswordUpdate() {
        // Add externalModel authenticationProvider into realm2 and point to realm1
        setupAuthenticationProviders();

        // Add john to realm2 and set authentication link
        UserModel john = realm2.addUser("john");
        john.setEnabled(true);
        realm2.setAuthenticationLink(john, new AuthenticationLinkModel(AuthProviderConstants.PROVIDER_NAME_EXTERNAL_MODEL, realm1.getUser("john").getId()));

        try {
            // this is needed for externalModel provider
            ResteasyProviderFactory.pushContext(KeycloakSession.class, identitySession);

            // Change credential via realm2 and validate that they are changed also in realm1
            AuthenticationProviderManager authProviderManager = AuthenticationProviderManager.getManager(realm2, providerSession);
            try {
                Assert.assertTrue(authProviderManager.updatePassword(john, "password-updated"));
            } catch (AuthenticationProviderException ape) {
                ape.printStackTrace();
                Assert.fail("Error not expected");
            }
            MultivaluedMap<String, String> formData = createFormData("john", "password-updated");
            Assert.assertEquals(AuthenticationManager.AuthenticationStatus.SUCCESS, am.authenticateForm(null, realm1, formData));
            Assert.assertEquals(AuthenticationManager.AuthenticationStatus.SUCCESS, am.authenticateForm(null, realm2, formData));


            // Switch to disallow password update propagation to realm1
            setPasswordUpdateForProvider(false, AuthProviderConstants.PROVIDER_NAME_EXTERNAL_MODEL, realm2);

            // Change credential and validate that password is updated just for realm2
            try {
                Assert.assertFalse(authProviderManager.updatePassword(john, "password-updated2"));
            } catch (AuthenticationProviderException ape) {
                ape.printStackTrace();
                Assert.fail("Error not expected");
            }
            formData = createFormData("john", "password-updated2");
            Assert.assertEquals(AuthenticationManager.AuthenticationStatus.INVALID_CREDENTIALS, am.authenticateForm(null, realm1, formData));
            Assert.assertEquals(AuthenticationManager.AuthenticationStatus.INVALID_CREDENTIALS, am.authenticateForm(null, realm2, formData));


            // Allow passwordUpdate propagation again
            setPasswordUpdateForProvider(true, AuthProviderConstants.PROVIDER_NAME_EXTERNAL_MODEL, realm2);

            // Set passwordPolicy for realm1 and verify that password update fail
            realm1.setPasswordPolicy(new PasswordPolicy("length(8)"));
            try {
                authProviderManager.updatePassword(john, "passw");
                Assert.fail("Update not expected to pass");
            } catch (AuthenticationProviderException ape) {

            }

        } finally {
            ResteasyProviderFactory.clearContextData();
        }
    }

    /**
     * Setup authentication providers into realm2
     */
    private void setupAuthenticationProviders() {
        AuthenticationProviderModel ap1 = new AuthenticationProviderModel(AuthProviderConstants.PROVIDER_NAME_MODEL, true, Collections.EMPTY_MAP);
        Map<String,String> config = new HashMap<String,String>();
        config.put(AuthProviderConstants.EXTERNAL_REALM_ID, "realm1");
        AuthenticationProviderModel ap2 = new AuthenticationProviderModel(AuthProviderConstants.PROVIDER_NAME_EXTERNAL_MODEL, true, config);
        realm2.setAuthenticationProviders(Arrays.asList(ap1, ap2));
    }

    public static void setPasswordUpdateForProvider(boolean isPasswordUpdate, String providerName, RealmModel realm) {
        List<AuthenticationProviderModel> authProviders = realm.getAuthenticationProviders();
        for (AuthenticationProviderModel authProvider : authProviders) {
            if (providerName.equals(authProvider.getProviderName())) {
                authProvider.setPasswordUpdateSupported(isPasswordUpdate);
                break;
            }
        }
        realm.setAuthenticationProviders(authProviders);
    }

    public static MultivaluedMap<String, String> createFormData(String username, String password) {
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<String, String>();
        formData.add("username", username);
        formData.add(CredentialRepresentation.PASSWORD, password);
        return formData;
    }
}
