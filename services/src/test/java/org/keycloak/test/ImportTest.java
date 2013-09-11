package org.keycloak.test;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.models.KeycloakSession;
import org.keycloak.services.models.KeycloakSessionFactory;
import org.keycloak.services.models.RealmModel;
import org.keycloak.services.models.RequiredCredentialModel;
import org.keycloak.services.models.ApplicationModel;
import org.keycloak.services.models.RoleModel;
import org.keycloak.services.models.SocialLinkModel;
import org.keycloak.services.models.UserModel;
import org.keycloak.services.resources.KeycloakApplication;
import org.keycloak.services.resources.SaasService;

import java.util.List;
import java.util.Set;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ImportTest {
    private KeycloakSessionFactory factory;
    private KeycloakSession identitySession;
    private RealmManager manager;
    private RealmModel realmModel;

    @Before
    public void before() throws Exception {
        factory = KeycloakApplication.buildSessionFactory();
        identitySession = factory.createSession();
        identitySession.getTransaction().begin();
        manager = new RealmManager(identitySession);
    }

    @After
    public void after() throws Exception {
        identitySession.getTransaction().commit();
        identitySession.close();
        factory.close();
    }

    @Test
    public void install() throws Exception {
        RealmModel defaultRealm = manager.createRealm(RealmModel.DEFAULT_REALM, RealmModel.DEFAULT_REALM);
        defaultRealm.setName(RealmModel.DEFAULT_REALM);
        defaultRealm.setEnabled(true);
        defaultRealm.setTokenLifespan(300);
        defaultRealm.setAccessCodeLifespan(60);
        defaultRealm.setSslNotRequired(false);
        defaultRealm.setCookieLoginAllowed(true);
        defaultRealm.setRegistrationAllowed(true);
        defaultRealm.setAutomaticRegistrationAfterSocialLogin(false);
        manager.generateRealmKeys(defaultRealm);
        defaultRealm.addRequiredCredential(CredentialRepresentation.PASSWORD);
        RoleModel role = defaultRealm.addRole(SaasService.REALM_CREATOR_ROLE);
        UserModel admin = defaultRealm.addUser("admin");
        defaultRealm.grantRole(admin, role);

        RealmRepresentation rep = AbstractKeycloakServerTest.loadJson("testrealm.json");
        RealmModel realm = manager.createRealm("demo", rep.getRealm());
        manager.importRealm(rep, realm);
        realm.addRealmAdmin(admin);

        Assert.assertFalse(realm.isAutomaticRegistrationAfterSocialLogin());
        List<RequiredCredentialModel> creds = realm.getRequiredCredentials();
        Assert.assertEquals(1, creds.size());
        RequiredCredentialModel cred = creds.get(0);
        Assert.assertEquals("password", cred.getFormLabel());
        Assert.assertEquals(2, realm.getDefaultRoles().size());

        Assert.assertNotNull(realm.getRole("foo"));
        Assert.assertNotNull(realm.getRole("bar"));

        UserModel user = realm.getUser("loginclient");
        Assert.assertNotNull(user);
        Set<String> scopes = realm.getScope(user);
        System.out.println("Scopes size: " + scopes.size());
        Assert.assertTrue(scopes.contains("*"));
        Assert.assertEquals(0, realm.getSocialLinks(user).size());

        List<ApplicationModel> resources = realm.getApplications();
        Assert.assertEquals(2, resources.size());
        List<RealmModel> realms = identitySession.getRealms(admin);
        Assert.assertEquals(1, realms.size());

        // Test scope relationship
        ApplicationModel application = realm.getResourceNameMap().get("Application");
        UserModel oauthClient = realm.getUser("oauthclient");
        Assert.assertNotNull(application);
        Assert.assertNotNull(oauthClient);
        Set<String> appScopes = application.getScope(oauthClient);
        Assert.assertTrue(appScopes.contains("user"));

        // Test social linking
        UserModel socialUser = realm.getUser("mySocialUser");
        Set<SocialLinkModel> socialLinks = realm.getSocialLinks(socialUser);
        Assert.assertEquals(3, socialLinks.size());
        int facebookCount = 0;
        int googleCount = 0;
        for (SocialLinkModel socialLinkModel : socialLinks) {
            if ("facebook".equals(socialLinkModel.getSocialProvider())) {
                facebookCount++;
            } else if ("google".equals(socialLinkModel.getSocialProvider())) {
                googleCount++;
                Assert.assertEquals(socialLinkModel.getSocialUsername(), "mySocialUser@gmail.com");
            }
        }
        Assert.assertEquals(2, facebookCount);
        Assert.assertEquals(1, googleCount);

        UserModel foundSocialUser = realm.getUserBySocialLink(new SocialLinkModel("facebook", "fbuser1"));
        Assert.assertEquals(foundSocialUser.getLoginName(), socialUser.getLoginName());
        Assert.assertNull(realm.getUserBySocialLink(new SocialLinkModel("facebook", "not-existing")));

    }

    @Test
    public void install2() throws Exception {
        RealmModel defaultRealm = manager.createRealm(RealmModel.DEFAULT_REALM, RealmModel.DEFAULT_REALM);
        defaultRealm.setName(RealmModel.DEFAULT_REALM);
        defaultRealm.setEnabled(true);
        defaultRealm.setTokenLifespan(300);
        defaultRealm.setAccessCodeLifespan(60);
        defaultRealm.setSslNotRequired(false);
        defaultRealm.setCookieLoginAllowed(true);
        defaultRealm.setRegistrationAllowed(true);
        defaultRealm.setAutomaticRegistrationAfterSocialLogin(false);
        manager.generateRealmKeys(defaultRealm);
        defaultRealm.addRequiredCredential(CredentialRepresentation.PASSWORD);
        RoleModel role = defaultRealm.addRole(SaasService.REALM_CREATOR_ROLE);
        UserModel admin = defaultRealm.addUser("admin");
        defaultRealm.grantRole(admin, role);

        RealmRepresentation rep = AbstractKeycloakServerTest.loadJson("testrealm-demo.json");
        RealmModel realm = manager.createRealm("demo", rep.getRealm());
        manager.importRealm(rep, realm);
        realm.addRealmAdmin(admin);

        Assert.assertTrue(realm.isAutomaticRegistrationAfterSocialLogin());
        verifyRequiredCredentials(realm.getRequiredCredentials(), "password");
        verifyRequiredCredentials(realm.getRequiredApplicationCredentials(), "totp");
        verifyRequiredCredentials(realm.getRequiredOAuthClientCredentials(), "cert");
    }

    private void verifyRequiredCredentials(List<RequiredCredentialModel> requiredCreds, String expectedType) {
        Assert.assertEquals(1, requiredCreds.size());
        Assert.assertEquals(expectedType, requiredCreds.get(0).getType());
    }

}
