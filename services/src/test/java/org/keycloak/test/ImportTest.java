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
        manager.generateRealmKeys(defaultRealm);
        defaultRealm.addRequiredCredential(CredentialRepresentation.PASSWORD);
        RoleModel role = defaultRealm.addRole(SaasService.REALM_CREATOR_ROLE);
        UserModel admin = defaultRealm.addUser("admin");
        defaultRealm.grantRole(admin, role);

        RealmRepresentation rep = KeycloakTestBase.loadJson("testrealm.json");
        RealmModel realm = manager.createRealm("demo", rep.getRealm());
        manager.importRealm(rep, realm);
        realm.addRealmAdmin(admin);
        List<RequiredCredentialModel> creds = realm.getRequiredCredentials();
        Assert.assertEquals(1, creds.size());
        RequiredCredentialModel cred = creds.get(0);
        Assert.assertEquals("Password", cred.getFormLabel());

        UserModel user = realm.getUser("loginclient");
        Assert.assertNotNull(user);
        Set<String> scopes = realm.getScope(user);
        System.out.println("Scopes size: " + scopes.size());
        Assert.assertTrue(scopes.contains("*"));
        List<ApplicationModel> resources = realm.getApplications();
        Assert.assertEquals(2, resources.size());
        List<RealmModel> realms = identitySession.getRealms(admin);
        Assert.assertEquals(1, realms.size());

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
        manager.generateRealmKeys(defaultRealm);
        defaultRealm.addRequiredCredential(CredentialRepresentation.PASSWORD);
        RoleModel role = defaultRealm.addRole(SaasService.REALM_CREATOR_ROLE);
        UserModel admin = defaultRealm.addUser("admin");
        defaultRealm.grantRole(admin, role);

        RealmRepresentation rep = KeycloakTestBase.loadJson("testrealm-demo.json");
        RealmModel realm = manager.createRealm("demo", rep.getRealm());
        manager.importRealm(rep, realm);
        realm.addRealmAdmin(admin);
    }





}
