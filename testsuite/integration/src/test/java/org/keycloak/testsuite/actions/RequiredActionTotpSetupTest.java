/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.keycloak.testsuite.actions;

import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserModel.RequiredAction;
import org.keycloak.testsuite.OAuthClient;
import org.keycloak.testsuite.pages.AccountTotpPage;
import org.keycloak.testsuite.pages.AppPage;
import org.keycloak.testsuite.pages.AppPage.RequestType;
import org.keycloak.testsuite.pages.LoginConfigTotpPage;
import org.keycloak.testsuite.pages.LoginPage;
import org.keycloak.testsuite.pages.RegisterPage;
import org.keycloak.testsuite.rule.KeycloakRule;
import org.keycloak.testsuite.rule.KeycloakRule.KeycloakSetup;
import org.keycloak.testsuite.rule.WebResource;
import org.keycloak.testsuite.rule.WebRule;
import org.openqa.selenium.WebDriver;
import org.picketlink.idm.credential.util.TimeBasedOTP;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class RequiredActionTotpSetupTest {

    @ClassRule
    public static KeycloakRule keycloakRule = new KeycloakRule(new KeycloakSetup() {

        @Override
        public void config(RealmManager manager, RealmModel defaultRealm, RealmModel appRealm) {
            appRealm.addRequiredCredential(CredentialRepresentation.TOTP);
            appRealm.setResetPasswordAllowed(true);
        }

    });

    @Rule
    public WebRule webRule = new WebRule(this);

    @WebResource
    protected WebDriver driver;

    @WebResource
    protected AppPage appPage;

    @WebResource
    protected LoginPage loginPage;

    @WebResource
    protected LoginConfigTotpPage totpPage;

    @WebResource
    protected AccountTotpPage accountTotpPage;

    @WebResource
    protected OAuthClient oauth;

    @WebResource
    protected RegisterPage registerPage;

    protected TimeBasedOTP totp = new TimeBasedOTP();

    @Test
    public void setupTotpRegister() {
        loginPage.open();
        loginPage.clickRegister();
        registerPage.register("firstName", "lastName", "email", "setupTotp", "password", "password");

        totpPage.assertCurrent();

        totpPage.configure(totp.generate(totpPage.getTotpSecret()));

        Assert.assertEquals(RequestType.AUTH_RESPONSE, appPage.getRequestType());
    }

    @Test
    public void setupTotpExisting() {
        loginPage.open();
        loginPage.login("test-user@localhost", "password");

        totpPage.assertCurrent();

        String totpSecret = totpPage.getTotpSecret();

        totpPage.configure(totp.generate(totpSecret));

        Assert.assertEquals(RequestType.AUTH_RESPONSE, appPage.getRequestType());

        oauth.openLogout();

        loginPage.open();
        loginPage.loginTotp("test-user@localhost", "password", totp.generate(totpSecret));

        Assert.assertEquals(RequestType.AUTH_RESPONSE, appPage.getRequestType());
    }

    @Test
    public void setupTotpRegisteredAfterTotpRemoval() {
        // Register new user
        loginPage.open();
        loginPage.clickRegister();
        registerPage.register("firstName2", "lastName2", "email2", "setupTotp2", "password2", "password2");

        // Configure totp
        totpPage.assertCurrent();

        String totpCode = totpPage.getTotpSecret();
        totpPage.configure(totp.generate(totpCode));

        // After totp config, user should be on the app page
        Assert.assertEquals(RequestType.AUTH_RESPONSE, appPage.getRequestType());

        // Logout
        oauth.openLogout();

        // Try to login after logout
        loginPage.open();
        loginPage.login("setupTotp2", "password2");

        // Totp is already configured, thus one-time password is needed, login page should be loaded
        Assert.assertTrue(loginPage.isCurrent());
        Assert.assertFalse(totpPage.isCurrent());

        // Login with one-time password
        loginPage.loginTotp("setupTotp2", "password2", totp.generate(totpCode));

        // Open account page
        accountTotpPage.open();
        accountTotpPage.assertCurrent();

        // Remove google authentificator
        accountTotpPage.removeTotp();

        // Logout
        oauth.openLogout();

        // Try to login
        loginPage.open();
        loginPage.login("setupTotp2", "password2");

        // Since the authentificator was removed, it has to be set up again
        totpPage.assertCurrent();
        totpPage.configure(totp.generate(totpPage.getTotpSecret()));

        Assert.assertEquals(RequestType.AUTH_RESPONSE, appPage.getRequestType());

    }
}
