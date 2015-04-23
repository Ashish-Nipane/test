package org.keycloak.testsuite.ui.test.account;

import org.jboss.arquillian.graphene.findby.FindByJQuery;
import org.jboss.arquillian.graphene.page.Page;
import org.junit.After;
import org.junit.Test;

import static org.keycloak.testsuite.ui.util.Constants.ADMIN_PSSWD;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.keycloak.testsuite.ui.AbstractKeyCloakTest;
import org.keycloak.testsuite.ui.fragment.FlashMessage;
import org.keycloak.testsuite.ui.model.Account;
import org.keycloak.testsuite.ui.page.account.AccountPage;
import org.keycloak.testsuite.ui.page.account.PasswordPage;

public class AccountManagementTest extends AbstractKeyCloakTest<AccountPage> {

	@FindByJQuery(".alert")
    private FlashMessage flashMessage;
	
    @Page
    private AccountPage accountPage;

    @Page
    private PasswordPage passwordPage;
	
    private static final String USERNAME = "admin";
    private static final String NEW_PASSWORD = "newpassword";
    private static final String WRONG_PASSWORD = "wrongpassword";

	@Before
	public void beforeAccountTest() {
		menuPage.goToAccountManagement();
	}
	
	@After
	public void afterAccountTest() {
		accountPage.keycloakConsole();
	}
	
	@Test
    public void passwordPageValidationTest() {
	    page.password();
        passwordPage.save();
        flashMessage.waitUntilPresent();
        assertTrue(flashMessage.getText(), flashMessage.isError());

        passwordPage.setPassword(WRONG_PASSWORD, NEW_PASSWORD);
        passwordPage.save();
        flashMessage.waitUntilPresent();
        assertTrue(flashMessage.getText(), flashMessage.isError());

        passwordPage.setOldPasswordField(ADMIN_PSSWD);
        passwordPage.setNewPasswordField("something");
        passwordPage.setConfirmField("something else");
        passwordPage.save();
        flashMessage.waitUntilPresent();
        assertTrue(flashMessage.getText(), flashMessage.isError());
    }

    @Test
    public void changePasswordTest() {
        page.password();
        passwordPage.setPassword(ADMIN_PSSWD, NEW_PASSWORD);
        passwordPage.save();
        flashMessage.waitUntilPresent();
        assertTrue(flashMessage.getText(), flashMessage.isSuccess());
        page.signOut();
        loginPage.login(USERNAME, NEW_PASSWORD);
        page.password();
        passwordPage.setPassword(NEW_PASSWORD, ADMIN_PSSWD);
        passwordPage.save();
        flashMessage.waitUntilPresent();
        assertTrue(flashMessage.getText(), flashMessage.isSuccess());
    }

    @Test
    public void accountPageTest() {
        page.account();
        Account adminAccount = accountPage.getAccount();
        assertEquals(adminAccount.getUsername(), USERNAME);
        adminAccount.setEmail("a@b");
        adminAccount.setFirstName("John");
        adminAccount.setLastName("Smith");
        accountPage.setAccount(adminAccount);
        accountPage.save();
        flashMessage.waitUntilPresent();
        assertTrue(flashMessage.getText(), flashMessage.isSuccess());

        page.signOut();
        loginPage.login(USERNAME, ADMIN_PSSWD);

        page.account();
        assertEquals(adminAccount, accountPage.getAccount());
    }

}
