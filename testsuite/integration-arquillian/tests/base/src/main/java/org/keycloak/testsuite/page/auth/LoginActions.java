package org.keycloak.testsuite.page.auth;

import javax.ws.rs.core.UriBuilder;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

/**
 *
 * @author tkyjovsk
 */
public class LoginActions extends AuthRealm {

    @Override
    public UriBuilder createUriBuilder() {
        return super.createUriBuilder()
                .path("login-actions");
    }

    @FindBy(css = "input[type='submit']")
    private WebElement loginButton;

    @FindBy(css = "div[id='kc-form-options'] span a")
    private WebElement backToLoginForm;

    public void backToLoginPage() {
        backToLoginForm.click();
    }

    public void submit(){
        loginButton.click();
    }

}
