package org.keycloak.models;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface RealmModel extends RoleContainerModel, RoleMapperModel, ScopeMapperModel {

    String getId();

    String getName();

    void setName(String name);

    boolean isEnabled();

    void setEnabled(boolean enabled);

    boolean isSslNotRequired();

    void setSslNotRequired(boolean sslNotRequired);

    boolean isCookieLoginAllowed();

    void setCookieLoginAllowed(boolean cookieLoginAllowed);

    boolean isRegistrationAllowed();

    void setRegistrationAllowed(boolean registrationAllowed);

    boolean isVerifyEmail();

    void setVerifyEmail(boolean verifyEmail);

    boolean isResetPasswordAllowed();

    void setResetPasswordAllowed(boolean resetPasswordAllowed);

    int getTokenLifespan();

    void setTokenLifespan(int tokenLifespan);

    int getAccessCodeLifespan();

    void setAccessCodeLifespan(int accessCodeLifespan);

    int getAccessCodeLifespanUserAction();

    void setAccessCodeLifespanUserAction(int accessCodeLifespanUserAction);

    String getPublicKeyPem();

    void setPublicKeyPem(String publicKeyPem);

    String getPrivateKeyPem();

    void setPrivateKeyPem(String privateKeyPem);

    PublicKey getPublicKey();

    void setPublicKey(PublicKey publicKey);

    PrivateKey getPrivateKey();

    void setPrivateKey(PrivateKey privateKey);

    List<RequiredCredentialModel> getRequiredCredentials();

    void addRequiredCredential(String cred);

    boolean validatePassword(UserModel user, String password);

    boolean validateTOTP(UserModel user, String password, String token);

    void updateCredential(UserModel user, UserCredentialModel cred);

    UserModel getUser(String name);

    UserModel addUser(String username);

    List<RoleModel> getDefaultRoles();
    
    void addDefaultRole(String name);
    
    void updateDefaultRoles(String[] defaultRoles);

    Map<String, ApplicationModel> getApplicationNameMap();

    List<ApplicationModel> getApplications();

    ApplicationModel addApplication(String name);

    List<RequiredCredentialModel> getRequiredApplicationCredentials();


    List<RequiredCredentialModel> getRequiredOAuthClientCredentials();

    ApplicationModel getApplicationById(String id);

    void addRequiredOAuthClientCredential(String type);

    void addRequiredResourceCredential(String type);

    void updateRequiredCredentials(Set<String> creds);

    void updateRequiredOAuthClientCredentials(Set<String> creds);

    void updateRequiredApplicationCredentials(Set<String> creds);

    UserModel getUserBySocialLink(SocialLinkModel socialLink);

    Set<SocialLinkModel> getSocialLinks(UserModel user);

    void addSocialLink(UserModel user, SocialLinkModel socialLink);

    void removeSocialLink(UserModel user, SocialLinkModel socialLink);

    boolean isSocial();

    void setSocial(boolean social);

    public boolean isAutomaticRegistrationAfterSocialLogin();

    public void setAutomaticRegistrationAfterSocialLogin(boolean automaticRegistrationAfterSocialLogin);

    List<UserModel> searchForUserByAttributes(Map<String, String> attributes);

    OAuthClientModel addOAuthClient(String name);

    OAuthClientModel getOAuthClient(String name);

    List<OAuthClientModel> getOAuthClients();
}
