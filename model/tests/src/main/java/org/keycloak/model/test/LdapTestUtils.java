package org.keycloak.model.test;

import org.keycloak.models.RealmModel;
import org.keycloak.authentication.picketlink.PicketlinkAuthenticationProvider;
import org.keycloak.picketlink.IdentityManagerProvider;
import org.keycloak.provider.ProviderSession;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.credential.Password;
import org.picketlink.idm.model.basic.BasicModel;
import org.picketlink.idm.model.basic.User;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class LdapTestUtils {

    public static void setLdapPassword(ProviderSession providerSession, RealmModel realm, String username, String password) {
        // Update password directly in ldap. It's workaround, but LDIF import doesn't seem to work on windows for ApacheDS
        try {
            IdentityManager identityManager = new PicketlinkAuthenticationProvider(providerSession.getProvider(IdentityManagerProvider.class)).getIdentityManager(realm);
            User user = BasicModel.getUser(identityManager, username);
            identityManager.updateCredential(user, new Password(password.toCharArray()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
