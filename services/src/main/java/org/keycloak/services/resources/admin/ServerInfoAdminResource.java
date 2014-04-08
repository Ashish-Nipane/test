package org.keycloak.services.resources.admin;

import org.keycloak.audit.AuditListener;
import org.keycloak.freemarker.Theme;
import org.keycloak.freemarker.ThemeProvider;
import org.keycloak.provider.ProviderSession;
import org.keycloak.social.SocialProvider;
import org.keycloak.authentication.AuthenticationProvider;
import org.keycloak.authentication.AuthenticationProviderManager;
import org.keycloak.util.ProviderLoader;

import javax.ws.rs.GET;
import javax.ws.rs.core.Context;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class ServerInfoAdminResource {

    @Context
    private ProviderSession providers;

    @GET
    public ServerInfoRepresentation getInfo() {
        ServerInfoRepresentation info = new ServerInfoRepresentation();
        setSocialProviders(info);
        setThemes(info);
        setAuthProviders(info);
        setAuditListeners(info);
        return info;
    }

    private void setThemes(ServerInfoRepresentation info) {
        Iterable<ThemeProvider> providers = ProviderLoader.load(ThemeProvider.class);
        info.themes = new HashMap<String, List<String>>();
        for (Theme.Type type : Theme.Type.values()) {
            List<String> themes = new LinkedList<String>();
            for (ThemeProvider p : providers) {
                themes.addAll(p.nameSet(type));
            }
            Collections.sort(themes);
            info.themes.put(type.toString().toLowerCase(), themes);
        }
    }

    private void setSocialProviders(ServerInfoRepresentation info) {
        info.socialProviders = new LinkedList<String>();
        for (SocialProvider p : ProviderLoader.load(SocialProvider.class)) {
            info.socialProviders.add(p.getId());
        }
        Collections.sort(info.socialProviders);
    }

    private void setAuthProviders(ServerInfoRepresentation info) {
        info.authProviders = new HashMap<String, List<String>>();
        Iterable<AuthenticationProvider> authProviders = providers.getAllProviders(AuthenticationProvider.class);
        for (AuthenticationProvider authProvider : authProviders) {
            info.authProviders.put(authProvider.getName(), authProvider.getAvailableOptions());
        }
    }

    private void setAuditListeners(ServerInfoRepresentation info) {
        info.auditListeners = new LinkedList<String>();

        Set<String> providers = this.providers.listProviderIds(AuditListener.class);
        if (providers != null) {
            info.auditListeners.addAll(providers);
        }
    }

    public static class ServerInfoRepresentation {

        private Map<String, List<String>> themes;

        private List<String> socialProviders;

        private Map<String, List<String>> authProviders;

        private List<String> auditListeners;

        public ServerInfoRepresentation() {
        }

        public Map<String, List<String>> getThemes() {
            return themes;
        }

        public List<String> getSocialProviders() {
            return socialProviders;
        }

        public Map<String, List<String>> getAuthProviders() {
            return authProviders;
        }

        public List<String> getAuditListeners() {
            return auditListeners;
        }
    }

}
