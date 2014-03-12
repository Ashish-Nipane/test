package org.keycloak.account.freemarker.model;

import java.net.URI;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ws.rs.core.UriBuilder;

import org.keycloak.models.RealmModel;
import org.keycloak.models.SocialLinkModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resources.flows.Urls;
import org.keycloak.social.SocialLoader;
import org.keycloak.social.SocialProvider;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AccountSocialBean {

    private final List<SocialLinkEntry> socialLinks;

    public AccountSocialBean(RealmModel realm, UserModel user, URI baseUri) {
        URI accountSocialUpdateUri = Urls.accountSocialUpdate(baseUri, realm.getName());
        this.socialLinks = new LinkedList<SocialLinkEntry>();

        Map<String, String> socialConfig = realm.getSocialConfig();
        Set<SocialLinkModel> userSocialLinks = realm.getSocialLinks(user);

        if (socialConfig != null && !socialConfig.isEmpty()) {
            for (SocialProvider provider : SocialLoader.load()) {
                String socialProviderId = provider.getId();
                if (socialConfig.containsKey(socialProviderId + ".key")) {
                    SocialLinkModel socialLink = getSocialLink(userSocialLinks, socialProviderId);

                    String action = socialLink != null ? "remove" : "add";
                    String actionUrl = UriBuilder.fromUri(accountSocialUpdateUri).queryParam("action", action).queryParam("provider_id", socialProviderId).build().toString();

                    SocialLinkEntry entry = new SocialLinkEntry(socialLink, provider.getName(), actionUrl);
                    this.socialLinks.add(entry);
                }
            }
        }
    }

    private SocialLinkModel getSocialLink(Set<SocialLinkModel> userSocialLinks, String socialProviderId) {
        for (SocialLinkModel link : userSocialLinks) {
            if (socialProviderId.equals(link.getSocialProvider())) {
                return link;
            }
        }
        return null;
    }

    public List<SocialLinkEntry> getLinks() {
        return socialLinks;
    }

    public class SocialLinkEntry {

        private SocialLinkModel link;
        private final String providerName;
        private final String actionUrl;

        public SocialLinkEntry(SocialLinkModel link, String providerName, String actionUrl) {
            this.link = link;
            this.providerName = providerName;
            this.actionUrl = actionUrl;
        }

        public String getProviderId() {
            return link != null ? link.getSocialProvider() : null;
        }

        public String getProviderName() {
            return providerName;
        }

        public String getSocialUserId() {
            return link != null ? link.getSocialUserId() : null;
        }

        public String getSocialUsername() {
            return link != null ? link.getSocialUsername() : null;
        }

        public boolean isConnected() {
            return link != null;
        }

        public String getActionUrl() {
            return actionUrl;
        }
    }
}
