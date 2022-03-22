package org.keycloak.protocol.oidc;

import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.common.util.Time;
import org.keycloak.models.*;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.storage.client.AbstractReadOnlyClientStorageAdapter;
import org.keycloak.utils.StringUtil;

import static org.keycloak.models.ClientSecretConstants.CLIENT_ROTATED_SECRET;
import static org.keycloak.models.ClientSecretConstants.CLIENT_ROTATED_SECRET_CREATION_TIME;
import static org.keycloak.models.ClientSecretConstants.CLIENT_ROTATED_SECRET_EXPIRATION_TIME;
import static org.keycloak.models.ClientSecretConstants.CLIENT_SECRET_CREATION_TIME;
import static org.keycloak.models.ClientSecretConstants.CLIENT_SECRET_EXPIRATION;
import static org.keycloak.models.ClientSecretConstants.CLIENT_SECRET_REMAINING_EXPIRATION_TIME;

/**
 * @author <a href="mailto:masales@redhat.com">Marcelo Sales</a>
 */
public class OIDCClientSecretConfigWrapper extends AbstractClientConfigWrapper {

    private OIDCClientSecretConfigWrapper(ClientModel client, ClientRepresentation clientRep) {
        super(client, clientRep);
    }

    public static OIDCClientSecretConfigWrapper fromClientModel(ClientModel client) {
        return new OIDCClientSecretConfigWrapper(client, null);
    }

    public static OIDCClientSecretConfigWrapper fromClientRepresentation(
            ClientRepresentation clientRep) {
        return new OIDCClientSecretConfigWrapper(null, clientRep);
    }

    public String getSecret() {
        if (clientModel != null) {
            return clientModel.getSecret();
        } else {
            return clientRep.getSecret();
        }
    }

    public String getId() {
        if (clientModel != null) {
            return clientModel.getId();
        } else {
            return clientRep.getId();
        }
    }

    public String getName() {
        if (clientModel != null) {
            return clientModel.getName();
        } else {
            return clientRep.getName();
        }
    }

    public void removeClientSecretRotationInfo() {
        setAttribute(CLIENT_SECRET_EXPIRATION, null);
        setAttribute(CLIENT_SECRET_REMAINING_EXPIRATION_TIME, null);
        removeClientSecretRotated();
    }

    public void removeClientSecretRotated() {
        if (hasRotatedSecret()) {
            setAttribute(CLIENT_ROTATED_SECRET, null);
            setAttribute(CLIENT_ROTATED_SECRET_CREATION_TIME, null);
            setAttribute(CLIENT_ROTATED_SECRET_EXPIRATION_TIME, null);
        }
    }

    public int getClientSecretCreationTime() {
        String creationTime = getAttribute(CLIENT_SECRET_CREATION_TIME);
        return StringUtil.isBlank(creationTime) ? 0 : Integer.parseInt(creationTime);
    }

    public void setClientSecretCreationTime(int creationTime) {
        setAttribute(CLIENT_SECRET_CREATION_TIME, String.valueOf(creationTime));
    }

    public boolean hasRotatedSecret() {
        return StringUtil.isNotBlank(getAttribute(CLIENT_ROTATED_SECRET)) && StringUtil.isNotBlank(
                getAttribute(CLIENT_ROTATED_SECRET_CREATION_TIME));
    }

    public String getClientRotatedSecret() {
        return getAttribute(CLIENT_ROTATED_SECRET);
    }

    public void setClientRotatedSecret(String secret) {
        setAttribute(CLIENT_ROTATED_SECRET, secret);
    }

    public int getClientRotatedSecretCreationTime() {
        String rotatedCreationTime = getAttribute(CLIENT_ROTATED_SECRET_CREATION_TIME);
        if (StringUtil.isNotBlank(rotatedCreationTime)) return Integer.parseInt(rotatedCreationTime);
        return 0;
    }

    public void setClientRotatedSecretCreationTime(Integer rotatedTime) {
        setAttribute(CLIENT_ROTATED_SECRET_CREATION_TIME, rotatedTime != null ? String.valueOf(rotatedTime) : null);
    }

    /*
    Update the creation time of a secret with current date time value
     */
    public void setClientSecretCreationTime() {
        setClientSecretCreationTime(Time.currentTime());
    }

    public void setClientRotatedSecretCreationTime() {
        setClientRotatedSecretCreationTime(Time.currentTime());
    }

    public void updateClientRepresentationAttributes(ClientRepresentation rep) {
        rep.getAttributes().put(CLIENT_ROTATED_SECRET, getAttribute(CLIENT_ROTATED_SECRET));
        rep.getAttributes()
                .put(CLIENT_SECRET_CREATION_TIME, getAttribute(CLIENT_SECRET_CREATION_TIME));
        rep.getAttributes().put(CLIENT_SECRET_EXPIRATION, getAttribute(CLIENT_SECRET_EXPIRATION));
        rep.getAttributes().put(CLIENT_ROTATED_SECRET_CREATION_TIME,
                getAttribute(CLIENT_ROTATED_SECRET_CREATION_TIME));
        rep.getAttributes().put(CLIENT_ROTATED_SECRET_EXPIRATION_TIME,
                getAttribute(CLIENT_ROTATED_SECRET_EXPIRATION_TIME));
    }

    public boolean hasClientSecretExpirationTime() {
        return getClientSecretExpirationTime() > 0;
    }

    public int getClientSecretExpirationTime() {
        String expiration = getAttribute(CLIENT_SECRET_EXPIRATION);
        return expiration == null ? 0 : Integer.parseInt(expiration);
    }

    public void setClientSecretExpirationTime(Integer expiration) {
        setAttribute(ClientSecretConstants.CLIENT_SECRET_EXPIRATION, expiration != null ? String.valueOf(expiration) : null);
    }

    public boolean isClientSecretExpired() {
        if (hasClientSecretExpirationTime()) {
            return getClientSecretExpirationTime() < Time.currentTime();
        }
        return false;
    }

    public int getClientRotatedSecretExpirationTime() {
        if (hasClientRotatedSecretExpirationTime()) {
            return Integer.valueOf(
                    getAttribute(ClientSecretConstants.CLIENT_ROTATED_SECRET_EXPIRATION_TIME));
        }
        return 0;
    }

    public void setClientRotatedSecretExpirationTime(Integer expiration) {
        setAttribute(ClientSecretConstants.CLIENT_ROTATED_SECRET_EXPIRATION_TIME,
                expiration != null ? String.valueOf(expiration) : null);
    }

    public boolean hasClientRotatedSecretExpirationTime() {
        return StringUtil.isNotBlank(
                getAttribute(ClientSecretConstants.CLIENT_ROTATED_SECRET_EXPIRATION_TIME));
    }

    public boolean isClientRotatedSecretExpired() {
        if (hasClientRotatedSecretExpirationTime()) {
            return getClientRotatedSecretExpirationTime() < Time.currentTime();
        }
        return true;
    }

    //validates the rotated secret (value and expiration)
    public boolean validateRotatedSecret(String secret) {

        // there must exist a rotated_secret
        if (hasRotatedSecret()) {
            // the rotated secret must not be outdated
            if (isClientRotatedSecretExpired()) {
                return false;
            }
        } else {
            return false;
        }

        return MessageDigest.isEqual(secret.getBytes(), getClientRotatedSecret().getBytes());

    }

    public String toJson() {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> map = new HashMap<>();
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
            map.put("clientId", getId());
            map.put("clientName", getName());
            map.put("secretCreationTimeSeconds", getClientSecretCreationTime());
            map.put("secretCreationTime", sdf.format(Time.toDate(getClientSecretCreationTime())));
            map.put("secretExpirationTimeSeconds", getClientSecretExpirationTime());
            map.put("secretExpirationTime", sdf.format(Time.toDate(getClientSecretExpirationTime())));
            map.put("rotatedSecretCreationTimeSeconds", getClientRotatedSecretCreationTime());
            map.put("rotatedSecretCreationTime", sdf.format(Time.toDate(getClientRotatedSecretCreationTime())));
            map.put("rotatedSecretExpirationTimeSeconds", getClientRotatedSecretExpirationTime());
            map.put("rotatedSecretExpirationTime", sdf.format(Time.toDate(getClientRotatedSecretExpirationTime())));
            return mapper.writeValueAsString(map);
        } catch (JsonProcessingException e) {
            return "";
        }
    }

    public ReadOnlyRotatedSecretClientModel toRotatedClientModel() {
        return new ReadOnlyRotatedSecretClientModel();
    }

    /**
     * Representation of a client model that passes information from a rotated secret. The goal is to act as a decorator/DTO just providing information and not updating objects persistently.
     */
    public class ReadOnlyRotatedSecretClientModel extends AbstractReadOnlyClientStorageAdapter {

        private ReadOnlyRotatedSecretClientModel() {
            super(null, null, null);
        }

        @Override
        public String getClientId() {
            return OIDCClientSecretConfigWrapper.this.getId();
        }

        @Override
        public String getName() {
            return null;
        }

        @Override
        public String getDescription() {
            return null;
        }

        @Override
        public boolean isEnabled() {
            return false;
        }

        @Override
        public boolean isAlwaysDisplayInConsole() {
            return false;
        }

        @Override
        public Set<String> getWebOrigins() {
            return null;
        }

        @Override
        public Set<String> getRedirectUris() {
            return null;
        }

        @Override
        public String getManagementUrl() {
            return null;
        }

        @Override
        public String getRootUrl() {
            return null;
        }

        @Override
        public String getBaseUrl() {
            return null;
        }

        @Override
        public boolean isBearerOnly() {
            return false;
        }

        @Override
        public int getNodeReRegistrationTimeout() {
            return 0;
        }

        @Override
        public String getClientAuthenticatorType() {
            return null;
        }

        @Override
        public boolean validateSecret(String secret) {
            return false;
        }

        @Override
        public String getSecret() {
            return OIDCClientSecretConfigWrapper.this.getClientRotatedSecret();
        }

        @Override
        public String getRegistrationToken() {
            return null;
        }

        @Override
        public String getProtocol() {
            return null;
        }

        @Override
        public String getAttribute(String name) {
            return OIDCClientSecretConfigWrapper.this.getAttribute(name);
        }

        @Override
        public Map<String, String> getAttributes() {
            return (Map<String, String>) OIDCClientSecretConfigWrapper.this.getAttributes();
        }

        @Override
        public String getAuthenticationFlowBindingOverride(String binding) {
            return null;
        }

        @Override
        public Map<String, String> getAuthenticationFlowBindingOverrides() {
            return null;
        }

        @Override
        public boolean isFrontchannelLogout() {
            return false;
        }

        @Override
        public boolean isFullScopeAllowed() {
            return false;
        }

        @Override
        public boolean isPublicClient() {
            return false;
        }

        @Override
        public boolean isConsentRequired() {
            return false;
        }

        @Override
        public boolean isStandardFlowEnabled() {
            return false;
        }

        @Override
        public boolean isImplicitFlowEnabled() {
            return false;
        }

        @Override
        public boolean isDirectAccessGrantsEnabled() {
            return false;
        }

        @Override
        public boolean isServiceAccountsEnabled() {
            return false;
        }

        @Override
        public Map<String, ClientScopeModel> getClientScopes(boolean defaultScope) {
            return null;
        }

        @Override
        public int getNotBefore() {
            return 0;
        }

        @Override
        public Stream<ProtocolMapperModel> getProtocolMappersStream() {
            return null;
        }

        @Override
        public ProtocolMapperModel getProtocolMapperById(String id) {
            return null;
        }

        @Override
        public ProtocolMapperModel getProtocolMapperByName(String protocol, String name) {
            return null;
        }

        @Override
        public Stream<RoleModel> getScopeMappingsStream() {
            return null;
        }

        @Override
        public Stream<RoleModel> getRealmScopeMappingsStream() {
            return null;
        }

        @Override
        public boolean hasScope(RoleModel role) {
            return false;
        }
    }
}
