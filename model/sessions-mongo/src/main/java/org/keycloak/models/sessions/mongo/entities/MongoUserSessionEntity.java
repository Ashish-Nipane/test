package org.keycloak.models.sessions.mongo.entities;

import com.mongodb.DBObject;
import com.mongodb.QueryBuilder;
import org.keycloak.connections.mongo.api.MongoCollection;
import org.keycloak.connections.mongo.api.MongoIdentifiableEntity;
import org.keycloak.connections.mongo.api.context.MongoStoreInvocationContext;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.entities.AbstractIdentifiableEntity;
import org.keycloak.util.MultivaluedHashMap;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@MongoCollection(collectionName = "sessions")
public class MongoUserSessionEntity extends AbstractIdentifiableEntity implements MongoIdentifiableEntity {

    private String realmId;

    private String user;

    private String loginUsername;

    private String ipAddress;

    private String authMethod;

    private MultivaluedHashMap<String, String> claims;

    private boolean rememberMe;

    private int started;

    private int lastSessionRefresh;

    private List<String> clientSessions = new ArrayList<String>();

    private Map<String, String> notes = new HashMap<String, String>();

    private UserSessionModel.State state;

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getLoginUsername() {
        return loginUsername;
    }

    public void setLoginUsername(String loginUsername) {
        this.loginUsername = loginUsername;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getAuthMethod() {
        return authMethod;
    }

    public void setAuthMethod(String authMethod) {
        this.authMethod = authMethod;
    }

    public boolean isRememberMe() {
        return rememberMe;
    }

    public void setRememberMe(boolean rememberMe) {
        this.rememberMe = rememberMe;
    }

    public int getStarted() {
        return started;
    }

    public void setStarted(int started) {
        this.started = started;
    }

    public int getLastSessionRefresh() {
        return lastSessionRefresh;
    }

    public void setLastSessionRefresh(int lastSessionRefresh) {
        this.lastSessionRefresh = lastSessionRefresh;
    }

    public List<String> getClientSessions() {
        return clientSessions;
    }

    public void setClientSessions(List<String> clientSessions) {
        this.clientSessions = clientSessions;
    }

    @Override
    public void afterRemove(MongoStoreInvocationContext context) {
        DBObject query = new QueryBuilder()
                .and("sessionId").is(getId())
                .get();
        context.getMongoStore().removeEntities(MongoClientSessionEntity.class, query, context);
    }

    public Map<String, String> getNotes() {
        return notes;
    }

    public void setNotes(Map<String, String> notes) {
        this.notes = notes;
    }

    public UserSessionModel.State getState() {
        return state;
    }

    public void setState(UserSessionModel.State state) {
        this.state = state;
    }

    public MultivaluedHashMap<String, String> getClaims() {
        return claims;
    }

    public void setClaims(MultivaluedHashMap<String, String> claims) {
        this.claims = claims;
    }
}
