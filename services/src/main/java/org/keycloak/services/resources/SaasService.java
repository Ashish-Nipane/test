package org.keycloak.services.resources;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;
import org.jboss.resteasy.spi.NotImplementedYetException;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.models.*;
import org.keycloak.services.resources.admin.RealmsAdminResource;
import org.keycloak.services.resources.flows.Flows;
import org.keycloak.services.validation.Validation;

import javax.ws.rs.*;
import javax.ws.rs.container.ResourceContext;
import javax.ws.rs.core.*;
import java.net.URI;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Path("/saas")
public class SaasService {
    protected static final Logger logger = Logger.getLogger(SaasService.class);
    public static final String REALM_CREATOR_ROLE = "realm-creator";
    public static final String SAAS_IDENTITY_COOKIE = "KEYCLOAK_SAAS_IDENTITY";

    @Context
    protected UriInfo uriInfo;

    @Context
    protected HttpRequest request;

    @Context
    protected HttpResponse response;

    @Context
    protected KeycloakSession session;

    @Context
    protected ResourceContext resourceContext;

    protected String adminPath = "/saas/admin/index.html";
    protected AuthenticationManager authManager = new AuthenticationManager();

    public static class WhoAmI {
        protected String userId;
        protected String displayName;

        public WhoAmI() {
        }

        public WhoAmI(String userId, String displayName) {
            this.userId = userId;
            this.displayName = displayName;
        }

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        public String getDisplayName() {
            return displayName;
        }

        public void setDisplayName(String displayName) {
            this.displayName = displayName;
        }
    }

    @Path("keepalive")
    @GET
    @NoCache
    public Response keepalive(final @Context HttpHeaders headers) {
        logger.debug("keepalive");
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.defaultRealm();
        if (realm == null)
            throw new NotFoundException();
        UserModel user = authManager.authenticateSaasIdentityCookie(realm, uriInfo, headers);
        if (user == null) {
            return Response.status(401).build();
        }
        NewCookie refreshCookie = authManager.createSaasIdentityCookie(realm, user, uriInfo);
        return Response.noContent().cookie(refreshCookie).build();
    }

    @Path("whoami")
    @GET
    @Produces("application/json")
    @NoCache
    public Response whoAmI(final @Context HttpHeaders headers) {
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.defaultRealm();
        if (realm == null)
            throw new NotFoundException();
        UserModel user = authManager.authenticateSaasIdentityCookie(realm, uriInfo, headers);
        if (user == null) {
            return Response.status(401).build();
        }
        return Response.ok(new WhoAmI(user.getLoginName(), user.getFirstName() + " " + user.getLastName())).build();
    }

    @Path("isLoggedIn.js")
    @GET
    @Produces("application/javascript")
    @NoCache
    public String isLoggedIn(final @Context HttpHeaders headers) {
        logger.debug("WHOAMI Javascript start.");
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.defaultRealm();
        if (realm == null) {
            return "var keycloakCookieLoggedIn = false;";

        }
        UserModel user = authManager.authenticateSaasIdentityCookie(realm, uriInfo, headers);
        if (user == null) {
            return "var keycloakCookieLoggedIn = false;";
        }
        logger.debug("WHOAMI: " + user.getLoginName());
        return "var keycloakCookieLoggedIn = true;";
    }

    public static UriBuilder contextRoot(UriInfo uriInfo) {
        return UriBuilder.fromUri(uriInfo.getBaseUri()).replacePath("/auth-server");
    }

    public static UriBuilder saasCookiePath(UriInfo uriInfo) {
        return contextRoot(uriInfo).path("rest").path(SaasService.class);
    }

    @Path("admin/realms")
    public RealmsAdminResource getRealmsAdmin(@Context final HttpHeaders headers) {
        RealmManager realmManager = new RealmManager(session);
        RealmModel saasRealm = realmManager.defaultRealm();
        if (saasRealm == null)
            throw new NotFoundException();
        UserModel admin = authManager.authenticateSaasIdentity(saasRealm, uriInfo, headers);
        if (admin == null) {
            throw new NotAuthorizedException("Bearer");
        }
        RoleModel creatorRole = saasRealm.getRole(SaasService.REALM_CREATOR_ROLE);
        if (!saasRealm.hasRole(admin, creatorRole)) {
            logger.warn("not a Realm creator");
            throw new NotAuthorizedException("Bearer");
        }
        RealmsAdminResource adminResource = new RealmsAdminResource(admin);
        resourceContext.initResource(adminResource);
        return adminResource;
    }

    @Path("login")
    @GET
    @NoCache
    public void loginPage() {
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.defaultRealm();
        authManager.expireSaasIdentityCookie(uriInfo);

        Flows.forms(realm, request).forwardToLogin();
    }

    @Path("registrations")
    @GET
    @NoCache
    public void registerPage() {
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.defaultRealm();
        authManager.expireSaasIdentityCookie(uriInfo);

        Flows.forms(realm, request).forwardToRegistration();
    }

    @Path("logout")
    @GET
    @NoCache
    public void logout() {
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.defaultRealm();
        authManager.expireSaasIdentityCookie(uriInfo);

        Flows.forms(realm, request).forwardToLogin();
    }

    @Path("logout-cookie")
    @GET
    @NoCache
    public void logoutCookie() {
        logger.debug("*** logoutCookie");
        authManager.expireSaasIdentityCookie(uriInfo);
    }

    @Path("login")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response processLogin(final MultivaluedMap<String, String> formData) {
        logger.info("processLogin start");
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.defaultRealm();
        if (realm == null)
            throw new NotFoundException();

        if (!realm.isEnabled()) {
            throw new NotImplementedYetException();
        }
        String username = formData.getFirst("username");
        UserModel user = realm.getUser(username);
        if (user == null) {
            logger.info("Not Authenticated! Incorrect user name");

            return Flows.forms(realm, request).setError(Messages.INVALID_USER).setFormData(formData)
                    .forwardToLogin();
        }
        if (!user.isEnabled()) {
            logger.info("Account is disabled, contact admin.");

            return Flows.forms(realm, request).setError(Messages.ACCOUNT_DISABLED)
                    .setFormData(formData).forwardToLogin();
        }

        boolean authenticated = authManager.authenticateForm(realm, user, formData);
        if (!authenticated) {
            logger.info("Not Authenticated! Invalid credentials");

            return Flows.forms(realm, request).setError(Messages.INVALID_PASSWORD).setFormData(formData)
                    .forwardToLogin();
        }

        NewCookie cookie = authManager.createSaasIdentityCookie(realm, user, uriInfo);
        return Response.status(302).cookie(cookie).location(contextRoot(uriInfo).path(adminPath).build()).build();
    }

    @Path("registrations")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response register(final UserRepresentation newUser) {
        RealmManager realmManager = new RealmManager(session);
        RealmModel defaultRealm = realmManager.defaultRealm();
        UserModel user = registerMe(defaultRealm, newUser);
        if (user == null) {
            return Response.status(400).type("text/plain").entity("Already exists").build();
        }
        URI uri = uriInfo.getBaseUriBuilder().path(RealmsResource.class).path(user.getLoginName()).build();
        return Response.created(uri).build();
    }

    @Path("registrations")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response processRegister(final MultivaluedMap<String, String> formData) {
        RealmManager realmManager = new RealmManager(session);
        RealmModel defaultRealm = realmManager.defaultRealm();

        List<String> requiredCredentialTypes = new LinkedList<String>();
        for (RequiredCredentialModel m : defaultRealm.getRequiredCredentials()) {
            requiredCredentialTypes.add(m.getType());
        }

        String error = Validation.validateRegistrationForm(formData, requiredCredentialTypes);
        if (error != null) {
            return Flows.forms(defaultRealm, request).setError(error).setFormData(formData)
                    .forwardToRegistration();
        }

        UserRepresentation newUser = new UserRepresentation();
        newUser.setUsername(formData.getFirst("username"));
        newUser.setEmail(formData.getFirst("email"));

        String fullname = formData.getFirst("name");
        if (fullname != null) {
            StringTokenizer tokenizer = new StringTokenizer(fullname, " ");
            StringBuffer first = null;
            String last = "";
            while (tokenizer.hasMoreTokens()) {
                String token = tokenizer.nextToken();
                if (tokenizer.hasMoreTokens()) {
                    if (first == null) {
                        first = new StringBuffer();
                    } else {
                        first.append(" ");
                    }
                    first.append(token);
                } else {
                    last = token;
                }
            }
            if (first == null)
                first = new StringBuffer();
            newUser.setFirstName(first.toString());
            newUser.setLastName(last);
        }

        if (requiredCredentialTypes.contains(CredentialRepresentation.PASSWORD)) {
            newUser.credential(CredentialRepresentation.PASSWORD, formData.getFirst("password"));
        }

        if (requiredCredentialTypes.contains(CredentialRepresentation.TOTP)) {
            newUser.credential(CredentialRepresentation.TOTP, formData.getFirst("password"));
        }

        UserModel user = registerMe(defaultRealm, newUser);
        if (user == null) {
            return Flows.forms(defaultRealm, request).setError(Messages.USERNAME_EXISTS)
                    .setFormData(formData).forwardToRegistration();

        }
        NewCookie cookie = authManager.createSaasIdentityCookie(defaultRealm, user, uriInfo);
        return Response.status(302).location(contextRoot(uriInfo).path(adminPath).build()).cookie(cookie).build();
    }

    protected UserModel registerMe(RealmModel defaultRealm, UserRepresentation newUser) {
        if (!defaultRealm.isEnabled()) {
            throw new ForbiddenException();
        }
        if (!defaultRealm.isRegistrationAllowed()) {
            throw new ForbiddenException();
        }
        UserModel user = defaultRealm.getUser(newUser.getUsername());
        if (user != null) {
            return null;
        }

        user = defaultRealm.addUser(newUser.getUsername());
        user.setFirstName(newUser.getFirstName());
        user.setLastName(newUser.getLastName());
        user.setEmail(newUser.getEmail());
        for (CredentialRepresentation cred : newUser.getCredentials()) {
            UserCredentialModel credModel = new UserCredentialModel();
            credModel.setType(cred.getType());
            credModel.setValue(cred.getValue());
            defaultRealm.updateCredential(user, credModel);
        }

        for (RoleModel role : defaultRealm.getDefaultRoles()) {
            defaultRealm.grantRole(user, role);
        }

        return user;
    }

}
