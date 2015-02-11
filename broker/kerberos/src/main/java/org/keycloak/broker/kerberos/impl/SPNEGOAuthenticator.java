package org.keycloak.broker.kerberos.impl;

import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;

import net.iharder.Base64;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.jboss.logging.Logger;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SPNEGOAuthenticator {

    private static final Logger log = Logger.getLogger(SPNEGOAuthenticator.class);

    private static final GSSManager GSS_MANAGER = GSSManager.getInstance();

    private final KerberosServerSubjectAuthenticator kerberosSubjectAuthenticator;
    private final String spnegoToken;

    private boolean authenticated = false;
    private String principal = null;
    private GSSCredential delegationCredential;
    private String responseToken = null;

    public SPNEGOAuthenticator(KerberosServerSubjectAuthenticator kerberosSubjectAuthenticator, String spnegoToken) {
        this.kerberosSubjectAuthenticator = kerberosSubjectAuthenticator;
        this.spnegoToken = spnegoToken;
    }

    public void authenticate() {
        if (log.isTraceEnabled()) {
            log.trace("SPNEGO Login with token: " + spnegoToken);
        }

        try {
            Subject serverSubject = kerberosSubjectAuthenticator.authenticateServerSubject();
            authenticated = Subject.doAs(serverSubject, new AcceptSecContext());
        } catch (Exception e) {
            String message = e.getMessage();
            if (e instanceof PrivilegedActionException && e.getCause() != null) {
                message = e.getCause().getMessage();
            }
            log.warn("SPNEGO login failed: " + message);
            if (log.isDebugEnabled()) {
                log.debug("SPNEGO login failed: " + message, e);
            }
        } finally {
            kerberosSubjectAuthenticator.logoutServerSubject();
        }
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public String getPrincipal() {
        return principal;
    }

    public String getResponseToken() {
        return responseToken;
    }

    public GSSCredential getDelegationCredential() {
        return delegationCredential;
    }

    private class AcceptSecContext implements PrivilegedExceptionAction<Boolean> {

        @Override
        public Boolean run() throws Exception {
            GSSContext gssContext = null;
            try {
                if (log.isTraceEnabled()) {
                    log.trace("Going to establish security context");
                }

                gssContext = establishContext();
                logAuthDetails(gssContext);

                if (gssContext.isEstablished()) {
                    principal = gssContext.getSrcName().toString();

                    // What should be done with delegation credential? Figure out if there are use-cases for storing it as claims in FederatedIdentity
                    if (gssContext.getCredDelegState()) {
                        delegationCredential = gssContext.getDelegCred();
                    }

                    return true;
                } else {
                    return false;
                }
            } finally {
                if (gssContext != null) {
                    gssContext.dispose();
                }
            }
        }

    }

    protected GSSContext establishContext() throws GSSException, IOException {
        GSSContext gssContext = GSS_MANAGER.createContext((GSSCredential) null);

        byte[] inputToken = Base64.decode(spnegoToken);
        byte[] respToken = gssContext.acceptSecContext(inputToken, 0, inputToken.length);
        responseToken = Base64.encodeBytes(respToken);

        return gssContext;
    }

    protected void logAuthDetails(GSSContext gssContext) throws GSSException {
        if (log.isDebugEnabled()) {
            String message = new StringBuilder("SPNEGO Security context accepted with token: " + responseToken)
                    .append(", established: ").append(gssContext.isEstablished())
                    .append(", credDelegState: ").append(gssContext.getCredDelegState())
                    .append(", mutualAuthState: ").append(gssContext.getMutualAuthState())
                    .append(", lifetime: ").append(gssContext.getLifetime())
                    .append(", confState: ").append(gssContext.getConfState())
                    .append(", integState: ").append(gssContext.getIntegState())
                    .append(", srcName: ").append(gssContext.getSrcName())
                    .append(", targName: ").append(gssContext.getTargName())
                    .toString();
            log.debug(message);
        }
    }

}
