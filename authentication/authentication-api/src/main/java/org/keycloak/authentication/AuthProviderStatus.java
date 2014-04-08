package org.keycloak.authentication;

/**
 * Result of authentication by AuthenticationProvider
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public enum AuthProviderStatus {

    SUCCESS, INVALID_CREDENTIALS, FAILED

}
