package org.keycloak.provider;

import java.util.Set;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public interface ProviderSession {

    <T extends Provider> T getProvider(Class<T> clazz);

    <T extends Provider> T getProvider(Class<T> clazz, String id);

    <T extends Provider> Set<String> listProviderIds(Class<T> clazz);

    <T extends Provider> Set<T> getAllProviders(Class<T> clazz);

    void close();

}
