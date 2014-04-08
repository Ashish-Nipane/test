package org.keycloak.provider;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public interface ProviderFactory<T extends Provider> {

    public T create(ProviderSession providerSession);

    public void init();

    public void close();

    public String getId();

    public boolean lazyLoad();

}
