package org.keycloak.services.listeners;

import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderSessionFactory;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class KeycloakSessionDestroyListener implements ServletContextListener {

    @Override
    public void contextInitialized(ServletContextEvent sce) {
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        ProviderSessionFactory providerSessionFactory = (ProviderSessionFactory) sce.getServletContext().getAttribute(ProviderSessionFactory.class.getName());
        KeycloakSessionFactory kcSessionFactory = (KeycloakSessionFactory) sce.getServletContext().getAttribute(KeycloakSessionFactory.class.getName());
        if (providerSessionFactory != null) {
            providerSessionFactory.close();
        }
        if (kcSessionFactory != null) {
            kcSessionFactory.close();
        }
    }

}
