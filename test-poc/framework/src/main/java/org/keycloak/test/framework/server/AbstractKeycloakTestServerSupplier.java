package org.keycloak.test.framework.server;

import org.keycloak.test.framework.KeycloakIntegrationTest;
import org.keycloak.test.framework.KeycloakTestDatabase;
import org.keycloak.test.framework.database.TestDatabase;
import org.keycloak.test.framework.injection.InstanceWrapper;
import org.keycloak.test.framework.injection.LifeCycle;
import org.keycloak.test.framework.injection.Registry;
import org.keycloak.test.framework.injection.Supplier;
import org.keycloak.test.framework.injection.SupplierHelpers;

public abstract class AbstractKeycloakTestServerSupplier implements Supplier<KeycloakTestServer, KeycloakIntegrationTest> {

    @Override
    public Class<KeycloakTestServer> getValueType() {
        return KeycloakTestServer.class;
    }

    @Override
    public Class<KeycloakIntegrationTest> getAnnotationClass() {
        return KeycloakIntegrationTest.class;
    }

    @Override
    public InstanceWrapper<KeycloakTestServer, KeycloakIntegrationTest> getValue(Registry registry, KeycloakIntegrationTest annotation) {
        KeycloakTestServerConfig serverConfig = SupplierHelpers.getInstance(annotation.config());
        InstanceWrapper<KeycloakTestServer, KeycloakIntegrationTest> wrapper = new InstanceWrapper<>(this, annotation);
        TestDatabase testDatabase = registry.getDependency(TestDatabase.class, wrapper);

        KeycloakTestServer keycloakTestServer = getServer();

        keycloakTestServer.start(serverConfig, testDatabase.getDatabaseConfig());
        wrapper.setValue(keycloakTestServer, LifeCycle.GLOBAL);

        return wrapper;
    }

    @Override
    public boolean compatible(InstanceWrapper<KeycloakTestServer, KeycloakIntegrationTest> a, InstanceWrapper<KeycloakTestServer, KeycloakIntegrationTest> b) {
        return a.getAnnotation().config().equals(b.getAnnotation().config());
    }

    @Override
    public void close(KeycloakTestServer keycloakTestServer) {
        keycloakTestServer.stop();
    }

    public abstract KeycloakTestServer getServer();

}
