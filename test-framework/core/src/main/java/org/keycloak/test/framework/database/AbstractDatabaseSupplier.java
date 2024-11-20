package org.keycloak.test.framework.database;

import org.keycloak.test.framework.annotations.InjectTestDatabase;
import org.keycloak.test.framework.injection.InstanceContext;
import org.keycloak.test.framework.injection.LifeCycle;
import org.keycloak.test.framework.injection.RequestedInstance;
import org.keycloak.test.framework.injection.Supplier;
import org.keycloak.test.framework.server.KeycloakTestServerConfigBuilder;

import java.util.Map;

public abstract class AbstractDatabaseSupplier implements Supplier<TestDatabase, InjectTestDatabase> {

    @Override
    public Class<InjectTestDatabase> getAnnotationClass() {
        return InjectTestDatabase.class;
    }

    @Override
    public Class<TestDatabase> getValueType() {
        return TestDatabase.class;
    }

    @Override
    public TestDatabase getValue(InstanceContext<TestDatabase, InjectTestDatabase> instanceContext) {
        TestDatabase testDatabase = getTestDatabase();
        testDatabase.start();
        return testDatabase;
    }

    @Override
    public boolean compatible(InstanceContext<TestDatabase, InjectTestDatabase> a, RequestedInstance<TestDatabase, InjectTestDatabase> b) {
        return true;
    }

    @Override
    public LifeCycle getDefaultLifecycle() {
        return LifeCycle.GLOBAL;
    }

    abstract TestDatabase getTestDatabase();

    @Override
    public void close(InstanceContext<TestDatabase, InjectTestDatabase> instanceContext) {
        instanceContext.getValue().stop();
    }

    @Override
    public void decorate(Object object, InstanceContext<TestDatabase, InjectTestDatabase> instanceContext) {
        if (object instanceof KeycloakTestServerConfigBuilder serverConfig) {
            serverConfig.options(instanceContext.getValue().serverConfig());
        }
    }
}
