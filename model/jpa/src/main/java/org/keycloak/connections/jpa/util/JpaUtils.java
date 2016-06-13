/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.connections.jpa.util;

import org.hibernate.boot.registry.classloading.internal.ClassLoaderServiceImpl;
import org.hibernate.jpa.boot.internal.ParsedPersistenceXmlDescriptor;
import org.hibernate.jpa.boot.internal.PersistenceXmlParser;
import org.hibernate.jpa.boot.spi.Bootstrap;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.ProvidedEntitiesClassLoader;
import org.keycloak.models.KeycloakSession;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.spi.PersistenceUnitTransactionType;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class JpaUtils {

    public static final String HIBERNATE_DEFAULT_SCHEMA = "hibernate.default_schema";

    public static String getTableNameForNativeQuery(String tableName, EntityManager em) {
        String schema = (String) em.getEntityManagerFactory().getProperties().get(HIBERNATE_DEFAULT_SCHEMA);
        return (schema==null) ? tableName : schema + "." + tableName;
    }

    /**
     * Create the entity manager factory. Typically, this would be done with:
     * 
     * <pre>
     * Persistence.createEntityManagerFactory(unitName, properties)
     * </pre>
     * 
     * But since we'd like to add extra entities to the entity manager besides the ones in the persistence.xml, we'll split this
     * process into separate steps. See comments in the code for details.
     * 
     * @param session the keycloak session
     * @param unitName the name of the persistence unit
     * @param properties entity manager properties
     * @param classLoader the classloader to use
     * @return the created entity manager factory
     */
    public static EntityManagerFactory createEntityManagerFactory(KeycloakSession session,
    		String unitName, Map<String, Object> properties, ClassLoader classLoader) {
        PersistenceXmlParser parser = new PersistenceXmlParser(new ClassLoaderServiceImpl(classLoader), PersistenceUnitTransactionType.RESOURCE_LOCAL);
        // Let Hibernate find all the available persistence units on the classpath.
        List<ParsedPersistenceXmlDescriptor> persistenceUnits = parser.doResolve(properties);
        for (ParsedPersistenceXmlDescriptor persistenceUnit : persistenceUnits) {
            // We should find a match on the persistence unit name.
            if (persistenceUnit.getName().equals(unitName)) {
                List<Class<?>> providedEntities = getProvidedEntities(session);
                for (Class<?> entityClass : providedEntities) {
                    // Add all extra entity classes to the persistence unit.
                    persistenceUnit.addClasses(entityClass.getName());
                }
                // Now build the entity manager factory, supplying a custom classloader, so Hibernate will be able
                // to find and load the extra provided entities. Set the provided classloader as parent classloader.
                return Bootstrap.getEntityManagerFactoryBuilder(persistenceUnit, properties,
                        new ProvidedEntitiesClassLoader(providedEntities, classLoader)).build();
            }
        }
        throw new RuntimeException("Persistence unit '" + unitName + "' not found");
    }
    
    /**
     * Get a list of all provided entities by looping over all configured entity providers.
     * 
     * @param session the keycloak session
     * @return a list of all provided entities (can be an empty list)
     */
    private static List<Class<?>> getProvidedEntities(KeycloakSession session) {
        List<Class<?>> providedEntityClasses = new ArrayList<>();
        // Get all configured entity providers.
        Set<JpaEntityProvider> entityProviders = session.getAllProviders(JpaEntityProvider.class);
        // For every provider, add all entity classes to the list.
        for (JpaEntityProvider entityProvider : entityProviders) {
            providedEntityClasses.addAll(entityProvider.getEntities());
        }
        return providedEntityClasses;
    }

}
