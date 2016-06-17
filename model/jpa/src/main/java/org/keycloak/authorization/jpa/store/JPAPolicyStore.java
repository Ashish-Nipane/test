/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.authorization.jpa.store;

import org.keycloak.authorization.jpa.entities.PolicyEntity;
import org.keycloak.authorization.jpa.entities.ResourceServerEntity;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.models.utils.KeycloakModelUtils;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.Query;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JPAPolicyStore implements PolicyStore {

    private final EntityManager entityManager;

    public JPAPolicyStore(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public Policy create(String name, String type, ResourceServer resourceServer) {
        PolicyEntity entity = new PolicyEntity();

        entity.setId(KeycloakModelUtils.generateId());
        entity.setName(name);
        entity.setType(type);
        entity.setResourceServer((ResourceServerEntity) resourceServer);

        this.entityManager.persist(entity);

        return entity;
    }

    public EntityManager getEntityManager() {
        return this.entityManager;
    }

    @Override
    public void delete(String id) {
        Policy policy = findById(id);

        if (policy != null) {
            getEntityManager().remove(policy);
        }
    }


    @Override
    public Policy findById(String id) {
        return getEntityManager().find(PolicyEntity.class, id);
    }

    @Override
    public Policy findByName(String name, String resourceServerId) {
        try {
            Query query = getEntityManager().createQuery("from PolicyEntity where name = :name and resourceServer.id = :serverId");

            query.setParameter("name", name);
            query.setParameter("serverId", resourceServerId);

            return (Policy) query.getSingleResult();
        } catch (NoResultException nre) {
            return null;
        }
    }

    @Override
    public List<Policy> findByResourceServer(final String resourceServerId) {
        Query query = getEntityManager().createQuery("from PolicyEntity where resourceServer.id = :serverId");

        query.setParameter("serverId", resourceServerId);

        return query.getResultList();
    }

    @Override
    public List<Policy> findByResource(final String resourceId) {
        Query query = getEntityManager().createQuery("select p from PolicyEntity p inner join p.resources r where r.id = :resourceId");

        query.setParameter("resourceId", resourceId);

        return query.getResultList();
    }

    @Override
    public List<Policy> findByResourceType(final String resourceType, String resourceServerId) {
        List<Policy> policies = new ArrayList<>();
        Query query = getEntityManager().createQuery("from PolicyEntity where resourceServer.id = :serverId");

        query.setParameter("serverId", resourceServerId);

        List<Policy> models = query.getResultList();

        for (Policy policy : models) {
            String defaultType = policy.getConfig().get("defaultResourceType");

            if (defaultType != null && defaultType.equals(resourceType) && policy.getResources().isEmpty()) {
                policies.add(policy);
            }
        }

        return policies;
    }

    @Override
    public List<Policy> findByScopeIds(List<String> scopeIds, String resourceServerId) {
        Query query = getEntityManager().createQuery("select p from PolicyEntity p inner join p.scopes s where p.resourceServer.id = :serverId and s.id in (:scopeIds) and p.resources is empty group by p.id order by p.name");

        query.setParameter("serverId", resourceServerId);
        query.setParameter("scopeIds", scopeIds);

        return query.getResultList();
    }

    @Override
    public List<Policy> findByType(String type) {
        Query query = getEntityManager().createQuery("select p from PolicyEntity p where p.type = :type");

        query.setParameter("type", type);

        return query.getResultList();
    }

    @Override
    public List<Policy> findDependentPolicies(String policyId) {
        Query query = getEntityManager().createQuery("select p from PolicyEntity p inner join p.associatedPolicies ap where ap.id in (:policyId)");

        query.setParameter("policyId", Arrays.asList(policyId));

        return query.getResultList();
    }
}
