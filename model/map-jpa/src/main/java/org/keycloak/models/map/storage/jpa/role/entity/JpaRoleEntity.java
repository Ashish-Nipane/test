/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.models.map.storage.jpa.role.entity;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import jakarta.persistence.Basic;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.persistence.Version;
import org.hibernate.annotations.Parameter;
import org.hibernate.annotations.Type;
import org.hibernate.usertype.UserTypeLegacyBridge;
import org.keycloak.models.map.common.DeepCloner;
import org.keycloak.models.map.common.UuidValidator;
import org.keycloak.models.map.role.MapRoleEntity.AbstractRoleEntity;
import static org.keycloak.models.map.storage.jpa.Constants.CURRENT_SCHEMA_VERSION_ROLE;
import org.keycloak.models.map.storage.jpa.JpaRootVersionedEntity;

/**
 * There are some fields marked by {@code @Column(insertable = false, updatable = false)}.
 * Those fields are automatically generated by database from json field, 
 * therefore marked as non-insertable and non-updatable to instruct hibernate.
 */
@Entity
@Table(name = "kc_role", uniqueConstraints = {@UniqueConstraint(columnNames = {"realmId", "clientId", "name"})})
public class JpaRoleEntity extends AbstractRoleEntity implements JpaRootVersionedEntity {

    @Id
    @Column
    private UUID id;

    //used for implicit optimistic locking
    @Version
    @Column
    private int version;

    @Type(value = UserTypeLegacyBridge.class, parameters = @Parameter(name = UserTypeLegacyBridge.TYPE_NAME_PARAM_KEY, value = "jsonb"))
    @Column(columnDefinition = "jsonb")
    private final JpaRoleMetadata metadata;

    @Column(insertable = false, updatable = false)
    @Basic(fetch = FetchType.LAZY)
    private Integer entityVersion;

    @Column(insertable = false, updatable = false)
    @Basic(fetch = FetchType.LAZY)
    private String realmId;

    @Column(insertable = false, updatable = false)
    @Basic(fetch = FetchType.LAZY)
    private String clientId;

    @Column(insertable = false, updatable = false)
    @Basic(fetch = FetchType.LAZY)
    private String name;

    @Column(insertable = false, updatable = false)
    @Basic(fetch = FetchType.LAZY)
    private String description;

    @OneToMany(mappedBy = "root", cascade = CascadeType.PERSIST, orphanRemoval = true)
    private final Set<JpaRoleAttributeEntity> attributes = new HashSet<>();

    /**
     * No-argument constructor, used by hibernate to instantiate entities.
     */
    public JpaRoleEntity() {
        this.metadata = new JpaRoleMetadata();
    }

    public JpaRoleEntity(DeepCloner cloner) {
        this.metadata = new JpaRoleMetadata(cloner);
    }

    /**
     * Used by hibernate when calling cb.construct from read(QueryParameters) method.
     * It is used to select role without metadata(json) field.
     */
    public JpaRoleEntity(UUID id, int version, Integer entityVersion, String realmId, String clientId, String name, String description) {
        this.id = id;
        this.version = version;
        this.entityVersion = entityVersion;
        this.realmId = realmId;
        this.clientId = clientId;
        this.name = name;
        this.description = description;
        this.metadata = null;
    }

    public boolean isMetadataInitialized() {
        return metadata != null;
    }

    @Override
    public Integer getCurrentSchemaVersion() {
        return CURRENT_SCHEMA_VERSION_ROLE;
    }

    @Override
    public Integer getEntityVersion() {
        if (isMetadataInitialized()) return metadata.getEntityVersion();
        return entityVersion;
    }

    @Override
    public void setEntityVersion(Integer entityVersion) {
        metadata.setEntityVersion(entityVersion);
    }

    @Override
    public int getVersion() {
        return version;
    }

    @Override
    public String getId() {
        return id == null ? null : id.toString();
    }

    @Override
    public void setId(String id) {
        String validatedId = UuidValidator.validateAndConvert(id);
        this.id = UUID.fromString(validatedId);
    }

    @Override
    public String getRealmId() {
        if (isMetadataInitialized()) return metadata.getRealmId();
        return realmId;
    }

    @Override
    public String getClientId() {
        if (isMetadataInitialized()) return metadata.getClientId();
        return clientId;
    }

    @Override
    public String getName() {
        if (isMetadataInitialized()) return metadata.getName();
        return name;
    }

    @Override
    public String getDescription() {
        if (isMetadataInitialized()) return metadata.getDescription();
        return description;
    }

    @Override
    public void setRealmId(String realmId) {
        metadata.setRealmId(realmId);
    }

    @Override
    public void setClientId(String clientId) {
        metadata.setClientId(clientId);
    }

    @Override
    public void setName(String name) {
        metadata.setName(name);
    }

    @Override
    public void setDescription(String description) {
        metadata.setDescription(description);
    }

    @Override
    public Set<String> getCompositeRoles() {
        throw new UnsupportedOperationException("this is implemented in JpaMapRoleEntityDelegate, should never be called");
    }

    @Override
    public void setCompositeRoles(Set<String> compositeRoles) {
        if (compositeRoles == null) {
            // this is called when cloning an entity during creation, can't be avoided with the current implementation
            return;
        }
        throw new UnsupportedOperationException("this is implemented in JpaMapRoleEntityDelegate, should never be called");

    }

    @Override
    public void addCompositeRole(String roleId) {
        throw new UnsupportedOperationException("this is implemented in JpaMapRoleEntityDelegate, should never be called");

    }

    @Override
    public void removeCompositeRole(String roleId) {
        throw new UnsupportedOperationException("this is implemented in JpaMapRoleEntityDelegate, should never be called");
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        Map<String, List<String>> result = new HashMap<>();
        for (JpaRoleAttributeEntity attribute : attributes) {
            List<String> values = result.getOrDefault(attribute.getName(), new LinkedList<>());
            values.add(attribute.getValue());
            result.put(attribute.getName(), values);
        }
        return result;
    }

    @Override
    public List<String> getAttribute(String name) {
        return attributes.stream()
                .filter(a -> Objects.equals(a.getName(), name))
                .map(JpaRoleAttributeEntity::getValue)
                .collect(Collectors.toList());
    }

    @Override
    public void setAttributes(Map<String, List<String>> attributes) {
        this.attributes.clear();
        if (attributes != null) {
            for (Map.Entry<String, List<String>> entry : attributes.entrySet()) {
                setAttribute(entry.getKey(), entry.getValue());
            }
        }
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        removeAttribute(name);
        for (String value : values) {
            JpaRoleAttributeEntity attribute = new JpaRoleAttributeEntity(this, name, value);
            attributes.add(attribute);
        }
    }

    @Override
    public void removeAttribute(String name) {
        attributes.removeIf(attr -> Objects.equals(attr.getName(), name));
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof JpaRoleEntity)) return false;
        return Objects.equals(getId(), ((JpaRoleEntity) obj).getId());
    }

}
