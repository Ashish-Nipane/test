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
package org.keycloak.services.resources.admin;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.extensions.Extension;
import org.eclipse.microprofile.openapi.annotations.headers.Header;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.resteasy.reactive.NoCache;
import org.keycloak.common.util.ObjectUtil;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.KeycloakOpenAPI;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.GroupPermissionEvaluator;
import org.keycloak.utils.GroupUtils;
import org.keycloak.utils.SearchQueryUtils;

/**
 * @resource Groups
 * @author Bill Burke
 */
@Extension(name = KeycloakOpenAPI.Profiles.ADMIN, value = "")
public class GroupsResource {

    private final RealmModel realm;
    private final KeycloakSession session;
    private final AdminPermissionEvaluator auth;
    private final AdminEventBuilder adminEvent;

    public GroupsResource(RealmModel realm, KeycloakSession session, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        this.realm = realm;
        this.session = session;
        this.auth = auth;
        this.adminEvent = adminEvent.resource(ResourceType.GROUP);

    }

    /**
     * Get group hierarchy.  Only name and ids are returned.
     *
     * @return
     */
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.GROUPS)
    @Operation( summary = "Get group hierarchy.  Only name and ids are returned.")
    public Stream<GroupRepresentation> getGroups(@QueryParam("search") String search,
                                                 @QueryParam("q") String searchQuery,
                                                 @QueryParam("exact") @DefaultValue("false") Boolean exact,
                                                 @QueryParam("first") Integer firstResult,
                                                 @QueryParam("max") Integer maxResults,
                                                 @QueryParam("briefRepresentation") @DefaultValue("true") boolean briefRepresentation,
                                                 @QueryParam("populateHierarchy") @DefaultValue("true") boolean populateHierarchy) {
        GroupPermissionEvaluator groupsEvaluator = auth.groups();
        groupsEvaluator.requireList();

        Stream<GroupModel> stream;
        if (Objects.nonNull(searchQuery)) {
            Map<String, String> attributes = SearchQueryUtils.getFields(searchQuery);
            stream = ModelToRepresentation.searchGroupModelsByAttributes(session, realm, attributes, firstResult, maxResults);
        } else if (Objects.nonNull(search)) {
            stream = session.groups().searchForGroupByNameStream(realm, search.trim(), exact, firstResult, maxResults);
        } else if(Objects.nonNull(firstResult) && Objects.nonNull(maxResults)) {
            stream = session.groups().getTopLevelGroupsStream(realm, firstResult, maxResults);
        } else {
            stream = session.groups().getTopLevelGroupsStream(realm);
        }

        if(populateHierarchy) {
            return GroupUtils.populateGroupHierarchyFromSubGroups(session, realm, stream, !briefRepresentation, groupsEvaluator);
        }
        boolean canViewGlobal = groupsEvaluator.canView();
        return stream
            .filter(g -> canViewGlobal || groupsEvaluator.canView(g))
            .map(g -> GroupUtils.populateSubGroupCount(g, GroupUtils.toRepresentation(groupsEvaluator, g, !briefRepresentation)));
    }

    /**
     * Does not expand hierarchy.  Subgroups will not be set.
     *
     * @param id
     * @return
     */
    @Path("{group-id}")
    public GroupResource getGroupById(@PathParam("group-id") String id) {
        GroupModel group = realm.getGroupById(id);
        if (group == null) {
            throw new NotFoundException("Could not find group by id");
        }
        return new GroupResource(realm, group, session, this.auth, adminEvent);
    }

    /**
     * Returns the groups counts.
     *
     * @return
     */
    @GET
    @NoCache
    @Path("count")
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.GROUPS)
    @Operation( summary = "Returns the groups counts.")
    public Map<String, Long> getGroupCount(@QueryParam("search") String search,
                                           @QueryParam("top") @DefaultValue("false") boolean onlyTopGroups) {
        GroupPermissionEvaluator groupsEvaluator = auth.groups();
        groupsEvaluator.requireList();
        Long results;
        Map<String, Long> map = new HashMap<>();
        if (Objects.nonNull(search)) {
            results = realm.getGroupsCountByNameContaining(search);
        } else {
            results = realm.getGroupsCount(onlyTopGroups);
        }
        map.put("count", results);
        return map;
    }

    /**
     * create or add a top level realm groupSet or create child.
     * This will update the group and set the parent if it exists.
     * Create it and set the parent if the group doesn't exist.
     *
     * @param groupRepresentation
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.GROUPS)
    @Operation( summary = "create or add a top level realm groupSet or create child.",
        description = "This will update the group and set the parent if it exists. Create it and set the parent if the group doesn’t exist.")
    @APIResponses({
        @APIResponse(
            responseCode = "201", description = "Group created",
            headers = @Header(name = "Location", description = "URL of the created group, including its id")
        ),
        @APIResponse(responseCode = "204", description = "Group updated"),
        @APIResponse(responseCode = "400", description = "Bad request - Group name is missing"),
        @APIResponse(responseCode = "403", description = "Forbidden - Insufficient permissions to create group"),
        @APIResponse(responseCode = "409", description = "Conflict - Top level group named '...' already exists")
    })
    public Response addTopLevelGroup(GroupRepresentation groupRepresentation) {
        auth.groups().requireManage();

        String groupName = groupRepresentation.getName();

        if (ObjectUtil.isBlank(groupName)) {
            throw ErrorResponse.error("Group name is missing", Response.Status.BAD_REQUEST);
        }

        Response.ResponseBuilder builder = Response.status(204);
        try {
            if (groupRepresentation.getId() != null) {
                GroupModel child = realm.getGroupById(groupRepresentation.getId());
                if (child == null) {
                    throw new NotFoundException("Could not find child by id");
                }
                if (child.getParentId() != null) {
                    realm.moveGroup(child, null);
                }
                adminEvent.operation(OperationType.UPDATE).resourcePath(session.getContext().getUri());
            } else {
                GroupModel child = realm.createGroup(groupName);
                GroupResource.updateGroup(groupRepresentation, child, realm, session);
                URI uri = session.getContext().getUri().getAbsolutePathBuilder()
                        .path(child.getId()).build();
                builder.status(201).location(uri);

                groupRepresentation.setId(child.getId());
                adminEvent.operation(OperationType.CREATE).resourcePath(session.getContext().getUri(), child.getId());
            }
        } catch (ModelDuplicateException mde) {
            throw ErrorResponse.exists("Top level group named '" + groupName + "' already exists.");
        }

        adminEvent.representation(groupRepresentation).success();
        return builder.build();
    }
}
