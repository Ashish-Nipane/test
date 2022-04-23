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

package org.keycloak.admin.client.resource;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import java.util.List;
import java.util.Map;

public interface RealmLocalizationResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    List<String> getRealmSpecificLocales();

    @Path("{locale}")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    Map<String, String> getRealmLocalizationTexts(final @PathParam("locale") String locale);


    @Path("{locale}/{key}")
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    String getRealmLocalizationText(final @PathParam("locale") String locale, final @PathParam("key") String key);


    @Path("{locale}")
    @DELETE
    void deleteRealmLocalizationTexts(@PathParam("locale") String locale);

    @Path("{locale}/{key}")
    @DELETE
    void deleteRealmLocalizationText(@PathParam("locale") String locale, @PathParam("key") String key);

    @Path("{locale}/{key}")
    @PUT
    @Consumes(MediaType.TEXT_PLAIN)
    void saveRealmLocalizationText(@PathParam("locale") String locale, @PathParam("key") String key, String text);

    @Path("{locale}")
    @POST
    @Consumes("application/json")
    void createOrUpdateRealmLocalizationTexts(@PathParam("locale") String locale, Map<String, String> localizationTexts);
}
