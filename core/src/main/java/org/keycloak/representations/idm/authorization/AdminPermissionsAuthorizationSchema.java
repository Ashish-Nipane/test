/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.representations.idm.authorization;

import java.util.Arrays;
import java.util.HashSet;

public class AdminPermissionsAuthorizationSchema extends AuthorizationSchema {

    public static final AdminPermissionsAuthorizationSchema INSTANCE = new AdminPermissionsAuthorizationSchema();

    private AdminPermissionsAuthorizationSchema() {
        super(new ResourceType("Users", new HashSet<>(Arrays.asList("manage"))),
              new ResourceType("Roles", new HashSet<>(Arrays.asList("map-role", "map-role-client-scope", "map-role-composite"))));
    }

}
