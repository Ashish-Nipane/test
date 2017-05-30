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

package org.keycloak.migration.migrators;


import org.keycloak.migration.ModelVersion;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;

public class MigrateTo3_2_0 implements Migration {

    public static final ModelVersion VERSION = new ModelVersion("3.1.0");

    @Override
    public void migrate(KeycloakSession session) {
        for (RealmModel realm : session.realms().getRealms()) {
            // At some point the default password policy was changed to increase the default hashing iterations. This
            // should have been done by setting a default value if not specified. If a realm has no hashing algorithm set
            // and has 20K hashing iterations this value is removed so the default value is used.
            PasswordPolicy.Builder builder = realm.getPasswordPolicy().toBuilder();
            if (!builder.contains(PasswordPolicy.HASH_ALGORITHM_ID) && "20000".equals(builder.get(PasswordPolicy.HASH_ITERATIONS_ID))) {
                realm.setPasswordPolicy(builder.remove(PasswordPolicy.HASH_ITERATIONS_ID).build(session));
            }
        }
    }

    @Override
    public ModelVersion getVersion() {
        return VERSION;
    }

}
