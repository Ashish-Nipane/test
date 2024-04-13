/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.crypto.elytron.test;

import org.junit.Ignore;
import org.junit.Test;
import org.keycloak.jose.jwk.JWKTest;

public class ElytronCryptoJWKTest extends JWKTest {
    @Ignore("Test not supported by Elytron")
    @Test
    public void publicEs256kSecp256k1() throws Exception {
        // Do nothing
    }
}
