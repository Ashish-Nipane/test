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

package org.keycloak.sdjwt;

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.crypto.AsymmetricSignatureVerifierContext;
import org.keycloak.crypto.ECDSASignatureVerifierContext;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.util.JWKSUtils;

import java.util.Objects;

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class JwkParsingUtils {

    public static SignatureVerifierContext convertJwkToVerifierContext(JsonNode jwkNode) {
        // Parse JWK

        KeyWrapper keyWrapper;

        try {
            JWK jwk = SdJwtUtils.mapper.convertValue(jwkNode, JWK.class);
            keyWrapper = JWKSUtils.getKeyWrapper(jwk);
            Objects.requireNonNull(keyWrapper);
        } catch (Exception e) {
            throw new IllegalArgumentException("Malformed or unsupported JWK");
        }

        // Build verifier

        // KeyType.EC
        if (keyWrapper.getType().equals(KeyType.EC)) {
            if (keyWrapper.getAlgorithm() == null) {
                Objects.requireNonNull(keyWrapper.getCurve());

                String alg = null;
                switch (keyWrapper.getCurve()) {
                    case "P-256":
                        alg = "ES256";
                        break;
                    case "P-384":
                        alg = "ES384";
                        break;
                    case "P-521":
                        alg = "ES512";
                        break;
                }

                keyWrapper.setAlgorithm(alg);
            }

            return new ECDSASignatureVerifierContext(keyWrapper);
        }

        // KeyType.RSA
        if (keyWrapper.getType().equals(KeyType.RSA)) {
            return new AsymmetricSignatureVerifierContext(keyWrapper);
        }

        // KeyType is not supported
        // This is unreachable as of now given that `JWKSUtils.getKeyWrapper` will fail
        // on JWKs with key type not equal to EC or RSA.
        throw new UnsupportedOperationException("JWK alg is not supported");
    }
}
