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

package org.keycloak.common.util;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.keycloak.common.crypto.CryptoIntegration;

/**
 * The Class CertificateUtils provides utility functions for generation of V1 and V3 {@link java.security.cert.X509Certificate}
 *
 */
@Deprecated
public class CertificateUtils {

    static {
        CryptoIntegration.init(ClassLoader.getSystemClassLoader());
    }


    /**
     * Generates version 3 {@link java.security.cert.X509Certificate}.
     *
     * @param keyPair the key pair
     * @param caPrivateKey the CA private key
     * @param caCert the CA certificate
     * @param subject the subject name
     * 
     * @return the x509 certificate
     * 
     * @throws Exception the exception
     */
    public static X509Certificate generateV3Certificate(KeyPair keyPair, PrivateKey caPrivateKey,
            X509Certificate caCert, String subject) throws Exception {
        return CryptoIntegration.getProvider().getCertificateUtils().generateV3Certificate(keyPair, caPrivateKey,
                caCert, subject);
    }

    /**
     * Generate version 1 self signed {@link java.security.cert.X509Certificate}..
     *
     * @param caKeyPair the CA key pair
     * @param subject the subject name
     * 
     * @return the x509 certificate
     * 
     * @throws Exception the exception
     */
    public static X509Certificate generateV1SelfSignedCertificate(KeyPair caKeyPair, String subject) {
        return CryptoIntegration.getProvider().getCertificateUtils().generateV1SelfSignedCertificate(caKeyPair, subject);
    } 

    public static X509Certificate generateV1SelfSignedCertificate(KeyPair caKeyPair, String subject, BigInteger serialNumber) {
        return CryptoIntegration.getProvider().getCertificateUtils().generateV1SelfSignedCertificate(caKeyPair, subject, serialNumber);
    }
        
}
