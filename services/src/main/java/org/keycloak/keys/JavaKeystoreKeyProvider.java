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

package org.keycloak.keys;

import org.keycloak.common.util.CertificateUtils;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.RealmModel;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class JavaKeystoreKeyProvider extends AbstractRsaKeyProvider {

    public JavaKeystoreKeyProvider(RealmModel realm, ComponentModel model, KeyStore trustStore) {
        super(realm, model);
        getKeysStream()
                .map(KeyWrapper::getCertificateChain)
                .filter(Objects::nonNull)
                .filter(list -> list.size() > 1)
                .findFirst()
                .ifPresent(chain -> validateCertificateChain(chain, trustStore));
    }

    @Override
    protected KeyWrapper loadKey(RealmModel realm, ComponentModel model) {
        try (FileInputStream is = new FileInputStream(model.get(JavaKeystoreKeyProviderFactory.KEYSTORE_KEY))) {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(is, model.get(JavaKeystoreKeyProviderFactory.KEYSTORE_PASSWORD_KEY).toCharArray());

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(model.get(JavaKeystoreKeyProviderFactory.KEY_ALIAS_KEY), model.get(JavaKeystoreKeyProviderFactory.KEY_PASSWORD_KEY).toCharArray());
            PublicKey publicKey = KeyUtils.extractPublicKey(privateKey);

            KeyPair keyPair = new KeyPair(publicKey, privateKey);

            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(model.get(JavaKeystoreKeyProviderFactory.KEY_ALIAS_KEY));
            if (certificate == null) {
                certificate = CertificateUtils.generateV1SelfSignedCertificate(keyPair, realm.getName());
            }

            List<X509Certificate> certificateChain = Optional.ofNullable(keyStore.getCertificateChain(model.get(JavaKeystoreKeyProviderFactory.KEY_ALIAS_KEY)))
                    .map(certificates -> Arrays.stream(certificates)
                            .map(X509Certificate.class::cast)
                            .collect(Collectors.toList()))
                    .orElseGet(Collections::emptyList);

            return createKeyWrapper(keyPair, certificate, certificateChain);
        } catch (KeyStoreException kse) {
            throw new RuntimeException("KeyStore error on server. " + kse.getMessage(), kse);
        } catch (FileNotFoundException fnfe) {
            throw new RuntimeException("File not found on server. " + fnfe.getMessage(), fnfe);
        } catch (IOException ioe) {
            throw new RuntimeException("IO error on server. " + ioe.getMessage(), ioe);
        } catch (NoSuchAlgorithmException nsae) {
            throw new RuntimeException("Algorithm not available on server. " + nsae.getMessage(), nsae);
        } catch (CertificateException ce) {
            throw new RuntimeException("Certificate error on server. " + ce.getMessage(), ce);
        } catch (UnrecoverableKeyException uke) {
            throw new RuntimeException("Keystore on server can not be recovered. " + uke.getMessage(), uke);
        }
    }

    private void validateCertificateChain(List<X509Certificate> certificateChain, KeyStore trustStore) {
        try {
            PKIXParameters params = new PKIXParameters(trustStore);
            params.setRevocationEnabled(false);

            final CertPath certPath = CertificateFactory.getInstance("X.509").generateCertPath(certificateChain);

            final CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(certPath, params);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to validate server certificate against certificate chain", e);
        }
    }
}
