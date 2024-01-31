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

package org.keycloak.it.cli.dist;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.keycloak.crypto.fips.KeycloakFipsSecurityProvider;
import org.keycloak.it.junit5.extension.CLIResult;
import org.keycloak.it.junit5.extension.DistributionTest;
import org.keycloak.it.junit5.extension.RawDistOnly;
import org.keycloak.it.utils.KeycloakDistribution;
import org.keycloak.it.utils.RawKeycloakDistribution;

import io.quarkus.test.junit.main.Launch;
import io.quarkus.test.junit.main.LaunchResult;

@DistributionTest(keepAlive = true, defaultOptions = { "--features=fips", "--http-enabled=true", "--hostname-strict=false", "--log-level=org.keycloak.common.crypto.CryptoIntegration:trace" })
@RawDistOnly(reason = "Containers are immutable")
public class FipsDistTest {

    @Test
    void testFipsNonApprovedMode(KeycloakDistribution dist) {
        runOnFipsEnabledDistribution(dist, () -> {
            CLIResult cliResult = dist.run("start");
            cliResult.assertStarted();
            // Not shown as FIPS is not a preview anymore
            cliResult.assertMessageWasShownExactlyNumberOfTimes("Preview features enabled: fips", 0);
            cliResult.assertMessage("Java security providers: [ \n"
                    + " KC(BCFIPS version 1.000203, FIPS-JVM: " + KeycloakFipsSecurityProvider.isSystemFipsEnabled() + ") version 1.0 - class org.keycloak.crypto.fips.KeycloakFipsSecurityProvider");
        });
    }

    @Test
    void testFipsApprovedMode(KeycloakDistribution dist) {
        runOnFipsEnabledDistribution(dist, () -> {
            dist.setEnvVar("KEYCLOAK_ADMIN", "admin");
            dist.setEnvVar("KEYCLOAK_ADMIN_PASSWORD", "admin");

            CLIResult cliResult = dist.run("start", "--fips-mode=strict");
            cliResult.assertStarted();
            cliResult.assertMessage(
                    "org.bouncycastle.crypto.fips.FipsUnapprovedOperationError: password must be at least 112 bits");
            cliResult.assertMessage("Java security providers: [ \n"
                    + " KC(BCFIPS version 1.000203 Approved Mode, FIPS-JVM: " + KeycloakFipsSecurityProvider.isSystemFipsEnabled() + ") version 1.0 - class org.keycloak.crypto.fips.KeycloakFipsSecurityProvider");

            dist.setEnvVar("KEYCLOAK_ADMIN_PASSWORD", "adminadminadmin");
            cliResult = dist.run("start", "--fips-mode=strict");
            cliResult.assertStarted();
            cliResult.assertMessage("Added user 'admin' to realm 'master'");
        });
    }

    @Test
    @Launch({ "start", "--fips-mode=non-strict" })
    void failStartDueToMissingFipsDependencies(LaunchResult result) {
        CLIResult cliResult = (CLIResult) result;
        cliResult.assertError("Failed to configure FIPS. Make sure you have added the Bouncy Castle FIPS dependencies to the 'providers' directory.");
    }

    @Test
    void testUnsupportedHttpsJksKeyStoreInStrictMode(KeycloakDistribution dist) {
        runOnFipsEnabledDistribution(dist, () -> {
            dist.copyOrReplaceFileFromClasspath("/server.keystore", Path.of("conf", "server.keystore"));
            CLIResult cliResult = dist.run("start", "--fips-mode=strict");
            dist.assertStopped();
            // after https://issues.redhat.com/browse/JBTM-3830 reenable this check
            //cliResult.assertMessage("ERROR: java.lang.IllegalArgumentException: malformed sequence");
        });
    }

    @Test
    void testHttpsBcfksKeyStoreInStrictMode(KeycloakDistribution dist) {
        runOnFipsEnabledDistribution(dist, () -> {
            dist.copyOrReplaceFileFromClasspath("/server.keystore.bcfks", Path.of("conf", "server.keystore"));
            CLIResult cliResult = dist.run("start", "--fips-mode=strict", "--https-key-store-password=passwordpassword");
            cliResult.assertStarted();
        });
    }

    @Test
    void testHttpsBcfksTrustStoreInStrictMode(KeycloakDistribution dist) {
        runOnFipsEnabledDistribution(dist, () -> {
            dist.copyOrReplaceFileFromClasspath("/server.keystore.bcfks", Path.of("conf", "server.keystore"));

            RawKeycloakDistribution rawDist = dist.unwrap(RawKeycloakDistribution.class);
            Path truststorePath = rawDist.getDistPath().resolve("conf").resolve("server.keystore").toAbsolutePath();

            // https-trust-store-type should be automatically set to bcfks in fips-mode=strict
            CLIResult cliResult = dist.run("--verbose", "start", "--fips-mode=strict", "--https-key-store-password=passwordpassword",
                    "--https-trust-store-file=" + truststorePath, "--https-trust-store-password=passwordpassword");
            cliResult.assertStarted();
        });
    }

    @Test
    void testUnsupportedHttpsPkcs12KeyStoreInStrictMode(KeycloakDistribution dist) {
        runOnFipsEnabledDistribution(dist, () -> {
            dist.copyOrReplaceFileFromClasspath("/server.keystore.pkcs12", Path.of("conf", "server.keystore"));
            CLIResult cliResult = dist.run("start", "--fips-mode=strict", "--https-key-store-password=passwordpassword");
            dist.assertStopped();
            // after https://issues.redhat.com/browse/JBTM-3830 reenable this check
            //cliResult.assertMessage("ERROR: java.lang.IllegalArgumentException: malformed sequence");
        });
    }

    @Test
    void testHttpsPkcs12KeyStoreInNonApprovedMode(KeycloakDistribution dist) {
        runOnFipsEnabledDistribution(dist, () -> {
            dist.copyOrReplaceFileFromClasspath("/server.keystore.pkcs12", Path.of("conf", "server.keystore"));
            CLIResult cliResult = dist.run("start", "--fips-mode=non-strict", "--https-key-store-password=passwordpassword");
            cliResult.assertStarted();
        });
    }

    @Test
    void testHttpsPkcs12TrustStoreInNonApprovedMode(KeycloakDistribution dist) {
        runOnFipsEnabledDistribution(dist, () -> {
            dist.copyOrReplaceFileFromClasspath("/server.keystore.pkcs12", Path.of("conf", "server.keystore"));

            RawKeycloakDistribution rawDist = dist.unwrap(RawKeycloakDistribution.class);
            Path truststorePath = rawDist.getDistPath().resolve("conf").resolve("server.keystore").toAbsolutePath();

            // https-trust-store-type should be automatically set to pkcs12 in fips-mode=non-strict
            CLIResult cliResult = dist.run("--verbose", "start", "--fips-mode=non-strict", "--https-key-store-password=passwordpassword",
                    "--https-trust-store-file=" + truststorePath, "--https-trust-store-password=passwordpassword");
            cliResult.assertStarted();
        });
    }

    private void runOnFipsEnabledDistribution(KeycloakDistribution dist, Runnable runnable) {
        installBcFips(dist);
        runnable.run();
    }

    private void installBcFips(KeycloakDistribution dist) {
        RawKeycloakDistribution rawDist = dist.unwrap(RawKeycloakDistribution.class);
        rawDist.copyProvider("org.bouncycastle", "bc-fips");
        rawDist.copyProvider("org.bouncycastle", "bctls-fips");
        rawDist.copyProvider("org.bouncycastle", "bcpkix-fips");
    }

}
