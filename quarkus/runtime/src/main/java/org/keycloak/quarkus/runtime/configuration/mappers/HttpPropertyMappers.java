package org.keycloak.quarkus.runtime.configuration.mappers;

import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigValue;
import org.keycloak.quarkus.runtime.Environment;
import org.keycloak.quarkus.runtime.configuration.MicroProfileConfigProvider;

import java.io.File;
import java.nio.file.Paths;
import java.util.Arrays;

import static org.keycloak.quarkus.runtime.configuration.mappers.PropertyMappers.getMapper;
import static org.keycloak.quarkus.runtime.integration.QuarkusPlatform.addInitializationException;

final class HttpPropertyMappers {

    private HttpPropertyMappers(){}

    public static PropertyMapper[] getHttpPropertyMappers() {
        return new PropertyMapper[] {
                builder().from("http.enabled")
                        .to("quarkus.http.insecure-requests")
                        .defaultValue(Boolean.FALSE.toString())
                        .transformer(HttpPropertyMappers::getHttpEnabledTransformer)
                        .description("Enables the HTTP listener.")
                        .expectedValues(Arrays.asList(Boolean.TRUE.toString(), Boolean.FALSE.toString()))
                        .build(),
                builder().from("http.host")
                        .to("quarkus.http.host")
                        .defaultValue("0.0.0.0")
                        .description("The used HTTP Host.")
                        .build(),
                builder().from("http.port")
                        .to("quarkus.http.port")
                        .defaultValue(String.valueOf(8080))
                        .description("The used HTTP port.")
                        .build(),
                builder().from("https.port")
                        .to("quarkus.http.ssl-port")
                        .defaultValue(String.valueOf(8443))
                        .description("The used HTTPS port.")
                        .build(),
                builder().from("https.client-auth")
                        .to("quarkus.http.ssl.client-auth")
                        .defaultValue("none")
                        .description("Configures the server to require/request client authentication. Possible Values: none, request, required.")
                        .expectedValues(Arrays.asList("none", "request", "required"))
                        .build(),
                builder().from("https.cipher-suites")
                        .to("quarkus.http.ssl.cipher-suites")
                        .description("The cipher suites to use. If none is given, a reasonable default is selected.")
                        .build(),
                builder().from("https.protocols")
                        .to("quarkus.http.ssl.protocols")
                        .description("The list of protocols to explicitly enable.")
                        .build(),
                builder().from("https.certificate.file")
                        .to("quarkus.http.ssl.certificate.file")
                        .description("The file path to a server certificate or certificate chain in PEM format.")
                        .build(),
                builder().from("https.certificate.key-file")
                        .to("quarkus.http.ssl.certificate.key-file")
                        .description("The file path to a private key in PEM format.")
                        .build(),
                builder().from("https.certificate.key-store-file")
                        .to("quarkus.http.ssl.certificate.key-store-file")
                        .defaultValue(getDefaultKeystorePathValue())
                        .description("The key store which holds the certificate information instead of specifying separate files.")
                        .build(),
                builder().from("https.certificate.key-store-password")
                        .to("quarkus.http.ssl.certificate.key-store-password")
                        .description("The password of the key store file. If not given, the default (\"password\") is used.")
                        .isMasked(true)
                        .build(),
                builder().from("https.certificate.key-store-file-type")
                        .to("quarkus.http.ssl.certificate.key-store-file-type")
                        .description("The type of the key store file. " +
                                "If not given, the type is automatically detected based on the file name.")
                        .build(),
                builder().from("https.certificate.trust-store-file")
                        .to("quarkus.http.ssl.certificate.trust-store-file")
                        .description("The trust store which holds the certificate information of the certificates to trust.")
                        .build(),
                builder().from("https.certificate.trust-store-password")
                        .to("quarkus.http.ssl.certificate.trust-store-password")
                        .description("The password of the trust store file.")
                        .isMasked(true)
                        .build(),
                builder().from("https.certificate.trust-store-file-type")
                        .to("quarkus.http.ssl.certificate.trust-store-file-type")
                        .defaultValue(getDefaultKeystorePathValue())
                        .description("The type of the trust store file. " +
                                "If not given, the type is automatically detected based on the file name.")
                        .build()

        };
    }

    private static String getHttpEnabledTransformer(String value, ConfigSourceInterceptorContext context) {
        boolean enabled = Boolean.parseBoolean(value);
        ConfigValue proxy = context.proceed(MicroProfileConfigProvider.NS_KEYCLOAK_PREFIX + "proxy");

        if (Environment.isDevMode() || Environment.isImportExportMode()
                || (proxy != null && "edge".equalsIgnoreCase(proxy.getValue()))) {
            enabled = true;
        }

        if (!enabled) {
            ConfigValue proceed = context.proceed("kc.https.certificate.file");

            if (proceed == null || proceed.getValue() == null) {
                proceed = getMapper("quarkus.http.ssl.certificate.key-store-file").getOrDefault(context, null);
            }

            if (proceed == null || proceed.getValue() == null) {
                addInitializationException(Messages.httpsConfigurationNotSet());
            }
        }

        return enabled ? "enabled" : "disabled";
    }

    private static String getDefaultKeystorePathValue() {
        String homeDir = Environment.getHomeDir();

        if (homeDir != null) {
            File file = Paths.get(homeDir, "conf", "server.keystore").toFile();

            if (file.exists()) {
                return file.getAbsolutePath();
            }
        }

        return null;
    }

    private static PropertyMapper.Builder builder() {
        return PropertyMapper.builder(ConfigCategory.HTTP);
    }
}

