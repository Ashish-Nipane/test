package org.keycloak.quarkus.runtime.configuration.mappers;

import static org.keycloak.quarkus.runtime.configuration.Configuration.getOptionalKcValue;
import static org.keycloak.quarkus.runtime.configuration.mappers.PropertyMapper.fromOption;

import java.io.File;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.BooleanSupplier;
import java.util.stream.Stream;

import org.keycloak.config.CachingOptions;
import org.keycloak.config.OptionBuilder;
import org.keycloak.config.OptionCategory;
import org.keycloak.infinispan.util.InfinispanUtils;
import org.keycloak.quarkus.runtime.Environment;

import io.smallrye.config.ConfigSourceInterceptorContext;

final class CachingPropertyMappers {

    private static final String REMOTE_HOST_SET = "remote host is set";

    private CachingPropertyMappers() {
    }

    public static PropertyMapper<?>[] getClusteringPropertyMappers() {
        List<PropertyMapper<?>> staticMappers = List.of(
              fromOption(CachingOptions.CACHE)
                    .paramLabel("type")
                    .build(),
              fromOption(CachingOptions.CACHE_STACK)
                    .to("kc.spi-connections-infinispan-quarkus-stack")
                    .paramLabel("stack")
                    .build(),
              fromOption(CachingOptions.CACHE_CONFIG_FILE)
                    .mapFrom(CachingOptions.CACHE, (value, context) -> {
                        if (CachingOptions.Mechanism.local.name().equals(value)) {
                            return "cache-local.xml";
                        } else if (CachingOptions.Mechanism.ispn.name().equals(value)) {
                            return "cache-ispn.xml";
                        } else
                            return null;
                    })
                    .to("kc.spi-connections-infinispan-quarkus-config-file")
                    .transformer(CachingPropertyMappers::resolveConfigFile)
                    .paramLabel("file")
                    .build(),
              fromOption(CachingOptions.CACHE_EMBEDDED_MTLS_ENABLED)
                    .build(),
              fromOption(CachingOptions.CACHE_EMBEDDED_MTLS_KEYSTORE.withRuntimeSpecificDefault(getDefaultKeystorePathValue()))
                    .paramLabel("file")
                    .build(),
              fromOption(CachingOptions.CACHE_EMBEDDED_MTLS_KEYSTORE_PASSWORD)
                    .paramLabel("password")
                    .isMasked(true)
                    .build(),
              fromOption(CachingOptions.CACHE_EMBEDDED_MTLS_TRUSTSTORE.withRuntimeSpecificDefault(getDefaultTruststorePathValue()))
                    .paramLabel("file")
                    .build(),
              fromOption(CachingOptions.CACHE_EMBEDDED_MTLS_TRUSTSTORE_PASSWORD)
                    .paramLabel("password")
                    .isMasked(true)
                    .build(),
              fromOption(CachingOptions.CACHE_REMOTE_HOST)
                    .paramLabel("hostname")
                    .build(),
              fromOption(CachingOptions.CACHE_REMOTE_PORT)
                    .isEnabled(CachingPropertyMappers::remoteHostSet, CachingPropertyMappers.REMOTE_HOST_SET)
                    .paramLabel("port")
                    .build(),
              fromOption(CachingOptions.CACHE_REMOTE_TLS_ENABLED)
                    .isEnabled(CachingPropertyMappers::remoteHostSet, CachingPropertyMappers.REMOTE_HOST_SET)
                    .build(),
              fromOption(CachingOptions.CACHE_REMOTE_USERNAME)
                    .isEnabled(CachingPropertyMappers::remoteHostSet, CachingPropertyMappers.REMOTE_HOST_SET)
                    .paramLabel("username")
                    .build(),
              fromOption(CachingOptions.CACHE_REMOTE_PASSWORD)
                    .isEnabled(CachingPropertyMappers::remoteHostSet, CachingPropertyMappers.REMOTE_HOST_SET)
                    .paramLabel("password")
                    .isMasked(true)
                    .build(),
              fromOption(CachingOptions.CACHE_METRICS_HISTOGRAMS_ENABLED)
                    .isEnabled(MetricsPropertyMappers::metricsEnabled, MetricsPropertyMappers.METRICS_ENABLED_MSG)
                    .build()
              );

        int numMappers = staticMappers.size() + CachingOptions.LOCAL_MAX_COUNT_CACHES.length + CachingOptions.CLUSTERED_MAX_COUNT_CACHES.length;
        List<PropertyMapper<?>> mappers = new ArrayList<>(numMappers);
        mappers.addAll(staticMappers);

        for (String cache : CachingOptions.LOCAL_MAX_COUNT_CACHES)
            mappers.add(maxCountOpt(cache, () -> true, ""));

        for (String cache : CachingOptions.CLUSTERED_MAX_COUNT_CACHES)
            mappers.add(maxCountOpt(cache, InfinispanUtils::isEmbeddedInfinispan, "embedded Infinispan clusters configured"));

        return mappers.toArray(new PropertyMapper[0]);
    }

    private static boolean remoteHostSet() {
        return getOptionalKcValue(CachingOptions.CACHE_REMOTE_HOST_PROPERTY).isPresent();
    }

    private static String resolveConfigFile(String value, ConfigSourceInterceptorContext context) {
        String pathPrefix;
        String homeDir = Environment.getHomeDir();

        if (homeDir == null) {
            pathPrefix = "";
        } else {
            pathPrefix = homeDir + File.separator + "conf" + File.separator;
        }

        return pathPrefix + value;
    }

    private static String getDefaultKeystorePathValue() {
        String homeDir = Environment.getHomeDir();

        if (homeDir != null) {
            File file = Paths.get(homeDir, "conf", "cache-mtls-keystore.p12").toFile();

            if (file.exists()) {
                return file.getAbsolutePath();
            }
        }

        return null;
    }

    private static String getDefaultTruststorePathValue() {
        String homeDir = Environment.getHomeDir();

        if (homeDir != null) {
            File file = Paths.get(homeDir, "conf", "cache-mtls-truststore.p12").toFile();

            if (file.exists()) {
                return file.getAbsolutePath();
            }
        }

        return null;
    }

    private static PropertyMapper<?> maxCountOpt(String cacheName, BooleanSupplier isEnabled, String enabledWhen) {
        return fromOption(CachingOptions.maxCountOption(cacheName))
              .isEnabled(isEnabled, enabledWhen)
              .paramLabel("max-count")
              .build();
    }
}
