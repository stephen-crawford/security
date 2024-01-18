/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.configuration;

import java.awt.geom.IllegalPathStateException;
import java.io.IOException;
import java.nio.file.Path;

import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Captor;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.transport.SecurityInterceptorTests;
import org.opensearch.threadpool.ThreadPool;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ConfigurationRepositoryTest {

    @Mock
    private Client localClient;
    @Mock
    private AuditLog auditLog;
    @Mock
    private Path path;
    @Mock
    private ClusterService clusterService;

    // This initializes all the above mocks
    @Rule
    public MockitoRule rule = MockitoJUnit.rule();

    private ThreadPool threadPool;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);

        Settings settings = Settings.builder()
            .put("node.name", SecurityInterceptorTests.class.getSimpleName())
            .put("request.headers.default", "1")
            .build();

        threadPool = new ThreadPool(settings);
    }

    private ConfigurationRepository createConfigurationRepository(Settings settings) {

        return ConfigurationRepository.create(settings, path, threadPool, localClient, clusterService, auditLog);
    }

    /**
     * A helper method for tests which require applying nested mocks to a spy'd version of the configuration repository. This is exhaustive so best to reuse
     * @param settings The settings to apply to the spy'd configuration reposiroty
     * @return A spy'd version of the configuration repository
     */
    private ConfigurationRepository createSpyConfigurationRepositoryWithMockedComponents(Settings settings) {

        // Mock the cluster service so that the config repository thinks the cluster is blocked
        ConfigurationRepository configRepository = spy(createConfigurationRepository(settings));
        when(clusterService.state()).thenReturn(mock(org.opensearch.cluster.ClusterState.class));
        when(clusterService.state().blocks()).thenReturn(mock(org.opensearch.cluster.block.ClusterBlocks.class));
        return configRepository;
    }

    @Test
    public void create_shouldReturnConfigurationRepository() {
        ConfigurationRepository configRepository = createConfigurationRepository(Settings.EMPTY);

        assertThat(configRepository, is(notNullValue()));
        assertThat(configRepository, instanceOf(ConfigurationRepository.class));
    }

    @Test
    public void initOnNodeStart_withSecurityIndexCreationEnabledShouldSetInstallDefaultConfigTrue() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true).build();

        ConfigurationRepository configRepository = createConfigurationRepository(settings);

        final var result = configRepository.initOnNodeStart();

        assertThat(result.join(), is(true));
    }

    @Test
    public void initOnNodeStart_withSecurityIndexNotCreatedShouldNotSetInstallDefaultConfig() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, false).build();

        ConfigurationRepository configRepository = createConfigurationRepository(settings);

        final var result = configRepository.initOnNodeStart();

        assertThat(result.join(), is(false));
    }

    @Test
    public void getConfiguration_withInvalidConfigurationShouldReturnNewEmptyConfigurationObject() throws IOException {
        ConfigurationRepository configRepository = createConfigurationRepository(Settings.EMPTY);

        SecurityDynamicConfiguration<?> config = configRepository.getConfiguration(CType.CONFIG);
        SecurityDynamicConfiguration<?> emptyConfig = SecurityDynamicConfiguration.empty();

        assertThat(config, is(instanceOf(SecurityDynamicConfiguration.class)));
        assertThat(config.getCEntries().size(), is(equalTo(0)));
        assertThat(config.getVersion(), is(equalTo(emptyConfig.getVersion())));
        assertThat(config.getCType(), is(equalTo(emptyConfig.getCType())));
        assertThat(config.getSeqNo(), is(equalTo(emptyConfig.getSeqNo())));
        assertThat(config, is(not(equalTo(emptyConfig))));
    }

    @Test
    public void initClusterConfiguration_withBlockedClusterShouldWait() {
        // Initialize security index if it is missing
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, true).build();

        ConfigurationRepository configurationRepository = createSpyConfigurationRepositoryWithMockedComponents(settings);
        when(clusterService.state().blocks().hasGlobalBlockWithStatus(RestStatus.SERVICE_UNAVAILABLE)).thenReturn(true);
        // Should wait for cluster to become available (blocked cluster)
        configurationRepository.initOnNodeStart();
        verify(configurationRepository, times(1)).initializeClusterConfiguration(true);
    }

    @Test
    public void initClusterConfiguration_withoutSecIndexShouldNotAttemptIndexCreation() {
        // Do not initialize security index if it is missing
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, false).build();

        ConfigurationRepository configurationRepository = createSpyConfigurationRepositoryWithMockedComponents(settings);

        // Should wait for cluster to become available (blocked cluster)
        configurationRepository.initOnNodeStart();
        verify(mockLogger, times(1)).info(
                "Will not attempt to create index {} and default configs if they are absent. Will not perform background initialization",
                ".opendistro_security"
        );
    }

    @Test
    public void initClusterConfiguration_withInstallDefaultShouldTryToLoadDefaults() {
        // Initialize security index if it is missing and allow default
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, true).put(ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true).build();

        ConfigurationRepository configurationRepository = createSpyConfigurationRepositoryWithMockedComponents(settings);
        when(clusterService.state().blocks().hasGlobalBlockWithStatus(RestStatus.SERVICE_UNAVAILABLE)).thenReturn(false);

        // Should wait for cluster to become available (blocked cluster)
        configurationRepository.initOnNodeStart();

        verify(mockLogger, times(1)).info("Background init thread started. Install default config?: true");
        verify(mockLogger, times(2)).error(stringCaptor.capture(), exceptionCaptor.capture());
        assertTrue(stringCaptor.getAllValues().get(0).contains("Cannot apply default config (this is maybe not an error!)"));
        Mockito.reset();
    }

    @Test
    public void initClusterConfiguration_shouldWaitForYellowSecurityIndex() {

        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, true).put(ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true).build();
        ConfigurationRepository configurationRepository = createSpyConfigurationRepositoryWithMockedComponents(settings);
        when(configurationRepository.securityConfigExists()).thenReturn(true);
        doReturn("").when(configurationRepository).getConfigurationDirectory();
        doReturn(false).when(configurationRepository).createSecurityIndexIfAbsent();

        configurationRepository.initOnNodeStart();

        verify(mockLogger, times(1)).info("Populating the threadcontext from the security configuration.");
        verify(mockLogger, times(1)).info("Node started, try to initialize it. Wait for at least yellow cluster state....");
        verify(mockLogger, times(1)).debug(
                "index '{}' not healthy yet, we try again ... (Reason: {})",
                ".opendistro_security",
                "no response"
        );
        Mockito.reset();
    }
}
