/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.transport;

// CS-SUPPRESS-SINGLE: RegexpSingleline Extensions manager used for creating a mock
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.Version;
import org.opensearch.action.search.PitService;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.core.transport.TransportResponse;
import org.opensearch.extensions.ExtensionsManager;
import org.opensearch.indices.IndicesService;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.ssl.SslExceptionHandler;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.transport.SSLConfig;
import org.opensearch.security.support.Base64Helper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.telemetry.tracing.noop.NoopTracer;
import org.opensearch.test.transport.MockTransport;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.Transport.Connection;
import org.opensearch.transport.TransportInterceptor.AsyncSender;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportRequestOptions;
import org.opensearch.transport.TransportResponseHandler;
import org.opensearch.transport.TransportService;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static java.util.Collections.emptySet;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SecurityInterceptorTests {

    private SecurityInterceptor securityInterceptor;

    @Mock
    private BackendRegistry backendRegistry;

    @Mock
    private AuditLog auditLog;

    @Mock
    private PrincipalExtractor principalExtractor;

    @Mock
    private InterClusterRequestEvaluator requestEvalProvider;

    @Mock
    private ClusterService clusterService;

    @Mock
    private SslExceptionHandler sslExceptionHandler;

    @Mock
    private ClusterInfoHolder clusterInfoHolder;

    @Mock
    private SSLConfig sslConfig;

    private Settings settings;

    private ThreadPool threadPool;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        settings = Settings.builder()
            .put("node.name", SecurityInterceptorTests.class.getSimpleName())
            .put("request.headers.default", "1")
            .build();
        threadPool = new ThreadPool(settings);
        securityInterceptor = new SecurityInterceptor(
            settings,
            threadPool,
            backendRegistry,
            auditLog,
            principalExtractor,
            requestEvalProvider,
            clusterService,
            sslExceptionHandler,
            clusterInfoHolder,
            sslConfig
        );
    }

    private void testSendRequestDecorate(Version remoteNodeVersion) {
        boolean useJDKSerialization = remoteNodeVersion.before(ConfigConstants.FIRST_CUSTOM_SERIALIZATION_SUPPORTED_OS_VERSION);
        ClusterName clusterName = ClusterName.DEFAULT;
        when(clusterService.getClusterName()).thenReturn(clusterName);

        MockTransport transport = new MockTransport();
        TransportService transportService = transport.createTransportService(
            Settings.EMPTY,
            threadPool,
            TransportService.NOOP_TRANSPORT_INTERCEPTOR,
            boundTransportAddress -> clusterService.state().nodes().get(SecurityInterceptor.class.getSimpleName()),
            null,
            emptySet(),
            NoopTracer.INSTANCE
        );

        // CS-SUPPRESS-SINGLE: RegexpSingleline Extensions manager used for creating a mock
        OpenSearchSecurityPlugin.GuiceHolder guiceHolder = new OpenSearchSecurityPlugin.GuiceHolder(
            mock(RepositoriesService.class),
            transportService,
            mock(IndicesService.class),
            mock(PitService.class),
            mock(ExtensionsManager.class)
        );
        // CS-ENFORCE-SINGLE

        User user = new User("John Doe");
        threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);

        String action = "testAction";
        TransportRequest request = mock(TransportRequest.class);
        TransportRequestOptions options = mock(TransportRequestOptions.class);
        @SuppressWarnings("unchecked")
        TransportResponseHandler<TransportResponse> handler = mock(TransportResponseHandler.class);

        InetAddress localAddress = null;
        InetAddress remoteAddress = null;
        try {
            localAddress = InetAddress.getByName("0.0.0.0");
            remoteAddress = InetAddress.getByName("1.1.1.1");
        } catch (final UnknownHostException uhe) {
            throw new RuntimeException(uhe);
        }

        DiscoveryNode localNode = new DiscoveryNode("local-node1", new TransportAddress(localAddress, 1234), Version.CURRENT);
        Connection connection1 = transportService.getConnection(localNode);

        DiscoveryNode otherNode = new DiscoveryNode("local-node2", new TransportAddress(localAddress, 4321), Version.CURRENT);
        Connection connection2 = transportService.getConnection(otherNode);

        DiscoveryNode remoteNode = new DiscoveryNode("remote-node", new TransportAddress(localAddress, 6789), remoteNodeVersion);
        Connection connection3 = transportService.getConnection(remoteNode);

        DiscoveryNode otherRemoteNode = new DiscoveryNode("remote-node2", new TransportAddress(remoteAddress, 9876), remoteNodeVersion);
        Connection connection4 = transportService.getConnection(otherRemoteNode);

        // from thread context inside sendRequestDecorate for local-node1 connection1
        AsyncSender sender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                User transientUser = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                assertEquals(transientUser, user);
            }
        };

        // local node request
        securityInterceptor.sendRequestDecorate(sender, connection1, action, request, options, handler, localNode);

        // from original context
        User transientUser = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertEquals(transientUser, user);
        assertEquals(threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER), null);

        // checking thread context inside sendRequestDecorate for local-node2 connection2
        sender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                User transientUser = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                assertEquals(transientUser, user);
            }
        };

        // this is also a local request
        securityInterceptor.sendRequestDecorate(sender, connection2, action, request, options, handler, otherNode);

        // from original context
        User transientUser2 = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertEquals(transientUser2, user);
        assertEquals(threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER), null);

        // checking thread context inside sendRequestDecorate for remote-node connection3
        sender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                String serializedUserHeader = threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER);
                assertEquals(serializedUserHeader, Base64Helper.serializeObject(user, useJDKSerialization));
            }
        };

        // this is a remote request
        securityInterceptor.sendRequestDecorate(sender, connection3, action, request, options, handler, localNode);

        // from original context
        User transientUser3 = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertEquals(transientUser3, user);
        assertEquals(threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER), null);

        // checking thread context inside sendRequestDecorate for remote-node2 connection4
        sender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                String serializedUserHeader = threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER);
                assertEquals(serializedUserHeader, Base64Helper.serializeObject(user, useJDKSerialization));
            }
        };

        // this is a remote request where the transport address is different
        securityInterceptor.sendRequestDecorate(sender, connection4, action, request, options, handler, localNode);

        // from original context
        User transientUser4 = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertEquals(transientUser4, user);
        assertEquals(threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER), null);

        // checking thread context inside sendRequestDecorate for connection1 with null local node -- we should serialize this
        sender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                String serializedUserHeader = threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER);
                assertEquals(serializedUserHeader, Base64Helper.serializeObject(user, useJDKSerialization));
            }
        };

        // this is a request where the local node is null; have to use the remote connection since the serialization will fail
        securityInterceptor.sendRequestDecorate(sender, connection3, action, request, options, handler, null);

        // from original context
        User transientUser5 = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertEquals(transientUser5, user);
        assertEquals(threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER), null);

        // test sending various missing decorates with missing request info

        // checking thread context inside sendRequestDecorate
        sender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                User transientUser = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                assertEquals(transientUser, user);
            }
        };

        // Having null connection will cause useJDKSerialization to throw npe
        AsyncSender finalSender = sender; // Have to do this because of being a runnable
        assertThrows(
            java.lang.NullPointerException.class,
            () -> securityInterceptor.sendRequestDecorate(finalSender, null, action, request, options, handler, localNode)
        );

        // Make the origin null should cause the ensureCorrectHeaders method to populate with Origin.LOCAL.toString()
        threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, null);

        sender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                    Connection connection,
                    String action,
                    TransportRequest request,
                    TransportRequestOptions options,
                    TransportResponseHandler<T> handler
            ) {
                User transientUser = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                assertEquals(transientUser, user);
            }
        };

        // This is a different way to get the same result which exercises the origin0 = null logic of ensureCorrectHeaders
        securityInterceptor.sendRequestDecorate(finalSender, connection1, action, request, options, handler, localNode);

        User transientUser7 = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertEquals(transientUser7, user);
        assertEquals(threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER), null);
    }

    private void testSendRequestDecorateWithEmptyUserHeader(Version remoteNodeVersion) {
        ClusterName clusterName = ClusterName.DEFAULT;
        when(clusterService.getClusterName()).thenReturn(clusterName);

        MockTransport transport = new MockTransport();
        TransportService transportService = transport.createTransportService(
            Settings.EMPTY,
            threadPool,
            TransportService.NOOP_TRANSPORT_INTERCEPTOR,
            boundTransportAddress -> clusterService.state().nodes().get(SecurityInterceptor.class.getSimpleName()),
            null,
            emptySet(),
            NoopTracer.INSTANCE
        );

        // Add a fake header to show it does not get misinterpreted
        threadPool.getThreadContext().putHeader("FAKE_HEADER", "fake_value");

        // Add a null header
        threadPool.getThreadContext().putHeader(null, null);
        threadPool.getThreadContext().putHeader(null, "null");

        // Add the other headers we check
        threadPool.getThreadContext()
            .putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "fake security config request header");
        threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER, "fake security origin header");
        threadPool.getThreadContext()
            .putHeader(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER, "fake security remote address header");
        threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER, "fake dls query header");
        threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER, "fake fls fields header");
        threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER, "fake masked field header");
        threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER, "fake doc allowlist header");
        threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE, "fake filter level dls header");
        threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_MODE_HEADER, "fake dls mode header");
        threadPool.getThreadContext()
            .putHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_FILTER_LEVEL_QUERY_HEADER, "fake dls filter header");
        threadPool.getThreadContext().putHeader("_opendistro_security_trace", "fake trace value");
        threadPool.getThreadContext()
            .putHeader(ConfigConstants.OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER, "fake initial action header");
        threadPool.getThreadContext().putHeader("_opendistro_security_source_field_context", "fake source field context value");
        threadPool.getThreadContext()
            .putHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION, "fake injected roles validation string");

        // CS-SUPPRESS-SINGLE: RegexpSingleline Extensions manager used for creating a mock
        OpenSearchSecurityPlugin.GuiceHolder guiceHolder = new OpenSearchSecurityPlugin.GuiceHolder(
            mock(RepositoriesService.class),
            transportService,
            mock(IndicesService.class),
            mock(PitService.class),
            mock(ExtensionsManager.class)
        );

        // CS-ENFORCE-SINGLE

        String action = "testAction";
        TransportRequest request = mock(TransportRequest.class);
        TransportRequestOptions options = mock(TransportRequestOptions.class);
        @SuppressWarnings("unchecked")
        TransportResponseHandler<TransportResponse> handler = mock(TransportResponseHandler.class);

        InetAddress localAddress = null;
        try {
            localAddress = InetAddress.getByName("0.0.0.0");
        } catch (final UnknownHostException uhe) {
            throw new RuntimeException(uhe);
        }

        DiscoveryNode localNode = new DiscoveryNode("local-node1", new TransportAddress(localAddress, 1234), Version.CURRENT);
        Connection connection1 = transportService.getConnection(localNode);

        DiscoveryNode remoteNode = new DiscoveryNode("remote-node", new TransportAddress(localAddress, 6789), remoteNodeVersion);
        Connection connection2 = transportService.getConnection(remoteNode);

        // from thread context should be null because there is no header
        AsyncSender sender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                User transientUser = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                assertEquals(transientUser, null);
            }
        };

        // local node request
        securityInterceptor.sendRequestDecorate(sender, connection1, action, request, options, handler, localNode);

        // from original context
        User transientUser = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertEquals(transientUser, null);
        assertEquals(threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER), null);

        // checking thread context for a remote context; does not matter should still be null
        sender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                User transientUser = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                assertEquals(transientUser, null);
            }
        };

        // this is also a local request
        securityInterceptor.sendRequestDecorate(sender, connection2, action, request, options, handler, remoteNode);

        // from original context
        User transientUser2 = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertEquals(transientUser2, null);
        assertEquals(threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER), null);

    }

    @Test
    public void testSendRequestDecorate() {
        testSendRequestDecorate(Version.CURRENT);
    }

    /**
     * Tests the scenario when remote node does not implement custom serialization protocol and uses JDK serialization
     */
    @Test
    public void testSendRequestDecorateWhenRemoteNodeUsesJDKSerde() {
        testSendRequestDecorate(Version.V_2_0_0);
    }

    @Test
    public void testSendRequestDecorateWithNullUser() {
        testSendRequestDecorateWithEmptyUserHeader(Version.CURRENT);
    }
}
