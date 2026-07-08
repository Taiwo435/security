/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.filter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportChannel;
import org.opensearch.transport.TransportInterceptor;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportRequestHandler;

/**
 * A transport-layer interceptor that logs audit events for inter-node
 * communication. Captures incoming transport requests on the receiving node.
 * Works in all security modes (FGAC, SSL-only, disabled).
 *
 * Only intercepts the handler side (incoming requests) to avoid double-logging
 * the same operation on both sender and receiver.
 */
public class AuditTransportInterceptor implements TransportInterceptor {

    private static final Logger log = LogManager.getLogger(AuditTransportInterceptor.class);

    private final AuditLog auditLog;
    private final ClusterService clusterService;
    private final ThreadPool threadPool;
    private final WildcardMatcher ignoreActionsMatcher;

    public AuditTransportInterceptor(AuditLog auditLog, ClusterService clusterService, ThreadPool threadPool, Settings settings) {
        this.auditLog = auditLog;
        this.clusterService = clusterService;
        this.threadPool = threadPool;

        // Skip internal cluster noise by default
        this.ignoreActionsMatcher = WildcardMatcher.from(
            "internal:*",
            "cluster:monitor/*",
            "indices:monitor/*"
        );
    }

    @Override
    public <T extends TransportRequest> TransportRequestHandler<T> interceptHandler(
        String action,
        String executor,
        boolean forceExecution,
        TransportRequestHandler<T> actualHandler
    ) {
        return new TransportRequestHandler<T>() {
            @Override
            public void messageReceived(T request, TransportChannel channel, Task task) throws Exception {
                // Skip noisy internal actions
                if (!ignoreActionsMatcher.test(action)) {
                    logTransportEvent(action, request, task);
                }
                // Always proceed — audit is non-blocking
                actualHandler.messageReceived(request, channel, task);
            }
        };
    }

    private <T extends TransportRequest> void logTransportEvent(String action, T request, Task task) {
        try {
            AuditMessage msg = new AuditMessage(AuditCategory.REQUEST_AUDIT, clusterService, Origin.TRANSPORT, Origin.TRANSPORT);

            // Action name
            msg.addPrivilege(action);

            // Request type
            msg.addRequestType(request.getClass().getSimpleName());

            // Source IP
            TransportAddress remoteAddress = request.remoteAddress();
            if (remoteAddress == null) {
                remoteAddress = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
            }
            msg.addRemoteAddress(remoteAddress);

            // Task ID
            if (task != null) {
                msg.addTaskId(task.getId());
                if (task.getParentTaskId() != null && task.getParentTaskId().isSet()) {
                    msg.addTaskParentId(task.getParentTaskId().toString());
                }
            }

            // User identity (from ThreadContext — available in FGAC, cert principal in SSL-only)
            String principal = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_PRINCIPAL);
            User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            if (user != null) {
                msg.addEffectiveUser(user.getName());
            } else if (principal != null) {
                msg.addEffectiveUser(principal);
            }

            auditLog.logRequestAudit(msg);
        } catch (Exception e) {
            log.debug("Failed to log transport audit event for action {}: {}", action, e.getMessage());
        }
    }
}
