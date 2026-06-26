/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.filter;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.IndicesRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.action.support.ActionFilterChain;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.core.xcontent.MediaType;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;

/**
 * A lightweight action filter that logs audit events without performing
 * authentication or authorization. Used in SSL-only and disabled modes
 * where the full SecurityFilter is not registered.
 *
 * Produces a single REQUEST_AUDIT event per request with:
 * source IP, action name, target indices, request type, node info,
 * task ID, client cert identity, request body, and filtered headers.
 */
public class AuditActionFilter implements ActionFilter {

    private static final WildcardMatcher AUTHORIZATION_HEADER = WildcardMatcher.from("Authorization").ignoreCase();

    private final AuditLog auditLog;
    private final ClusterService clusterService;
    private final ThreadPool threadPool;
    private final boolean logRequestBody;
    private final boolean excludeSensitiveHeaders;
    private final WildcardMatcher ignoreUsersMatcher;
    private final WildcardMatcher ignoreRequestsMatcher;

    public AuditActionFilter(AuditLog auditLog, ClusterService clusterService, ThreadPool threadPool, Settings settings) {
        this.auditLog = auditLog;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.logRequestBody = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, true);
        this.excludeSensitiveHeaders = settings.getAsBoolean(
            ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS,
            true
        );
        List<String> ignoreUsers = settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, Collections.singletonList("kibanaserver"));
        this.ignoreUsersMatcher = WildcardMatcher.from(ignoreUsers);
        List<String> ignoreRequests = settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS, Collections.emptyList());
        this.ignoreRequestsMatcher = WildcardMatcher.from(ignoreRequests);
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE;
    }

    @Override
    public <Request extends ActionRequest, Response extends ActionResponse> void apply(
        Task task,
        String action,
        Request request,
        ActionRequestMetadata<Request, Response> actionRequestMetadata,
        ActionListener<Response> listener,
        ActionFilterChain<Request, Response> chain
    ) {
        // Skip internal actions
        if (action != null && action.startsWith("internal:")) {
            chain.proceed(task, action, request, listener);
            return;
        }

        // Skip ignored users
        String principal = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_PRINCIPAL);
        User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        String effectiveUser = user != null ? user.getName() : principal;
        if (effectiveUser != null && ignoreUsersMatcher.test(effectiveUser)) {
            chain.proceed(task, action, request, listener);
            return;
        }

        // Skip ignored requests (matches action name or request class name)
        if (ignoreRequestsMatcher.test(action) || ignoreRequestsMatcher.test(request.getClass().getSimpleName())) {
            chain.proceed(task, action, request, listener);
            return;
        }

        AuditMessage msg = new AuditMessage(AuditCategory.REQUEST_AUDIT, clusterService, Origin.REST, Origin.TRANSPORT);

        // Source IP
        TransportAddress remoteAddress = request.remoteAddress();
        if (remoteAddress == null) {
            remoteAddress = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
        }
        msg.addRemoteAddress(remoteAddress);

        // Action name
        msg.addPrivilege(action);

        // Request type
        msg.addRequestType(request.getClass().getSimpleName());

        // Target indices
        if (request instanceof IndicesRequest) {
            msg.addIndices(((IndicesRequest) request).indices());
        }

        // Task ID
        if (task != null) {
            msg.addTaskId(task.getId());
            if (task.getParentTaskId() != null && task.getParentTaskId().isSet()) {
                msg.addTaskParentId(task.getParentTaskId().toString());
            }
        }

        // Client cert identity
        if (principal != null) {
            msg.addEffectiveUser(principal);
        }

        // Authenticated user identity (when FGAC is active)
        if (user != null) {
            msg.addEffectiveUser(user.getName());
        }

        // REST headers (stashed by REST wrapper, filtered here)
        Map<String, List<String>> headers = threadPool.getThreadContext()
            .getTransient(ConfigConstants.SECURITY_AUDIT_REST_HEADERS);
        if (headers != null && !headers.isEmpty()) {
            Map<String, List<String>> filteredHeaders = new HashMap<>(headers);
            if (excludeSensitiveHeaders) {
                filteredHeaders.keySet().removeIf(AUTHORIZATION_HEADER);
            }
            msg.addRestHeaders(filteredHeaders, false, null);
        }

        // Request body (extracted from transport request object)
        if (logRequestBody) {
            addRequestBody(msg, request);
        }

        auditLog.logRequestAudit(msg);
        chain.proceed(task, action, request, listener);
    }

    private void addRequestBody(AuditMessage msg, ActionRequest request) {
        if (request instanceof SearchRequest) {
            SearchRequest sr = (SearchRequest) request;
            if (sr.source() != null) {
                msg.addMapToRequestBody(Utils.convertJsonToxToStructuredMap(sr.source()));
            }
        } else if (request instanceof IndexRequest) {
            IndexRequest ir = (IndexRequest) request;
            if (ir.source() != null) {
                msg.addTupleToRequestBody(new Tuple<MediaType, BytesReference>(ir.getContentType(), ir.source()));
            }
        } else if (request instanceof UpdateRequest) {
            UpdateRequest ur = (UpdateRequest) request;
            if (ur.doc() != null && ur.doc().source() != null) {
                msg.addTupleToRequestBody(new Tuple<MediaType, BytesReference>(ur.doc().getContentType(), ur.doc().source()));
            }
        }
    }
}
