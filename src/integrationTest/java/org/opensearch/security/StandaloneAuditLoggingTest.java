/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*/
package org.opensearch.security;

import java.util.Map;

import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.audit.TestRuleAuditLogSink;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

/**
 * Integration tests for standalone audit logging in SSL-only mode.
 * Verifies that REQUEST_AUDIT events are produced with correct fields
 * when no authentication/authorization layer is active.
 */
public class StandaloneAuditLoggingTest {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_SSL_ONLY, true,
                "plugins.security.audit.type", TestRuleAuditLogSink.class.getName()
            )
        )
        .sslOnly(true)
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @Test
    public void shouldCaptureAllFieldsForSearchRequest() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.get("test-index/_search");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (!"SearchRequest".equals(msg.getRequestType())) return false;

            Map<String, Object> fields = msg.getAsMap();

            // Indices
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;

            // Node/cluster info (populated by AuditMessage constructor from ClusterService)
            if (fields.get(AuditMessage.NODE_NAME) == null) return false;
            if (fields.get(AuditMessage.NODE_ID) == null) return false;
            if (fields.get(AuditMessage.CLUSTER_NAME) == null) return false;
            if (fields.get(AuditMessage.NODE_HOST_ADDRESS) == null) return false;

            // Task ID
            if (fields.get(AuditMessage.TASK_ID) == null) return false;

            // Timestamp
            if (fields.get(AuditMessage.UTC_TIMESTAMP) == null) return false;

            // Action/privilege
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/read/search")) return false;

            return true;
        });
    }

    @Test
    public void shouldProduceRequestAuditEventForIndexOperation() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("test-index/_doc/1", "{\"field\": \"value\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:data/write")
        );
    }

    @Test
    public void shouldCaptureClusterHealthWithNoIndices() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.get("_cluster/health");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("cluster:monitor/health")) return false;

            Map<String, Object> fields = msg.getAsMap();
            // No indices for cluster-level request
            if (fields.get(AuditMessage.INDICES) != null) return false;

            // But node info and timestamp should still be present
            if (fields.get(AuditMessage.NODE_NAME) == null) return false;
            if (fields.get(AuditMessage.UTC_TIMESTAMP) == null) return false;
            if (fields.get(AuditMessage.TASK_ID) == null) return false;

            return true;
        });
    }

    @Test
    public void shouldNotProduceAuthRelatedEvents() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.get("_cat/indices");
        }

        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.AUTHENTICATED
                || msg.getCategory() == AuditCategory.GRANTED_PRIVILEGES
                || msg.getCategory() == AuditCategory.FAILED_LOGIN
        );
    }

    @Test
    public void shouldCaptureMultipleIndicesFromBulkRequest() {
        try (TestRestClient client = cluster.getRestClient()) {
            String bulkBody = "{ \"index\": { \"_index\": \"bulk-index-a\", \"_id\": \"1\" } }\n"
                + "{ \"field\": \"value1\" }\n"
                + "{ \"index\": { \"_index\": \"bulk-index-b\", \"_id\": \"2\" } }\n"
                + "{ \"field\": \"value2\" }\n";
            client.postJson("_bulk", bulkBody);
        }

        // BulkRequest implements CompositeIndicesRequest — its indices() returns
        // the union of all sub-request indices
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/write/bulk")) return false;
            return true;
        });
    }

    @Test
    public void shouldLogWildcardIndexAsRawString() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.get("logs-2026.*/_search");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (!"SearchRequest".equals(msg.getRequestType())) return false;

            Map<String, Object> fields = msg.getAsMap();
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;
            String[] indexArr = (String[]) indices;
            for (String idx : indexArr) {
                if ("logs-2026.*".equals(idx)) return true;
            }
            return false;
        });
    }

}
