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

import org.awaitility.Awaitility;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.Matchers.containsString;

/**
 * Integration tests verifying that real audit sinks work end-to-end
 * in SSL-only standalone mode (not using the test sink).
 */
public class StandaloneAuditSinksTest {

    /**
     * Cluster using internal_opensearch sink — writes audit events to an index
     * on the same cluster.
     */
    @ClassRule
    public static LocalCluster internalSinkCluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_SSL_ONLY, true,
                "plugins.security.audit.type", "internal_opensearch"
            )
        )
        .sslOnly(true)
        .build();

    @Test
    public void internalOpenSearchSinkShouldCreateAuditIndex() {
        // Send a request to trigger an audit event
        try (TestRestClient client = internalSinkCluster.getRestClient()) {
            client.get("_cluster/health");
        }

        // Verify the audit index was created and contains data
        try (TestRestClient client = internalSinkCluster.getRestClient()) {
            Awaitility.await()
                .alias("Audit index created with events")
                .atMost(10, java.util.concurrent.TimeUnit.SECONDS)
                .pollInterval(1, java.util.concurrent.TimeUnit.SECONDS)
                .until(() -> client.get("security-auditlog-*/_search").getBody(), containsString("REQUEST_AUDIT"));
        }
    }

    @Test
    public void internalOpenSearchSinkShouldCaptureCorrectFields() {
        try (TestRestClient client = internalSinkCluster.getRestClient()) {
            client.get("test-index/_search");
        }

        try (TestRestClient client = internalSinkCluster.getRestClient()) {
            Awaitility.await()
                .alias("Audit event has expected fields")
                .atMost(10, java.util.concurrent.TimeUnit.SECONDS)
                .pollInterval(1, java.util.concurrent.TimeUnit.SECONDS)
                .until(
                    () -> client.get("security-auditlog-*/_search?q=audit_transport_request_type:SearchRequest").getBody(),
                    containsString("audit_request_privilege")
                );
        }
    }
}
