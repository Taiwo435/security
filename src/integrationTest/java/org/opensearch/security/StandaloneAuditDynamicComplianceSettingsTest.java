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
 * Integration tests verifying that dynamic compliance settings can be
 * changed at runtime via PUT _cluster/settings without a node restart.
 * Tests compliance.enabled and write_watched_indices dynamic toggling.
 */
public class StandaloneAuditDynamicComplianceSettingsTest {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_SSL_ONLY, true,
                "plugins.security.audit.type", TestRuleAuditLogSink.class.getName(),
                // Start with compliance enabled and watching "compliance-*" indices
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES,
                "compliance-*"
            )
        )
        .sslOnly(true)
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    // =====================================================================
    // compliance.enabled — toggle at runtime
    // =====================================================================

    @Test
    public void shouldProduceComplianceWriteEventsWhenEnabled() {
        try (TestRestClient client = cluster.getRestClient()) {
            // Ensure compliance is enabled
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.enabled\": true}}");

            // Write to a watched index
            client.putJson("compliance-test/_doc/1?refresh=true", "{\"name\": \"sensitive-data\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE
        );
    }

    @Test
    public void shouldStopComplianceWriteEventsWhenDisabledAtRuntime() {
        try (TestRestClient client = cluster.getRestClient()) {
            // Disable compliance at runtime
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.enabled\": false}}");

            // Write to watched index — should NOT produce compliance event
            client.putJson("compliance-test/_doc/2?refresh=true", "{\"name\": \"should-not-track\"}");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE
        );

        // Reset
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.enabled\": true}}");
        }
    }

    @Test
    public void shouldResumeComplianceWriteEventsWhenReenabled() {
        try (TestRestClient client = cluster.getRestClient()) {
            // Disable then re-enable
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.enabled\": false}}");
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.enabled\": true}}");

            // Write should be tracked again
            client.putJson("compliance-test/_doc/3?refresh=true", "{\"name\": \"tracked-again\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE
        );
    }

    // =====================================================================
    // write_watched_indices — change at runtime
    // =====================================================================

    @Test
    public void shouldTrackNewWatchedIndexAddedAtRuntime() {
        try (TestRestClient client = cluster.getRestClient()) {
            // Change watched indices to a new pattern at runtime
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.write_watched_indices\": [\"dynamic-watch-*\"]}}");

            // Write to the new watched pattern
            client.putJson("dynamic-watch-test/_doc/1?refresh=true", "{\"secret\": \"new-pattern\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE
        );

        // Reset
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.write_watched_indices\": [\"compliance-*\"]}}");
        }
    }

    @Test
    public void shouldStopTrackingOldPatternWhenWatchedIndicesChanged() {
        try (TestRestClient client = cluster.getRestClient()) {
            // Change watched indices to something else
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.write_watched_indices\": [\"only-this-*\"]}}");

            // Write to the OLD pattern — should NOT produce compliance event
            client.putJson("compliance-test/_doc/4?refresh=true", "{\"name\": \"old-pattern\"}");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE
        );

        // Reset
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.write_watched_indices\": [\"compliance-*\"]}}");
        }
    }
}
