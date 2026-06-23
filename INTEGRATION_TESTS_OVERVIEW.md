# Integration Tests Overview — Standalone Audit Logging

## Test Files (5 files, 28 tests total)

All located in: `src/integrationTest/java/org/opensearch/security/`

---

## 1. StandaloneAuditLoggingTest.java (23 tests)

**Cluster config:** SSL-only mode, TestRuleAuditLogSink (captures events in memory)

**Purpose:** Verify AuditActionFilter produces REQUEST_AUDIT events with correct fields for every type of request.

| Test | Request | Assertion |
|------|---------|-----------|
| shouldCaptureAllFieldsForSearchRequest | GET test-index/_search | category, requestType, indices, node info, task ID, timestamp, privilege all present |
| shouldProduceRequestAuditEventForIndexOperation | PUT test-index/_doc/1 | privilege contains indices:data/write |
| shouldCaptureClusterHealthWithNoIndices | GET _cluster/health | privilege=cluster:monitor/health, indices=null, node info present |
| shouldNotProduceAuthRelatedEvents | GET _cat/indices | 0 events with AUTHENTICATED/GRANTED_PRIVILEGES/FAILED_LOGIN |
| shouldCaptureMultipleIndicesFromBulkRequest | POST _bulk (2 indices) | privilege contains indices:data/write/bulk |
| shouldLogWildcardIndexAsRawString | GET logs-2026.*/_search | indices array contains literal "logs-2026.*" |
| shouldCaptureDeleteDocumentRequest | DELETE del-test/_doc/1 | privilege contains indices:data/write/delete |
| shouldCaptureDeleteIndexRequest | DELETE to-delete | privilege contains indices:admin/delete |
| shouldCaptureMgetRequest | POST _mget | privilege contains indices:data/read/mget |
| shouldCaptureMultiSearchRequest | POST _msearch | privilege contains indices:data/read/msearch |
| shouldCaptureUpdateDocumentRequest | POST update-test/_update/1 | privilege contains indices:data/write/update |
| shouldCaptureCreateIndexRequest | PUT new-index-test | privilege contains indices:admin/create |
| shouldCaptureClusterSettingsRequest | GET _cluster/settings | requestType=ClusterStateRequest |
| shouldCaptureNodesInfoRequest | GET _nodes | privilege contains cluster:monitor/nodes/info |
| shouldCaptureGetDocumentRequest | GET get-test/_doc/1 | privilege contains indices:data/read/get |
| shouldCaptureHeadRequest | HEAD test-head-index | privilege contains indices:admin |
| shouldCaptureRequestToNonExistentIndex | GET does-not-exist/_doc/999 | privilege contains indices:data/read/get (event even for 404) |
| shouldCaptureMultipleRapidRequests | 20x GET _cluster/health | At least 20 events (no drops under load) |
| shouldCaptureAliasOperation | POST _aliases | privilege contains indices:admin/aliases |
| shouldCaptureCountRequest | GET test-index/_count | privilege contains indices:data/read/search |
| shouldCapturePatchRequest | PATCH patch-test/_doc/1 | privilege contains indices:data/write |

---

## 2. StandaloneAuditDisabledCategoryTest.java (1 test)

**Cluster config:** SSL-only, TestRuleAuditLogSink, disabled_categories: [REQUEST_AUDIT]

| Test | Request | Assertion |
|------|---------|-----------|
| shouldSuppressEventsWhenRequestAuditIsDisabled | health + search | Exactly 0 REQUEST_AUDIT events |

---

## 3. StandaloneAuditMtlsTest.java (1 test)

**Cluster config:** SSL-only, TestRuleAuditLogSink, clientauth_mode: OPTIONAL

| Test | Request | Assertion |
|------|---------|-----------|
| shouldCaptureClientCertPrincipalAsEffectiveUser | GET _cluster/health with admin cert | effective_user contains "CN=kirk" |

---

## 4. StandaloneAuditSinksTest.java (3 tests)

**Cluster configs:** Two clusters — internal_opensearch sink + log4j sink

| Test | Sink | Assertion |
|------|------|-----------|
| internalOpenSearchSinkShouldCreateAuditIndex | internal_opensearch | Query security-auditlog-* returns REQUEST_AUDIT |
| internalOpenSearchSinkShouldCaptureCorrectFields | internal_opensearch | SearchRequest event has audit_request_privilege |
| log4jSinkShouldNotCrashAndProcessRequests | log4j | 10+ requests succeed with status 200 |

---

## 5. StandaloneAuditWebhookSinkTest.java (1 test)

**Cluster config:** SSL-only, TestRuleAuditLogSink with webhook URL configured

| Test | Assertion |
|------|-----------|
| shouldProduceAuditEventsWithWebhookConfigured | At least 1 REQUEST_AUDIT event with cluster:monitor/health |

---

## What Are We Testing?

1. **Logs are produced in SSL-only mode** — the full pipeline works (REST wrapper → ThreadContext → AuditActionFilter → AuditLogImpl → router → sink)
2. **REQUEST_AUDIT category has correct fields** — not just existence, but content (indices, action, node info, timestamps, task IDs)
3. **Category suppression works** — disabled_categories honored
4. **Identity enrichment works** — mTLS cert DN in effective_user
5. **Real sinks work** — internal_opensearch indexes, log4j doesn't crash
6. **No auth events leak** — FGAC categories suppressed

---

## Edge Cases Covered

| Edge case | Test |
|-----------|------|
| Wildcard index (raw, not resolved) | shouldLogWildcardIndexAsRawString |
| Non-existent index (404 still logged) | shouldCaptureRequestToNonExistentIndex |
| Cluster-level request (no indices) | shouldCaptureClusterHealthWithNoIndices |
| Rapid sequential requests (no drops) | shouldCaptureMultipleRapidRequests |
| Bulk with multiple indices | shouldCaptureMultipleIndicesFromBulkRequest |
| Disabled categories suppresses events | shouldSuppressEventsWhenRequestAuditIsDisabled |
| Auth categories never fire | shouldNotProduceAuthRelatedEvents |
| mTLS cert principal captured | shouldCaptureClientCertPrincipalAsEffectiveUser |
| Internal sink creates real index | internalOpenSearchSinkShouldCreateAuditIndex |

---

## Edge Cases NOT Yet Covered

| Edge case | Why | Risk |
|-----------|-----|------|
| Disabled mode (not SSL-only) | No integration test yet — code exists but untested | Medium |
| Multi-node cluster | All tests use SINGLENODE | Low |
| Concurrent requests from multiple clients | Only sequential single client | Medium |
| Self-referential audit (audit write triggers audit) | Not tested with internal_opensearch | Low |
| Invalid/malformed request | Not tested | Unknown |
| External_opensearch sink | Needs 2nd cluster | Low |
| Kafka sink | Needs Kafka broker | Low |
| Node restart/recovery | Not tested | Low |
