# OpenSearch Audit Logging — User Perspective Research

## What It Currently Does (FGAC Mode)

- **Logs auth events**: AUTHENTICATED (success), FAILED_LOGIN, MISSING_PRIVILEGES, SSL_EXCEPTION, BAD_HEADERS
- **Compliance tracking**: Document-level read/write tracking with field-level granularity (which user read which fields of which doc)
- **Rich context captured**: IP address, username, action, indices, request body, HTTP headers, node info
- **Multiple sinks**: log4j (stdout/file), internal_opensearch (index on same cluster), external_opensearch (remote cluster), webhook (HTTP endpoint for SIEM)
- **Filtering**: ignore_users, ignore_requests, disabled_categories (REST and transport separately)
- **Dynamic config**: Can change audit settings at runtime via security REST API without restart
- **Index resolution**: Expands wildcards (`my-*` → `my-index`) in audit events

## What It Doesn't Do Well (User Pain Points)

### No correlation ID
A single user request (e.g., `POST /my-index/_search`) generates multiple audit events across layers:
1. `AUTHENTICATED` at REST layer (no task ID)
2. `GRANTED_PRIVILEGES` at TRANSPORT layer (has task ID but REST event doesn't reference it)
3. `COMPLIANCE_DOC_READ` (also no shared ID)

With thousands of events/second from multiple users, you **cannot group events back to the originating request**. There's no shared UUID (Universally Unique Identifier) tying them together.

### Event explosion
One `GET _cluster/health` → 2+ events. One search → 3 events. One bulk with 3 docs → 3 compliance write events + auth events. A `_cat/indices` call generates 4+ transport-layer events (ClusterState, IndicesStats, GetSettings, ClusterHealth). Users report INDEX_EVENT flooding at thousands/hour.

### REST/transport category split is confusing
Users had to independently configure `disabled_rest_categories` and `disabled_transport_categories`. The distinction (REST = HTTP layer, transport = internal action layer) is invisible to end users and caused silent misconfigurations ([Issue #3380](https://github.com/opensearch-project/security/issues/3380), [Issue #2673](https://github.com/opensearch-project/security/issues/2673)).

### Compliance read logging exposes sensitive data
`COMPLIANCE_DOC_READ` logs the **actual values** of watched fields: `"audit_request_body":"{\"secret\":\"hunter2\",\"email\":\"john@example.com\",\"ssn\":\"123-45-6789\"}"`. The audit log itself becomes a PII/secrets hotspot. Anyone with access to audit logs gets the sensitive data.

### Only works with FGAC enabled
Users running OpenSearch for log analytics, observability, or dev/test without full security have **zero audit trail**. Compliance frameworks (SOC2, HIPAA, PCI-DSS) require audit logs regardless of access control mode.

### Self-referential problem
When using `internal_opensearch` sink, writing an audit event to the audit index triggers more audit events (the write itself is auditable). Creates a recursion/noise loop users must work around with `ignore_requests` patterns.

### Unclear destructive action identification
Deleting an index fires `INDEX_EVENT` — the same category as creating an index. Without inspecting the `audit_request_privilege` field (`indices:admin/delete` vs `indices:admin/create`), you can't tell destructive from constructive operations at a glance.

### INDEX_EVENT is meaningless as a signal
`INDEX_EVENT` fires for `FlushRequest`, `ShardFlushRequest`, `CreateIndexRequest`, `DeleteIndexRequest` — basically anything that touches index metadata. A non-destructive `_flush` triggers the same category as deleting an index. Users who enable `INDEX_EVENT` expecting to catch dangerous operations get flooded with routine shard maintenance instead.

### Admin operations cascade into shard-level events
A simple `POST /my-index/_flush` generates 5 audit events: `AUTHENTICATED` + `GRANTED_PRIVILEGES` for FlushRequest + `INDEX_EVENT` for FlushRequest + `GRANTED_PRIVILEGES` for ShardFlushRequest + `INDEX_EVENT` for ShardFlushRequest. On a 10-shard index, one admin action could produce 20+ events.

### Internal system operations log with no user
Startup compliance config reads and internal cluster operations log with `user: NONE`. If shipping to a SIEM, these look like anonymous access attempts and require filtering rules to exclude.

## Things It Could Do Better

- **Single event per user request** instead of fragmented REST + TRANSPORT + compliance events
- **Correlation ID** stamped on all events from the same originating request
- **Sane defaults** out of the box (currently: too noisy with everything on, useless with everything off)
- **Separate destructive action category** instead of overloading INDEX_EVENT
- **Compliance read logging should log field NAMES, not VALUES** — or at least provide an option to mask
- **Work without FGAC** — our project addresses this

## Known Issues (GitHub + Forums)

| Issue | Source | Impact |
|-------|--------|--------|
| INDEX_EVENT flooding — thousands/hour filling disk | [Forum](https://forum.opensearch.org/t/index-event-flooding-audit-logs/10674) | Storage explosion, unreadable logs |
| Settings not working — disabled_categories confusing | [#2673](https://github.com/opensearch-project/security/issues/2673) | Users can't filter noise |
| REST vs transport category split confusing | [#3380](https://github.com/opensearch-project/security/issues/3380) | Silent misconfigurations |
| Failed requests not logged — malformed body drops event | [#1849](https://github.com/opensearch-project/security/issues/1849) | Security blind spots |
| No audit without FGAC | [#501](https://github.com/opensearch-project/.github/issues/501), [#502](https://github.com/opensearch-project/.github/issues/502) | Zero visibility for non-FGAC users |

---

## Fixes We've Shipped (and Why)

### 1. Unified `disabled_categories` setting
**Problem observed:** Users had to configure `disabled_rest_categories` and `disabled_transport_categories` separately. The REST/transport distinction is an internal implementation detail invisible to users. This caused silent misconfigurations where users thought they disabled a category but only disabled it on one layer.

**Fix:** Single `plugins.security.audit.config.disabled_categories` setting that applies to both layers. Old settings deprecated with warning log. ([Issue #6222](https://github.com/opensearch-project/security/issues/6222))

### 2. Standalone audit logging (entire project)
**Problem observed:** Audit logging is coupled to the FGAC authentication/authorization stack. Users running SSL-only or disabled security mode get zero audit trail despite compliance requirements.

**Fix:** `AuditActionFilter` — lightweight ActionFilter that captures request audit events directly from request context (bypasses ThreadContext since it's empty without FGAC). Works in SSL-only and disabled modes. New `REQUEST_AUDIT` category with no misleading auth semantics.

### 3. Config validation warnings
**Problem observed:** Users enable auth-specific categories (FAILED_LOGIN, MISSING_PRIVILEGES) in standalone mode where no auth exists. Events never fire, users think audit is broken.

**Fix:** Startup validation that warns when auth-only categories are enabled with no auth stack active.

### 4. Single event per request (by design)
**Problem observed:** FGAC audit fragments one user request into 2-4+ events across REST and TRANSPORT layers with no correlation ID.

**Fix:** `AuditActionFilter` fires once at the transport layer, producing one audit event per user action. Contains all context (IP, action, indices, user if available, task ID, node info) in a single log line. No fragmentation, no need for correlation IDs. no http request sent tho.

---

## How This Defends Our Design Choices

| Design Decision | User Pain Point It Addresses | Evidence |
|----------------|------------------------------|----------|
| `REQUEST_AUDIT` instead of reusing `GRANTED_PRIVILEGES` | Confusing category names (#3380, #2673) | Observed: users don't understand REST vs transport semantics |
| Standalone instead of fixing FGAC | "Must adopt full security plugin for basic audit" (#502) | Massive over-engineering for log analytics users |
| Unified `disabled_categories` | REST/transport split caused #3380, #2673 | Directly caused silent misconfigurations |
| Single-layer event (transport only) | Event explosion, no correlation ID | Observed: one `_cat/indices` → 4+ transport events |
| All existing sinks preserved | Compliance requires separate audit storage | SOC2/HIPAA mandate external log storage |

## References

- [OpenSearch Audit Logs Docs](https://docs.opensearch.org/latest/security/audit-logs/storage-types/)
- [Repo Request #502 — opensearch-audit-logging](https://github.com/opensearch-project/.github/issues/502)
- [Proposal #501 — Standalone audit logging](https://github.com/opensearch-project/.github/issues/501)
- [AWS OpenSearch Audit Docs](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/audit-logs.html)


Do we wanna log REST-specific metadata (HTTP method,path, headers) ?