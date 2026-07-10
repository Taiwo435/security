# Standalone Audit Logging for OpenSearch — Design Doc

## Project Overview

**Goal**: Make audit logging an independent capability that works in ALL security modes (FGAC, SSL-only, and disabled), not just FGAC.

**Why**: Users running OpenSearch without full security (for log analytics, observability, etc.) currently have zero audit trail. Compliance frameworks (SOC2, HIPAA, PCI-DSS, GDPR) require audit logs even without access control.

**Solution**: A single setting enables standalone audit logging:
```yaml
plugins.security.audit.standalone_enabled: true
plugins.security.audit.type: log4j
```

---

## Repo & Branch

- **Repo**: `git@github.com:Taiwo435/security.git`
- **Branch**: `standalone-audit-loggin`
- **Local path**: `/Users/muzzajol/Desktop/security`
- **Upstream**: `opensearch-project/security` (main)

---

## Current State (Prototype)

The prototype commit (`4fa7be5d`) proves the concept with ~30 lines of production code:

### What exists:
1. **`AuditActionFilter.java`** — lightweight ActionFilter that intercepts all requests without auth
2. **`initStandaloneAuditIfEnabled()`** in `OpenSearchSecurityPlugin.java` — initializes AuditLogImpl before the SSL-only early return
3. **`getActionFilters()`** modification — registers AuditActionFilter when a real AuditLog is available in non-FGAC modes

### Deliberate shortcuts in prototype (to fix):
- Reuses `logGrantedPrivileges()` + `logIndexEvent()` — misleading category names
- `logIndexEvent()` only logs `indices:admin/*` actions — misses searches, writes, etc.
- Settings registration still gated behind `!sslOnlyMode` in `getSettings()`
- Disabled mode has `settings=null` — prototype uses `environment.settings()` fallback
- Default disabled categories filter out events needed in standalone mode

---

## Security Modes Explained

| Mode | Auth? | RBAC? | Audit today? | Standalone audit? |
|------|-------|-------|--------------|-------------------|
| FGAC | Yes | Yes | Yes | N/A (already works) |
| SSL-only | No (TLS only) | No | No | Yes — our target |
| Disabled | No | No | No | Yes — our target |

---

## New Category: REQUEST_AUDIT

**Purpose**: Captures all REST/transport actions without implying authentication or authorization occurred.

**Why not reuse existing categories**:
- `GRANTED_PRIVILEGES` implies a privilege check happened
- `AUTHENTICATED` implies auth happened
- In non-FGAC modes, no decisions are made — requests just execute

**Fields captured**:
- `@timestamp`
- `audit_cluster_name`, `audit_node_name`, `audit_node_id`
- `audit_rest_request_method`, `audit_rest_request_path`
- `audit_request_body` (configurable)
- `audit_request_remote_address` (source IP)
- `audit_trace_indices`
- `audit_transport_request_type` (e.g., IndexRequest, SearchRequest)
- `audit_request_layer` (REST vs TRANSPORT)
- `audit_format_version`

**NOT included** (no auth layer):
- `audit_request_effective_user`
- `audit_request_privilege`
- `audit_request_effective_user_is_admin`

**Identity by mode**:
- FGAC: username (from ThreadContext, if coexisting)
- SSL-only: source IP + cert CN/SAN (subject DN from client cert when mTLS configured)
- Disabled: source IP only

---

## Category Relevance by Mode

| Category | FGAC | SSL-only | Disabled |
|----------|------|----------|----------|
| AUTHENTICATED | ✓ | ✗ | ✗ |
| FAILED_LOGIN | ✓ | ✗ | ✗ |
| GRANTED_PRIVILEGES | ✓ | ✗ | ✗ |
| MISSING_PRIVILEGES | ✓ | ✗ | ✗ |
| OPENDISTRO_SECURITY_INDEX_ATTEMPT | ✓ | ✗ | ✗ |
| API_TOKEN_WRITE | ✓ | ✗ | ✗ |
| **REQUEST_AUDIT** | ✗ | **✓** | **✓** |
| BAD_HEADERS | ✓ | ✓ | ✓ |
| SSL_EXCEPTION | ✓ | ✓ | ✗ |
| INDEX_EVENT | ✓ | ✓ | ✓ |
| CLUSTER_SETTINGS_CHANGED | ✓ | ✓ | ✓ |
| INDEX_SETTINGS_CHANGED | ✓ | ✓ | ✓ |
| COMPLIANCE_DOC_READ | ✓ | Phase 3 | Phase 3 |
| COMPLIANCE_DOC_WRITE | ✓ | Phase 3 | Phase 3 |

---

## Phases

### Phase 1 (Weeks 1–4): Define the Audit Event Model
- [x] Add `REQUEST_AUDIT` to `AuditCategory` enum
- [x] Build proper event construction in `AuditActionFilter` (source IP, indices, action, request type, timestamp, node info, task ID)
- [x] Add `logRequestAudit(AuditMessage msg)` to `AuditLog` interface and implement in `AbstractAuditLog`
- [x] Add config validation — warn when auth-related categories are enabled with no auth active
- [x] Unit tests for `AuditActionFilter` (event fields, category, chain continuation)
- [x] Move ALL audit settings registration outside the `!sslOnlyMode` gate
- [x] Write integration tests validating event content (not just existence)
- [x] Issue #6222: Add unified `disabled_categories` setting (ramp-up task)
- [x] Remote address capture via REST handler wrapper + ThreadContext fallback
- [x] Disabled mode support (initStandaloneAuditIfEnabled in disabled path)
- [x] Fix: logRequestAudit respects disabled_categories

### Phase 2 (Weeks 5–8): Production Hardening
- [x] Verify all sinks work end-to-end (Log4j, internal index, external ES, webhook, Kafka)
- [x] Client cert identity enrichment — CN/SAN from peer cert when mTLS configured (effective_user field)
- [x] User identity enrichment — read user from ThreadContext when FGAC coexists
- [x] Request body logging with sensitive header exclusion
- [x] Index resolution and bulk request handling
- [x] Ignore-users and ignore-requests filtering
- [ ] Performance testing (AuditActionFilter overhead on latency/throughput)

### Phase 3 (Weeks 9–12): Stretch Goals
- [ ] Document-level compliance tracking (IndexingOperationListener) in non-FGAC modes
- [ ] REST API for audit configuration (GET/PUT `/_plugins/_audit/config`)
- [x] Transport-layer interception
- [x] Dynamic config reload without restart
- [ ] Documentation and blog post

---

## Key Files

| File | Path | Role |
|------|------|------|
| AuditCategory.java | `src/main/java/.../auditlog/impl/AuditCategory.java` | Enum of event types — add REQUEST_AUDIT here |
| AuditConfig.java | `src/main/java/.../auditlog/config/AuditConfig.java` | Config model (filtering, categories, compliance) |
| AuditLog.java | `src/main/java/.../auditlog/AuditLog.java` | Interface — all audit event methods |
| AuditLogImpl.java | `src/main/java/.../auditlog/impl/AuditLogImpl.java` | Delegates to AbstractAuditLog + router |
| AbstractAuditLog.java | `src/main/java/.../auditlog/impl/AbstractAuditLog.java` | Builds AuditMessage objects (~44KB, core logic) |
| AuditMessage.java | `src/main/java/.../auditlog/impl/AuditMessage.java` | The event object — fields, serialization |
| AuditMessageRouter.java | `src/main/java/.../auditlog/routing/AuditMessageRouter.java` | Routes messages to sinks (async) |
| AuditActionFilter.java | `src/main/java/.../filter/AuditActionFilter.java` | Our lightweight filter (prototype) |
| SecurityFilter.java | `src/main/java/.../filter/SecurityFilter.java` | Full FGAC filter (reference for how auth works) |
| OpenSearchSecurityPlugin.java | `src/main/java/.../security/OpenSearchSecurityPlugin.java` | Plugin entry point, settings, component init |

---

## Challenges & Decisions

| Challenge | Notes |
|-----------|-------|
| Settings gated behind `!sslOnlyMode` | OpenSearch rejects unknown settings at startup. Must move audit settings outside gate. |
| Disabled mode has `settings=null` | Parent class nulls settings when disabled. Use `environment.settings()` fallback. |
| `logIndexEvent()` only logs `indices:admin/*` | Need new code path for general requests (search, write, etc.) |
| Default disabled categories | GRANTED_PRIVILEGES disabled by default — standalone needs different defaults |
| Self-referential logging | Audit writes to an index → triggers more audit events. Must exclude audit index. |
| Identity in SSL-only | Source IP guaranteed. Client cert CN/SAN possible if mTLS configured. TBD. |
| Performance | AuditActionFilter fires on every request. Must be lightweight. |

---

## Testing Strategy

- **Integration tests**: Spin up real clusters in SSL-only and disabled modes, perform actions, verify audit events exist with correct category and fields
- **Unit tests**: AuditActionFilter, config validation, category filtering
- **Coexistence test**: FGAC mode + standalone enabled simultaneously

---

## Resources

- [Intern Project PDF](/Users/muzzajol/Downloads/Intern Project_ Standalone Audit Logging for OpenSearch (Summer 2026).pdf)
- [Issue #6222](https://github.com/opensearch-project/security/issues/6222) — First task (unified disabled_categories)
- [Proposal #501](https://github.com/opensearch-project/.github/issues/501) — Broader vision
- [OpenSearch Audit Docs](https://opensearch.org/docs/latest/security/audit-logs/)
- Mentor: Darshit Chanpura
- Sr. SDE: Craig Perkins

---

## REST-Layer Events in SSL-Only Mode

In SSL-only mode, the REST-layer events that could make sense:

- `BAD_HEADERS` — malformed or suspicious headers (already works in SSL-only, it's not auth-dependent)
- `SSL_EXCEPTION` — TLS handshake failures (already works)

That's about it for what FGAC already produces at REST. The other FGAC REST events (`AUTHENTICATED`, `FAILED_LOGIN`) are auth-only and meaningless in SSL-only mode.

**Could we have added our own REST event?** We could have logged something like:
- HTTP method (GET/PUT/POST/DELETE)
- URL path (`/my-index/_search`)
- Query parameters
- Source IP at HTTP layer (before transport conversion)
- Raw HTTP body (before it's parsed into a transport request)

**Why we didn't:**

1. **One event is better than two** — FGAC's #1 user complaint is fragmentation. One `GET _cluster/health` produces 2+ events with no way to correlate them. We solved this by logging once with everything.
2. **We already capture all that info** — the REST wrapper stashes headers and IP into ThreadContext, then the action filter pulls them back. The end result is one event with REST info (headers, IP) + transport info (action, indices, body). Best of both worlds.
3. **No information loss** — anything the REST layer knows that the transport layer doesn't (HTTP method, raw path, query params) could be added to our single event by stashing more in ThreadContext. We just haven't needed it yet.

So it's a design tradeoff: FGAC gives you two events (one REST, one transport) that are hard to correlate. We give you one event with everything. If users specifically need the raw HTTP method/path (not just the transport action name), we could add those fields to our single event without creating a separate REST event.
