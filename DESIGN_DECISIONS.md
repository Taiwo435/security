# Design Decisions — Standalone Audit Logging

This document records the major design decisions made during implementation, what alternatives were considered, and why we chose the approach we did.

---

## 1. Event Construction: Build in AuditActionFilter vs Delegate to AbstractAuditLog

**Task:** Construct REQUEST_AUDIT events with source IP, action, indices, request type, etc.

**What we did:** Build the AuditMessage directly in AuditActionFilter using data from the request parameters.

**Alternative:** Delegate to AbstractAuditLog (like all existing FGAC categories do) — call a method like `logRequestAudit(action, request, task)` and let AbstractAuditLog's helper methods build the message.

| | Our approach (build in filter) | Delegate to AbstractAuditLog |
|---|---|---|
| ThreadContext dependency | None — reads directly from request objects | Relies on ThreadContext being populated (getRemoteAddress, getUser, getOrigin) |
| Works in non-FGAC modes | Yes — self-contained | No — helpers return null because SecurityRequestHandler doesn't run |
| Coupling | Filter is independent, doesn't affect FGAC | Would need to modify AbstractAuditLog or hack ThreadContext population |
| Testability | Easy to unit test with mocks | Requires full FGAC infrastructure in tests |

**Why we chose this:** ThreadContext is empty in SSL-only and disabled modes because the security interceptors that populate it are gated behind `!sslOnlyMode`. Building directly in the filter avoids coupling to infrastructure that isn't active in our target modes.

---

## 2. Remote Address Capture: REST Wrapper + ThreadContext vs TransportRequest.remoteAddress()

**Task:** Capture the client's source IP in audit events.

**What we did:** Store the IP in ThreadContext via a REST handler wrapper, then read it back in AuditActionFilter as a fallback when `request.remoteAddress()` is null.

**Alternative A:** Use `TransportRequest.remoteAddress()` directly.

**Alternative B:** Modify the transport layer to propagate the IP from REST to transport requests.

| | REST wrapper + ThreadContext | TransportRequest.remoteAddress() | Modify transport layer |
|---|---|---|---|
| Works for REST-originated requests | Yes — wrapper captures IP before conversion | No — returns null (IP only exists at HTTP layer) | Yes but invasive |
| Code impact | Small — one wrapper method | None (but doesn't work) | Large — core OpenSearch change |
| Consistency with FGAC | Uses same ThreadContext key (OPENDISTRO_SECURITY_REMOTE_ADDRESS) | N/A | Different mechanism |
| Internal requests | Falls back gracefully (no IP) | Also no IP | Would need filtering |

**Why we chose this:** `TransportRequest.remoteAddress()` is null for REST-originated requests (the IP only exists at the HTTP/TCP layer). The REST wrapper approach reuses the same ThreadContext key that FGAC's BackendRegistry uses, keeping things consistent. The wrapper is registered via `getRestHandlerWrapper()` which already exists as an extension point.

---

## 3. Identity Enrichment: Client Cert CN/SAN vs No Identity

**Task:** Provide user identity in audit events for SSL-only mode (where no username exists).

**What we did:** Extract the client certificate's subject DN from the SSLEngine when mTLS is configured (needClientAuth or wantClientAuth), store it in ThreadContext, and add it as `effective_user` in the audit event.

**Alternative A:** No identity — just log source IP.

**Alternative B:** Add a custom header-based identity (X-Audit-User or similar).

| | Client cert CN/SAN | IP only | Custom header |
|---|---|---|---|
| Security | Strong — cryptographically verified identity | Weak — IP can be shared/spoofed | Weak — header can be forged |
| Requires config | mTLS must be enabled (clientauth_mode: OPTIONAL or REQUIRED) | Nothing | Application must send header |
| Consistency | Reuses existing OPENDISTRO_SECURITY_SSL_PRINCIPAL key | N/A | New mechanism |
| Fallback | IP always present, identity additive | Always works | Breaks if header missing |

**Why we chose this:** In SSL-only mode, client certificates are the only cryptographically verified identity available. IP is always captured as baseline; cert identity is additive when mTLS is configured. Using the existing `OPENDISTRO_SECURITY_SSL_PRINCIPAL` ThreadContext key means downstream code already understands the field.

---

## 4. Request Body Logging: Extract from Transport Request vs Stash Raw HTTP Body

**Task:** Include the request body in audit events for forensic analysis.

**What we did:** Extract body from parsed transport request objects in AuditActionFilter (`SearchRequest.source()`, `IndexRequest.source()`, `UpdateRequest.doc().source()`).

**Alternative:** Stash the raw HTTP body in ThreadContext at the REST wrapper (`request.content().utf8ToString()`) and read it back in AuditActionFilter.

| | Our approach (parsed objects) | ThreadContext (raw body) |
|---|---|---|
| Where body comes from | Parsed Java objects at transport layer | Raw HTTP string stashed at REST layer |
| Memory | No extra copy — request object already exists | Extra copy of entire body in ThreadContext (duplicated in memory) |
| Bulk requests | Can iterate sub-operations individually | Just one giant raw JSON blob |
| Type awareness | Know it's a SearchRequest query vs IndexRequest doc | Just a string — no context about what it means |
| Code complexity | Switch on request types (more code) | One line to read (simpler) |

**Why we chose this:** We already need the typed request object for other things (indices, doc IDs, shard info). Extracting body from it avoids duplicating potentially large payloads in memory. It also gives us type-aware body extraction — we know a SearchRequest body is a query, not a document. For bulk requests specifically, this lets us log individual sub-operation bodies rather than one giant blob.

---

## 5. Headers: Stash in ThreadContext vs Capture at REST Layer Separately

**Task:** Include HTTP headers in audit events while stripping sensitive ones (Authorization).

**What we did:** Stash all headers in ThreadContext at the REST wrapper, read them in AuditActionFilter, strip Authorization header using WildcardMatcher.

**Alternative:** Log headers in a separate REST-layer event (like FGAC does with `addRestRequestInfo`).

| | ThreadContext stash (our approach) | Separate REST event |
|---|---|---|
| Number of events | One event with everything | Two events (REST + transport) — fragmentation |
| Headers available at transport layer | Yes — pulled from ThreadContext | No — only in REST event |
| Memory overhead | Small — headers are key-value maps (kilobytes) | None for transport, but two events to store |
| Correlation | Single event, no correlation needed | Need correlation ID to link REST + transport events |

**Why we chose this:** Headers are small (unlike body), so stashing them in ThreadContext is cheap. This lets us include everything in a single audit event — avoiding the fragmentation problem that FGAC has (one request → multiple events with no correlation ID).

---

## 6. Category Filtering: Check in logRequestAudit vs Check in AuditActionFilter

**Task:** Respect `disabled_categories` to suppress REQUEST_AUDIT events when configured.

**What we did:** Check `disabledTransportCategories.contains(REQUEST_AUDIT)` in `AbstractAuditLog.logRequestAudit()` before calling `save()`.

**Alternative:** Check in AuditActionFilter before even building the AuditMessage.

| | Check in AbstractAuditLog | Check in AuditActionFilter |
|---|---|---|
| Consistency | Same pattern as all other categories (checkTransportFilter) | Different pattern — filter does its own checking |
| Performance | Builds AuditMessage then discards if disabled | Skips message construction entirely |
| Code location | Filtering logic centralized in AbstractAuditLog | Filtering logic split between filter and AbstractAuditLog |
| Dynamic config | Picks up config changes via setConfig() automatically | Would need its own config refresh mechanism |

**Why we chose this:** Consistency with existing categories. All other audit methods (logGrantedPrivileges, logMissingPrivileges, etc.) check disabled categories inside AbstractAuditLog. This keeps filtering logic centralized and automatically picks up dynamic config changes. The performance cost of building one AuditMessage that gets discarded is negligible.

---

## 7. Unified disabled_categories: Null When Not Configured vs Default Value

**Task:** Add a unified `disabled_categories` setting that takes precedence over split REST/transport settings.

**What we did:** Set `disabledCategories = null` when not explicitly configured. Getter returns empty set for null-safety. `@JsonInclude(NON_EMPTY)` suppresses serialization.

**Alternative:** Always populate with a default value (like the split settings do).

| | Null when not configured (our approach) | Always populated with default |
|---|---|---|
| Serialization | Field absent from JSON when not configured | Always present in JSON output |
| Round-trip safety | Re-parsing JSON won't see the field → fallback works | Re-parsing sees it → treats as "configured" → overrides split settings |
| Backward compatibility | Split settings continue working unchanged | Split settings silently ignored by defaults |
| Complexity | Need null-safety in getter, @JsonInclude annotation | Simpler code but breaks existing behavior |

**Why we chose this:** The round-trip problem was the root cause of 17 CI test failures. When the field was always populated, serializing a Filter to JSON and parsing it back would trigger the unified precedence logic even though the user never configured it — breaking all tests that use split settings. Null-when-not-configured means the field is absent from JSON, so re-parsing correctly falls back to split settings.

---

## 8. Ignore-Users/Requests: Early Return in Filter vs Delegate to AbstractAuditLog

**Task:** Skip audit events for configured ignored users and request patterns.

**What we did:** Check ignore patterns in AuditActionFilter with early returns before building the AuditMessage.

**Alternative:** Let AbstractAuditLog's `checkTransportFilter()` handle it (which already does ignore-users and ignore-requests for existing categories).

| | Early return in filter (our approach) | Use checkTransportFilter |
|---|---|---|
| Performance | Skips message construction entirely | Builds partial message, then discards |
| Self-contained | Filter handles its own filtering | Depends on AbstractAuditLog internals |
| Internal actions | Filter skips `internal:*` explicitly | checkTransportFilter also skips internals |
| Future extraction | Filter can move to standalone plugin easily | Tied to AbstractAuditLog's implementation |

**Why we chose this:** The filter is intended to be self-contained for eventual extraction into a standalone plugin. Doing ignore checks early avoids constructing an AuditMessage that will just be thrown away. For `internal:*` cluster housekeeping actions (which fire thousands of times per minute), this saves significant overhead.

---

## 9. Audit Settings Registration: Outside the sslOnlyMode Gate vs Inside

**Task:** Allow users to configure audit settings in opensearch.yml when running in SSL-only or disabled mode.

**What we did:** Moved ALL audit settings registration outside the `if (!SSLConfig.isSslOnlyMode())` block in `getSettings()`.

**Alternative:** Register only the subset of settings needed for standalone audit (audit.type, disabled_categories, ignore_users).

| | Move all settings outside gate | Move only needed settings |
|---|---|---|
| Completeness | All sink configs work (webhook URLs, log4j settings, external ES) | Only basic settings, sinks partially configured |
| Risk | Non-audit settings (RBAC, Kerberos) stay gated — no impact | Same |
| User experience | Users can configure any sink in any mode | Users limited to subset — confusing if they try others |
| Code simplicity | One block move | Cherry-pick individual settings — error-prone |

**Why we chose this:** Users should be able to configure any audit sink (webhook, external ES, log4j, internal index) regardless of security mode. Moving the entire audit settings block is simpler and less error-prone than selectively picking settings. Non-audit settings (Kerberos, RBAC, compliance) remain gated since they're genuinely FGAC-only.

---

## 10. Config Initialization: Explicit setConfig() vs EventBus

**Task:** Initialize audit logging in non-FGAC modes where the EventBus/ConfigurationRepository doesn't exist.

**What we did:** After creating AuditLogImpl in `initStandaloneAuditIfEnabled()`, explicitly call `auditLogImpl.setConfig(AuditConfig.from(settings))` to read config from opensearch.yml and set `enabled = true`.

**Alternative A:** Partially bootstrap the EventBus/ConfigurationRepository for audit config only.

**Alternative B:** Change AuditLogImpl to default `enabled = true`.

| | Explicit setConfig() (our approach) | Partial EventBus bootstrap | Default enabled=true |
|---|---|---|---|
| Complexity | One line — minimal | Large — need security index, event bus, config repo | One line but risky |
| Side effects | None — reads from settings only | Creates security index, starts background threads | All AuditLogImpl instances start enabled (breaks FGAC) |
| Config source | opensearch.yml (static) | Security index (dynamic) — but index doesn't exist in non-FGAC | N/A |
| Mimics FGAC | Yes — same setConfig() call that EventBus would trigger | Yes but overkill | No — changes global behavior |

**Why we chose this:** `setConfig()` is the exact method the EventBus calls in FGAC mode when config is loaded. Calling it directly with settings-derived config is the minimal mimicry needed. No infrastructure bootstrapping, no side effects, one line of code.

---

## 11. Auth-Only vs Mode-Independent Category Classification

**Task:** Determine which existing audit categories make sense in non-FGAC modes vs which require authentication infrastructure.

**What we did:** Defined `AUTH_ONLY_CATEGORIES` as a constant set: AUTHENTICATED, FAILED_LOGIN, GRANTED_PRIVILEGES, MISSING_PRIVILEGES, OPENDISTRO_SECURITY_INDEX_ATTEMPT, API_TOKEN_WRITE. These can never fire in non-FGAC modes.

**Alternative:** Don't classify — let all categories remain "enabled" silently and just never produce events.

| | Explicit classification (our approach) | No classification |
|---|---|---|
| User clarity | Warning tells users which categories are dead | Users think audit is broken when categories produce nothing |
| Code documentation | AUTH_ONLY_CATEGORIES constant documents the dependency | Tribal knowledge only |
| Future-proofing | Clear contract for what needs auth vs what doesn't | New categories have no guidance |
| Runtime cost | One-time check at startup | None |

**Why we chose this:** Users who migrate from FGAC to SSL-only might leave auth categories enabled. Without a warning, they'd think audit logging is broken when FAILED_LOGIN never fires. The classification makes the dependency explicit and the warning provides visibility.

---

## 12. Config Validation: Warn vs Reject for Auth Categories in Non-FGAC

**Task:** Handle the case where auth-only categories are "enabled" (not in disabled list) when no auth layer is active.

**What we did:** Log a WARNING at startup listing which auth categories will never produce events. Don't reject the config or prevent startup.

**Alternative:** Reject the config and fail startup if auth categories are enabled in non-FGAC mode.

| | Warning (our approach) | Reject/fail startup |
|---|---|---|
| User impact | Cluster starts normally, user sees warning in logs | Cluster won't start until config is fixed |
| Proportionality | Auth categories being "enabled" has zero functional impact | Crashing for a non-issue is disproportionate |
| Migration path | Users can migrate incrementally | Forces config change before cluster starts |
| Backward compatibility | Existing configs work unchanged | Existing configs break |

**Why we chose this:** Auth categories being "enabled" in non-FGAC mode is harmless — the code that triggers them simply doesn't exist. Crashing the node would be disproportionate to a cosmetic misconfiguration. A single warning provides visibility without disruption.

---

## 13. Index Resolution: IndexNameExpressionResolver vs Raw Indices Only

**Task:** Expand wildcard index patterns (e.g., `my-*`) to actual matching indices in audit events.

**What we did:** Use `IndexNameExpressionResolver` to resolve patterns against cluster state. Log BOTH raw patterns (`audit_trace_indices`) and resolved indices (`audit_trace_resolved_indices`). Respects `resolve_indices` setting. Try/catch for safety if cluster state isn't ready.

**Alternative A:** Only log raw patterns (what the user sent).

**Alternative B:** Only log resolved indices (what actually matched).

| | Both raw + resolved (our approach) | Raw only | Resolved only |
|---|---|---|---|
| Forensic value | Full picture — intent + impact | Know what user asked for, not what matched | Know what matched, not what user asked |
| Wildcard visibility | `my-*` preserved AND expanded | Wildcards visible | Wildcards lost |
| Performance | One extra resolution call per request | Minimal | Same resolution cost |
| Consistency with FGAC | FGAC also logs both when resolve_indices=true | Different | Same as FGAC |
| Failure handling | Falls back to raw if cluster state unavailable | Always works | Fails if cluster state unavailable |

**Why we chose this:** For security forensics, you need both: "what did the user ask for" (raw pattern) and "what did it actually affect" (resolved indices). A user searching `logs-*` hitting 50 indices is very different from hitting 2. Logging both follows FGAC's existing behavior and the `resolve_indices` setting already exists to control this.

---

## 14. Bulk Request Handling: Per-Item Events vs Single Event

**Task:** Handle bulk requests that contain multiple sub-operations targeting different indices.

**What we did:** When `resolve_bulk_requests: true`, iterate over `BulkShardRequest.items()` and log one event per sub-operation (with specific index, doc ID, shard ID, body). When false (default), log one event for the whole bulk.

**Alternative A:** Always log one event per bulk (aggregated).

**Alternative B:** Always log per-item (expanded).

| | Configurable (our approach) | Always aggregated | Always expanded |
|---|---|---|---|
| Granularity control | User decides based on needs | Coarse — can't see individual docs | Fine — always noisy |
| Compliance use case | Per-item when tracking individual doc access | Insufficient for doc-level audit | Always sufficient |
| Performance use case | Aggregated when bulk throughput matters | Good for perf | Bad for high-throughput bulk |
| Event volume | Controlled by setting | Low | High (N events per bulk) |
| Consistency with FGAC | Same setting name and behavior | Different | Different |

**Why we chose this:** Different use cases need different granularity. A compliance team tracking individual document access needs per-item events. A log analytics cluster doing bulk ingestion at 100K docs/sec needs aggregated events to avoid audit volume exceeding data volume. The existing `resolve_bulk_requests` setting already controls this in FGAC — we reuse it for consistency.

---

## 15. Sink Verification: Test One Real Sink vs Test All Sinks

**Task:** Verify all audit sinks (internal_opensearch, external_opensearch, log4j, webhook, Kafka) work in standalone mode.

**What we did:** Full integration test for `internal_opensearch` (verifies audit index created with correct events). Log4j verified via cluster boot (no crash). Webhook verified via TestRuleAuditLogSink (proves routing). Documented external_opensearch and Kafka as skipped (need external infrastructure).

**Alternative:** Full integration test for every sink type.

| | Test one + verify routing (our approach) | Full test for every sink |
|---|---|---|
| Coverage confidence | High — all sinks share same code path after AuditMessageRouter.route() | Maximum — but diminishing returns |
| Infrastructure needs | Single cluster | Need Kafka broker, 2nd ES cluster, HTTP server for webhook |
| Test complexity | Low — one real sink + routing verification | High — external dependencies, flaky network |
| What it proves | Message construction correct + routing works + one real sink writes | Each sink's serialization + delivery works |
| Existing unit tests | WebhookAuditLogTest, Log4jAuditLogTest already test individual sinks | Redundant with existing tests |

**Why we chose this:** All sinks receive the same `AuditMessage` (a `Map<String, Object>`) via `AuditMessageRouter.route()`. The router doesn't care which category created the message — it just serializes and delivers. Testing `internal_opensearch` end-to-end proves the message is correctly constructed and routable. Individual sink delivery (HTTP POST for webhook, Kafka produce, etc.) is already unit tested in the existing test suite. Adding external infrastructure (Kafka, 2nd cluster) to integration tests adds flakiness with minimal additional confidence.

---

## 16. Dynamic Audit Toggle: Cluster Setting vs Reuse FGAC's Security Index

**Task:** Allow toggling audit logging on/off at runtime without restarting the cluster. Previously, `enabled` was hardcoded to `true` at startup with no way to change it in non-FGAC modes.

**What we did:** Registered a dynamic cluster setting (`plugins.security.audit.enabled`) with `Property.Dynamic`. OpenSearch's built-in `PUT _cluster/settings` API handles the REST endpoint, validation, persistence to cluster state, and propagation to all nodes. A settings update consumer on each node calls `AuditLogImpl.setEnabled(newValue)` to flip the runtime toggle.

**Alternative:** Partially bootstrap FGAC's ConfigurationRepository in non-FGAC mode — create the `.opendistro_security` index, store audit config there, and use the EventBus to push changes to AuditLogImpl (the same mechanism FGAC uses).

| | Cluster setting (our approach) | Reuse FGAC security index |
|---|---|---|
| Implementation effort | ~20 lines (define setting + register + consumer) | 200+ lines (bootstrap ConfigurationRepository, create index, handle permissions) |
| Infrastructure needed | None — cluster state is built-in | Security index must be created and managed |
| Multi-node propagation | Automatic via cluster state | Automatic via EventBus + index change detection |
| REST API | Built-in (`PUT _cluster/settings`) | Would reuse existing `/_plugins/_security/api/audit/config` |
| Config richness | Simple boolean toggle | Full structured config (categories, ignore lists, compliance) |
| Contradiction | None | Contradicts "standalone" premise — reintroduces security index dependency |
| Persistence | Survives restart (persistent cluster settings) | Survives restart (index persists) |
| Works without auth | Yes — cluster settings API has no auth requirement in non-FGAC | Security index API requires admin certs in FGAC — unclear how it works without auth |

**Why we chose this:** The cluster setting approach gives us a runtime toggle with near-zero implementation cost. OpenSearch handles all the plumbing (API, persistence, propagation). Bootstrapping the security index in non-FGAC mode would reintroduce the very infrastructure dependency we're trying to avoid — and would require solving permissions without an auth layer. The cluster setting is also the first step toward Craig's suggestion of extracting the enabled toggle from the security index entirely, so FGAC could eventually use the same mechanism.

---

## 17. Dynamic Filter Settings: Volatile Fields + Setters vs Rebuild Filter Atomically

**Task:** Make the 11 audit filter settings (log_request_body, ignore_users, disabled_categories, etc.) dynamically configurable via `PUT _cluster/settings` without restart.

**What we did:** Made the relevant `AuditConfig.Filter` fields `volatile` (non-final), added setter methods for each, defined `Setting` constants in `SecuritySettings.java` with `Property.Dynamic`, replaced the inline switch in `getSettings()` with those constants, and wired `addSettingsUpdateConsumer` for each setting that calls the corresponding setter.

**Alternative A:** Rebuild the entire `Filter` object atomically on each settings change using `AtomicReference<Filter>`.

**Alternative B:** Keep fields `final`, rebuild a new `Filter` from current settings + the changed value, and swap via `onAuditConfigFilterChanged()`.

| | Volatile fields + setters (our approach) | AtomicReference\<Filter\> rebuild | Full rebuild via onAuditConfigFilterChanged |
|---|---|---|---|
| Consistency with codebase | Matches existing pattern (SSLConfig.setDualModeEnabled, DlsFlsValveImpl) | Not used anywhere in the codebase | Used for security index config changes only |
| Atomicity | Individual field updates — not atomic across multiple fields | Full object swap — atomic | Full object swap — atomic |
| Performance | Single field write per change | Full object construction per change | Full object construction per change |
| Thread safety | Volatile guarantees visibility across threads | AtomicReference guarantees visibility | Volatile reference guarantees visibility |
| Code complexity | One setter per field (~40 lines total) | Factory method + rebuild logic (~80 lines) | Reuse existing from() + full settings object construction |
| Partial update risk | If 2 settings change simultaneously, there's a brief window where one is updated and other isn't | No risk — all-or-nothing swap | No risk — all-or-nothing swap |

**Why we chose this:** The existing codebase consistently uses the simple setter pattern for dynamic settings (SSLConfig, DlsFlsValveImpl, BackendRegistry). The partial update risk is negligible in practice — cluster settings updates are rare (operator actions, not per-request), and the window between two field writes is nanoseconds. Rebuilding the entire Filter for a single boolean change is wasteful. The volatile keyword ensures all request-handling threads see the updated value immediately.

**Key implementation detail:** We defined `Setting` constants in `SecuritySettings.java` (not inline in the switch) so they can be referenced in both `getSettings()` for registration and `addSettingsUpdateConsumer()` for the consumer wiring — following the same pattern as `AUDIT_ENABLED_SETTING`, `SSL_DUAL_MODE_SETTING`, etc. The inline switch: Before our change, the getSettings() method had a switch that created Setting objects on the fly inside the lambda:
case LOG_REQUEST_BODY:
    return Setting.boolSetting(filterEntry.getKeyWithNamespace(), true, Property.NodeScope, Property.Filtered);

These were "inline" because the Setting objects were created anonymously — never stored in a variable, just returned and added to the list. That meant we couldn't reference them later for
addSettingsUpdateConsumer (you need to pass the same Setting object).

---

## 18. Compliance Write Tracking in Non-FGAC: Reuse Existing Listener vs New Implementation

**Task:** Enable document-level write tracking (`COMPLIANCE_DOC_WRITE`) in SSL-only and disabled modes, where the `ComplianceIndexingOperationListenerImpl` was previously never registered.

**What we did:** Reused the existing `ComplianceIndexingOperationListenerImpl` as-is — registered it in an `else if` block in `onIndexModule()` for non-FGAC modes when audit is active. Added a `plugins.security.audit.compliance.enabled` setting to control it, and moved compliance settings outside the `!sslOnlyMode` gate.

**Alternative A:** Create a new, standalone compliance listener specifically for non-FGAC modes (without any FGAC-specific logic).

**Alternative B:** Make `ComplianceIndexingOperationListenerImpl` conditional on a runtime flag instead of a gate in `onIndexModule()`.

| | Reuse existing listener (our approach) | New standalone listener | Runtime flag |
|---|---|---|---|
| Code duplication | None — same class, different registration path | Full duplication of listener logic | None |
| Correctness | Proven — same logic that FGAC uses in production | Needs new testing from scratch | Same logic |
| FGAC dependencies | None — listener only depends on AuditLog + ThreadPool + ComplianceConfig | None | None |
| Registration complexity | One else-if block in onIndexModule() | New class + new registration | Modify existing if-condition |
| Future extraction | Listener already self-contained, moves easily to standalone plugin | Would be the thing that moves | Entangles registration logic |
| Read wrapper coupling | Not relevant (listener is only for writes) | Same | Same |

**Why we chose this:** `ComplianceIndexingOperationListenerImpl` has zero FGAC dependencies — it only needs an `AuditLog` instance, a `ThreadPool`, and a `ComplianceConfig`. It doesn't call SecurityFilter, BackendRegistry, or read from the security index. The only reason it didn't work in non-FGAC mode was that `onIndexModule()` never registered it. Adding an else-if block is minimal code with maximum reuse.

---

## 19. Compliance Settings: New Prefix + Legacy Fallback vs Migrate Everything

**Task:** Make compliance settings available in non-FGAC modes (outside the `!sslOnlyMode` gate) and dynamically configurable.

**What we did:** Defined new `Setting` constants in `SecuritySettings.java` under `plugins.security.audit.compliance.*` with `Property.Dynamic`. Kept the existing `opendistro_security.compliance.*` registrations as legacy fallbacks (non-dynamic, `Property.NodeScope` only). `ComplianceConfig.from(Settings)` reads from the new prefix for `enabled`, while other fields still read from legacy keys.

**Alternative A:** Migrate all compliance settings to `plugins.security.*` prefix in one go and remove the `opendistro_security.*` registrations.

**Alternative B:** Just add `Property.Dynamic` to the existing `opendistro_security.*` registrations without introducing new prefix.

| | New prefix + legacy fallback (our approach) | Full migration | Dynamic on legacy only |
|---|---|---|---|
| Backwards compatibility | Users with opendistro_security.* in opensearch.yml still work | Breaking — users must update all configs | Full compat |
| New users | Use modern plugins.security.* prefix | Same | Stuck with legacy prefix |
| Dynamic support | New prefix settings are dynamic | Would be dynamic | Dynamic |
| Migration path | Gradual — can migrate other fields later | All-or-nothing | No migration |
| Code complexity | Both registered (two paths) | One path (cleaner) | One path |
| Consistency with Craig's guidance | Matches "use plugins.security for new settings, leave legacy for old" | Goes further than asked | Doesn't follow guidance |

**Why we chose this:** Craig's feedback on the `disabled_categories` PR was explicit: "for new settings use `plugins.security` prefix, for existing ones leave legacy with deprecation." This approach follows that pattern exactly. `compliance.enabled` is effectively a new setting (it was hardcoded before, never user-configurable from opensearch.yml), so it gets the new prefix. The other fields already exist under `opendistro_security.*` — users have them in their configs. We keep those working while introducing the new prefix for dynamic support. Full migration can happen in a follow-up PR.

---

## 20. Compliance Read Tracking in Non-FGAC: New Lightweight Wrapper vs Reuse FGAC Wrapper vs SearchOperationListener

**Task:** Enable document-level read tracking (`COMPLIANCE_DOC_READ`) in non-FGAC modes, where `SecurityFlsDlsIndexSearcherWrapper` is never registered.

**What we chose:** Option 1 — create a new lightweight `ComplianceReadIndexSearcherWrapper` that wraps the Lucene `DirectoryReader` with compliance tracking only. No DLS/FLS logic. Uses `FieldMasking.FieldMaskingRule.ALLOW_ALL` and reuses the existing `FieldReadCallback` directly.

**Alternative A (Option 2):** Register the full `SecurityFlsDlsIndexSearcherWrapper` in non-FGAC mode with null/no-op values for FGAC dependencies.

**Alternative B (Option 3):** Use `SearchOperationListener` for search-level tracking without field granularity.

| | New lightweight wrapper (our choice) | Full FGAC wrapper with nulls | SearchOperationListener |
|---|---|---|---|
| Field-level granularity | Yes — intercepts every field read via StoredFieldVisitor | Yes — same mechanism | No — only knows "a search happened" |
| `read_watched_fields` support | Yes — FieldReadCallback checks field against config | Yes | No — can't watch specific fields |
| FGAC dependencies | None — self-contained | Many nulls needed (PrivilegesEvaluationContext, DlsFlsBaseContext, etc.) | None |
| Risk of NPE / breakage | None — clean class with no null paths | High — SecurityFlsDlsIndexSearcherWrapper expects non-null FGAC objects | None |
| Code complexity | ~150-200 lines new code | Null checks scattered in existing security-critical class | ~30 lines |
| Testability | Unit testable with mocks | Requires understanding full FGAC flow | Very easy |
| Maintainability | Independent — changes to FGAC wrapper don't affect us | Tied to FGAC internals — FGAC refactors break our path | Independent |
| Upstream reviewer acceptance | Good — clean separation, doesn't touch FGAC code | Bad — reviewers won't want nulls in security-critical class | Good but incomplete feature |
| Matches FGAC compliance behavior | Yes — same FieldReadCallback, same events | Yes | No — different semantics entirely |
| Future plugin extraction | Easy — self-contained class moves cleanly | Hard — entangled with FGAC class | Easy |
| `setReaderWrapper()` availability | Free in non-FGAC (nobody else uses it) | Conflicts with FGAC in same mode | Not applicable (different extension point) |

**Why we chose Option 1:**
- Field-level read tracking is the whole point of compliance read — Option 3 doesn't deliver it
- Option 2 dirties a security-critical FGAC class with null checks and would likely be rejected by upstream reviewers
- `FieldReadCallback` itself has zero FGAC dependencies — it just needs `auditLog`, `indexService`, `clusterService`, `threadContext`, and a `FieldMaskingRule`. Wrapping it in a clean reader wrapper is straightforward.
- `indexModule.setReaderWrapper()` is available in non-FGAC mode (the FGAC path uses it but is gated)
- Matches the pattern we've established: self-contained classes (`AuditActionFilter`, `AuditTransportInterceptor`, reused `ComplianceIndexingOperationListenerImpl`) that can be extracted into a standalone plugin later

---

## 21. Transport-Layer Interception: Separate Class vs Piggyback on Existing Interceptor

**Task:** Add audit logging at the transport layer to capture inter-node communication, replica writes, and forwarded requests that `ActionFilter` doesn't see.

**What we did:** Created a new `AuditTransportInterceptor` class (Approach B+D) — a standalone `TransportInterceptor` that only intercepts the handler side (incoming requests). Registered unconditionally for all modes alongside the existing FGAC auth interceptor.

**Alternative A:** Piggyback on the existing FGAC `TransportInterceptor` — add audit calls inside it.

**Alternative B:** Create a separate `AuditTransportInterceptor` class.

**Alternative C:** Add audit calls inside `SecurityInterceptor` (the class the FGAC interceptor delegates to).

**Alternative D:** Only intercept handler side (receiving node), skip sender side.

| | Separate class + handler only (our approach: B+D) | Piggyback on FGAC interceptor (A) | Inside SecurityInterceptor (C) | Both sender + handler |
|---|---|---|---|---|
| Separation of concerns | Clean — audit logic isolated | Mixed with auth propagation | Deep in FGAC internals | Clean |
| Works in non-FGAC | Yes — registered outside gate | No — FGAC interceptor is gated | No — SecurityInterceptor is FGAC-only | Yes |
| Works in FGAC | Yes — both interceptors coexist | Yes | Yes | Yes |
| Event duplication | None — only receiver logs | None | None | Double-logged (sender + receiver) |
| Future extraction | Easy — self-contained class | Would need untangling | Deep coupling | Easy |
| Performance | One handler wrap per action | Same | Same | Two wraps per action |
| Testability | Unit testable with mocks | Harder — entangled with auth | Very hard | Same as ours |

**Why we chose B+D:**
- Matches the established pattern (`AuditActionFilter` is also a separate, self-contained class)
- Works in all modes without touching the FGAC interceptor
- Handler-only avoids double-logging (the same request logged on both sender and receiver)
- FGAC's existing interceptor continues doing its auth job undisturbed
- Easy to unit test — 10 tests covering all edge cases
- Ready for extraction into standalone plugin

**Key design detail:** We filter `internal:*`, `cluster:monitor/*`, and `indices:monitor/*` to avoid flooding logs with cluster housekeeping traffic. These fire thousands of times per minute and have no forensic value for compliance auditing.
