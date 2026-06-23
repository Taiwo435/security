# OpenSearch FGAC Audit Logging — User Perspective Research

## What FGAC Audit Logging Currently Does Well

1. **Comprehensive event categories**: AUTHENTICATED, FAILED_LOGIN, GRANTED_PRIVILEGES, MISSING_PRIVILEGES, SSL_EXCEPTION, BAD_HEADERS, compliance doc read/write, settings changes
2. **Multiple sink options**: internal_opensearch (index on same cluster), internal_opensearch_data_stream, external_opensearch (remote cluster), webhook (arbitrary HTTP endpoint — Slack, SIEM), log4j (file-based, with any Log4j appender including Kafka, JDBC, Cassandra)
3. **Granular filtering**: disable specific categories, ignore specific users (e.g., kibanaserver), ignore specific request patterns, exclude sensitive headers
4. **Compliance features**: document-level read/write tracking (which user read which fields of which documents), field-level watching
5. **Dynamic configuration**: can change audit config at runtime via the security index without restarting the cluster

## Known Issues & User Complaints (GitHub + Forums)

| Issue | Source | Impact |
|-------|--------|--------|
| INDEX_EVENT flooding — thousands/hour filling disk | [OpenSearch Forum](https://forum.opensearch.org/t/index-event-flooding-audit-logs/10674) | Storage explosion, unreadable logs |
| Settings not working — disabled_categories ignored or confusing | [Issue #2673](https://github.com/opensearch-project/security/issues/2673) | Users can't filter noise |
| REST vs transport category split is confusing | [Issue #3380](https://github.com/opensearch-project/security/issues/3380) | Silent misconfigurations |
| Failed requests not logged — malformed body drops event | [Issue #1849](https://github.com/opensearch-project/security/issues/1849) | Security blind spots |
| No audit without FGAC | [Issue #501](https://github.com/opensearch-project/.github/issues/501), [#502](https://github.com/opensearch-project/.github/issues/502) | Zero visibility for non-FGAC users |
| plugins.security.disabled broken in 2.12 | [Issue #4062](https://github.com/opensearch-project/security/issues/4062) | Deployment friction |

## What FGAC Currently Cannot Do (Gaps)

1. No audit without full security stack — the #1 gap our project addresses
2. No custom SIEM sink interface — users want Splunk, Datadog, etc. without modifying plugin code
3. No alerting on audit events — can't trigger alerts on suspicious patterns ([alerting #108](https://github.com/opensearch-project/alerting/issues/108))
4. Self-referential logging — writing audit to internal index generates more audit events (recursion)
5. No dynamic config in non-FGAC mode — config is in security index, which doesn't exist without FGAC
6. Audit log message truncation — AWS limits to 10,000 chars. Large resolved_indices fields get cut off.
7. No independent release cycle — audit improvements blocked by unrelated security plugin releases

## Storage Options (Ranked by Production-Readiness)

| Sink | Pros | Cons | Best for |
|------|------|------|----------|
| log4j (file) | Simple, low overhead, any Log4j appender (Kafka, etc.) | Requires log rotation, can fill disk, no search | Dev/testing, or input to log shipper |
| internal_opensearch | Searchable, integrated with Dashboards | Self-referential, impacts cluster perf | Small clusters, low audit volume |
| internal_opensearch_data_stream | Better lifecycle mgmt, rollover | Same self-referential problem | Medium clusters with ISM policies |
| external_opensearch | Separates audit from data workload | Requires second cluster | Production compliance |
| webhook | Real-time, integrates with any SIEM | Network dependency, potential data loss | SIEM integration (Splunk, Datadog) |

## Compliance Best Practices

- **SOC2/HIPAA/PCI-DSS**: Audit logs should be stored on a SEPARATE system (prevents attackers from covering tracks)
- **Immutability**: Logs should be append-only with retention policies. Data streams + ISM rollover.
- **Real-time alerting**: Webhook to SIEM with correlation rules (e.g., "5 failed logins in 60 seconds")
- **Retention**: HIPAA requires 6 years, PCI-DSS requires 1 year, SOC2 varies by org policy

## How This Defends Our Design Choices

1. **Why REQUEST_AUDIT instead of reusing GRANTED_PRIVILEGES?** — Users already complained about confusing category names (#3380, #2673). Misleading semantics worsen the problem.
2. **Why standalone instead of fixing FGAC?** — Issue #502: "Users who only need audit trails must adopt the full security plugin" — massive over-engineering.
3. **Why unified disabled_categories?** — The REST/transport split directly caused #3380 and #2673. The distinction is invisible to users.
4. **Why multiple sinks matter?** — Compliance says audit logs belong on a separate system. We preserve all existing sink options.
5. **Why not just a log shipper (Fluent Bit)?** — Shippers capture stdout generically. They don't understand OpenSearch request semantics. Structured events enable meaningful SIEM rules.

## References

- [OpenSearch Audit Logs Docs](https://docs.opensearch.org/latest/security/audit-logs/storage-types/)
- [Repo Request #502 — opensearch-audit-logging](https://github.com/opensearch-project/.github/issues/502)
- [Proposal #501 — Standalone audit logging](https://github.com/opensearch-project/.github/issues/501)
- [AWS OpenSearch Audit Docs](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/audit-logs.html)
- [Opster Guide — OpenSearch Audit Logs](https://opster.com/guides/opensearch/opensearch-security/opensearch-audit-logs/)
- [DataSunrise — native logs rarely satisfy regulatory requirements on their own](https://www.datasunrise.com/knowledge-center/amazon-opensearch-audit-log/)
