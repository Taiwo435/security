# Docker Testing Commands Reference

## Terminal 1 — Watch Logs

```bash
# View ALL logs in real time (follow mode)
docker logs -f opensearch-audit-test

# View only audit events in real time
docker logs -f opensearch-audit-test 2>&1 | grep "REQUEST_AUDIT"

# View only YOUR requests (from Mac, not internal cluster ops)
docker logs -f opensearch-audit-test 2>&1 | grep "172.19.0.1"

# View startup warnings (deprecation + auth categories)
docker logs opensearch-audit-test 2>&1 | grep -i "deprecated\|will not produce"

# Pretty-print audit events
docker logs opensearch-audit-test 2>&1 | grep "REQUEST_AUDIT" | grep "172.19.0.1" | python3 -c "
import sys, json
for line in sys.stdin:
    start = line.find('{')
    if start >= 0:
        try:
            data = json.loads(line[start:])
            print(json.dumps(data, indent=2))
        except: pass
"

# Count total audit events
docker logs opensearch-audit-test 2>&1 | grep "REQUEST_AUDIT" | wc -l

# Count only your requests
docker logs opensearch-audit-test 2>&1 | grep "REQUEST_AUDIT" | grep "172.19.0.1" | wc -l
```

## Terminal 2 — Send Requests

```bash
# Cluster health
curl -sk https://localhost:9200/_cluster/health

# Create index
curl -sk -X PUT https://localhost:9200/my-test-index -H 'Content-Type: application/json' -d '{"settings":{"number_of_shards":1}}'

# Index document
curl -sk -X PUT https://localhost:9200/my-test-index/_doc/1 -H 'Content-Type: application/json' -d '{"name":"taiwo","role":"intern"}'

# Get document
curl -sk https://localhost:9200/my-test-index/_doc/1

# Search
curl -sk https://localhost:9200/my-test-index/_search

# Update document
curl -sk -X POST https://localhost:9200/my-test-index/_update/1 -H 'Content-Type: application/json' -d '{"doc":{"role":"engineer"}}'

# Bulk (multiple indices)
curl -sk -X POST https://localhost:9200/_bulk -H 'Content-Type: application/json' -d '
{"index":{"_index":"logs-2026.06.24","_id":"1"}}
{"message":"server started","level":"info"}
{"index":{"_index":"logs-2026.06.24","_id":"2"}}
{"message":"request received","level":"debug"}
'

# Multi-get
curl -sk -X POST https://localhost:9200/_mget -H 'Content-Type: application/json' -d '{"docs":[{"_index":"my-test-index","_id":"1"},{"_index":"logs-2026.06.24","_id":"1"}]}'

# Wildcard search
curl -sk https://localhost:9200/logs-*/_search

# Non-existent index (404 — still logged)
curl -sk https://localhost:9200/does-not-exist/_doc/999

# Delete document
curl -sk -X DELETE https://localhost:9200/my-test-index/_doc/1

# Nodes info
curl -sk https://localhost:9200/_nodes

# Alias
curl -sk -X POST https://localhost:9200/_aliases -H 'Content-Type: application/json' -d '{"actions":[{"add":{"index":"logs-2026.06.24","alias":"current-logs"}}]}'

# Count
curl -sk https://localhost:9200/logs-2026.06.24/_count

# Delete index
curl -sk -X DELETE https://localhost:9200/my-test-index
```

## Docker Container Commands

```bash
# List running containers
docker ps

# Exec into container
docker exec -it opensearch-audit-test bash

# Check our plugin is installed (run inside container)
ls /usr/share/opensearch/plugins/opensearch-security/

# Check opensearch.yml config (run inside container)
cat /usr/share/opensearch/config/opensearch.yml

# Exit container
exit

# Stop cluster
cd ~/Desktop/security/docker && docker compose down

# Start fresh cluster
cd ~/Desktop/security/docker && docker compose down && docker compose up -d

# Rebuild plugin and restart (after code changes)
cd ~/Desktop/security && ./gradlew bundlePlugin -x test -x integrationTest
cd docker/plugin && rm -rf * && unzip ../build/distributions/opensearch-security-3.8.0.0-SNAPSHOT.zip && sed -i '' 's/opensearch.version=3.8.0/opensearch.version=3.7.0/' plugin-descriptor.properties
cd .. && docker compose down && docker compose up -d
```

## Grep Filters

```bash
# Only searches
docker logs opensearch-audit-test 2>&1 | grep "REQUEST_AUDIT" | grep "SearchRequest"

# Only writes (index, update, delete, bulk)
docker logs opensearch-audit-test 2>&1 | grep "REQUEST_AUDIT" | grep "data/write"

# Only admin ops (create index, delete index, aliases)
docker logs opensearch-audit-test 2>&1 | grep "REQUEST_AUDIT" | grep "indices:admin"

# Only cluster ops
docker logs opensearch-audit-test 2>&1 | grep "REQUEST_AUDIT" | grep "cluster:"

# Events with specific index
docker logs opensearch-audit-test 2>&1 | grep "REQUEST_AUDIT" | grep "my-test-index"

# Events with wildcard indices
docker logs opensearch-audit-test 2>&1 | grep "REQUEST_AUDIT" | grep "logs-\*"
```


## Testing CN/SAN (Client Certificate Identity)

```bash
# Request WITHOUT client cert (only IP in audit event)
curl -sk https://localhost:9200/_cluster/health

# Request WITH client cert (CN=taiwo shows as effective_user)
curl -sk --cert ~/Desktop/security/docker/certs/client.pem --key ~/Desktop/security/docker/certs/client-key.pem https://localhost:9200/_cluster/health

# Compare the two in logs (look for audit_request_effective_user)
docker logs opensearch-audit-test 2>&1 | grep "172.19.0.1" | grep "ClusterHealthRequest"
```

## Verifying Warnings at Startup

```bash
# Deprecation warning (split settings detected)
docker logs opensearch-audit-test 2>&1 | grep "deprecated"

# Auth-only categories warning
docker logs opensearch-audit-test 2>&1 | grep "will not produce"

# SSL-only mode confirmation
docker logs opensearch-audit-test 2>&1 | grep "ssl only mode"
```
