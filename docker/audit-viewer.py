#!/usr/bin/env python3
"""Pretty-print standalone audit log events from docker logs in real-time.
Filters out internal plugin activity to show only user-initiated requests."""
import sys
import json

INTERNAL_INDEX_PREFIXES = ('.opensearch-', '.plugins-', 'top_queries-')

for line in sys.stdin:
    if '"REQUEST_AUDIT"' not in line:
        continue
    try:
        start = line.index('{')
        event = json.loads(line[start:])
        
        # Skip events targeting internal indices
        indices = event.get('audit_trace_indices', [])
        if indices and all(any(idx.startswith(p) for p in INTERNAL_INDEX_PREFIXES) for idx in indices):
            continue
        
        # Skip if no remote address (internal cluster operations)
        if 'audit_request_remote_address' not in event and 'audit_rest_request_headers' not in event:
            continue

        print(json.dumps(event, indent=2))
        print()
        sys.stdout.flush()
    except (ValueError, json.JSONDecodeError):
        pass
