"""Sample answers of the tools behind the ported connectors — NOT collected by pytest.

Shared by `rust_parity_graylog_e2e.py` (its Graylog / InfluxDB / Grafana / Portainer stand-ins
answer with these) and `scripts/gen-connector-model-vectors.py` (the model vectors are built from
them and their mutations). Shapes follow the tools' real APIs: Graylog 6.1 and 7.0 (the 7.x
personality differs where 7.0 does: encrypted input attributes as `{"is_set": …}`, the URL
allowlist path), InfluxDB 2.7, Grafana 11, Portainer 2.21.
"""

import copy

GRAYLOG_SYSTEM_6 = {
    "facility": "graylog-server",
    "codename": "Noir",
    "node_id": "5ca1ab1e-0000-4000-8000-000000000001",
    "cluster_id": "c1a55e00-0000-4000-8000-000000000001",
    "version": "6.1.4+d7b6e3c",
    "started_at": "2026-10-01T08:00:00.000Z",
    "hostname": "graylog01",
    "lifecycle": "running",
    "lb_status": "alive",
    "timezone": "UTC",
    "operating_system": "Linux 6.8.0",
    "is_processing": True,
}
GRAYLOG_SYSTEM_7 = {**GRAYLOG_SYSTEM_6, "version": "7.0.1+abc1234", "codename": "Siracusa"}


def _shard(docs):
    op = {"total": 3, "time_seconds": 0}
    return {
        "documents": {"count": docs, "deleted": 0},
        "flush": dict(op),
        "get": dict(op),
        "index": {"total": docs, "time_seconds": 1},
        "merge": dict(op),
        "open_search_contexts": 0,
        "refresh": dict(op),
        "search_fetch": dict(op),
        "search_query": dict(op),
        "segments": 4,
        "store_size_bytes": 123456 + docs,
    }


def _index_info(docs):
    return {
        "primary_shards": _shard(docs),
        "all_shards": _shard(docs),
        "routing": [
            {
                "id": 0,
                "state": "STARTED",
                "active": True,
                "primary": True,
                "node_id": "nodeA",
                "node_name": "opensearch01",
                "node_hostname": "10.0.0.5",
                "relocating_to": None,
            },
        ],
        "reopened": False,
    }


GRAYLOG_INDICES = {
    "closed": {"indices": [], "total": 0},
    "all": {
        "indices": {
            "wazuh-alerts-3x_0": _index_info(10),
            "wazuh-alerts-3x_1": _index_info(7),
            "gl-events_0": _index_info(2),
        },
        "total": 3,
    },
}

_TLS_PASSWORD_6 = ""
_TLS_PASSWORD_7 = {"is_set": False}


def _attributes(tls_password, port=12201):
    return {
        "recv_buffer_size": 1048576,
        "tcp_keepalive": False,
        "use_null_delimiter": True,
        "number_worker_threads": 4,
        "tls_client_auth_cert_file": "",
        "bind_address": "0.0.0.0",
        "tls_cert_file": "",
        "decompress_size_limit": 8388608,
        "port": port,
        "tls_key_file": "",
        "tls_enable": False,
        "tls_key_password": tls_password,
        "max_message_size": 2097152,
        "tls_client_auth": "disabled",
        "override_source": None,
        "charset_name": "UTF-8",
    }


def graylog_input(input_id, title, tls_password=_TLS_PASSWORD_6, port=12201):
    return {
        "title": title,
        "global": True,
        "name": "GELF TCP",
        "content_pack": None,
        "created_at": "2026-01-02T03:04:05.678Z",
        "type": "org.graylog2.inputs.gelf.tcp.GELFTCPInput",
        "creator_user_id": "admin",
        "attributes": _attributes(tls_password, port),
        "static_fields": {"source_tag": "wazuh"},
        "node": None,
        "id": input_id,
    }


def graylog_inputs(version):
    tls = _TLS_PASSWORD_7 if version == 7 else _TLS_PASSWORD_6
    return {
        "inputs": [
            graylog_input("65a000000000000000000001", "Wazuh GELF", tls),
            graylog_input("65a000000000000000000002", "Syslog TCP", {"is_set": True} if version == 7 else "secret", 1514),
        ],
        "total": 2,
    }


def graylog_input_states(version):
    states = []
    for i, inp in enumerate(graylog_inputs(version)["inputs"]):
        message_input = copy.deepcopy(inp)
        for key in ("force_rdns", "store_full_message", "expand_structured_data", "override_source", "charset_name", "allow_override_date"):
            message_input["attributes"].pop(key, None)
        states.append(
            {
                "id": inp["id"],
                "state": "RUNNING" if i == 0 else "FAILED",
                "started_at": "2026-10-01T08:00:01.000Z",
                "detailed_message": None if i == 0 else "Address already in use",
                "message_input": message_input,
            },
        )
    return {"states": states}


def graylog_event_definition(def_id, title, expression=None, series=None):
    return {
        "id": def_id,
        "title": title,
        "description": f"{title} description",
        "priority": 2,
        "alert": True,
        "config": {
            "type": "aggregation-v1",
            "query": "rule_level:>=12",
            "query_parameters": [],
            "streams": ["000000000000000000000001"],
            "group_by": ["agent_name"],
            "series": series if series is not None else [],
            "conditions": {"expression": expression},
            "search_within_ms": 60000,
            "execute_every_ms": 60000,
            "event_limit": 100,
        },
        "field_spec": {
            "COPILOT_ALERT_ID": {
                "data_type": "string",
                "providers": [{"type": "template-v1", "template": "NONE", "require_values": False}],
            },
        },
        "key_spec": [],
        "notification_settings": {"grace_period_ms": 0, "backlog_size": 0},
        "notifications": [{"notification_id": "6600000000000000000000aa", "notification_parameters": None}],
        "storage": [{"type": "persist-to-streams-v1", "streams": ["000000000000000000000002"]}],
        "_scope": "DEFAULT",
        "state": "ENABLED",
    }


GRAYLOG_EVENT_DEFINITIONS = [
    graylog_event_definition("6600000000000000000000d1", "WAZUH SYSLOG LEVEL ALERT"),
    graylog_event_definition(
        "6600000000000000000000d2",
        "SOCFORTRESS WAF BRUTE FORCE",
        expression={
            "expr": ">=",
            "left": {"expr": "number-ref", "ref": "count-"},
            "right": {"expr": "number", "value": 30},
        },
        series=[{"id": "count-", "type": "count", "field": None}],
    ),
    graylog_event_definition("6600000000000000000000d3", "OFFICE365 ALERT", series=[{"id": "card-x", "type": "card", "field": "x"}]),
]

GRAYLOG_ALERT_EVENT = {
    "event": {
        "id": "01JABCDEF0000000000000000A",
        "event_definition_type": "aggregation-v1",
        "event_definition_id": "6600000000000000000000d1",
        "origin_context": "urn:graylog:message:es:wazuh-alerts-3x_0:abc",
        "timestamp": "2026-10-15T10:00:00.000Z",
        "timestamp_processing": "2026-10-15T10:00:01.000Z",
        "timerange_start": None,
        "timerange_end": None,
        "streams": ["000000000000000000000002"],
        "source_streams": ["000000000000000000000001"],
        "message": "WAZUH SYSLOG LEVEL ALERT",
        "source": "graylog01",
        "key_tuple": [],
        "key": None,
        "priority": 2,
        "alert": True,
        "fields": {"COPILOT_ALERT_ID": "NONE"},
        "group_by_fields": {},
        "replay_info": None,
    },
    "index_name": "gl-events_0",
    "index_type": "message",
}

GRAYLOG_EVENTS_SEARCH = {
    "events": [GRAYLOG_ALERT_EVENT],
    "used_indices": ["gl-events_0"],
    "parameters": {
        "page": 1,
        "per_page": 100,
        "timerange": {"type": "relative", "range": 86400},
        "query": "",
        "filter": {"alerts": "only", "event_definitions": []},
        "sort_by": "timestamp",
        "sort_direction": "desc",
    },
    "total_events": 1,
    "duration": 7,
    "context": {
        "event_definitions": {
            "6600000000000000000000d1": {
                "id": "6600000000000000000000d1",
                "title": "WAZUH SYSLOG LEVEL ALERT",
                "description": "x",
            },
        },
        "streams": {"000000000000000000000002": {"id": "000000000000000000000002", "title": "All events", "description": "Stream"}},
    },
}

GRAYLOG_URL_ALLOWLIST = {
    "entries": [
        {"id": "0e1f0000-0000-4000-8000-000000000001", "value": "https://copilot.example/api", "title": "CoPilot", "type": "literal"},
        {"id": "0e1f0000-0000-4000-8000-000000000002", "value": "https://.*\\.example", "title": "Regex", "type": "regex"},
    ],
    "disabled": False,
}

GRAYLOG_MESSAGES = {
    "messages": [
        {
            "caller": "org.graylog2.periodical.IndexRetentionThread",
            "content": "Index rotation done",
            "node_id": "5ca1ab1e-0000-4000-8000-000000000001",
            "timestamp": "2026-10-15T09:00:00.000Z",
        },
        {"caller": "x", "content": "Ünïcödé ✓", "node_id": "n", "timestamp": "2026-10-15T09:00:01.000Z"},
    ],
    "total": 42,
}

GRAYLOG_METRICS = {
    "version": "4.0.0",
    "gauges": {
        "org.graylog2.buffers.input.usage": {"value": 0},
        "jvm.memory.heap.used": {"value": 123},
        "org.graylog2.buffers.output.usage": {"value": 3},
        "org.graylog2.throughput.input.1-sec-rate": {"value": 12.5},
        "org.graylog2.buffers.process.usage": {"value": 1e-07},
        "org.graylog2.throughput.output.1-sec-rate": {"value": 10000000000000000.0},
    },
    "counters": {
        "org.graylog2.throughput.output": {"count": 1000},
        "org.graylog2.throughput.input": {"count": 1200, "value": "7"},
    },
    "histograms": {},
    "meters": {},
    "timers": {},
}

GRAYLOG_JOURNAL = {
    "enabled": True,
    "append_events_per_second": 0,
    "read_events_per_second": 0,
    "uncommitted_journal_entries": 17,
    "journal_size": 1024,
    "journal_size_limit": 5368709120,
    "number_of_segments": 1,
}

GRAYLOG_EVENT_NOTIFICATIONS = {
    "total": 1,
    "page": 1,
    "per_page": 50,
    "count": 1,
    "notifications": [
        {
            "id": "6600000000000000000000aa",
            "title": "SEND TO COPILOT",
            "description": "Notification to CoPilot",
            "config": {
                "type": "http-notification-v1",
                "url": "http://copilot:5000/api/x",
                "basic_auth": {"is_set": False},
                "api_key_as_header": False,
                "api_key": "",
                "api_secret": {"is_set": False},
                "skip_tls_verification": False,
            },
        },
    ],
    "query": "",
    "grand_total": 1,
}

GRAYLOG_STREAMS = {
    "total": 2,
    "streams": [
        {
            "id": "000000000000000000000001",
            "creator_user_id": "local:admin",
            "outputs": [],
            "matching_type": "AND",
            "description": "Contains messages that are not explicitly routed to other streams",
            "created_at": "2026-01-01T00:00:00.000Z",
            "disabled": False,
            "rules": [],
            "alert_conditions": [],
            "title": "Default Stream",
            "content_pack": None,
            "remove_matches_from_default_stream": False,
            "index_set_id": "65a0000000000000000000f1",
            "is_default": True,
            "is_editable": False,
            "categories": [],
        },
        {
            "id": "65a0000000000000000000a1",
            "creator_user_id": "admin",
            "outputs": [{"id": "o1"}],
            "matching_type": "OR",
            "description": None,
            "created_at": "2026-02-01T00:00:00.000Z",
            "disabled": False,
            "rules": [
                {
                    "field": "agent_labels_customer",
                    "stream_id": "65a0000000000000000000a1",
                    "description": "",
                    "id": "65a0000000000000000000b1",
                    "type": 1,
                    "inverted": False,
                    "value": "acme",
                },
            ],
            "title": "ACME",
            "content_pack": None,
            "remove_matches_from_default_stream": True,
            "index_set_id": "65a0000000000000000000f2",
            "is_default": False,
            "is_editable": True,
            "categories": [],
        },
    ],
}

GRAYLOG_PIPELINES = [
    {
        "id": "65a0000000000000000000c1",
        "title": "WAZUH PROCESSING PIPELINE",
        "description": "Processing pipeline for Wazuh",
        "source": 'pipeline "WAZUH PROCESSING PIPELINE"\nstage 0 match either\nrule "WAZUH CREATE FIELD SYSLOG LEVEL - ALERT"\nrule "missing rule"\nend',
        "created_at": "2026-01-01T00:00:00.000Z",
        "modified_at": "2026-01-02T00:00:00.000Z",
        "stages": [
            {"stage": 0, "match_all": False, "match": "EITHER", "rules": ["WAZUH CREATE FIELD SYSLOG LEVEL - ALERT", "missing rule"]},
            {"stage": 1, "match_all": True, "match": "ALL", "rules": []},
        ],
        "errors": None,
    },
    {
        "id": "65a0000000000000000000c2",
        "title": "No description",
        "source": 'pipeline "x"\nend',
        "created_at": "2026-01-03T00:00:00.000Z",
        "stages": [],
    },
]

GRAYLOG_PIPELINE_RULES = [
    {
        "id": "65a0000000000000000000e1",
        "title": "WAZUH CREATE FIELD SYSLOG LEVEL - ALERT",
        "description": "",
        "source": 'rule "WAZUH CREATE FIELD SYSLOG LEVEL - ALERT"\nwhen true\nthen\nend',
        "created_at": "2026-01-01T00:00:00.000Z",
        "modified_at": "2026-01-01T00:00:00.000Z",
        "errors": None,
    },
    {
        "id": "65a0000000000000000000e2",
        "title": "Other",
        "source": 'rule "Other" when false then end',
        "created_at": "2026-01-01T00:00:00.000Z",
    },
]
