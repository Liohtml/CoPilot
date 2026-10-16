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


# --- InfluxDB 2.7 ----------------------------------------------------------------------------------
#
# The `statuses` rows of InfluxDB's `_monitoring` bucket, as three checks of a SOCFortress stack
# write them, and a stand-in for the query engine: the Flux texts CoPilot sends are recognised (the
# state query's `last()`, the rows query's level filters / `group()` / `limit`, check-name
# `distinct`, `schema.tagValues`, the Telegraf metric queries) and answered in annotated CSV the way
# InfluxDB writes it (one annotation block per schema, table ids running across blocks, CRLF).

INFLUX_START, INFLUX_STOP = "2026-10-08T10:00:00Z", "2026-10-15T10:30:00Z"
_CPU, _SVC, _DISK = "0c1a2b3c4d5e6f70", "0d1a2b3c4d5e6f71", "0e1a2b3c4d5e6f72"


def _status(minute, check_id, check_name, level, message, **tags):
    return {
        "_time": f"2026-10-15T10:{minute:02d}:00Z" if minute != 9 else "2026-10-15T10:09:00.123456789Z",
        "_value": message,
        "_check_id": check_id,
        "_check_name": check_name,
        "_field": "_message",
        "_level": level,
        "_measurement": "statuses",
        "_source_measurement": tags.pop("source", "cpu"),
        "_type": "threshold",
        **tags,
    }


INFLUX_STATUSES = [
    _status(0, _CPU, "CPU CHECK", "crit", "CPU usage is 97% — hot", host="web-01", cpu="cpu-total"),
    _status(5, _CPU, "CPU CHECK", "ok", "CPU usage is 12%", host="web-01", cpu="cpu-total"),
    _status(3, _CPU, "CPU CHECK", "warn", 'CPU usage is 81%, "busy"', host="db-01", cpu="cpu-total"),
    _status(
        1,
        _SVC,
        "CRITICAL SERVICES CHECK",
        "crit",
        "wazuh-manager failed",
        source="systemd_units",
        host="web-01",
        name="wazuh-manager.service",
        active="failed",
        sub="failed",
        load="loaded",
    ),
    _status(
        6,
        _SVC,
        "CRITICAL SERVICES CHECK",
        "ok",
        "wazuh-manager running",
        source="systemd_units",
        host="web-01",
        name="wazuh-manager.service",
        active="active",
        sub="running",
        load="loaded",
    ),
    _status(
        4,
        _SVC,
        "CRITICAL SERVICES CHECK",
        "crit",
        "graylog-server failed",
        source="systemd_units",
        host="web-01",
        name="graylog-server.service",
        active="failed",
        sub="failed",
        load="loaded",
    ),
    _status(
        9,
        _SVC,
        "CRITICAL SERVICES CHECK",
        "ok",
        "nginx running",
        source="systemd_units",
        host="db-01",
        name="nginx.service",
        active="active",
        sub="running",
        load="loaded",
    ),
    _status(
        2,
        _DISK,
        "Disk Usage",
        "warn",
        "/ is 85% full",
        source="disk",
        host="web-01",
        path="/",
        device="sda1",
        fstype="ext4",
        mode="rw",
    ),
    _status(7, _DISK, "Disk Usage", "ok", "/ is 40% full", source="disk", host="web-01", path="/", device="sda1", fstype="ext4", mode="rw"),
    _status(
        7,
        _DISK,
        "Disk Usage",
        "crit",
        "/ is read-only",
        source="disk",
        host="web-01",
        path="/",
        device="sda1",
        fstype="ext4",
        mode="ro",
    ),
]

_TIME_COLUMNS = ("_start", "_stop", "_time")


def flux_csv(blocks):
    """Annotated CSV: `blocks` is a list of (columns, tables); a column is (name, datatype, group),
    a table a list of rows (dicts). Table ids run across the blocks."""
    import csv
    import io

    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    table_id = 0
    for columns, tables in blocks:
        writer.writerow(["#group", "false", "false", *("true" if c[2] else "false" for c in columns)])
        writer.writerow(["#datatype", "string", "long", *(c[1] for c in columns)])
        writer.writerow(["#default", "_result", "", *("" for _ in columns)])
        writer.writerow(["", "result", "table", *(c[0] for c in columns)])
        for rows in tables:
            for row in rows:
                writer.writerow(["", "", str(table_id), *(str(row.get(c[0], "")) for c in columns)])
            table_id += 1
        out.write("\r\n")
    return out.getvalue() or "\r\n"


def _status_columns(rows, grouped):
    names = []
    for row in rows:
        for key in row:
            if key not in names:
                names.append(key)
    order = ["_start", "_stop", "_time", "_value"] + sorted(n for n in names if n not in ("_start", "_stop", "_time", "_value"))
    return [(n, "dateTime:RFC3339" if n in _TIME_COLUMNS else "string", grouped and n not in ("_time", "_value")) for n in order]


def _flux_unescape(literal):
    return literal.replace('\\"', '"').replace("\\${", "${").replace("\\\\", "\\")


def _series_key(row):
    return tuple(sorted((k, v) for k, v in row.items() if k not in ("_start", "_stop", "_time", "_value")))


def influx_statuses(query, statuses):
    import re

    rows = [{"_start": INFLUX_START, "_stop": INFLUX_STOP, **r} for r in statuses]
    for name in ("check_name_pattern", "sensor_type_pattern"):
        m = re.search(name + r' = regexp\.compile\(v: regexp\.quoteMeta\(v: "((?:[^"\\]|\\.)*)"\)\)', query)
        if m:
            needle = _flux_unescape(m.group(1))
            rows = [r for r in rows if needle in r["_check_name"]]
    if "|> last()" in query:
        latest = {}
        for row in rows:
            key = _series_key(row)
            if key not in latest or row["_time"] > latest[key]["_time"]:
                latest[key] = row
        blocks = {}
        for row in latest.values():
            schema = tuple(sorted(k for k in row))
            blocks.setdefault(schema, []).append([row])
        return flux_csv([(_status_columns([t[0] for t in tables], True), tables) for tables in blocks.values()])
    wanted = re.findall(r'r\._level == "(\w+)"', query)
    if wanted:
        rows = [r for r in rows if r["_level"] in wanted]
    if 'r._level != "ok"' in query:
        rows = [r for r in rows if r["_level"] != "ok"]
    rows.sort(key=lambda r: r["_time"], reverse=True)
    m = re.search(r"limit\(n: (\d+)\)", query)
    if m:
        rows = rows[: int(m.group(1))]
    if not rows:
        return "\r\n"
    return flux_csv([(_status_columns(rows, False), [rows])])


INFLUX_HOSTS = ["web-01", "db-01", ""]
_METRIC_TAGS = {
    "cpu": [{"cpu": "cpu-total"}],
    "disk": [
        {"path": "/", "device": "sda1", "fstype": "ext4", "mode": "rw"},
        {"path": "/boot", "device": "sda2", "fstype": "ext4", "mode": "rw"},
    ],
    "diskio": [{"name": "sda"}, {"name": "sdb"}],
    "net": [{"interface": "eth0"}, {"interface": "lo"}],
}
_LONG_FIELDS = {"uptime", "total", "n_cpus", "n_users", "free", "running", "sleeping", "unknown", "zombies", "tcp_established", "used"}


def _metric_value(measurement, field, index, point):
    if field == "total" and measurement == "mem":
        return 16794951680
    if field == "uptime":
        return 1234567
    if field == "usage_idle":
        return 1e-7 if index else 97.25
    if field == "bytes_recv":
        return 1e16 + point
    return (
        round((len(measurement) * 7 + len(field) * 3 + index * 5 + point) / 3, 12) if point % 2 else (len(field) * 10 + index + point) / 3
    )


def influx_metric(query):
    import re

    m = re.search(r'r\["_measurement"\] == "(\w+)"', query)
    if not m:
        return "\r\n"
    measurement = m.group(1)
    fields = re.findall(r'r\["_field"\] == "(\w+)"', query)
    host = re.search(r'r\["host"\] == "(.*)"\)\n', query)
    host = host.group(1) if host else ""
    if host not in INFLUX_HOSTS[:2]:
        return "\r\n"
    last = query.rstrip().endswith("|> last()")
    tag_sets = _METRIC_TAGS.get(measurement, [{}])
    tag_names = sorted({k for t in tag_sets for k in t})
    columns = [("_start", "dateTime:RFC3339", True), ("_stop", "dateTime:RFC3339", True), ("_time", "dateTime:RFC3339", False)]
    long_values = last and all(f in _LONG_FIELDS for f in fields) and measurement != "disk"
    columns.append(("_value", "long" if long_values else "double", False))
    columns += [("_field", "string", True), ("_measurement", "string", True)]
    columns += (
        [(t, "string", True) for t in tag_names if t < "host"]
        + [("host", "string", True)]
        + [(t, "string", True) for t in tag_names if t > "host"]
    )
    tables = []
    for field in fields:
        for index, tags in enumerate(tag_sets):
            points = [9] if last else [0, 1, 2]
            rows = []
            for point in points:
                value = _metric_value(measurement, field, index, point)
                if measurement == "disk" and field == "total":
                    value = float(250059350016 if index == 0 else 1023303680)
                rows.append(
                    {
                        "_start": INFLUX_START,
                        "_stop": INFLUX_STOP,
                        "_time": f"2026-10-15T10:{point * 10:02d}:00Z" if point != 9 else "2026-10-15T10:29:59.999999999Z",
                        "_value": int(value) if long_values else repr(float(value)),
                        "_field": field,
                        "_measurement": measurement,
                        "host": host,
                        **tags,
                    },
                )
            tables.append(rows)
    return flux_csv([(columns, tables)])


def influx_answer(query, statuses):
    """The CSV InfluxDB would answer for one of CoPilot's Flux queries."""
    if 'r._measurement == "statuses"' in query and "distinct(" not in query:
        return influx_statuses(query, statuses)
    if 'distinct(column: "_check_name")' in query:
        names = sorted({r["_check_name"] for r in statuses})
        return flux_csv([([("_check_name", "string", True)], [[{"_check_name": n}] for n in names])])
    if "schema.tagValues" in query:
        return flux_csv([([("_value", "string", False)], [[{"_value": h} for h in INFLUX_HOSTS]])])
    return influx_metric(query)


# --- Grafana 11 ------------------------------------------------------------------------------------

GRAFANA_ORGS = [{"id": 1, "name": "Main Org."}, {"id": 44, "name": "ACME Corp"}]


def _hit(hit_id, uid, title, kind="dash-db", folder=None, tags=()):
    hit = {
        "id": hit_id,
        "uid": uid,
        "orgId": 44,
        "title": title,
        "uri": f"db/{title.lower().replace(' ', '-')}",
        "url": f"/d/{uid}/{title.lower().replace(' ', '-')}" if kind == "dash-db" else f"/dashboards/f/{uid}/",
        "slug": "",
        "type": kind,
        "tags": list(tags),
        "isStarred": False,
        "sortMeta": 0,
        "permanentlyDeleteDate": "0001-01-01T00:00:00Z",
    }
    if folder:
        hit.update({"folderId": folder[0], "folderUid": folder[1], "folderTitle": folder[2], "folderUrl": f"/dashboards/f/{folder[1]}/"})
    return hit


GRAFANA_SEARCH = {
    1: [_hit(3, "home01", "Home")],
    44: [
        _hit(5, "f1huntress", "HUNTRESS", kind="dash-folder"),
        _hit(12, "ab9bab2c-5d86-43e7-bac2-c1d68fc91342", "HUNTRESS - SUMMARY", folder=(5, "f1huntress", "HUNTRESS"), tags=["huntress"]),
        _hit(13, "sap01", "SAP Users Auth", folder=(5, "f1huntress", "HUNTRESS")),
    ],
}


def _timeseries(panel_id, title, x=0, y=0):
    return {
        "datasource": {"type": "grafana-opensearch-datasource", "uid": "ds1"},
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "palette-classic"},
                "custom": {"drawStyle": "line", "lineWidth": 1, "fillOpacity": 10},
                "mappings": [],
                "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "red", "value": 80}]},
            },
            "overrides": [],
        },
        "gridPos": {"h": 8, "w": 12, "x": x, "y": y},
        "id": panel_id,
        "options": {
            "legend": {"calcs": [], "displayMode": "list", "placement": "bottom", "showLegend": True},
            "tooltip": {"mode": "single", "sort": "none"},
        },
        "targets": [{"query": "*", "refId": "A"}],
        "title": title,
        "type": "timeseries",
    }


GRAFANA_DASHBOARD = {
    "meta": {
        "type": "db",
        "canSave": True,
        "canEdit": True,
        "canAdmin": True,
        "canStar": True,
        "canDelete": True,
        "slug": "huntress-summary",
        "url": "/d/ab9bab2c-5d86-43e7-bac2-c1d68fc91342/huntress-summary",
        "expires": "0001-01-01T00:00:00Z",
        "created": "2026-01-01T10:00:00Z",
        "updated": "2026-01-02T10:00:00Z",
        "updatedBy": "admin",
        "createdBy": "admin",
        "version": 3,
        "hasAcl": False,
        "isFolder": False,
        "folderId": 5,
        "folderUid": "f1huntress",
        "folderTitle": "HUNTRESS",
        "folderUrl": "/dashboards/f/f1huntress/huntress",
        "provisioned": False,
        "provisionedExternalId": "",
        "annotationsPermissions": {
            "dashboard": {"canAdd": True, "canEdit": True, "canDelete": True},
            "organization": {"canAdd": True, "canEdit": True, "canDelete": True},
        },
        "publicDashboardEnabled": False,
    },
    "dashboard": {
        "annotations": {
            "list": [
                {
                    "builtIn": 1,
                    "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                    "enable": True,
                    "hide": True,
                    "iconColor": "rgba(0, 211, 255, 1)",
                    "name": "Annotations & Alerts",
                    "type": "dashboard",
                },
            ],
        },
        "editable": True,
        "fiscalYearStartMonth": 0,
        "graphTooltip": 0,
        "id": 12,
        "links": [],
        "liveNow": False,
        "panels": [
            _timeseries(1, "Incidents over time"),
            {
                "collapsed": True,
                "gridPos": {"h": 1, "w": 24, "x": 0, "y": 8},
                "id": 7,
                "panels": [_timeseries(8, "Agents — détails", y=9)],
                "title": "Details",
                "type": "row",
            },
            {"datasource": {"uid": "ds1"}, "gridPos": {"h": 4, "w": 6, "x": 12, "y": 0}, "id": 4, "title": "Total", "type": "stat"},
        ],
        "refresh": "",
        "schemaVersion": 39,
        "tags": ["huntress"],
        "templating": {"list": []},
        "time": {"from": "now-24h", "to": "now"},
        "timepicker": {},
        "timezone": "browser",
        "title": "HUNTRESS - SUMMARY",
        "uid": "ab9bab2c-5d86-43e7-bac2-c1d68fc91342",
        "version": 3,
        "weekStart": "",
    },
}
