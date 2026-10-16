//! IP blocking on a customer's WAF (#1167) — port of
//! `app/customer_waf/services/blocks.py`.
//!
//! The WAF has no blocklist API: a block is a custom Coraza rule denying
//! `REMOTE_ADDR` in phase 1. CoPilot creates exactly one rule shape:
//!
//! ```text
//! SecRule REMOTE_ADDR "@ipMatch <target>" "id:AUTO,phase:1,deny,status:403,log,msg:'CoPilot block: <target>',tag:'copilot-block'"
//! ```
//!
//! - **The rule text is built here from a parsed network**, never from the
//!   request: only `ip_network`'s canonical string reaches SecLang, and the
//!   analyst's reason goes into the rule's *description*. Unlike Python, a
//!   target whose canonical form keeps an IPv6 zone (`fe80::1%…`) is refused:
//!   `ipaddress` accepts any text after the `%`, quotes included, which would
//!   reach the rule text (RUST_MIGRATION.md §4).
//! - **Only CoPilot's own rules are changed** (`tag:'copilot-block'`); the
//!   WAF's own IP blocks are listed and respected, never modified.
//! - **Unblock disables, never deletes**; a re-block re-enables.
//! - **Over-broad ranges are refused**: IPv4 wider than /16, IPv6 wider than /48.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{construct, kwargs};
use copilot_upstream::py::{PyExc, getitem, int_of};
use http::Method;

use crate::client::{Call, WafClient, WafResult};
use crate::ip::{Network, ip_network};
use crate::schema::WAF_BLOCK;
use crate::store::WafRow;

/// `COPILOT_BLOCK_TAG`.
pub const COPILOT_BLOCK_TAG: &str = "copilot-block";
/// `COPILOT_BLOCK_NAME_PREFIX`.
pub const COPILOT_BLOCK_NAME_PREFIX: &str = "CoPilot block: ";
/// `WRITE_TIMEOUT` (seconds): a rule write reloads Caddy on the WAF.
pub const WRITE_TIMEOUT: f64 = 30.0;

/// `normalize_target`: the canonical network, or `BlockTargetError`'s text.
pub fn normalize_target(value: &str) -> Result<Network, String> {
    let raw = copilot_web::form::py_strip(value);
    let invalid = || format!("'{raw}' is not an IPv4/IPv6 address or CIDR range");
    let network = ip_network(raw).ok_or_else(invalid)?;
    if network.scope.is_some() {
        // The zone would reach the rule text verbatim (see the module docs).
        return Err(invalid());
    }
    let minimum = if network.v6 { 48 } else { 16 };
    if network.prefix < minimum {
        return Err(format!(
            "{network} is too broad to block from CoPilot (IPv{} ranges must be /{minimum} or \
             narrower)",
            network.version()
        ));
    }
    Ok(network)
}

/// `display`: a single host as an address, a range as CIDR.
pub fn display(network: &Network) -> String {
    if network.prefix == network.max_prefixlen() {
        network.address_str()
    } else {
        network.to_string()
    }
}

/// `target_warnings`.
pub fn target_warnings(network: &Network) -> Vec<String> {
    let a = network.address();
    if a.is_loopback() || a.is_unspecified() {
        return vec![format!(
            "{} is a loopback/unspecified address — blocking it has no useful effect.",
            display(network)
        )];
    }
    if a.is_private() || a.is_link_local() || a.is_reserved() || a.is_multicast() {
        return vec![format!(
            "{} is not a public address. That is expected only if the WAF sits behind a load \
             balancer or proxy that it sees traffic from — blocking the proxy's address would \
             block everyone behind it.",
            display(network)
        )];
    }
    Vec::new()
}

/// `build_rule_text` — the only place SecLang for a CoPilot block is made.
pub fn build_rule_text(network: &Network) -> String {
    let target = display(network);
    format!(
        "SecRule REMOTE_ADDR \"@ipMatch {target}\" \"id:AUTO,phase:1,deny,status:403,log,msg:'\
         {COPILOT_BLOCK_NAME_PREFIX}{target}',tag:'{COPILOT_BLOCK_TAG}'\""
    )
}

/// `" ".join(text.split())`.
pub fn collapse_whitespace(text: &str) -> String {
    text.split(copilot_web::form::is_py_space)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `build_description`.
pub fn build_description(
    reason: &str,
    username: &str,
    alert_id: Option<i64>,
    case_id: Option<i64>,
) -> String {
    let mut parts = vec![
        collapse_whitespace(reason),
        format!("by {username} via CoPilot"),
    ];
    if let Some(a) = alert_id {
        parts.push(format!("alert #{a}"));
    }
    if let Some(c) = case_id {
        parts.push(format!("case #{c}"));
    }
    parts.join(" | ")
}

// --- reading the WAF's rules -------------------------------------------------------

/// `rule.get(key) or ""` for a text column (a non-string is `str()`-ed only
/// where Python formats it; here it is a `TypeError` in `in`/`startswith`).
fn text_or_empty(rule: &PyValue, key: &str) -> Result<String, PyExc> {
    match copilot_upstream::py::get(rule, key)? {
        None => Ok(String::new()),
        Some(v) if !v.truthy() => Ok(String::new()),
        Some(PyValue::Str(s)) => Ok(s.clone()),
        Some(other) => Err(PyExc::TypeError(format!(
            "expected string or bytes-like object, got '{}'",
            copilot_upstream::py::type_name(other)
        ))),
    }
}

/// `is_copilot_rule`.
pub fn is_copilot_rule(rule: &PyValue) -> Result<bool, PyExc> {
    let conf = text_or_empty(rule, "conf_text")?;
    if conf.contains(&format!("tag:'{COPILOT_BLOCK_TAG}'")) {
        return Ok(true);
    }
    Ok(text_or_empty(rule, "name")?.starts_with(COPILOT_BLOCK_NAME_PREFIX))
}

/// `_SPLIT.split(value)` with `[,\s]+`.
fn split_tokens(value: &str) -> Vec<&str> {
    value
        .split(|c: char| c == ',' || copilot_web::form::is_py_space(c))
        .collect()
}

/// `rule_networks`: the networks a simple `REMOTE_ADDR @ipMatch` deny rule
/// blocks; `[]` for any other rule (judged by its text, not its stored
/// `action`).
pub fn rule_networks(rule: &PyValue) -> Result<Vec<Network>, PyExc> {
    let field = text_or_empty(rule, "field")?;
    let operator = text_or_empty(rule, "operator")?;
    if field.to_uppercase() != "REMOTE_ADDR" || operator != "@ipMatch" {
        return Ok(Vec::new());
    }
    let conf = text_or_empty(rule, "conf_text")?;
    if !conf.contains("deny") || conf.contains("chain") || conf.contains("ctl:ruleEngine") {
        return Ok(Vec::new());
    }
    let value = text_or_empty(rule, "value")?;
    Ok(split_tokens(&value)
        .into_iter()
        .filter_map(ip_network)
        .collect())
}

/// `to_block(rule, network)`: the `WafBlock` dump.
pub fn to_block(rule: &PyValue, network: Option<&Network>) -> Result<PyValue, PyExc> {
    let nets = rule_networks(rule)?;
    let target = match network {
        Some(n) => display(n),
        None => {
            let joined = nets.iter().map(display).collect::<Vec<_>>().join(", ");
            if joined.is_empty() {
                match copilot_upstream::py::get(rule, "value")? {
                    Some(v) if v.truthy() => match v {
                        PyValue::Str(s) => s.clone(),
                        // Pydantic gets the raw value as `target`.
                        other => return block_dump(rule, other.clone()),
                    },
                    _ => String::new(),
                }
            } else {
                joined
            }
        }
    };
    block_dump(rule, PyValue::Str(target))
}

fn block_dump(rule: &PyValue, target: PyValue) -> Result<PyValue, PyExc> {
    let id = getitem(rule, "id")?.py_str();
    let rule_id = int_of(getitem(rule, "rule_id")?)?;
    let get = |k: &str| copilot_upstream::py::get(rule, k).map(|v| v.cloned());
    let or_empty = |v: Option<PyValue>| match v {
        Some(v) if v.truthy() => v,
        _ => PyValue::Str(String::new()),
    };
    construct(
        &WAF_BLOCK,
        &kwargs(vec![
            ("target", target),
            ("rule_uuid", PyValue::Str(id)),
            ("rule_id", PyValue::Int(rule_id)),
            ("name", or_empty(get("name")?)),
            ("description", or_empty(get("description")?)),
            (
                "enabled",
                PyValue::Bool(get("is_enabled")?.is_some_and(|v| v.truthy())),
            ),
            ("created_by_copilot", PyValue::Bool(is_copilot_rule(rule)?)),
            ("created_at", get("created_at")?.unwrap_or(PyValue::None)),
        ]),
    )
}

/// `fetch_rules`: `list(await waf_request(…, "GET", "/rules/custom") or [])`.
pub async fn fetch_rules(client: &WafClient, row: &WafRow) -> WafResult<Vec<PyValue>> {
    let body = client
        .request(row, Call::new(Method::GET, "/rules/custom"))
        .await?;
    if !body.truthy() {
        return Ok(Vec::new());
    }
    Ok(copilot_upstream::py::iterate(&body)?)
}

/// `ip_block_rules`: (CoPilot's IP blocks, the WAF's own IP blocks).
pub fn ip_block_rules(rules: &[PyValue]) -> Result<(Vec<PyValue>, Vec<PyValue>), PyExc> {
    let (mut copilot, mut other) = (Vec::new(), Vec::new());
    for rule in rules {
        if rule_networks(rule)?.is_empty() {
            continue;
        }
        if is_copilot_rule(rule)? {
            copilot.push(rule.clone());
        } else {
            other.push(rule.clone());
        }
    }
    Ok((copilot, other))
}

/// `_covers`.
pub fn covers(rule: &PyValue, network: &Network) -> Result<bool, PyExc> {
    Ok(rule_networks(rule)?
        .iter()
        .any(|n| n.v6 == network.v6 && network.subnet_of(n)))
}

/// `_exact`.
pub fn exact(rule: &PyValue, network: &Network) -> Result<bool, PyExc> {
    Ok(rule_networks(rule)?.iter().any(|n| n == network))
}

fn enabled(rule: &PyValue) -> Result<bool, PyExc> {
    Ok(copilot_upstream::py::get(rule, "is_enabled")?.is_some_and(PyValue::truthy))
}

fn rule_uuid(rule: &PyValue) -> Result<String, PyExc> {
    Ok(getitem(rule, "id")?.py_str())
}

/// What `block` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockAction {
    /// A new rule.
    Created,
    /// CoPilot's disabled rule re-enabled.
    Reenabled,
    /// CoPilot already blocks it.
    AlreadyBlocked,
    /// A WAF-owned rule already blocks it.
    BlockedByWafRule,
}

impl BlockAction {
    /// The literal.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Reenabled => "reenabled",
            Self::AlreadyBlocked => "already_blocked",
            Self::BlockedByWafRule => "blocked_by_waf_rule",
        }
    }
}

/// `block`: make sure `network` is blocked; `(action, rule)`.
pub async fn block(
    client: &WafClient,
    row: &WafRow,
    network: &Network,
    description: &str,
) -> WafResult<(BlockAction, PyValue)> {
    let rules = fetch_rules(client, row).await?;
    let (copilot, other) = ip_block_rules(&rules)?;
    let mut mine = Vec::new();
    for r in &copilot {
        if exact(r, network)? {
            mine.push(r.clone());
        }
    }
    for r in &mine {
        if enabled(r)? {
            return Ok((BlockAction::AlreadyBlocked, r.clone()));
        }
    }
    for r in copilot.iter().chain(other.iter()) {
        if enabled(r)? && covers(r, network)? {
            let action = if is_copilot_rule(r)? {
                BlockAction::AlreadyBlocked
            } else {
                BlockAction::BlockedByWafRule
            };
            return Ok((action, r.clone()));
        }
    }
    if let Some(first) = mine.first() {
        let body = kwargs(vec![
            ("is_enabled", PyValue::Bool(true)),
            ("description", PyValue::Str(description.to_string())),
        ]);
        let rule = client
            .request(
                row,
                Call::new(Method::PUT, format!("/rules/custom/{}", rule_uuid(first)?))
                    .json(body)
                    .timeout(WRITE_TIMEOUT),
            )
            .await?;
        return Ok((BlockAction::Reenabled, rule));
    }
    let body = kwargs(vec![
        (
            "name",
            PyValue::Str(format!("{COPILOT_BLOCK_NAME_PREFIX}{}", display(network))),
        ),
        ("description", PyValue::Str(description.to_string())),
        ("raw_conf_text", PyValue::Str(build_rule_text(network))),
    ]);
    let rule = client
        .request(
            row,
            Call::new(Method::POST, "/rules/custom")
                .json(body)
                .timeout(WRITE_TIMEOUT),
        )
        .await?;
    Ok((BlockAction::Created, rule))
}

/// What `unblock` found: `(unblocked?, rules, the WAF's own covering rule)`.
pub type Unblocked = (bool, Vec<PyValue>, Option<PyValue>);

/// `unblock`: disable CoPilot's rule(s) for exactly `network`.
pub async fn unblock(client: &WafClient, row: &WafRow, network: &Network) -> WafResult<Unblocked> {
    let rules = fetch_rules(client, row).await?;
    let (copilot, other) = ip_block_rules(&rules)?;
    let mut mine = Vec::new();
    for r in &copilot {
        if exact(r, network)? {
            mine.push(r.clone());
        }
    }
    let mut waf_rule = None;
    for r in &other {
        if enabled(r)? && covers(r, network)? {
            waf_rule = Some(r.clone());
            break;
        }
    }
    let mut active = Vec::new();
    for r in &mine {
        if enabled(r)? {
            active.push(r.clone());
        }
    }
    if active.is_empty() {
        return Ok((false, mine, waf_rule));
    }
    let mut updated = Vec::new();
    for r in &active {
        updated.push(
            client
                .request(
                    row,
                    Call::new(Method::PUT, format!("/rules/custom/{}", rule_uuid(r)?))
                        .json(kwargs(vec![("is_enabled", PyValue::Bool(false))]))
                        .timeout(WRITE_TIMEOUT),
                )
                .await?,
        );
    }
    Ok((true, updated, waf_rule))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::ip_network;
    use copilot_upstream::json::pydantic_json;
    use copilot_upstream::respond::from_json;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("waf_vectors.json")).unwrap()
    }

    #[test]
    fn targets_like_python() {
        for case in vectors()["targets"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let got = normalize_target(input);
            match case.get("network") {
                Some(net) => {
                    let net = net.as_str().unwrap();
                    if net.contains('%') {
                        // Deliberate: a zone would reach the rule text.
                        assert!(got.is_err(), "{input:?} must be refused");
                        continue;
                    }
                    let n = got.unwrap_or_else(|e| panic!("{input:?}: {e}"));
                    assert_eq!(n.to_string(), net, "{input:?}");
                    assert_eq!(display(&n), case["display"].as_str().unwrap());
                    assert_eq!(i64::from(n.version()), case["version"].as_i64().unwrap());
                    let warnings: Vec<String> = case["warnings"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|w| w.as_str().unwrap().to_string())
                        .collect();
                    assert_eq!(target_warnings(&n), warnings, "{input:?}");
                    assert_eq!(build_rule_text(&n), case["rule_text"].as_str().unwrap());
                }
                None => assert_eq!(
                    got.unwrap_err(),
                    case["error"].as_str().unwrap(),
                    "{input:?}"
                ),
            }
        }
    }

    #[test]
    fn rules_like_python() {
        let v = vectors();
        let rules: Vec<PyValue> = v["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| from_json(&r["rule"]))
            .collect();
        for (case, rule) in v["rules"].as_array().unwrap().iter().zip(&rules) {
            let nets: Vec<String> = rule_networks(rule)
                .unwrap()
                .iter()
                .map(ToString::to_string)
                .collect();
            let want: Vec<String> = case["networks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_str().unwrap().to_string())
                .collect();
            assert_eq!(nets, want);
            assert_eq!(
                is_copilot_rule(rule).unwrap(),
                case["is_copilot"].as_bool().unwrap()
            );
            let block = to_block(rule, None).unwrap();
            let want: Value = case["block"].clone();
            let got: Value = serde_json::from_str(&pydantic_json(&block)).unwrap();
            assert_eq!(got, want);
        }
        let (copilot, other) = ip_block_rules(&rules).unwrap();
        let ids = |rs: &[PyValue]| -> Vec<i64> {
            rs.iter()
                .map(|r| {
                    int_of(getitem(r, "rule_id").unwrap())
                        .unwrap()
                        .parse()
                        .unwrap()
                })
                .collect()
        };
        assert_eq!(Value::from(ids(&copilot)), v["split"]["copilot"].clone());
        assert_eq!(Value::from(ids(&other)), v["split"]["other"].clone());
        for m in v["matrix"].as_array().unwrap() {
            let rule = rules
                .iter()
                .find(|r| {
                    from_json(&m["rule_id"]).py_str() == getitem(r, "rule_id").unwrap().py_str()
                })
                .unwrap();
            let target = ip_network(m["target"].as_str().unwrap()).unwrap();
            assert_eq!(
                covers(rule, &target).unwrap(),
                m["covers"].as_bool().unwrap(),
                "{m}"
            );
            assert_eq!(
                exact(rule, &target).unwrap(),
                m["exact"].as_bool().unwrap(),
                "{m}"
            );
        }
        for d in v["descriptions"].as_array().unwrap() {
            assert_eq!(
                build_description(
                    d["reason"].as_str().unwrap(),
                    d["username"].as_str().unwrap(),
                    d["alert_id"].as_i64(),
                    d["case_id"].as_i64()
                ),
                d["out"].as_str().unwrap()
            );
        }
    }
}
