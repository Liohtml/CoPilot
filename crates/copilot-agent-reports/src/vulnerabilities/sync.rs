//! The vulnerability sync — `sync_vulnerabilities_for_agent`,
//! `_sync_vulnerabilities_bulk_mode` and `sync_all_vulnerabilities`.
//!
//! What the ORM does is reproduced as its effect on the table: the batch
//! mode keeps one in-memory object per `{agent_id}_{cve}_{package}` key (a
//! row read at the start, or one created by an earlier document), applies
//! each document to it, and flushes a batch as one transaction — the
//! updates, then the inserts in the order they were added. A failed batch is
//! rolled back: the objects it created are detached (a later document of
//! theirs adds them again), the rows it changed read as stored. The bulk
//! mode inserts every document it does not find among the rows read at the
//! start (duplicates included) and then runs one `UPDATE` per match, after
//! the inserts (the ORM's autoflush), all in one transaction.
//!
//! A database error is SQLAlchemy's text (`(pymysql.err.IntegrityError)
//! (1452, '…')\n[SQL: …]\n[parameters: …]\n(Background on this error at:
//! …)`), with the autoflush note when an `UPDATE` statement flushed the
//! inserts.

use std::collections::HashMap;

use chrono::NaiveDateTime;
use serde_json::Value;

use copilot_auth::pyvalue::str_repr;
use copilot_ingest::py::IsoDateTime;
use copilot_wazuh::error::PyErr;

use crate::AgentReportsState;
use crate::agents::{self, On};

use super::db::{self, NewVuln, VulnRow, VulnUpdate};
use super::indexer::{self, VulnData, doc_id};

/// `VulnerabilitySyncResponse`'s fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    /// `success`.
    pub success: bool,
    /// `message`.
    pub message: String,
    /// `synced_count`.
    pub synced: i64,
    /// `errors`.
    pub errors: Vec<String>,
    /// Whether the sync went through `session.rollback()`: every object the
    /// session held is expired then, and the next agent of a loop over
    /// them is `MissingGreenlet` (not part of the answer).
    pub rolled_back: bool,
}

/// `str(MissingGreenlet)`: what reading an expired attribute raises in an
/// `AsyncSession`.
pub const MISSING_GREENLET: &str = "greenlet_spawn has not been called; can't call await_only() \
    here. Was IO attempted in an unexpected place? (Background on this error at: \
    https://sqlalche.me/e/20/xd2s)";

impl SyncOutcome {
    fn ok(message: String, synced: i64, errors: Vec<String>) -> Self {
        Self {
            success: true,
            message,
            synced,
            errors,
            rolled_back: false,
        }
    }

    /// The response dump.
    pub fn dump(&self) -> copilot_auth::pyvalue::PyValue {
        super::schema::sync_response(
            self.success,
            self.message.clone(),
            self.synced,
            &self.errors,
        )
    }
}

/// `str()` of a database error the service catches (`except Exception`).
pub fn db_text(e: &copilot_db::DbError) -> String {
    e.to_string()
}

/// What MySQL stores for a datetime the ORM binds: `pymysql` writes the
/// wall time (an offset is dropped), the column keeps whole seconds.
pub fn stored(dt: &IsoDateTime) -> NaiveDateTime {
    copilot_core::time::mysql_datetime(dt.wall)
}

/// `repr()` of a `datetime` among SQLAlchemy's `[parameters: …]`.
fn datetime_param(dt: &IsoDateTime) -> String {
    let base = crate::pyfmt::datetime_repr(dt.wall);
    let Some(off) = dt.offset_us else {
        return base;
    };
    let tz = if off == 0 {
        "datetime.timezone.utc".to_string()
    } else {
        format!(
            "datetime.timezone({})",
            copilot_ingest::py::timedelta_repr(off)
        )
    };
    format!("{}, tzinfo={tz})", base.trim_end_matches(')'))
}

fn opt_repr(v: &Option<String>) -> String {
    v.as_deref().map_or_else(|| "None".into(), str_repr)
}

/// The ORM's `INSERT` of an `AgentVulnerabilities` row.
const INSERT_SQL: &str = "INSERT INTO agent_vulnerabilities (cve_id, severity, title, \
    `references`, status, discovered_at, remediated_at, epss_score, epss_percentile, \
    package_name, agent_id, customer_code) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, \
    %s)";

/// One object the ORM would hold for a new row.
#[derive(Debug, Clone)]
struct Pending {
    cve_id: String,
    vals: Vals,
    agent_id: String,
    customer_code: Option<String>,
}

/// The columns a document sets.
#[derive(Debug, Clone)]
struct Vals {
    severity: String,
    title: String,
    references: Option<String>,
    discovered_at: IsoDateTime,
    epss_score: Option<String>,
    package_name: Option<String>,
}

impl Pending {
    fn row(&self) -> NewVuln {
        NewVuln {
            cve_id: self.cve_id.clone(),
            severity: self.vals.severity.clone(),
            title: self.vals.title.clone(),
            references: self.vals.references.clone(),
            discovered_at: stored(&self.vals.discovered_at),
            epss_score: self.vals.epss_score.clone(),
            package_name: self.vals.package_name.clone(),
            agent_id: self.agent_id.clone(),
            customer_code: self.customer_code.clone(),
        }
    }

    fn params(&self) -> String {
        format!(
            "({}, {}, {}, {}, 'Active', {}, None, {}, None, {}, {}, {})",
            str_repr(&self.cve_id),
            str_repr(&self.vals.severity),
            str_repr(&self.vals.title),
            opt_repr(&self.vals.references),
            datetime_param(&self.vals.discovered_at),
            opt_repr(&self.vals.epss_score),
            opt_repr(&self.vals.package_name),
            str_repr(&self.agent_id),
            opt_repr(&self.customer_code),
        )
    }
}

/// An insert that failed: SQLAlchemy's text of the flush error.
fn insert_error(e: &sqlx::Error, p: &Pending) -> String {
    copilot_incidents::datastore::services::sqlalchemy_error(e, INSERT_SQL, &p.params()).text()
}

const AUTOFLUSH: &str = "(raised as a result of Query-invoked autoflush; consider using a \
    session.no_autoflush block if this flush is occurring prematurely)";

fn key_package(p: &Option<String>) -> &str {
    p.as_deref().filter(|p| !p.is_empty()).unwrap_or("None")
}

fn vals_of(v: &VulnData) -> Vals {
    Vals {
        severity: v.severity.clone(),
        title: v.title.clone(),
        references: v.references.clone(),
        discovered_at: v.detected_at,
        epss_score: None,
        package_name: v.package_name.clone(),
    }
}

/// A row read at the start, as the ORM holds it.
#[derive(Debug, Clone)]
struct Held {
    id: i64,
    committed: Vals,
    current: Vals,
}

fn vals_of_row(r: &VulnRow) -> Vals {
    Vals {
        severity: r.severity.clone(),
        title: r.title.clone(),
        references: r.references.clone(),
        discovered_at: crate::pyfmt::naive(r.discovered_at),
        epss_score: r.epss_score.clone(),
        package_name: r.package_name.clone(),
    }
}

#[derive(Debug, Clone)]
enum Slot {
    Held(Held),
    /// Created by a document; `added` while the session holds it.
    New {
        obj: Pending,
        added: bool,
    },
}

/// `sync_vulnerabilities_for_agent(agent_name, customer_code, batch_size,
/// use_bulk_mode)`.
pub async fn sync_for_agent(
    st: &AgentReportsState,
    agent_name: &str,
    customer_code: Option<&str>,
    batch_size: i64,
    bulk: bool,
) -> SyncOutcome {
    match run_for_agent(st, agent_name, customer_code, batch_size, bulk).await {
        Ok(outcome) => outcome,
        Err(text) => {
            tracing::error!("Error syncing vulnerabilities for agent {agent_name}: {text}");
            SyncOutcome {
                success: false,
                message: format!("Failed to sync vulnerabilities for agent {agent_name}: {text}"),
                synced: 0,
                errors: vec![text],
                rolled_back: true,
            }
        }
    }
}

async fn run_for_agent(
    st: &AgentReportsState,
    agent_name: &str,
    customer_code: Option<&str>,
    batch_size: i64,
    bulk: bool,
) -> Result<SyncOutcome, String> {
    let db = &st.ctx.db;
    let agent = agents::first(db, &[On::Hostname(agent_name)])
        .await
        .map_err(|e| db_text(&e))?;
    let Some(agent) = agent else {
        return Ok(SyncOutcome {
            success: false,
            message: format!("Agent {agent_name} not found in database"),
            synced: 0,
            errors: vec![format!("Agent {agent_name} not found")],
            rolled_back: false,
        });
    };
    let customer_code = match customer_code {
        Some(c) if !c.is_empty() => Some(c.to_string()),
        _ => agent.customer_code.clone(),
    };
    let agent_id = agent.agent_id.clone();
    let docs = indexer::fetch_for_agent(&st.wazuh, agent_name)
        .await
        .map_err(|e: PyErr| e.py_str())?;
    tracing::info!(
        "Fetched {} vulnerabilities for agent {agent_name}",
        docs.len()
    );
    if docs.is_empty() {
        return Ok(SyncOutcome::ok(
            format!("No vulnerabilities found for agent {agent_name}"),
            0,
            Vec::new(),
        ));
    }
    if bulk {
        tracing::info!(
            "Using BULK MODE for {} vulnerabilities for agent {agent_name}",
            docs.len()
        );
        return Ok(bulk_mode(st, &agent_id, agent_name, customer_code, &docs).await);
    }
    if batch_size == 0 {
        return Err("range() arg 3 must not be zero".into());
    }
    let existing = db::existing(db, &agent_id).await.map_err(|e| db_text(&e))?;
    let mut slots: Vec<Slot> = Vec::new();
    let mut lookup: HashMap<String, usize> = HashMap::new();
    for r in &existing {
        let key = format!(
            "{}_{}_{}",
            r.agent_id,
            r.cve_id,
            key_package(&r.package_name)
        );
        let vals = vals_of_row(r);
        slots.push(Slot::Held(Held {
            id: i64::from(r.id),
            committed: vals.clone(),
            current: vals,
        }));
        lookup.insert(key, slots.len() - 1);
    }
    let mut synced = 0i64;
    let mut errors: Vec<String> = Vec::new();
    let mut rolled_back = false;
    let total = docs.len();
    let step = usize::try_from(batch_size).unwrap_or(0);
    if step == 0 {
        // A negative step: `range(0, n, step)` is empty.
        return Ok(finished(agent_name, synced, errors));
    }
    let mut start = 0usize;
    while start < total {
        let end = (start + step).min(total);
        tracing::info!(
            "Processing batch {}: vulnerabilities {}-{end} of {total} for agent {agent_name}",
            start / step + 1,
            start + 1
        );
        let mut touched: Vec<usize> = Vec::new();
        let mut added: Vec<usize> = Vec::new();
        let (mut updates, mut inserts) = (0i64, 0i64);
        let mut batch_errors: Vec<String> = Vec::new();
        for doc in &docs[start..end] {
            let v = match indexer::process_document(doc) {
                Ok(v) => v,
                Err(e) => {
                    let msg = format!("Error processing vulnerability {}: {e}", doc_id(doc));
                    tracing::error!("{msg}");
                    batch_errors.push(msg);
                    continue;
                }
            };
            let key = format!("{agent_id}_{}_{}", v.cve_id, key_package(&v.package_name));
            if let Some(&i) = lookup.get(&key) {
                apply_update(&mut slots[i], &v);
                match &mut slots[i] {
                    Slot::Held(_) => {
                        if !touched.contains(&i) {
                            touched.push(i);
                        }
                    }
                    Slot::New {
                        added: is_added, ..
                    } => {
                        if !*is_added {
                            *is_added = true;
                            added.push(i);
                        }
                    }
                }
                updates += 1;
            } else {
                slots.push(Slot::New {
                    obj: Pending {
                        cve_id: v.cve_id.clone(),
                        vals: vals_of(&v),
                        agent_id: agent_id.clone(),
                        customer_code: customer_code.clone(),
                    },
                    added: true,
                });
                lookup.insert(key, slots.len() - 1);
                added.push(slots.len() - 1);
                inserts += 1;
            }
        }
        match flush(st, &mut slots, &touched, &added).await {
            Ok(()) => {
                synced += updates + inserts;
                tracing::info!(
                    "Batch {} completed: {updates} updates, {inserts} inserts, {} errors",
                    start / step + 1,
                    batch_errors.len()
                );
                errors.extend(batch_errors);
            }
            Err(e) => {
                rollback(&mut slots, &added);
                rolled_back = true;
                let msg = format!("Error processing batch {start}-{end}: {e}");
                tracing::error!("{msg}");
                errors.push(msg);
            }
        }
        start += step;
    }
    Ok(SyncOutcome {
        rolled_back,
        ..finished(agent_name, synced, errors)
    })
}

fn finished(agent_name: &str, synced: i64, errors: Vec<String>) -> SyncOutcome {
    SyncOutcome::ok(
        format!(
            "Successfully synced {synced} vulnerabilities for agent {agent_name} ({}",
            errors.len()
        ),
        synced,
        errors,
    )
}

/// The batch mode's update of an object (`existing_vuln.severity = …`).
fn apply_update(slot: &mut Slot, v: &VulnData) {
    let vals = match slot {
        Slot::Held(h) => &mut h.current,
        Slot::New { obj, .. } => &mut obj.vals,
    };
    vals.severity = v.severity.clone();
    vals.title = v.title.clone();
    vals.references = v.references.clone();
    vals.discovered_at = v.detected_at;
    if v.base_score_truthy() {
        vals.epss_score = v.base_score_text();
    }
    vals.package_name = v.package_name.clone();
}

/// The commit of one batch: the changed rows (by id), then the new ones in
/// the order they were added.
async fn flush(
    st: &AgentReportsState,
    slots: &mut [Slot],
    touched: &[usize],
    added: &[usize],
) -> Result<(), String> {
    let mut tx = st.ctx.db.pool().begin().await.map_err(|e| e.to_string())?;
    let mut held: Vec<usize> = touched.to_vec();
    held.sort_by_key(|&i| match &slots[i] {
        Slot::Held(h) => h.id,
        Slot::New { .. } => i64::MAX,
    });
    for &i in &held {
        if let Slot::Held(h) = &slots[i] {
            let u = VulnUpdate {
                severity: h.current.severity.clone(),
                title: h.current.title.clone(),
                references: h.current.references.clone(),
                discovered_at: stored(&h.current.discovered_at),
                epss_score: Some(h.current.epss_score.clone()),
                package_name: h.current.package_name.clone(),
            };
            db::update(&mut tx, h.id, &u)
                .await
                .map_err(|e| e.to_string())?;
        }
    }
    let mut ids: Vec<(usize, i64)> = Vec::new();
    for &i in added {
        if let Slot::New { obj, .. } = &slots[i] {
            match db::insert(&mut tx, &obj.row()).await {
                Ok(id) => ids.push((i, id)),
                Err(e) => {
                    let text = insert_error(&e, obj);
                    let _ = tx.rollback().await;
                    return Err(text);
                }
            }
        }
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    for slot in slots.iter_mut() {
        if let Slot::Held(h) = slot {
            h.committed = h.current.clone();
        }
    }
    for (i, id) in ids {
        if let Slot::New { obj, .. } = &slots[i] {
            let vals = obj.vals.clone();
            slots[i] = Slot::Held(Held {
                id,
                committed: vals.clone(),
                current: vals,
            });
        }
    }
    Ok(())
}

/// `session.rollback()`: the batch's new objects leave the session, the
/// rows it changed read as stored again.
fn rollback(slots: &mut [Slot], added: &[usize]) {
    for slot in slots.iter_mut() {
        if let Slot::Held(h) = slot {
            h.current = h.committed.clone();
        }
    }
    for &i in added {
        if let Slot::New { added, .. } = &mut slots[i] {
            *added = false;
        }
    }
}

/// `_sync_vulnerabilities_bulk_mode(...)`.
async fn bulk_mode(
    st: &AgentReportsState,
    agent_id: &str,
    agent_name: &str,
    customer_code: Option<String>,
    docs: &[Value],
) -> SyncOutcome {
    tracing::info!(
        "BULK MODE: Processing {} vulnerabilities for agent {agent_name}",
        docs.len()
    );
    let mut processed: Vec<VulnData> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for doc in docs {
        match indexer::process_document(doc) {
            Ok(v) => processed.push(v),
            Err(e) => {
                let msg = format!("Error processing vulnerability {}: {e}", doc_id(doc));
                tracing::error!("{msg}");
                errors.push(msg);
            }
        }
    }
    if processed.is_empty() {
        return SyncOutcome::ok(
            format!("No valid vulnerabilities to process for agent {agent_name}"),
            0,
            errors,
        );
    }
    let failed = |text: String| {
        tracing::error!("BULK MODE: Error syncing vulnerabilities for agent {agent_name}: {text}");
        SyncOutcome {
            success: false,
            message: format!(
                "BULK MODE: Failed to sync vulnerabilities for agent {agent_name}: {text}"
            ),
            synced: 0,
            errors: vec![text],
            rolled_back: true,
        }
    };
    let existing = match db::existing(&st.ctx.db, agent_id).await {
        Ok(rows) => rows,
        Err(e) => return failed(db_text(&e)),
    };
    let mut lookup: HashMap<String, &VulnRow> = HashMap::new();
    for r in &existing {
        lookup.insert(format!("{}_{}", r.cve_id, key_package(&r.package_name)), r);
    }
    let mut new_rows: Vec<Pending> = Vec::new();
    let mut updates: Vec<(i64, VulnUpdate)> = Vec::new();
    for v in &processed {
        let key = format!("{}_{}", v.cve_id, key_package(&v.package_name));
        match lookup.get(&key) {
            Some(r) => updates.push((
                i64::from(r.id),
                VulnUpdate {
                    severity: v.severity.clone(),
                    title: v.title.clone(),
                    references: v.references.clone(),
                    discovered_at: stored(&v.detected_at),
                    epss_score: Some(if v.base_score_truthy() {
                        v.base_score_text()
                    } else {
                        r.epss_score.clone()
                    }),
                    package_name: v.package_name.clone(),
                },
            )),
            None => new_rows.push(Pending {
                cve_id: v.cve_id.clone(),
                vals: vals_of(v),
                agent_id: agent_id.to_string(),
                customer_code: customer_code.clone(),
            }),
        }
    }
    let (inserted, updated) = (new_rows.len() as i64, updates.len() as i64);
    let run = async {
        let mut tx = st.ctx.db.pool().begin().await.map_err(|e| e.to_string())?;
        for p in &new_rows {
            if let Err(e) = db::insert(&mut tx, &p.row()).await {
                let text = insert_error(&e, p);
                let _ = tx.rollback().await;
                // An `UPDATE` statement flushed the inserts.
                return Err(if updates.is_empty() {
                    text
                } else {
                    format!("{AUTOFLUSH}\n{text}")
                });
            }
        }
        for (id, u) in &updates {
            db::update(&mut tx, *id, u)
                .await
                .map_err(|e| e.to_string())?;
        }
        tx.commit().await.map_err(|e| e.to_string())
    };
    if let Err(text) = run.await {
        return failed(text);
    }
    let total = inserted + updated;
    tracing::info!(
        "BULK MODE: Successfully synced {total} vulnerabilities ({inserted} new, {updated} updated)"
    );
    SyncOutcome::ok(
        format!(
            "BULK MODE: Successfully synced {total} vulnerabilities for agent {agent_name} ({inserted} new, {updated} updated)"
        ),
        total,
        errors,
    )
}

/// `sync_all_vulnerabilities(customer_code, batch_size, use_bulk_mode)`.
pub async fn sync_all(
    st: &AgentReportsState,
    customer_code: Option<&str>,
    batch_size: i64,
    bulk: bool,
) -> SyncOutcome {
    let mode = if bulk {
        "bulk mode".to_string()
    } else {
        format!("batch mode (size: {batch_size})")
    };
    let code = customer_code.filter(|c| !c.is_empty());
    tracing::info!(
        "Starting bulk vulnerability sync for customer: {} using {mode}",
        code.unwrap_or("all agents")
    );
    let terms: Vec<On<'_>> = code.map(On::Customer).into_iter().collect();
    let agents = match agents::select(&st.ctx.db, &terms).await {
        Ok(a) => a,
        Err(e) => {
            let text = db_text(&e);
            tracing::error!("Error in bulk vulnerability sync: {text}");
            return SyncOutcome {
                success: false,
                message: format!("Failed to sync vulnerabilities: {text}"),
                synced: 0,
                errors: vec![text],
                rolled_back: false,
            };
        }
    };
    if agents.is_empty() {
        let message = match code {
            Some(c) => format!("No agents found for customer {c}"),
            None => "No agents found in database".to_string(),
        };
        return SyncOutcome::ok(message, 0, Vec::new());
    }
    let mut total = 0i64;
    let mut errors: Vec<String> = Vec::new();
    let mut expired = false;
    for agent in &agents {
        // `agent.hostname` of an object a rollback expired.
        if expired {
            tracing::error!("Error in bulk vulnerability sync: {MISSING_GREENLET}");
            return SyncOutcome {
                success: false,
                message: format!("Failed to sync vulnerabilities: {MISSING_GREENLET}"),
                synced: 0,
                errors: vec![MISSING_GREENLET.to_string()],
                rolled_back: false,
            };
        }
        if agent.hostname.is_empty() {
            continue;
        }
        tracing::info!("Starting sync for agent: {} using {mode}", agent.hostname);
        let r = sync_for_agent(
            st,
            &agent.hostname,
            agent.customer_code.as_deref(),
            batch_size,
            bulk,
        )
        .await;
        expired = r.rolled_back;
        total += r.synced;
        errors.extend(r.errors);
    }
    let mut message = format!(
        "Completed vulnerability sync for {} agents using {mode}",
        agents.len()
    );
    match code {
        Some(c) => message.push_str(&format!(" (customer: {c})")),
        None => message.push_str(" (all agents in database)"),
    }
    SyncOutcome::ok(message, total, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_are_sqlalchemys() {
        let at = |s: &str| NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f").unwrap();
        let p = Pending {
            cve_id: "CVE-1".into(),
            vals: Vals {
                severity: "High".into(),
                title: "ssl".into(),
                references: None,
                discovered_at: IsoDateTime {
                    wall: at("2026-01-02 03:04:05.123"),
                    offset_us: Some(0),
                },
                epss_score: None,
                package_name: Some("ssl".into()),
            },
            agent_id: "001".into(),
            customer_code: Some("X".into()),
        };
        assert_eq!(
            p.params(),
            "('CVE-1', 'High', 'ssl', None, 'Active', datetime.datetime(2026, 1, 2, 3, 4, 5, \
             123000, tzinfo=datetime.timezone.utc), None, None, None, 'ssl', '001', 'X')"
        );
        let east = IsoDateTime {
            wall: at("2026-01-02 03:04:00"),
            offset_us: Some(-3600 * 1_000_000),
        };
        assert_eq!(
            datetime_param(&east),
            "datetime.datetime(2026, 1, 2, 3, 4, tzinfo=datetime.timezone(datetime.timedelta(days=-1, seconds=82800)))"
        );
        assert_eq!(
            stored(&IsoDateTime {
                wall: at("2026-01-02 03:04:05.6"),
                offset_us: None
            }),
            at("2026-01-02 03:04:06")
        );
    }
}
