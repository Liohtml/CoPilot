//! `/api/patch-tuesday` — port of `routes/microsoft_patch_tuesday.py`: six
//! GET routes, every one `require_any_scope("admin", "analyst")`. Patch
//! Tuesday data is public and deployment-wide: no route is tenant-scoped,
//! as in Python.
//!
//! FastAPI's order: the token, then the path, then the query parameters in
//! declaration order (`cycle`'s pattern, Pydantic's lax `bool`, `top_n`'s
//! bounds, every error in one 422).

use axum::Router;
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::get;
use copilot_uba::params::{NumSpec, StrSpec, q_bool_or, q_int_or, q_opt_str};
use copilot_upstream::respond::model_response;
use copilot_web::validate::{Validator, loc};
use copilot_web::{AdminOrAnalyst, ApiResult, Authorized, QueryPairs};

use crate::PatchTuesdayState;
use crate::py::upper;
use crate::services::{self, Http, PtResponse, SystemClock};

type Reader = Authorized<AdminOrAnalyst>;

/// `pattern=r"^\d{4}-(Jan|…|Dec)$"` of every `cycle` parameter.
pub const CYCLE_PATTERN: &str = r"^\d{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$";

/// The six routes (full paths), behind the encoded-slash hand-off.
pub fn router(state: PatchTuesdayState) -> Router {
    let p = |s: &str| format!("/api/patch-tuesday{s}");
    let legacy = state.legacy.clone();
    Router::new()
        .route(&p(""), get(full))
        .route(&p("/summary"), get(summary))
        .route(&p("/cycles"), get(cycles))
        .route(&p("/search"), get(search))
        .route(&p("/priority/{priority_level}"), get(by_priority))
        .route(&p("/kev"), get(kev))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            legacy,
            copilot_wazuh::decoded_slash_to_legacy,
        ))
}

fn ok(dump: &copilot_auth::pyvalue::PyValue) -> Response {
    model_response(dump)
}

/// `cycle`, `include_epss`, `include_kev`.
fn common(q: &QueryPairs, v: &mut Validator) -> (Option<String>, bool, bool) {
    let cycle = q_opt_str(q, v, "cycle", StrSpec::pattern(CYCLE_PATTERN));
    let epss = q_bool_or(q, v, "include_epss", true);
    let kev = q_bool_or(q, v, "include_kev", true);
    (cycle, epss, kev)
}

async fn full(_: Reader, State(st): State<PatchTuesdayState>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let (cycle, epss, kev) = common(&q, &mut v);
    v.finish()?;
    tracing::info!(
        "Fetching Patch Tuesday data for cycle: {}",
        cycle.as_deref().unwrap_or("current")
    );
    let response =
        services::get_patch_tuesday(&Http, &SystemClock, &st.urls, cycle.as_deref(), epss, kev)
            .await;
    Ok(ok(&response.dump()))
}

async fn summary(_: Reader, State(st): State<PatchTuesdayState>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let (cycle, epss, kev) = common(&q, &mut v);
    let top_n = q_int_or(&q, &mut v, "top_n", NumSpec::range(1.0, 100.0), 25);
    v.finish()?;
    tracing::info!(
        "Fetching Patch Tuesday summary for cycle: {}",
        cycle.as_deref().unwrap_or("current")
    );
    let top_n: usize = top_n.parse().unwrap_or(25);
    let dump = services::get_patch_tuesday_summary(
        &Http,
        &SystemClock,
        &st.urls,
        cycle.as_deref(),
        epss,
        kev,
        top_n,
    )
    .await;
    Ok(ok(&dump))
}

async fn cycles(_: Reader) -> ApiResult {
    tracing::info!("Fetching available Patch Tuesday cycles");
    Ok(ok(&services::get_available_cycles(&SystemClock)))
}

async fn search(_: Reader, State(st): State<PatchTuesdayState>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let cve_ids = q.get_all("cve_ids");
    if cve_ids.is_empty() {
        v.missing(loc("query", "cve_ids"));
    }
    let cycle = q_opt_str(&q, &mut v, "cycle", StrSpec::pattern(CYCLE_PATTERN));
    let product = q_opt_str(&q, &mut v, "product", StrSpec::ANY);
    v.finish()?;
    tracing::info!(
        "Searching for CVEs: {cve_ids:?} in cycle: {} product: {}",
        cycle.as_deref().unwrap_or("current"),
        product.as_deref().unwrap_or("any")
    );
    let response = services::search_cves(
        &Http,
        &SystemClock,
        &st.urls,
        &cve_ids,
        cycle.as_deref(),
        product.as_deref(),
    )
    .await;
    Ok(ok(&response.dump()))
}

async fn by_priority(
    _: Reader,
    State(st): State<PatchTuesdayState>,
    Path(priority_level): Path<String>,
    q: QueryPairs,
) -> ApiResult {
    let mut v = Validator::new();
    let (cycle, epss, kev) = common(&q, &mut v);
    v.finish()?;
    tracing::info!(
        "Fetching {priority_level} priority items for cycle: {}",
        cycle.as_deref().unwrap_or("current")
    );
    let level = upper(&priority_level);
    let slot = match level.as_str() {
        "P0" => 0,
        "P1" => 1,
        "P2" => 2,
        "P3" => 3,
        _ => {
            let failed = PtResponse::failed(format!(
                "Invalid priority level '{level}'. Valid values: P0, P1, P2, P3"
            ));
            return Ok(ok(&failed.dump()));
        }
    };
    let response =
        services::get_patch_tuesday(&Http, &SystemClock, &st.urls, cycle.as_deref(), epss, kev)
            .await;
    if !response.success {
        return Ok(ok(&response.dump()));
    }
    let filtered: Vec<_> = response
        .items
        .iter()
        .filter(|i| i.priority.level == level)
        .cloned()
        .collect();
    let summary = response.summary.as_ref().map(|full| {
        let mut families = Vec::new();
        for item in &filtered {
            crate::schema::bump(&mut families, item.family);
        }
        let mut by_priority = [0usize; 4];
        by_priority[slot] = filtered.len();
        let unique: std::collections::BTreeSet<&str> =
            filtered.iter().map(|i| i.cve.as_str()).collect();
        crate::schema::Summary {
            cycle: full.cycle.clone(),
            patch_tuesday_date: full.patch_tuesday_date.clone(),
            generated_utc: full.generated_utc.clone(),
            unique_cves: unique.len(),
            total_records: filtered.len(),
            by_priority,
            by_family: crate::schema::sorted_counts(families),
            by_severity: full.by_severity.clone(),
        }
    });
    let out = PtResponse {
        success: true,
        message: format!("Found {} {level} priority items", filtered.len()),
        summary,
        items: filtered,
    };
    Ok(ok(&out.dump()))
}

async fn kev(_: Reader, State(st): State<PatchTuesdayState>, q: QueryPairs) -> ApiResult {
    let mut v = Validator::new();
    let cycle = q_opt_str(&q, &mut v, "cycle", StrSpec::pattern(CYCLE_PATTERN));
    v.finish()?;
    tracing::info!(
        "Fetching KEV items for cycle: {}",
        cycle.as_deref().unwrap_or("current")
    );
    let response =
        services::get_patch_tuesday(&Http, &SystemClock, &st.urls, cycle.as_deref(), true, true)
            .await;
    if !response.success {
        return Ok(ok(&response.dump()));
    }
    let items: Vec<_> = response
        .items
        .iter()
        .filter(|i| i.in_kev)
        .cloned()
        .collect();
    let out = PtResponse {
        success: true,
        message: format!("Found {} known exploited vulnerabilities", items.len()),
        summary: response.summary.clone(),
        items,
    };
    Ok(ok(&out.dump()))
}
