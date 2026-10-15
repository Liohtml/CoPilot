//! Alert filter options — `get_alert_filter_options` and
//! `search_alert_asset_names`, over the caller's alert visibility (a
//! subquery of visible alert ids, as `_visible_alert_ids` builds it).

use sqlx::{MySql, QueryBuilder};

use copilot_db::visibility::AlertVisibility;
use copilot_db::{Db, DbError};

fn push_visible_ids(qb: &mut QueryBuilder<'_, MySql>, vis: &AlertVisibility) {
    qb.push("(SELECT a.id FROM incident_management_alert a WHERE 1=1");
    vis.push_and(qb, "a");
    qb.push(")");
}

fn truthy(v: Vec<Option<String>>) -> Vec<String> {
    v.into_iter().flatten().filter(|s| !s.is_empty()).collect()
}

/// Sources, asset names (unless `include_assets` is false) and tags of the
/// visible alerts.
pub async fn alert_filter_options(
    db: &Db,
    vis: Option<&AlertVisibility>,
    include_assets: bool,
) -> Result<(Vec<String>, Vec<String>, Vec<String>), DbError> {
    let Some(vis) = vis else {
        return Ok((Vec::new(), Vec::new(), Vec::new()));
    };
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT DISTINCT a.source FROM incident_management_alert a WHERE 1=1",
    );
    vis.push_and(&mut qb, "a");
    qb.push(" ORDER BY a.source");
    let sources = truthy(qb.build_query_scalar().fetch_all(db.pool()).await?);
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT DISTINCT tg.tag FROM incident_management_alerttag tg \
         JOIN incident_management_alert_to_tag att ON att.tag_id = tg.id WHERE att.alert_id IN ",
    );
    push_visible_ids(&mut qb, vis);
    qb.push(" ORDER BY tg.tag");
    let tags = truthy(qb.build_query_scalar().fetch_all(db.pool()).await?);
    let assets = if include_assets {
        asset_names(db, vis, None, None).await?
    } else {
        Vec::new()
    };
    Ok((sources, assets, tags))
}

/// `_asset_names`: distinct asset names of the visible alerts, optionally
/// matching `search` (case-insensitive `LIKE`, wildcards kept), at most
/// `limit`.
pub async fn asset_names(
    db: &Db,
    vis: &AlertVisibility,
    search: Option<&str>,
    limit: Option<i64>,
) -> Result<Vec<String>, DbError> {
    let mut qb = QueryBuilder::<MySql>::new(
        "SELECT DISTINCT s.asset_name FROM incident_management_asset s WHERE s.alert_linked IN ",
    );
    push_visible_ids(&mut qb, vis);
    if let Some(term) = search {
        qb.push(" AND lower(s.asset_name) LIKE lower(")
            .push_bind(format!("%{term}%"))
            .push(")");
    }
    qb.push(" ORDER BY s.asset_name");
    if let Some(limit) = limit {
        qb.push(" LIMIT ").push_bind(limit);
    }
    Ok(truthy(qb.build_query_scalar().fetch_all(db.pool()).await?))
}
