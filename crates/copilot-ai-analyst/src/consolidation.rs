//! The palace consolidation digest — port of `get_palace_consolidation`,
//! `_find_duplicate_pairs` and `_render_consolidation_markdown`. Pure: the
//! service hands in the active lessons and the clock.

use std::collections::BTreeMap;

use chrono::{Duration, NaiveDateTime};
use serde::Serialize;

use copilot_core::time::{py_round, pydantic, to_pydantic_iso};
use copilot_db::ai_analyst::PalaceLessonRow;

use crate::difflib;

/// One-off lessons are swept this many days after ingestion.
pub const ONE_OFF_EXPIRY_DAYS: i64 = 7;
/// "Expiring soon" window.
pub const EXPIRY_SOON_WINDOW_DAYS: i64 = 2;
/// Near-duplicate threshold (`SequenceMatcher.ratio()`).
pub const DUPLICATE_SIMILARITY_THRESHOLD: f64 = 0.70;

/// `PalaceConsolidationLesson`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConsolidationLesson {
    /// Id.
    pub id: i32,
    /// Room.
    pub lesson_type: String,
    /// Text.
    pub lesson_text: String,
    /// Durability.
    pub durability: String,
    /// Status.
    pub status: String,
    /// MemPalace drawer.
    pub drawer_id: Option<String>,
    /// Queued.
    #[serde(serialize_with = "pydantic::datetime")]
    pub created_at: NaiveDateTime,
    /// Ingested.
    #[serde(serialize_with = "pydantic::opt_datetime")]
    pub ingested_at: Option<NaiveDateTime>,
    /// Whole days left (Python `timedelta.days`, i.e. floored).
    pub days_until_expiry: Option<i64>,
}

/// `PalaceConsolidationRoomGroup`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RoomGroup {
    /// Room name.
    pub room: String,
    /// Lessons in the room.
    pub total: usize,
    /// Durable ones.
    pub durable: usize,
    /// One-off ones.
    pub one_off: usize,
    /// The lessons.
    pub lessons: Vec<ConsolidationLesson>,
}

/// `PalaceConsolidationDuplicatePair`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DuplicatePair {
    /// Room.
    pub room: String,
    /// First lesson.
    pub lesson_a_id: i32,
    /// Second lesson.
    pub lesson_b_id: i32,
    /// First text (original casing).
    pub lesson_a_text: String,
    /// Second text.
    pub lesson_b_text: String,
    /// Ratio rounded to 3 places.
    pub similarity: f64,
}

/// The digest (everything in `PalaceConsolidationResponse` but the envelope).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Digest {
    /// Customer.
    pub customer_code: String,
    /// Clock used.
    #[serde(serialize_with = "pydantic::datetime")]
    pub generated_at: NaiveDateTime,
    /// Active lessons.
    pub total_lessons: usize,
    /// Durable lessons.
    pub total_durable: usize,
    /// One-off lessons.
    pub total_one_off: usize,
    /// Waiting for the drainer.
    pub total_pending: usize,
    /// In MemPalace.
    pub total_ingested: usize,
    /// One-offs within the expiry window, soonest first.
    pub upcoming_expirations: Vec<ConsolidationLesson>,
    /// Lessons by room, rooms sorted.
    pub rooms: Vec<RoomGroup>,
    /// Similar pairs, most similar first.
    pub duplicate_candidates: Vec<DuplicatePair>,
    /// The same, as Markdown.
    pub markdown: String,
}

impl Digest {
    /// The response message.
    pub fn message(&self) -> String {
        format!(
            "Palace consolidation for {}: {} active lesson(s), {} duplicate pair(s), {} expiring soon",
            self.customer_code,
            self.total_lessons,
            self.duplicate_candidates.len(),
            self.upcoming_expirations.len()
        )
    }
}

/// Python's `timedelta.days`: whole days, floored.
fn floor_days(d: Duration) -> i64 {
    let micros = d
        .num_microseconds()
        .unwrap_or(d.num_seconds().saturating_mul(1_000_000));
    micros.div_euclid(86_400 * 1_000_000)
}

fn to_lesson(row: &PalaceLessonRow, now: NaiveDateTime) -> ConsolidationLesson {
    let days_until_expiry = match (row.durability.as_str(), row.ingested_at) {
        ("one_off", Some(ingested)) => Some(floor_days(
            ingested + Duration::days(ONE_OFF_EXPIRY_DAYS) - now,
        )),
        _ => None,
    };
    ConsolidationLesson {
        id: row.id,
        lesson_type: row.lesson_type.clone(),
        lesson_text: row.lesson_text.clone().unwrap_or_default(),
        durability: row.durability.clone(),
        status: row.status.clone(),
        drawer_id: row.drawer_id.clone(),
        created_at: row.created_at,
        ingested_at: row.ingested_at,
        days_until_expiry,
    }
}

/// `_find_duplicate_pairs`: pairwise within each room, in input order.
pub fn find_duplicate_pairs(lessons: &[ConsolidationLesson]) -> Vec<DuplicatePair> {
    let mut rooms: Vec<(String, Vec<&ConsolidationLesson>)> = Vec::new();
    for l in lessons {
        match rooms.iter_mut().find(|(r, _)| *r == l.lesson_type) {
            Some((_, v)) => v.push(l),
            None => rooms.push((l.lesson_type.clone(), vec![l])),
        }
    }
    let mut pairs = Vec::new();
    for (room, members) in rooms {
        let normalized: Vec<(&ConsolidationLesson, String)> = members
            .into_iter()
            .map(|l| (l, l.lesson_text.trim().to_lowercase()))
            .collect();
        for i in 0..normalized.len() {
            let (a, a_text) = &normalized[i];
            if a_text.is_empty() {
                continue;
            }
            for (b, b_text) in &normalized[i + 1..] {
                if b_text.is_empty() {
                    continue;
                }
                let ratio = difflib::ratio(a_text, b_text);
                if ratio >= DUPLICATE_SIMILARITY_THRESHOLD {
                    pairs.push(DuplicatePair {
                        room: room.clone(),
                        lesson_a_id: a.id,
                        lesson_b_id: b.id,
                        lesson_a_text: a.lesson_text.clone(),
                        lesson_b_text: b.lesson_text.clone(),
                        similarity: py_round(ratio, 3),
                    });
                }
            }
        }
    }
    // Stable, so equal similarities keep their discovery order (Python's
    // `sort(reverse=True)` is stable too).
    pairs.sort_by(|a, b| b.similarity.total_cmp(&a.similarity));
    pairs
}

/// Build the digest. `rows` must be the customer's pending/ingested lessons
/// ordered by room ascending, then newest first.
pub fn build(customer_code: &str, rows: &[PalaceLessonRow], now: NaiveDateTime) -> Digest {
    let lessons: Vec<ConsolidationLesson> = rows.iter().map(|r| to_lesson(r, now)).collect();
    let count = |f: &dyn Fn(&ConsolidationLesson) -> bool| lessons.iter().filter(|l| f(l)).count();
    let total_durable = count(&|l| l.durability == "durable");
    let total_one_off = count(&|l| l.durability == "one_off");
    let total_pending = count(&|l| l.status == "pending");
    let total_ingested = count(&|l| l.status == "ingested");

    let mut upcoming: Vec<ConsolidationLesson> = lessons
        .iter()
        .filter(|l| {
            l.durability == "one_off"
                && l.days_until_expiry
                    .is_some_and(|d| d <= EXPIRY_SOON_WINDOW_DAYS)
        })
        .cloned()
        .collect();
    upcoming.sort_by_key(|l| l.days_until_expiry.unwrap_or(0));

    let mut by_room: BTreeMap<String, Vec<ConsolidationLesson>> = BTreeMap::new();
    for l in &lessons {
        by_room
            .entry(l.lesson_type.clone())
            .or_default()
            .push(l.clone());
    }
    let rooms: Vec<RoomGroup> = by_room
        .into_iter()
        .map(|(room, ls)| RoomGroup {
            total: ls.len(),
            durable: ls.iter().filter(|l| l.durability == "durable").count(),
            one_off: ls.iter().filter(|l| l.durability == "one_off").count(),
            room,
            lessons: ls,
        })
        .collect();

    let duplicates = find_duplicate_pairs(&lessons);
    let markdown = render_markdown(
        customer_code,
        now,
        lessons.len(),
        total_durable,
        total_one_off,
        &rooms,
        &duplicates,
        &upcoming,
    );
    Digest {
        customer_code: customer_code.to_string(),
        generated_at: now,
        total_lessons: lessons.len(),
        total_durable,
        total_one_off,
        total_pending,
        total_ingested,
        upcoming_expirations: upcoming,
        rooms,
        duplicate_candidates: duplicates,
        markdown,
    }
}

/// `_render_consolidation_markdown`, line for line.
#[allow(clippy::too_many_arguments)]
pub fn render_markdown(
    customer_code: &str,
    generated_at: NaiveDateTime,
    total_lessons: usize,
    total_durable: usize,
    total_one_off: usize,
    rooms: &[RoomGroup],
    duplicates: &[DuplicatePair],
    upcoming: &[ConsolidationLesson],
) -> String {
    let mut lines: Vec<String> = vec![
        format!("# Palace consolidation — {customer_code}"),
        format!("_Generated {} UTC_", to_pydantic_iso(generated_at)),
        String::new(),
        "## Summary".into(),
        format!("- Total active lessons: **{total_lessons}**"),
        format!("- Durable: {total_durable} | One-off: {total_one_off}"),
    ];
    if !upcoming.is_empty() {
        lines.push(format!(
            "- **{} one-off lesson(s) expiring within {EXPIRY_SOON_WINDOW_DAYS} day(s)** — \
             consider promoting to durable.",
            upcoming.len()
        ));
    }
    if !duplicates.is_empty() {
        lines.push(format!(
            "- **{} near-duplicate pair(s)** flagged for review.",
            duplicates.len()
        ));
    }
    lines.push(String::new());

    if !upcoming.is_empty() {
        lines.push("## Upcoming expirations".into());
        for l in upcoming {
            let due = l
                .days_until_expiry
                .map_or_else(|| "?".to_string(), |d| d.to_string());
            lines.push(format!(
                "- _{}_ (id {}, in {due}d): {}",
                l.lesson_type, l.id, l.lesson_text
            ));
        }
        lines.push(String::new());
    }

    if !duplicates.is_empty() {
        lines.push("## Near-duplicate candidates".into());
        for p in duplicates {
            let pct = (p.similarity * 100.0).trunc() as i64;
            lines.push(format!("- **{}** — {pct}% similar", p.room));
            lines.push(format!("  - #{}: {}", p.lesson_a_id, p.lesson_a_text));
            lines.push(format!("  - #{}: {}", p.lesson_b_id, p.lesson_b_text));
        }
        lines.push(String::new());
    }

    lines.push("## Rooms".into());
    for g in rooms {
        lines.push(format!(
            "### {}  ({} total — {} durable, {} one-off)",
            g.room, g.total, g.durable, g.one_off
        ));
        for l in &g.lessons {
            let tag = if l.durability == "durable" {
                "🧷"
            } else {
                "⏳"
            };
            let suffix = match (l.durability.as_str(), l.days_until_expiry) {
                ("one_off", Some(d)) => format!(" _(expires in {d}d)_"),
                _ => String::new(),
            };
            lines.push(format!("- {tag} #{}{suffix}: {}", l.id, l.lesson_text));
        }
        lines.push(String::new());
    }
    format!("{}\n", lines.join("\n").trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
    }

    fn row(
        id: i32,
        room: &str,
        text: &str,
        durability: &str,
        ingested: Option<&str>,
    ) -> PalaceLessonRow {
        PalaceLessonRow {
            id,
            review_id: None,
            customer_code: "acme".into(),
            lesson_type: room.into(),
            lesson_text: Some(text.into()),
            durability: durability.into(),
            status: if ingested.is_some() {
                "ingested"
            } else {
                "pending"
            }
            .into(),
            ingested_at: ingested.map(t),
            created_at: t("2026-10-01 00:00:00"),
            drawer_id: ingested.map(|_| format!("d{id}")),
            expired_at: None,
        }
    }

    #[test]
    fn floor_days_matches_timedelta() {
        assert_eq!(floor_days(Duration::seconds(-1)), -1);
        assert_eq!(floor_days(Duration::hours(47)), 1);
        assert_eq!(floor_days(Duration::days(2)), 2);
    }

    #[test]
    fn digest_end_to_end() {
        let now = t("2026-10-10 12:00:00");
        let rows = vec![
            row(
                1,
                "assets",
                "DC01 runs SCCM patching at 02:00",
                "durable",
                Some("2026-10-01 00:00:00"),
            ),
            row(
                2,
                "assets",
                "dc01 runs sccm patching at 02:00 nightly",
                "one_off",
                Some("2026-10-05 00:00:00"),
            ),
            row(
                3,
                "environment",
                "VPN egress is 203.0.113.7",
                "durable",
                None,
            ),
        ];
        let d = build("acme", &rows, now);
        assert_eq!(
            (d.total_lessons, d.total_durable, d.total_one_off),
            (3, 2, 1)
        );
        assert_eq!((d.total_pending, d.total_ingested), (1, 2));
        // ingested 10-05 + 7d = 10-12 00:00, now 10-10 12:00 → 1 day 12h → 1
        assert_eq!(d.upcoming_expirations[0].days_until_expiry, Some(1));
        assert_eq!(
            d.rooms.iter().map(|r| r.room.as_str()).collect::<Vec<_>>(),
            vec!["assets", "environment"]
        );
        assert_eq!(d.duplicate_candidates.len(), 1);
        assert_eq!(
            (
                d.duplicate_candidates[0].lesson_a_id,
                d.duplicate_candidates[0].lesson_b_id
            ),
            (1, 2)
        );
        assert!(
            d.markdown.starts_with(
                "# Palace consolidation — acme\n_Generated 2026-10-10T12:00:00 UTC_\n"
            )
        );
        assert!(
            d.markdown
                .contains("- ⏳ #2 _(expires in 1d)_: dc01 runs sccm patching at 02:00 nightly")
        );
        assert!(
            d.markdown
                .contains("### assets  (2 total — 1 durable, 1 one-off)")
        );
        assert!(d.markdown.ends_with("VPN egress is 203.0.113.7\n"));
        assert_eq!(
            d.message(),
            "Palace consolidation for acme: 3 active lesson(s), 1 duplicate pair(s), 1 expiring soon"
        );
    }
}
