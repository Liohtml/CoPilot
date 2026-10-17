//! The `branding` template variable
//! (`notifications/services/templates.build_branding_context`), for named
//! notification templates and the temporary-password email: the
//! customer's portal branding (`customer_portal/services/branding.py`,
//! resolved field by field) turned into the report palette
//! (`incidents/services/customer_report_branding.py`).
//!
//! One difference by design: without a brand colour, Python derives one from
//! the logo's pixels with Pillow (quantizing a thumbnail). That is not
//! reproduced; the palette falls back to the SOCFortress orange, which is
//! also what Python does whenever Pillow cannot read the logo.

use copilot_db::Db;
use copilot_db::branding::{self, BrandingRow};
use copilot_jinja::Input;
use copilot_web::form::py_strip;

/// The SOCFortress orange: the palette's base when nothing else applies.
pub const SOCF_BASE: &str = "#fc862e";
const DARK_TEXT: &str = "#0f172a";
const WHITE_TEXT: &str = "#ffffff";
const INK: &str = "#0b1220";
const INK_SOFT: &str = "#0f1a30";
const MIN_TEXT_ON_WHITE: f64 = 3.5;

/// `_FALLBACK_BRANDING`: what a template sees when branding cannot be read.
pub fn fallback() -> Input {
    Input::Dict(vec![
        ("logo".into(), Input::None),
        ("title".into(), "CoPilot".into()),
        ("footer_brand".into(), "CoPilot".into()),
        ("accent".into(), "#1f2937".into()),
        ("accent_strong".into(), "#2563eb".into()),
        ("accent_text".into(), "#ffffff".into()),
        ("accent_soft".into(), "#e5e7eb".into()),
    ])
}

/// `EffectiveBranding`, the fields the palette reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    /// Portal title.
    pub title: String,
    /// Logo, base64 or a data URI.
    pub logo_base64: Option<String>,
    /// The logo's MIME type.
    pub logo_mime_type: Option<String>,
    /// `#RRGGBB`, as stored.
    pub brand_color: Option<String>,
}

/// `_normalize`: blank is unset.
fn normalize(value: Option<&str>) -> Option<String> {
    value
        .map(py_strip)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// `build_effective_branding(global, override, customer_code)` in full:
/// the merged fields, where they came from and the customer they were
/// resolved for (the portal's `EffectiveBranding`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The merged fields.
    pub branding: Effective,
    /// `"custom"` when the override supplied the title, the logo or the
    /// colour (not the MIME type alone), else `"global"`.
    pub source: &'static str,
    /// `customer_code`, when the override supplied a field.
    pub customer_code: Option<String>,
}

/// `build_effective_branding(global, override, customer_code)`: an enabled
/// override's fields win one by one; the logo comes with its own MIME type
/// (`image/png` when it has none).
pub fn resolve(
    global: Option<&BrandingRow>,
    custom: Option<&BrandingRow>,
    customer_code: Option<&str>,
) -> Resolved {
    let g = |f: fn(&BrandingRow) -> Option<&str>| normalize(global.and_then(f));
    let global_title = g(|r| r.title.as_deref()).unwrap_or_else(|| "CoPilot".into());
    let global_logo = g(|r| r.logo_base64.as_deref());
    let global_mime = g(|r| r.logo_mime_type.as_deref());
    let global_color = g(|r| r.brand_color.as_deref());
    let Some(c) = custom.filter(|c| c.enabled) else {
        return Resolved {
            branding: Effective {
                title: global_title,
                logo_base64: global_logo,
                logo_mime_type: global_mime,
                brand_color: global_color,
            },
            source: "global",
            customer_code: None,
        };
    };
    let custom_title = normalize(c.title.as_deref());
    let custom_logo = normalize(c.logo_base64.as_deref());
    let custom_color = normalize(c.brand_color.as_deref());
    let used_custom = custom_title.is_some() || custom_logo.is_some() || custom_color.is_some();
    Resolved {
        branding: Effective {
            title: custom_title.unwrap_or(global_title),
            logo_mime_type: if custom_logo.is_some() {
                Some(normalize(c.logo_mime_type.as_deref()).unwrap_or_else(|| "image/png".into()))
            } else {
                global_mime
            },
            logo_base64: custom_logo.or(global_logo),
            brand_color: custom_color.or(global_color),
        },
        source: if used_custom { "custom" } else { "global" },
        customer_code: customer_code.filter(|_| used_custom).map(str::to_string),
    }
}

/// `build_effective_branding(global, override)`: the merged fields only.
pub fn effective(global: Option<&BrandingRow>, custom: Option<&BrandingRow>) -> Effective {
    resolve(global, custom, None).branding
}

/// `int(text, 16)` for the two-character slices `_hex_to_rgb` takes.
fn py_hex(text: &str) -> Option<i64> {
    let t = py_strip(text);
    let (neg, rest) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let rest = rest
        .strip_prefix("0x")
        .or_else(|| rest.strip_prefix("0X"))
        .map(|r| r.strip_prefix('_').unwrap_or(r))
        .unwrap_or(rest);
    if rest.is_empty() || rest.starts_with('_') || rest.ends_with('_') || rest.contains("__") {
        return None;
    }
    let mut n: i64 = 0;
    for c in rest.chars() {
        if c == '_' {
            continue;
        }
        n = n * 16 + i64::from(c.to_digit(16)?);
    }
    Some(if neg { -n } else { n })
}

type Rgb = (i64, i64, i64);

/// `_hex_to_rgb`.
fn hex_to_rgb(value: &str) -> Option<Rgb> {
    if value.is_empty() {
        return None;
    }
    let v = py_strip(value).trim_start_matches('#');
    let chars: Vec<char> = v.chars().collect();
    let chars: Vec<char> = if chars.len() == 3 {
        chars.iter().flat_map(|c| [*c, *c]).collect()
    } else {
        chars
    };
    if chars.len() != 6 {
        return None;
    }
    let part = |i: usize| py_hex(&chars[i..i + 2].iter().collect::<String>());
    Some((part(0)?, part(2)?, part(4)?))
}

/// `_rgb_to_hex`: rounded half to even, clamped.
fn rgb_to_hex(r: f64, g: f64, b: f64) -> String {
    let c = |x: f64| x.round_ties_even().clamp(0.0, 255.0) as u8;
    format!("#{:02x}{:02x}{:02x}", c(r), c(g), c(b))
}

fn int_rgb_to_hex(rgb: Rgb) -> String {
    let c = |x: i64| x.clamp(0, 255);
    format!("#{:02x}{:02x}{:02x}", c(rgb.0), c(rgb.1), c(rgb.2))
}

/// `_normalize_hex`.
fn normalize_hex(value: Option<&str>) -> Option<String> {
    value.and_then(hex_to_rgb).map(int_rgb_to_hex)
}

fn lighten(value: &str, amount: f64) -> String {
    let (r, g, b) = hex_to_rgb(value).unwrap_or((0, 0, 0));
    let mix = |c: i64| c as f64 + (255 - c) as f64 * amount;
    rgb_to_hex(mix(r), mix(g), mix(b))
}

fn darken(value: &str, amount: f64) -> String {
    let (r, g, b) = hex_to_rgb(value).unwrap_or((0, 0, 0));
    let mix = |c: i64| c as f64 * (1.0 - amount);
    rgb_to_hex(mix(r), mix(g), mix(b))
}

fn relative_luminance((r, g, b): Rgb) -> f64 {
    let lin = |c: i64| {
        let c = c as f64 / 255.0;
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

fn contrast_ratio(a: Rgb, b: Rgb) -> f64 {
    let (l1, l2) = (relative_luminance(a), relative_luminance(b));
    let (hi, lo) = if l1 >= l2 { (l1, l2) } else { (l2, l1) };
    (hi + 0.05) / (lo + 0.05)
}

const WHITE: Rgb = (255, 255, 255);

fn contrast_text(value: &str) -> &'static str {
    let rgb = hex_to_rgb(value).unwrap_or((0, 0, 0));
    let dark = hex_to_rgb(DARK_TEXT).unwrap_or((0, 0, 0));
    if contrast_ratio(rgb, dark) >= contrast_ratio(rgb, WHITE) {
        DARK_TEXT
    } else {
        WHITE_TEXT
    }
}

fn readable_on_white(value: &str) -> String {
    let Some(base) = hex_to_rgb(value) else {
        return DARK_TEXT.into();
    };
    if contrast_ratio(base, WHITE) >= MIN_TEXT_ON_WHITE {
        return int_rgb_to_hex(base);
    }
    for step in 1..21 {
        let candidate = darken(value, f64::from(step) * 0.05);
        if hex_to_rgb(&candidate).is_some_and(|rgb| contrast_ratio(rgb, WHITE) >= MIN_TEXT_ON_WHITE)
        {
            return candidate;
        }
    }
    DARK_TEXT.into()
}

fn readable_on_dark(value: &str, background: &str) -> String {
    let bg = hex_to_rgb(background).unwrap_or((0, 0, 0));
    let Some(base) = hex_to_rgb(value) else {
        return WHITE_TEXT.into();
    };
    if contrast_ratio(base, bg) >= 4.0 {
        return int_rgb_to_hex(base);
    }
    for step in 1..21 {
        let candidate = lighten(value, f64::from(step) * 0.05);
        if hex_to_rgb(&candidate).is_some_and(|rgb| contrast_ratio(rgb, bg) >= 4.0) {
            return candidate;
        }
    }
    WHITE_TEXT.into()
}

/// `_build_palette(base, logo, title, footer_brand)`.
pub fn palette(base: Option<&str>, logo: Option<String>, title: &str, footer_brand: &str) -> Input {
    let base = normalize_hex(base).unwrap_or_else(|| SOCF_BASE.into());
    let s = |v: String| Input::Str(v);
    Input::Dict(vec![
        ("logo".into(), logo.map_or(Input::None, Input::Str)),
        ("title".into(), title.into()),
        ("footer_brand".into(), footer_brand.into()),
        ("accent".into(), s(readable_on_white(&base))),
        ("accent_strong".into(), s(base.clone())),
        ("accent_text".into(), contrast_text(&base).into()),
        ("accent_soft".into(), s(lighten(&base, 0.82))),
        ("accent_dark".into(), s(darken(&base, 0.30))),
        ("ink".into(), INK.into()),
        ("ink_soft".into(), INK_SOFT.into()),
        ("accent_on_dark".into(), s(readable_on_dark(&base, INK))),
        ("chart_bar".into(), s(base.clone())),
        ("chart_evo_alerts".into(), s(base.clone())),
        ("chart_evo_cases".into(), s(darken(&base, 0.22))),
    ])
}

/// `_customer_theme(settings)`.
pub fn customer_theme(e: &Effective) -> Input {
    let title = if e.title.is_empty() {
        "CoPilot"
    } else {
        e.title.as_str()
    };
    let logo = e.logo_base64.as_ref().map(|logo| {
        if logo.starts_with("data:") {
            logo.clone()
        } else {
            format!(
                "data:{};base64,{logo}",
                e.logo_mime_type.as_deref().unwrap_or("image/png")
            )
        }
    });
    let mut base = normalize_hex(e.brand_color.as_deref());
    if base.is_none() && e.logo_base64.is_some() {
        let svg = e
            .logo_mime_type
            .as_deref()
            .is_some_and(|m| m.to_lowercase().contains("svg"));
        if !svg {
            tracing::warn!(
                "no brand colour set: the email palette uses the SOCFortress orange \
                 instead of a colour derived from the logo"
            );
        }
    }
    if base.is_none() {
        base = Some(SOCF_BASE.into());
    }
    palette(base.as_deref(), logo, title, title)
}

/// `build_branding_context(customer_code)`: the customer's palette, or the
/// fallback when it cannot be read.
pub async fn context(db: &Db, customer_code: Option<&str>) -> Input {
    let global = match branding::global_settings(db).await {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(error = %e, "could not read the portal branding");
            return fallback();
        }
    };
    let custom = match customer_code {
        Some(code) if !code.is_empty() => match branding::customer_override(db, code).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "could not read the portal branding");
                return fallback();
            }
        },
        _ => None,
    };
    customer_theme(&effective(global.as_ref(), custom.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(d: &Input, key: &str) -> String {
        let Input::Dict(pairs) = d else { panic!() };
        match pairs.iter().find(|(k, _)| k == key) {
            Some((_, Input::Str(s))) => s.clone(),
            other => panic!("{key}: {other:?}"),
        }
    }

    #[test]
    fn palette_matches_python() {
        // `_build_palette(base, None, "T", "T")` in the backend's venv:
        // accent, accent_strong, accent_text, accent_soft, accent_dark,
        // accent_on_dark, chart_evo_cases.
        let cases = [
            (
                "#fc862e",
                [
                    "#ca6b25", "#fc862e", "#0f172a", "#fee9d9", "#b05e20", "#fc862e", "#c56924",
                ],
            ),
            (
                "#123",
                [
                    "#112233", "#112233", "#ffffff", "#d4d7da", "#0c1824", "#707a85", "#0d1b28",
                ],
            ),
            (
                " #FFFFFF ",
                [
                    "#808080", "#ffffff", "#0f172a", "#ffffff", "#b2b2b2", "#ffffff", "#c7c7c7",
                ],
            ),
            (
                "nope",
                [
                    "#ca6b25", "#fc862e", "#0f172a", "#fee9d9", "#b05e20", "#fc862e", "#c56924",
                ],
            ),
            (
                "#000000",
                [
                    "#000000", "#000000", "#ffffff", "#d1d1d1", "#000000", "#808080", "#000000",
                ],
            ),
            (
                "#777777",
                [
                    "#777777", "#777777", "#ffffff", "#e7e7e7", "#535353", "#777777", "#5d5d5d",
                ],
            ),
            (
                "#-1-1-1",
                [
                    "#000000", "#000000", "#ffffff", "#d1d1d1", "#000000", "#808080", "#000000",
                ],
            ),
            (
                "#2563eb",
                [
                    "#2563eb", "#2563eb", "#ffffff", "#d8e3fb", "#1a45a4", "#3b73ed", "#1d4db7",
                ],
            ),
            (
                "#ffff00",
                [
                    "#8c8c00", "#ffff00", "#0f172a", "#ffffd1", "#b2b200", "#ffff00", "#c7c700",
                ],
            ),
        ];
        let keys = [
            "accent",
            "accent_strong",
            "accent_text",
            "accent_soft",
            "accent_dark",
            "accent_on_dark",
            "chart_evo_cases",
        ];
        for (base, want) in cases {
            let p = palette(Some(base), None, "T", "T");
            let got: Vec<String> = keys.iter().map(|k| get(&p, k)).collect();
            assert_eq!(got, want, "{base:?}");
        }
    }

    #[test]
    fn hex_parsing_is_int_base_16() {
        assert_eq!(hex_to_rgb("#+1-1 1"), Some((1, -1, 1)));
        assert_eq!(hex_to_rgb("##abc"), Some((0xaa, 0xbb, 0xcc)));
        assert_eq!(hex_to_rgb("#abcd"), None);
        assert_eq!(hex_to_rgb("#0xabcd"), None);
        assert_eq!(normalize_hex(Some("#-1-1-1")).as_deref(), Some("#000000"));
    }

    #[test]
    fn overrides_merge_field_by_field() {
        let global = BrandingRow {
            title: Some(" Global ".into()),
            logo_base64: Some("AAA".into()),
            logo_mime_type: Some("image/jpeg".into()),
            brand_color: Some("#111111".into()),
            ..BrandingRow::default()
        };
        let custom = BrandingRow {
            enabled: true,
            title: Some("  ".into()),
            logo_base64: Some("BBB".into()),
            logo_mime_type: None,
            brand_color: None,
        };
        let e = effective(Some(&global), Some(&custom));
        assert_eq!(e.title, "Global");
        assert_eq!(e.logo_base64.as_deref(), Some("BBB"));
        assert_eq!(e.logo_mime_type.as_deref(), Some("image/png"));
        assert_eq!(e.brand_color.as_deref(), Some("#111111"));
        let off = BrandingRow {
            enabled: false,
            ..custom
        };
        assert_eq!(
            effective(Some(&global), Some(&off)).logo_base64.as_deref(),
            Some("AAA")
        );
        assert_eq!(effective(None, None).title, "CoPilot");
    }

    #[test]
    fn source_names_the_override_only_when_it_supplied_a_field() {
        let mime_only = BrandingRow {
            enabled: true,
            logo_mime_type: Some("image/gif".into()),
            ..BrandingRow::default()
        };
        let r = resolve(None, Some(&mime_only), Some("acme"));
        assert_eq!((r.source, r.customer_code), ("global", None));
        assert_eq!(r.branding.logo_mime_type, None);
        let colour = BrandingRow {
            enabled: true,
            brand_color: Some(" #abc ".into()),
            ..BrandingRow::default()
        };
        let r = resolve(None, Some(&colour), Some("acme"));
        assert_eq!(
            (r.source, r.customer_code.as_deref()),
            ("custom", Some("acme"))
        );
        assert_eq!(r.branding.brand_color.as_deref(), Some("#abc"));
        let off = BrandingRow {
            enabled: false,
            ..colour
        };
        assert_eq!(resolve(None, Some(&off), Some("acme")).source, "global");
    }
}
