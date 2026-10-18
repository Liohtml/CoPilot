//! Port of `app/customer_portal/schema/settings.py` and `schema/branding.py`:
//! the three request models as Pydantic validates them, and the responses
//! in their field order.

use serde::Serialize;
use serde_json::{Map, Value};

use copilot_web::validate::{Loc, LocPart, StrRules, Validator};

use super::validators::{validate_brand_color, validate_logo_base64, validate_logo_mime_type};

/// The four branding fields of a request, in declaration order.
pub const BRANDING_FIELDS: [&str; 4] = ["title", "logo_base64", "logo_mime_type", "brand_color"];

/// `ResettableField`.
pub const RESETTABLE: [&str; 3] = ["title", "logo", "brand_color"];

fn child(at: &Loc, name: &str) -> Loc {
    let mut l = at.clone();
    l.push(LocPart::Key(name.into()));
    l
}

/// A `field_validator` of `utils/validators.py`.
type FieldValidator = fn(Option<&str>) -> Result<Option<String>, String>;

/// An `Optional[str]` field with length rules and an after-validator: the
/// type and length checks first, then the validator — on `None` too, as
/// Pydantic runs it on the validated value.
fn checked_str(
    v: &mut Validator,
    obj: &Map<String, Value>,
    at: &Loc,
    name: &str,
    rules: StrRules,
    validator: Option<FieldValidator>,
) -> Option<String> {
    let before = v.errors().len();
    let raw = v.opt_str(obj, at, name, rules);
    if v.errors().len() > before {
        return None;
    }
    match validator {
        None => raw,
        Some(check) => match check(raw.as_deref()) {
            Ok(value) => value,
            Err(msg) => {
                v.push(
                    "value_error",
                    child(at, name),
                    format!("Value error, {msg}"),
                );
                None
            }
        },
    }
}

/// The branding fields every request model shares: `title` (`max_length`
/// 255, `min_length` when given), the logo, its MIME type (50) and the colour
/// (9), each through its validator.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrandingFields {
    /// `title`.
    pub title: Option<String>,
    /// `logo_base64` (a data URL reduced to its payload).
    pub logo_base64: Option<String>,
    /// `logo_mime_type`.
    pub logo_mime_type: Option<String>,
    /// `brand_color` (lower-cased).
    pub brand_color: Option<String>,
}

impl BrandingFields {
    fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc, title_rules: StrRules) -> Self {
        Self {
            title: checked_str(v, obj, at, "title", title_rules, None),
            logo_base64: checked_str(
                v,
                obj,
                at,
                "logo_base64",
                StrRules::any(),
                Some(validate_logo_base64),
            ),
            logo_mime_type: checked_str(
                v,
                obj,
                at,
                "logo_mime_type",
                StrRules::max(50),
                Some(validate_logo_mime_type),
            ),
            brand_color: checked_str(
                v,
                obj,
                at,
                "brand_color",
                StrRules::max(9),
                Some(validate_brand_color),
            ),
        }
    }

    /// The value of one of [`BRANDING_FIELDS`].
    pub fn get(&self, name: &str) -> Option<&str> {
        match name {
            "title" => self.title.as_deref(),
            "logo_base64" => self.logo_base64.as_deref(),
            "logo_mime_type" => self.logo_mime_type.as_deref(),
            _ => self.brand_color.as_deref(),
        }
    }
}

/// `UpdatePortalSettingsRequest` (`POST /settings`): every field optional; a
/// missing or null one restores its default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdatePortalSettingsRequest {
    /// The four fields.
    pub fields: BrandingFields,
}

impl UpdatePortalSettingsRequest {
    /// Validate a body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        Self {
            fields: BrandingFields::read(v, obj, at, StrRules::max(255)),
        }
    }
}

/// `PatchPortalSettingsRequest` (`PATCH /settings`): only the fields sent,
/// defaults restored through `reset`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PatchPortalSettingsRequest {
    /// The four fields.
    pub fields: BrandingFields,
    /// The fields the body carried (`model_fields_set` without `reset`), in
    /// declaration order.
    pub sent: Vec<&'static str>,
    /// `reset`.
    pub reset: Vec<&'static str>,
}

impl PatchPortalSettingsRequest {
    /// Validate a body: the fields, then (all valid) `check_consistency`.
    ///
    /// Python iterates the sent fields as a `set`, whose order follows the
    /// process's string hashes: with several of them `null`, the one it names
    /// varies from process to process. Here it is the first in declaration
    /// order.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let fields = BrandingFields::read(v, obj, at, StrRules::max(255).min(1));
        let mut reset = Vec::new();
        match obj.get("reset") {
            None => {}
            Some(Value::Array(items)) => {
                for (i, item) in items.iter().enumerate() {
                    let mut l = child(at, "reset");
                    l.push(LocPart::Index(i));
                    match item
                        .as_str()
                        .and_then(|s| RESETTABLE.iter().find(|r| **r == s))
                    {
                        Some(r) => reset.push(*r),
                        None => v.push(
                            "literal_error",
                            l,
                            "Input should be 'title', 'logo' or 'brand_color'",
                        ),
                    }
                }
            }
            Some(_) => v.push(
                "list_type",
                child(at, "reset"),
                "Input should be a valid list",
            ),
        }
        let sent: Vec<&'static str> = BRANDING_FIELDS
            .into_iter()
            .filter(|f| obj.contains_key(*f))
            .collect();
        let req = Self {
            fields,
            sent,
            reset,
        };
        if !v.has_errors() {
            if let Err(msg) = req.check_consistency() {
                v.push("value_error", at.clone(), format!("Value error, {msg}"));
            }
        }
        req
    }

    /// `check_consistency`.
    fn check_consistency(&self) -> Result<(), String> {
        fn reset_name(field: &str) -> &str {
            if field.starts_with("logo_") {
                "logo"
            } else {
                field
            }
        }
        for field in &self.sent {
            if self.fields.get(field).is_none() {
                return Err(format!(
                    "{field} cannot be empty; to restore its default send reset: [\"{}\"]",
                    reset_name(field)
                ));
            }
        }
        if self.sent.contains(&"logo_base64") != self.sent.contains(&"logo_mime_type") {
            return Err("logo_base64 and logo_mime_type must be sent together".into());
        }
        let mut both: Vec<&str> = self
            .sent
            .iter()
            .map(|f| reset_name(f))
            .filter(|t| self.reset.contains(t))
            .collect();
        both.sort_unstable();
        both.dedup();
        if !both.is_empty() {
            return Err(format!("Cannot both set and reset: {}", both.join(", ")));
        }
        if self.sent.is_empty() && self.reset.is_empty() {
            return Err("Nothing to update".into());
        }
        Ok(())
    }
}

/// Pydantic's lax `bool` (`bool_parsing` / `bool_type`): `true`/`false`,
/// the integers 0 and 1, the floats 0.0 and 1.0, and the strings
/// `0 1 f t n y no on off yes true false` in any case, nothing trimmed.
pub fn py_bool(value: &Value) -> Result<bool, (&'static str, &'static str)> {
    const PARSING: (&str, &str) = (
        "bool_parsing",
        "Input should be a valid boolean, unable to interpret input",
    );
    const TYPE: (&str, &str) = ("bool_type", "Input should be a valid boolean");
    match value {
        Value::Bool(b) => Ok(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                match i {
                    0 => Ok(false),
                    1 => Ok(true),
                    _ => Err(PARSING),
                }
            } else if n.is_u64() {
                Err(TYPE)
            } else {
                match n.as_f64() {
                    Some(0.0) => Ok(false),
                    Some(1.0) => Ok(true),
                    _ => Err(TYPE),
                }
            }
        }
        Value::String(s) => match s.to_lowercase().as_str() {
            "0" | "off" | "f" | "false" | "n" | "no" => Ok(false),
            "1" | "on" | "t" | "true" | "y" | "yes" => Ok(true),
            _ => Err(PARSING),
        },
        _ => Err(TYPE),
    }
}

/// `UpdateCustomerBrandingRequest` (`PUT /branding/{customer_code}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateCustomerBrandingRequest {
    /// `enabled` (default `true`).
    pub enabled: bool,
    /// The four fields (`title` has no validator here).
    pub fields: BrandingFields,
}

impl UpdateCustomerBrandingRequest {
    /// Validate a body.
    pub fn read(v: &mut Validator, obj: &Map<String, Value>, at: &Loc) -> Self {
        let enabled = match obj.get("enabled") {
            None => true,
            Some(value) => match py_bool(value) {
                Ok(b) => b,
                Err((kind, msg)) => {
                    v.push(kind, child(at, "enabled"), msg);
                    true
                }
            },
        };
        Self {
            enabled,
            fields: BrandingFields::read(v, obj, at, StrRules::max(255)),
        }
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// `UpdatePortalSettingsResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdatePortalSettingsResponse {
    /// Always `true`.
    pub success: bool,
    /// Message.
    pub message: String,
}

/// `PortalSettingsData` (`GET /settings/global`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortalSettingsData {
    /// Row id (`0` for the unsaved defaults).
    pub id: i32,
    /// Title.
    pub title: String,
    /// The logo, inline.
    pub logo_base64: Option<String>,
    /// Its MIME type.
    pub logo_mime_type: Option<String>,
    /// Colour.
    pub brand_color: Option<String>,
    /// `updated_at.isoformat()`.
    pub updated_at: String,
}

/// `PortalSettingsResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortalSettingsResponse {
    /// Always `true`.
    pub success: bool,
    /// Message.
    pub message: String,
    /// The settings.
    pub settings: Option<PortalSettingsData>,
}

/// `PublicPortalSettingsData` (`GET /settings`): no inline logo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicPortalSettingsData {
    /// Row id (`0` without a row).
    pub id: i32,
    /// Title.
    pub title: String,
    /// Versioned logo path, relative to the API root.
    pub logo_url: Option<String>,
    /// The logo's MIME type.
    pub logo_mime_type: Option<String>,
    /// Colour.
    pub brand_color: Option<String>,
    /// `updated_at.isoformat()`, `None` without a row.
    pub updated_at: Option<String>,
}

/// `PublicPortalSettingsResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicPortalSettingsResponse {
    /// Always `true`.
    pub success: bool,
    /// Message.
    pub message: String,
    /// The settings.
    pub settings: Option<PublicPortalSettingsData>,
}

/// `CustomerBrandingOverride`: the stored override row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CustomerBrandingOverride {
    /// Row id.
    pub id: i32,
    /// Customer.
    pub customer_code: String,
    /// The switch.
    pub enabled: bool,
    /// Title.
    pub title: Option<String>,
    /// Logo.
    pub logo_base64: Option<String>,
    /// Its MIME type.
    pub logo_mime_type: Option<String>,
    /// Colour.
    pub brand_color: Option<String>,
    /// `updated_at.isoformat()`.
    pub updated_at: String,
    /// Who saved it.
    pub updated_by: Option<i32>,
}

/// `EffectiveBranding`: what resolves, the logo inline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EffectiveBranding {
    /// Title.
    pub title: String,
    /// Logo.
    pub logo_base64: Option<String>,
    /// Its MIME type.
    pub logo_mime_type: Option<String>,
    /// Colour.
    pub brand_color: Option<String>,
    /// `custom` or `global`.
    pub source: String,
    /// The customer the override was resolved for.
    pub customer_code: Option<String>,
}

/// `CustomerBrandingResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CustomerBrandingResponse {
    /// Always `true`.
    pub success: bool,
    /// Message.
    pub message: String,
    /// The stored override.
    #[serde(rename = "override")]
    pub override_row: Option<CustomerBrandingOverride>,
    /// What resolves for the customer.
    pub effective: Option<EffectiveBranding>,
}

/// `CustomerBrandingListItem`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CustomerBrandingListItem {
    /// Customer.
    pub customer_code: String,
    /// The switch.
    pub enabled: bool,
    /// Title.
    pub title: Option<String>,
    /// `bool(logo_base64)`.
    pub has_logo: bool,
    /// Colour.
    pub brand_color: Option<String>,
    /// `updated_at.isoformat()`.
    pub updated_at: String,
}

/// `CustomerBrandingListResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CustomerBrandingListResponse {
    /// Always `true`.
    pub success: bool,
    /// Message.
    pub message: String,
    /// The overrides, by customer code.
    pub overrides: Vec<CustomerBrandingListItem>,
}

/// `PortalEffectiveBranding`: the logo as a versioned URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortalEffectiveBranding {
    /// Title.
    pub title: String,
    /// `/customer_portal/settings/effective/logo?v=<hash>`.
    pub logo_url: Option<String>,
    /// Its MIME type.
    pub logo_mime_type: Option<String>,
    /// Colour.
    pub brand_color: Option<String>,
    /// `custom` or `global`.
    pub source: String,
    /// The customer the override was resolved for.
    pub customer_code: Option<String>,
}

/// `EffectiveBrandingResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EffectiveBrandingResponse {
    /// Always `true`.
    pub success: bool,
    /// Message.
    pub message: String,
    /// The branding.
    pub settings: Option<PortalEffectiveBranding>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use copilot_web::validate::body_loc;
    use serde_json::json;

    fn patch(body: Value) -> Result<PatchPortalSettingsRequest, Vec<(String, String)>> {
        let mut v = Validator::new();
        let Value::Object(obj) = body else {
            panic!("object")
        };
        let req = PatchPortalSettingsRequest::read(&mut v, &obj, &body_loc());
        if v.has_errors() {
            Err(v
                .errors()
                .iter()
                .map(|e| (e.kind.clone(), e.msg.clone()))
                .collect())
        } else {
            Ok(req)
        }
    }

    #[test]
    fn patch_consistency_in_python_order() {
        let first = |b: Value| patch(b).unwrap_err()[0].1.clone();
        assert_eq!(first(json!({})), "Value error, Nothing to update");
        assert_eq!(
            first(json!({"title": null, "brand_color": null})),
            "Value error, title cannot be empty; to restore its default send reset: [\"title\"]"
        );
        assert_eq!(
            first(json!({"logo_base64": "QQ=="})),
            "Value error, logo_base64 and logo_mime_type must be sent together"
        );
        assert_eq!(
            first(
                json!({"logo_base64": "QQ==", "logo_mime_type": "image/png", "title": "x", "reset": ["logo", "title"]})
            ),
            "Value error, Cannot both set and reset: logo, title"
        );
        let ok = patch(json!({"brand_color": " #ABC ", "reset": ["logo", "logo"]})).unwrap();
        assert_eq!(ok.fields.brand_color.as_deref(), Some("#abc"));
        assert_eq!(ok.sent, ["brand_color"]);
        assert_eq!(ok.reset, ["logo", "logo"]);
        let errs = patch(json!({"title": "", "brand_color": "zz", "reset": [5]})).unwrap_err();
        let kinds: Vec<&str> = errs.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(kinds, ["string_too_short", "value_error", "literal_error"]);
    }

    #[test]
    fn pydantic_bool() {
        assert_eq!(py_bool(&json!("TRUE")), Ok(true));
        assert_eq!(py_bool(&json!(1.0)), Ok(true));
        assert_eq!(py_bool(&json!(-0.0)), Ok(false));
        assert_eq!(py_bool(&json!(" true")).unwrap_err().0, "bool_parsing");
        assert_eq!(py_bool(&json!(2)).unwrap_err().0, "bool_parsing");
        assert_eq!(py_bool(&json!(0.5)).unwrap_err().0, "bool_type");
        assert_eq!(py_bool(&json!(u64::MAX)).unwrap_err().0, "bool_type");
        assert_eq!(py_bool(&Value::Null).unwrap_err().0, "bool_type");
    }
}
