//! Port of `app/customer_portal/utils/validators.py`: the branding fields
//! shared by the global settings and the per-customer overrides.
//!
//! One definition, so an override can never carry a payload the global
//! settings would have rejected (or the other way round). An empty value
//! normalises to `None`. A failure is the `ValueError` text Pydantic turns
//! into the standard 422 naming the field.

use copilot_auth::pybase64::b64decode_validate;
use copilot_web::form::py_strip;

/// `ALLOWED_LOGO_MIME_TYPES`, in Python's order (the error names them so).
pub const ALLOWED_LOGO_MIME_TYPES: [&str; 6] = [
    "image/png",
    "image/jpeg",
    "image/jpg",
    "image/gif",
    "image/svg+xml",
    "image/webp",
];

/// `MAX_LOGO_BASE64_BYTES`: 5 MiB of base64 text (counted in characters).
pub const MAX_LOGO_BASE64_BYTES: usize = 5 * 1024 * 1024;

/// `_HEX_COLOR.match(value)`: `#RGB` or `#RRGGBB` (the value is already
/// stripped, so `$`'s trailing-newline allowance cannot apply).
fn is_hex_color(value: &str) -> bool {
    let Some(hex) = value.strip_prefix('#') else {
        return false;
    };
    (hex.len() == 3 || hex.len() == 6) && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `^[A-Za-z0-9+/]*={0,2}` matched to the very end.
fn is_base64_shape(value: &str) -> bool {
    let data = value.trim_end_matches('=');
    value.len() - data.len() <= 2
        && data
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// `_BASE64.match(value)`: Python's `$` also matches before a final `\n`.
fn matches_base64_pattern(value: &str) -> bool {
    is_base64_shape(value) || value.strip_suffix('\n').is_some_and(is_base64_shape)
}

/// `validate_brand_color`: a hex colour (`#RGB` or `#RRGGBB`), lower-cased.
pub fn validate_brand_color(value: Option<&str>) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = py_strip(value);
    if value.is_empty() {
        return Ok(None);
    }
    if !is_hex_color(value) {
        return Err("Expected a hex color like #RGB or #RRGGBB".into());
    }
    Ok(Some(value.to_ascii_lowercase()))
}

/// `validate_logo_base64`: base64 within the size limit; a data URL is
/// reduced to its payload.
pub fn validate_logo_base64(value: Option<&str>) -> Result<Option<String>, String> {
    let Some(mut value) = value else {
        return Ok(None);
    };
    if value.starts_with("data:") {
        if let Some((_, payload)) = value.split_once(',') {
            value = payload;
        }
    }
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().count() > MAX_LOGO_BASE64_BYTES {
        return Err(format!(
            "Logo file too large. Maximum size is {}MB (base64-encoded)",
            MAX_LOGO_BASE64_BYTES / (1024 * 1024)
        ));
    }
    if !matches_base64_pattern(value) {
        return Err("Not a valid base64 string".into());
    }
    if b64decode_validate(value).is_err() {
        return Err("Base64 data cannot be decoded".into());
    }
    Ok(Some(value.to_string()))
}

/// `validate_logo_mime_type`: one of the image types a logo may be served as.
pub fn validate_logo_mime_type(value: Option<&str>) -> Result<Option<String>, String> {
    match value {
        None | Some("") => Ok(None),
        Some(v) if ALLOWED_LOGO_MIME_TYPES.contains(&v) => Ok(Some(v.to_string())),
        Some(_) => Err(format!(
            "Unsupported MIME type. Allowed types are: {}",
            ALLOWED_LOGO_MIME_TYPES.join(", ")
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_rules() {
        assert_eq!(
            validate_brand_color(Some(" #ABC ")),
            Ok(Some("#abc".into()))
        );
        assert_eq!(validate_brand_color(Some("  ")), Ok(None));
        assert!(validate_brand_color(Some("#12345")).is_err());
        assert_eq!(
            validate_logo_base64(Some("data:image/png;base64,iVBORw0KGgo=")),
            Ok(Some("iVBORw0KGgo=".into()))
        );
        assert_eq!(validate_logo_base64(Some("data:,")), Ok(None));
        assert_eq!(
            validate_logo_base64(Some("data:x")),
            Err("Not a valid base64 string".into())
        );
        assert_eq!(
            validate_logo_base64(Some("QQ==\n")),
            Err("Base64 data cannot be decoded".into()),
            "`$` matches before the final newline; the decoder refuses it"
        );
        assert_eq!(validate_logo_base64(Some("QR==")), Ok(Some("QR==".into())));
        assert_eq!(validate_logo_mime_type(Some("")), Ok(None));
        assert!(validate_logo_mime_type(Some("application/pdf")).is_err());
    }
}
