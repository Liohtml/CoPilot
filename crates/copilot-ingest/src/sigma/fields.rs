//! `extract_event_fields` — the single definition of what an exclusion's
//! `field_matches` key can refer to. The ingest-time matcher, the draft's
//! candidate list and the dry-run all read the map this builds, so a rule
//! drafted from an alert can only name fields the ingest will find.
//!
//! Python builds it from `dir(parsed_event.EventData)`: the model's
//! *declared* fields, in sorted order, each as `str()` of its validated
//! value (extras are not listed by `dir()`). PowerShell's `ContextInfo`
//! extra is then split into `key = value` lines, each added under its own
//! name and, for a name with spaces, a lowerCamelCase variant.

use copilot_auth::pyvalue::PyValue;

use super::events::{ParseError, ParsedEvent, SigmaEvent, get_parsed_event};
use crate::py::{capitalize, dict_set, py_strip, split_ws, splitlines};

/// `extract_event_fields(alert)`; `Err` is the exception it raises (an
/// unparseable event, a `ContextInfo` that is not a string).
pub fn extract_event_fields(
    channel: &str,
    event: &SigmaEvent,
) -> Result<Vec<(String, String)>, ParseError> {
    let parsed = get_parsed_event(channel, event)?;
    fields_of(&parsed)
}

/// The map for an already parsed event.
pub fn fields_of(parsed: &ParsedEvent) -> Result<Vec<(String, String)>, ParseError> {
    let mut names: Vec<&(String, PyValue)> = parsed.fields.iter().collect();
    names.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out: Vec<(String, PyValue)> = names
        .into_iter()
        .map(|(k, v)| (k.clone(), PyValue::Str(v.py_str())))
        .collect();
    if let Some(info) = parsed.data("ContextInfo").filter(|v| v.truthy()) {
        let PyValue::Str(text) = info else {
            return Err(ParseError(format!(
                "'{}' object has no attribute 'splitlines'",
                crate::py::type_name(info)
            )));
        };
        for line in splitlines(text) {
            let line = py_strip(line);
            let Some((key, value)) = line.split_once(" = ") else {
                continue;
            };
            if line.is_empty() {
                continue;
            }
            let key = py_strip(key);
            let value = py_strip(value).to_string();
            dict_set(&mut out, key, PyValue::Str(value.clone()));
            if key.contains(' ') {
                let camel: String = split_ws(key).into_iter().map(capitalize).collect();
                let mut chars = camel.chars();
                let camel = match chars.next() {
                    Some(first) => {
                        let mut s: String = first.to_lowercase().collect();
                        s.push_str(chars.as_str());
                        s
                    }
                    None => camel,
                };
                dict_set(&mut out, &camel, PyValue::Str(value));
            }
        }
    }
    // Pydantic models expose their config too - it is not an event field.
    for k in [
        "model_config",
        "model_fields",
        "model_computed_fields",
        "model_extra",
        "model_fields_set",
    ] {
        crate::py::dict_pop(&mut out, k);
    }
    Ok(out
        .into_iter()
        .map(|(k, v)| match v {
            PyValue::Str(s) => (k, s),
            other => (k, other.py_str()),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma::events::EventKind;

    #[test]
    fn context_info_lines() {
        let parsed = ParsedEvent {
            kind: EventKind::Generic,
            system: Vec::new(),
            fields: vec![
                ("Path".into(), PyValue::Str("p".into())),
                ("MessageNumber".into(), PyValue::Int("1".into())),
            ],
            extras: vec![(
                "ContextInfo".into(),
                PyValue::Str(
                    "  Host Application = powershell.exe -c x\r\n  Engine Version = 5\nnoequals\n"
                        .into(),
                ),
            )],
        };
        let f = fields_of(&parsed).unwrap();
        assert_eq!(
            f,
            vec![
                ("MessageNumber".into(), "1".into()),
                ("Path".into(), "p".into()),
                ("Host Application".into(), "powershell.exe -c x".into()),
                ("hostApplication".into(), "powershell.exe -c x".into()),
                ("Engine Version".into(), "5".into()),
                ("engineVersion".into(), "5".into()),
            ]
        );
    }
}
