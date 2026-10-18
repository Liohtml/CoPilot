//! Pydantic's `UUID4` on a JSON value, with pydantic-core 2.46's errors: a
//! string parsed by the `uuid` crate release it embeds (whose messages, and
//! 1-based positions, are not those of the release this workspace uses),
//! then the version check.

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{Loc, PyError};

/// `UUID4` → the canonical text (`str(UUID)`), or the error line.
pub fn check(value: &PyValue, field: &str) -> Result<String, PyError> {
    let error = |kind: &'static str, msg: String| PyError {
        loc: vec![Loc::Key(field.to_string())],
        kind,
        msg,
        input: value.clone(),
    };
    let PyValue::Str(s) = value else {
        return Err(error(
            "uuid_type",
            "UUID input should be a string, bytes or UUID object".into(),
        ));
    };
    match uuid::Uuid::parse_str(s) {
        Ok(u) if u.get_version_num() == 4 => Ok(u.hyphenated().to_string()),
        Ok(_) => Err(error("uuid_version", "UUID version 4 expected".into())),
        Err(_) => Err(error(
            "uuid_parsing",
            format!("Input should be a valid UUID, {}", parse_error(s)),
        )),
    }
}

/// `InvalidUuid::into_err()` of the `uuid` release pydantic-core embeds.
fn parse_error(input: &str) -> String {
    // `try_parse` hands `InvalidUuid` the inner part of a braced (38 bytes)
    // or URN (45 bytes) input whose hyphenated parse failed.
    let whole = input.as_bytes();
    let input = if whole.len() == 38 && whole[0] == b'{' && whole[37] == b'}' {
        &input[1..37]
    } else if whole.len() == 45 && input.starts_with("urn:uuid:") {
        &input[9..]
    } else {
        input
    };
    let bytes = input.as_bytes();
    let (body, offset, simple): (&str, usize, bool) =
        if bytes.len() >= 2 && bytes[0] == b'{' && bytes[bytes.len() - 1] == b'}' {
            (&input[1..input.len() - 1], 1, false)
        } else if let Some(rest) = input.strip_prefix("urn:uuid:") {
            (rest, "urn:uuid:".len(), false)
        } else {
            (input, 0, true)
        };
    let mut hyphens = 0usize;
    let mut bounds = [0usize; 4];
    for (index, character) in body.char_indices() {
        let byte = (character as u32 & 0xff) as u8;
        if character as u32 != u32::from(byte) {
            return format!(
                "invalid character: found `{character}` at {}",
                index + offset + 1
            );
        } else if byte == b'-' {
            if hyphens < 4 {
                bounds[hyphens] = index;
            }
            hyphens += 1;
        } else if !byte.is_ascii_hexdigit() {
            return format!(
                "invalid character: found `{}` at {}",
                char::from(byte),
                index + offset + 1
            );
        }
    }
    if hyphens == 0 && simple {
        return format!(
            "invalid length: expected length 32 for simple format, found {}",
            input.len()
        );
    }
    if hyphens != 4 {
        return format!("invalid group count: expected 5, found {}", hyphens + 1);
    }
    const STARTS: [usize; 5] = [0, 9, 14, 19, 24];
    const LENGTHS: [usize; 5] = [8, 4, 4, 4, 12];
    for i in 0..4 {
        if bounds[i] != STARTS[i + 1] - 1 {
            return format!(
                "invalid group length in group {i}: expected {}, found {}",
                LENGTHS[i],
                bounds[i].saturating_sub(STARTS[i])
            );
        }
    }
    format!(
        "invalid group length in group 4: expected 12, found {}",
        input.len().saturating_sub(STARTS[4])
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured from pydantic 2.13 (pydantic-core 2.46.4).
    const VECTORS: &[(&str, &str, &str)] = &[
        (
            "x",
            "uuid_parsing",
            "Input should be a valid UUID, invalid character: found `x` at 1",
        ),
        (
            "abc",
            "uuid_parsing",
            "Input should be a valid UUID, invalid length: expected length 32 for simple format, found 3",
        ),
        (
            "12345678-1234-1234-1234-1234567890ab",
            "uuid_version",
            "UUID version 4 expected",
        ),
        (
            "12345678123412341234123456789",
            "uuid_parsing",
            "Input should be a valid UUID, invalid length: expected length 32 for simple format, found 29",
        ),
        (
            "{12345678-1234-4234-8234-1234567890ab}",
            "ok",
            "12345678-1234-4234-8234-1234567890ab",
        ),
        (
            "urn:uuid:12345678-1234-4234-8234-1234567890ab",
            "ok",
            "12345678-1234-4234-8234-1234567890ab",
        ),
        (
            "12345678-1234-4234-8234-1234567890AB",
            "ok",
            "12345678-1234-4234-8234-1234567890ab",
        ),
        (
            "12345678-1234-4234-8234-1234567890ab-",
            "uuid_parsing",
            "Input should be a valid UUID, invalid group count: expected 5, found 6",
        ),
        (
            "1234567-81234-4234-8234-1234567890ab",
            "uuid_parsing",
            "Input should be a valid UUID, invalid group length in group 0: expected 8, found 7",
        ),
        (
            "",
            "uuid_parsing",
            "Input should be a valid UUID, invalid length: expected length 32 for simple format, found 0",
        ),
        (
            " 12345678-1234-4234-8234-1234567890ab",
            "uuid_parsing",
            "Input should be a valid UUID, invalid character: found ` ` at 1",
        ),
        (
            "é",
            "uuid_parsing",
            "Input should be a valid UUID, invalid character: found `é` at 1",
        ),
        (
            "aé",
            "uuid_parsing",
            "Input should be a valid UUID, invalid character: found `é` at 2",
        ),
        (
            "{1234567x-1234-4234-8234-1234567890ab}",
            "uuid_parsing",
            "Input should be a valid UUID, invalid character: found `x` at 8",
        ),
        (
            "urn:uuid:12345678-1234-4234-8234-1234567890a",
            "uuid_parsing",
            "Input should be a valid UUID, invalid group length in group 4: expected 12, found 20",
        ),
        (
            "urn:uuid:12345678-1234-4234-8234-1234567890abc",
            "uuid_parsing",
            "Input should be a valid UUID, invalid group length in group 4: expected 12, found 22",
        ),
        (
            "{12345678-1234-4234-8234-1234567890ab",
            "uuid_parsing",
            "Input should be a valid UUID, invalid character: found `{` at 1",
        ),
        (
            "12345678-1234-4234-8234-1234567890a",
            "uuid_parsing",
            "Input should be a valid UUID, invalid group length in group 4: expected 12, found 11",
        ),
        (
            "12345678-1234-4234-8234-1234567890abc",
            "uuid_parsing",
            "Input should be a valid UUID, invalid group length in group 4: expected 12, found 13",
        ),
        (
            "123456781234423482341234567890ab",
            "ok",
            "12345678-1234-4234-8234-1234567890ab",
        ),
        (
            "12345678-12344-234-8234-1234567890ab",
            "uuid_parsing",
            "Input should be a valid UUID, invalid group length in group 1: expected 4, found 5",
        ),
        (
            "12345678-1234-4234-82341-234567890ab",
            "uuid_parsing",
            "Input should be a valid UUID, invalid group length in group 3: expected 4, found 5",
        ),
        (
            "12345678-1234-4234-8234-12345678-90ab",
            "uuid_parsing",
            "Input should be a valid UUID, invalid group count: expected 5, found 6",
        ),
        (
            "g2345678123442348234123456789012",
            "uuid_parsing",
            "Input should be a valid UUID, invalid character: found `g` at 1",
        ),
        (
            "{}",
            "uuid_parsing",
            "Input should be a valid UUID, invalid group count: expected 5, found 1",
        ),
        (
            "urn:uuid:",
            "uuid_parsing",
            "Input should be a valid UUID, invalid group count: expected 5, found 1",
        ),
        (
            "--------",
            "uuid_parsing",
            "Input should be a valid UUID, invalid group count: expected 5, found 9",
        ),
        (
            "12345678-1234-4234-8234-1234567890ab12",
            "uuid_parsing",
            "Input should be a valid UUID, invalid group length in group 4: expected 12, found 14",
        ),
        (
            "ffffffff-ffff-4fff-bfff-ffffffffffff",
            "ok",
            "ffffffff-ffff-4fff-bfff-ffffffffffff",
        ),
        (
            "00000000-0000-0000-0000-000000000000",
            "uuid_version",
            "UUID version 4 expected",
        ),
        (
            "{12345678-1234-4234-8234-1234567890abc}",
            "uuid_parsing",
            "Input should be a valid UUID, invalid group length in group 4: expected 12, found 15",
        ),
        (
            "URN:UUID:12345678-1234-4234-8234-1234567890ab",
            "uuid_parsing",
            "Input should be a valid UUID, invalid character: found `U` at 1",
        ),
        (
            "12345678-1234-4234-8234-1234567890€b",
            "uuid_parsing",
            "Input should be a valid UUID, invalid character: found `€` at 35",
        ),
        (
            "urn:uuid:1234567x-1234-4234-8234-1234567890ab",
            "uuid_parsing",
            "Input should be a valid UUID, invalid character: found `x` at 8",
        ),
        (
            "urn:uuid:x",
            "uuid_parsing",
            "Input should be a valid UUID, invalid character: found `x` at 10",
        ),
        (
            "{x}",
            "uuid_parsing",
            "Input should be a valid UUID, invalid character: found `x` at 2",
        ),
        (
            "{12345678-1234-4234-8234-1234567890€}",
            "uuid_parsing",
            "Input should be a valid UUID, invalid character: found `€` at 36",
        ),
        (
            "urn:uuid:12345678-1234-4234-8234-1234567890a€",
            "uuid_parsing",
            "Input should be a valid UUID, invalid character: found `€` at 45",
        ),
    ];

    #[test]
    fn uuid4_reads_like_pydantic() {
        for (input, kind, text) in VECTORS {
            let got = check(&PyValue::Str((*input).into()), "a");
            match got {
                Ok(s) => assert_eq!(("ok", s.as_str()), (*kind, *text), "{input}"),
                Err(e) => assert_eq!((e.kind, e.msg.as_str()), (*kind, *text), "{input}"),
            }
        }
        let e = check(&PyValue::Int("5".into()), "a").unwrap_err();
        assert_eq!(e.kind, "uuid_type");
    }
}
