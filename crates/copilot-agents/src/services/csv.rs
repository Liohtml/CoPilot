//! `csv.writer(io.StringIO())` with the default `excel` dialect: `,`
//! between fields, `\r\n` after each row, a field quoted (quotes doubled)
//! when it holds `,`, `"`, `\r` or `\n`; `None` is empty, other values are
//! their `str()`.

use copilot_auth::pyvalue::PyValue;

/// One field.
pub fn field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// `str()` of a cell value, `None` as empty.
pub fn cell(value: &PyValue) -> String {
    match value {
        PyValue::None => String::new(),
        other => other.py_str(),
    }
}

/// `writer.writerow(row)`.
pub fn row(out: &mut String, cells: &[String]) {
    let fields: Vec<String> = cells.iter().map(|c| field(c)).collect();
    out.push_str(&fields.join(","));
    out.push_str("\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excel_dialect() {
        let mut out = String::new();
        row(
            &mut out,
            &[
                "a".into(),
                "b,c".into(),
                "say \"hi\"".into(),
                "x\ny".into(),
                String::new(),
                cell(&PyValue::Float(7.0)),
                cell(&PyValue::None),
            ],
        );
        assert_eq!(out, "a,\"b,c\",\"say \"\"hi\"\"\",\"x\ny\",,7.0,\r\n");
    }
}
