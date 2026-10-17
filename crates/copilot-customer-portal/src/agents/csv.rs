//! CPython's `csv.writer` with the default `excel` dialect: `,` between
//! fields, `\r\n` after each row, a field quoted (`"` doubled) when it holds
//! the delimiter, the quote character, `\r` or `\n` (`QUOTE_MINIMAL`).

/// One row, line terminator included.
pub fn row<S: AsRef<str>>(fields: &[S]) -> String {
    let mut out = String::new();
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let field = field.as_ref();
        if field.contains([',', '"', '\r', '\n']) {
            out.push('"');
            out.push_str(&field.replace('"', "\"\""));
            out.push('"');
        } else {
            out.push_str(field);
        }
    }
    out.push_str("\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_minimal() {
        assert_eq!(row(&["a", "", "b c"]), "a,,b c\r\n");
        assert_eq!(
            row(&["a,b", "say \"hi\"", "x\ny"]),
            "\"a,b\",\"say \"\"hi\"\"\",\"x\ny\"\r\n"
        );
        assert_eq!(row(&["\r"]), "\"\r\"\r\n");
    }
}
