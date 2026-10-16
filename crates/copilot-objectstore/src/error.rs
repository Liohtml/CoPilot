//! What miniopy-async raises, as values.
//!
//! [`MinioError::S3`] is `S3Error` (its `code` decides `bucket_exists` and
//! the `RetryHead` retry); everything else — `InvalidResponseError`,
//! `ServerError`, the `ValueError`s of its argument checks, aiohttp's
//! connection errors, `ParseError` — is already the [`PyExc`] the data store
//! operations see, with Python's `str(e)`.

use copilot_upstream::py::PyExc;

/// `S3Error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Error {
    /// `code`.
    pub code: Option<String>,
    /// `message`.
    pub message: Option<String>,
    /// `resource`.
    pub resource: Option<String>,
    /// `request_id`.
    pub request_id: Option<String>,
    /// `host_id`.
    pub host_id: Option<String>,
    /// `bucket_name`.
    pub bucket_name: Option<String>,
    /// `object_name`.
    pub object_name: Option<String>,
    /// For a `RetryHead`: the code and message `_handle_redirect_response`
    /// gives the same answer without the retry (what a second `RetryHead`
    /// is reported as).
    pub unretried: Option<(Option<String>, Option<String>)>,
}

fn none_or(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or("None")
}

impl S3Error {
    /// `str(S3Error)`.
    pub fn text(&self) -> String {
        let bucket = match self.bucket_name.as_deref() {
            Some(b) if !b.is_empty() => format!(", bucket_name: {b}"),
            _ => String::new(),
        };
        let object = match self.object_name.as_deref() {
            Some(o) if !o.is_empty() => format!(", object_name: {o}"),
            _ => String::new(),
        };
        format!(
            "S3 operation failed; code: {}, message: {}, resource: {}, request_id: {}, \
             host_id: {}{bucket}{object}",
            none_or(&self.code),
            none_or(&self.message),
            none_or(&self.resource),
            none_or(&self.request_id),
            none_or(&self.host_id),
        )
    }

    /// `S3Error.copy(code, message)`.
    pub fn copy(&self, code: Option<String>, message: Option<String>) -> Self {
        Self {
            code,
            message,
            unretried: None,
            ..self.clone()
        }
    }
}

/// A failed client call.
#[derive(Debug, Clone, PartialEq)]
pub enum MinioError {
    /// `S3Error`.
    S3(Box<S3Error>),
    /// Anything else, as the exception Python would hold.
    Py(PyExc),
}

impl MinioError {
    /// The S3 error code, if this is an `S3Error`.
    pub fn code(&self) -> Option<&str> {
        match self {
            MinioError::S3(e) => e.code.as_deref(),
            MinioError::Py(_) => None,
        }
    }

    /// The exception as the data store operations hold it.
    pub fn into_py(self) -> PyExc {
        match self {
            MinioError::S3(e) => PyExc::Other("S3Error", e.text()),
            MinioError::Py(e) => e,
        }
    }

    /// A `ValueError`.
    pub fn value(text: impl Into<String>) -> Self {
        MinioError::Py(PyExc::ValueError(text.into()))
    }
}

impl From<PyExc> for MinioError {
    fn from(e: PyExc) -> Self {
        MinioError::Py(e)
    }
}

/// `bytes.decode()` (UTF-8, strict): `UnicodeDecodeError` — a `ValueError`
/// — in CPython's words.
pub fn utf8(body: &[u8]) -> Result<String, PyExc> {
    match std::str::from_utf8(body) {
        Ok(s) => Ok(s.to_string()),
        Err(e) => {
            let start = e.valid_up_to();
            let (from, to, reason) = match e.error_len() {
                Some(n) => {
                    let first = body[start];
                    let reason = if (0x80..=0xC1).contains(&first) || first >= 0xF5 {
                        "invalid start byte"
                    } else {
                        "invalid continuation byte"
                    };
                    (start, start + n - 1, reason)
                }
                None => (start, body.len() - 1, "unexpected end of data"),
            };
            let text = if from == to {
                format!(
                    "'utf-8' codec can't decode byte 0x{:02x} in position {from}: {reason}",
                    body[start]
                )
            } else {
                format!("'utf-8' codec can't decode bytes in position {from}-{to}: {reason}")
            };
            Err(PyExc::ValueError(text))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_error_reads_like_miniopy() {
        let e = S3Error {
            code: Some("NoSuchBucket".into()),
            message: Some("The specified bucket does not exist".into()),
            resource: Some("/nobucket".into()),
            request_id: Some("18A2F7C3D4E5F601".into()),
            host_id: Some("dd90".into()),
            bucket_name: Some("nobucket".into()),
            object_name: Some(String::new()),
            unretried: None,
        };
        assert_eq!(
            e.text(),
            "S3 operation failed; code: NoSuchBucket, message: The specified bucket does not \
             exist, resource: /nobucket, request_id: 18A2F7C3D4E5F601, host_id: dd90, \
             bucket_name: nobucket"
        );
        let head = S3Error {
            code: Some("NoSuchKey".into()),
            message: Some("Object does not exist".into()),
            resource: Some("/b/k".into()),
            request_id: None,
            host_id: None,
            bucket_name: Some("b".into()),
            object_name: Some("k".into()),
            unretried: None,
        };
        assert!(
            head.text()
                .ends_with("request_id: None, host_id: None, bucket_name: b, object_name: k")
        );
    }

    #[test]
    fn unicode_errors_read_like_cpython() {
        assert_eq!(
            utf8(b"ab\xffc").unwrap_err().text(),
            "'utf-8' codec can't decode byte 0xff in position 2: invalid start byte"
        );
        assert_eq!(
            utf8(b"ab\xc3").unwrap_err().text(),
            "'utf-8' codec can't decode byte 0xc3 in position 2: unexpected end of data"
        );
    }
}
