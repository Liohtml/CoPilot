//! AWS Signature Version 4 as miniopy-async's `signer.py` computes it.
//!
//! The canonical request is `signer._get_canonical_request_hash`'s: the
//! method, the already-quoted path (`/` when empty), the query split on `&`
//! and `=` and sorted as lists, every header but `Authorization` and
//! `User-Agent` (names lower-cased, runs of spaces collapsed, values
//! stripped, sorted by name), the signed-header list and the payload hash.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use copilot_web::form::py_strip;

/// What a request is signed with.
#[derive(Debug, Clone)]
pub struct Credentials {
    /// Access key (`MINIO_ROOT_USER`).
    pub access_key: String,
    /// Secret key (`MINIO_ROOT_PASSWORD`).
    pub secret_key: String,
}

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC takes keys of any length.
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Hex SHA-256 (`sha256_hash`).
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// `_get_canonical_query_string`.
pub fn canonical_query(query: &str) -> String {
    let mut pairs: Vec<Vec<&str>> = query.split('&').map(|p| p.split('=').collect()).collect();
    pairs.sort();
    pairs
        .iter()
        .map(|p| p.join("="))
        .collect::<Vec<_>>()
        .join("&")
}

/// `_MULTI_SPACE_REGEX.sub(" ", value).strip()`.
fn canonical_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut previous_space = false;
    for c in value.chars() {
        if c == ' ' {
            if !previous_space {
                out.push(' ');
            }
            previous_space = true;
        } else {
            out.push(c);
            previous_space = false;
        }
    }
    py_strip(&out).to_string()
}

/// `_get_canonical_headers`: the canonical header block and the signed
/// header names.
pub fn canonical_headers(headers: &[(String, String)]) -> (String, String) {
    let mut ordered: Vec<(String, String)> = Vec::new();
    for (name, value) in headers {
        let key = name.to_lowercase();
        if key == "authorization" || key == "user-agent" {
            continue;
        }
        let value = canonical_value(value);
        match ordered.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = value,
            None => ordered.push((key, value)),
        }
    }
    ordered.sort_by(|a, b| a.0.cmp(&b.0));
    let signed = ordered
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let block = ordered
        .iter()
        .map(|(k, v)| format!("{k}:{v}"))
        .collect::<Vec<_>>()
        .join("\n");
    (block, signed)
}

/// The canonical request (`_get_canonical_request_hash` before hashing).
pub fn canonical_request(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    content_sha256: &str,
) -> (String, String) {
    let (block, signed) = canonical_headers(headers);
    let path = if path.is_empty() { "/" } else { path };
    (
        format!(
            "{method}\n{path}\n{}\n{block}\n\n{signed}\n{content_sha256}",
            canonical_query(query)
        ),
        signed,
    )
}

/// `sign_v4_s3`: the `Authorization` header value. `amz_date` is
/// `%Y%m%dT%H%M%SZ`; its first eight characters are the scope date.
#[allow(clippy::too_many_arguments)]
pub fn authorization(
    method: &str,
    path: &str,
    query: &str,
    region: &str,
    headers: &[(String, String)],
    credentials: &Credentials,
    content_sha256: &str,
    amz_date: &str,
) -> String {
    let date = amz_date.get(..8).unwrap_or(amz_date);
    let scope = format!("{date}/{region}/s3/aws4_request");
    let (canonical, signed) = canonical_request(method, path, query, headers, content_sha256);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical.as_bytes())
    );
    let mut key = hmac(
        format!("AWS4{}", credentials.secret_key).as_bytes(),
        date.as_bytes(),
    );
    for part in [region, "s3", "aws4_request"] {
        key = hmac(&key, part.as_bytes());
    }
    let signature = hex::encode(hmac(&key, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
        credentials.access_key
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn canonical_query_sorts_split_pairs() {
        assert_eq!(canonical_query(""), "");
        assert_eq!(canonical_query("location="), "location=");
        assert_eq!(
            canonical_query("uploadId=x&partNumber=2"),
            "partNumber=2&uploadId=x"
        );
    }

    #[test]
    fn headers_collapse_spaces_and_skip_user_agent() {
        let (block, signed) = canonical_headers(&h(&[
            ("Content-Type", "text/plain;   charset=x "),
            ("Host", "h:9000"),
            ("User-Agent", "MinIO"),
            ("x-amz-date", "20260101T000000Z"),
        ]));
        assert_eq!(signed, "content-type;host;x-amz-date");
        assert_eq!(
            block,
            "content-type:text/plain; charset=x\nhost:h:9000\nx-amz-date:20260101T000000Z"
        );
    }

    /// The signature miniopy-async 1.23.5 computes for this request
    /// (recorded from `sign_v4_s3`).
    #[test]
    fn signature_matches_miniopy() {
        let creds = Credentials {
            access_key: "admin".into(),
            secret_key: "password".into(),
        };
        let headers = h(&[
            ("Host", "127.0.0.1:5760"),
            ("User-Agent", "MinIO (Linux; x86_64) miniopy-async/1.23.5"),
            (
                "x-amz-content-sha256",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            ("x-amz-date", "20261016T091227Z"),
        ]);
        let auth = authorization(
            "GET",
            "/copilot-cases",
            "location=",
            "us-east-1",
            &headers,
            &creds,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "20261016T091227Z",
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=admin/20261016/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=a7b79e3de59569225ad0e08b06dd8731a96f79fbcdd48ecc74469e4f5c6cd0dd"
        );
    }
}
