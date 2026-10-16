//! `ssl.create_default_context(cadata=pem)` as `_clean_ca_cert` uses it to
//! validate an uploaded CA: CPython's `_add_ca_certs` reads PEM certificates
//! with OpenSSL until one fails, and decides from how many it loaded.
//!
//! | Input | Python |
//! |---|---|
//! | not ASCII | `TypeError` (a bare 500) |
//! | no certificate that parses | `no start line: cadata does not contain a certificate (_ssl.c:4049)` |
//! | one or more, then a block that does not parse | `[PEM] ASN1 lib (_ssl.c:4062)` |
//! | one or more, then nothing | accepted |
//!
//! A certificate "parses" when its PEM block is well formed, its base64
//! decodes and the DER is an X.509 certificate (`x509-cert`'s parser in place
//! of OpenSSL's `d2i_X509`; the two agree on certificates). The `_ssl.c` line
//! numbers are those of the CPython 3.11 build the backend runs.

use base64::Engine as _;
use x509_cert::der::Decode as _;

/// What a CA upload is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PemCheck {
    /// Loaded.
    Ok,
    /// `ssl.SSLError(text)`.
    SslError(String),
    /// `TypeError`.
    NotAscii,
}

/// The message for "no certificate at all".
pub const NO_CERTIFICATE: &str =
    "no start line: cadata does not contain a certificate (_ssl.c:4049)";
/// The message for a broken certificate after a good one.
pub const ASN1_LIB: &str = "[PEM] ASN1 lib (_ssl.c:4062)";

const LABELS: &[&str] = &["CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"];

/// Check `pem` as `ssl.create_default_context(cadata=pem)` would.
pub fn check(pem: &str) -> PemCheck {
    if !pem.is_ascii() {
        return PemCheck::NotAscii;
    }
    let lines: Vec<&str> = pem
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .collect();
    let mut loaded = 0usize;
    let mut i = 0usize;
    loop {
        // The next BEGIN line of a certificate label.
        let mut found = None;
        while i < lines.len() {
            let line = lines[i];
            i += 1;
            if let Some(label) = line
                .strip_prefix("-----BEGIN ")
                .and_then(|r| r.strip_suffix("-----"))
            {
                if LABELS.contains(&label) {
                    found = Some(label);
                    break;
                }
            }
        }
        let Some(label) = found else {
            // End of input: "no start line", which is EOF once one loaded.
            return if loaded == 0 {
                PemCheck::SslError(NO_CERTIFICATE.into())
            } else {
                PemCheck::Ok
            };
        };
        let end = format!("-----END {label}-----");
        let mut body = String::new();
        let mut closed = false;
        while i < lines.len() {
            let line = lines[i];
            i += 1;
            if line == end {
                closed = true;
                break;
            }
            body.push_str(line.trim());
        }
        let parsed = closed
            && base64::engine::general_purpose::STANDARD
                .decode(body.as_bytes())
                .ok()
                .is_some_and(|der| x509_cert::Certificate::from_der(&der).is_ok());
        if !parsed {
            return PemCheck::SslError(if loaded == 0 {
                NO_CERTIFICATE.into()
            } else {
                ASN1_LIB.into()
            });
        }
        loaded += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openssl_outcomes() {
        assert_eq!(
            check("not a cert"),
            PemCheck::SslError(NO_CERTIFICATE.into())
        );
        assert_eq!(
            check("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"),
            PemCheck::SslError(NO_CERTIFICATE.into())
        );
        assert_eq!(check("é"), PemCheck::NotAscii);
    }
}
