//! BoringSSL's partial-chain rule, which grpc's channel credentials apply:
//! every certificate in the root store is a trust anchor, whatever it is —
//! the server's own certificate included. webpki anchors a chain at the
//! certificate that *issued* the server's, so an `api.config.yaml` whose
//! `ca_certificate` is the server certificate itself (pinned rather than its
//! CA) connects from Python and would not from here. [`PartialChainVerifier`]
//! accepts exactly such a certificate — for the server name and within its
//! validity, as BoringSSL checks it — and leaves every other chain to webpki.

use std::sync::Arc;

use chrono::NaiveDate;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{WebPkiServerVerifier, verify_server_name};
use rustls::crypto::CryptoProvider;
use rustls::server::ParsedCertificate;
use rustls::{CertificateError, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

/// webpki, plus the root store's own certificates as end entities.
#[derive(Debug)]
pub struct PartialChainVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pinned: Vec<CertificateDer<'static>>,
}

impl PartialChainVerifier {
    /// Over `roots` (built from `pinned`, the configured certificates).
    pub fn new(
        roots: RootCertStore,
        pinned: Vec<CertificateDer<'static>>,
        provider: Arc<CryptoProvider>,
    ) -> Result<Self, String> {
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { inner, pinned })
    }
}

impl ServerCertVerifier for PartialChainVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let refused = match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => return Ok(verified),
            Err(e) => e,
        };
        if !self
            .pinned
            .iter()
            .any(|p| p.as_ref() == end_entity.as_ref())
        {
            return Err(refused);
        }
        let parsed = ParsedCertificate::try_from(end_entity)?;
        verify_server_name(&parsed, server_name)?;
        let Some((not_before, not_after)) = validity(end_entity.as_ref()) else {
            return Err(refused);
        };
        let now = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
        if now < not_before {
            return Err(Error::InvalidCertificate(CertificateError::NotValidYet));
        }
        if now > not_after {
            return Err(Error::InvalidCertificate(CertificateError::Expired));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// One DER element: `(tag, contents, rest)`.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let first = *b.get(1)?;
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(*b.get(2 + i)?);
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    Some((tag, b.get(header..end)?, b.get(end..)?))
}

/// A `Time` (UTCTime or GeneralizedTime, `Z`) as seconds since the epoch.
fn time(tag: u8, s: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(s).ok()?.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 => {
            let yy: i32 = s.get(..2)?.parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, s.get(2..)?)
        }
        0x18 => (s.get(..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    if rest.len() != 10 || !rest.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let n = |i: usize| rest.get(i..i + 2).and_then(|x| x.parse::<u32>().ok());
    let at = NaiveDate::from_ymd_opt(year, n(0)?, n(2)?)?.and_hms_opt(n(4)?, n(6)?, n(8)?)?;
    Some(at.and_utc().timestamp())
}

/// `tbsCertificate.validity` of a certificate: `(notBefore, notAfter)`.
pub fn validity(der: &[u8]) -> Option<(i64, i64)> {
    let (_, cert, _) = tlv(der)?;
    let (_, tbs, _) = tlv(cert)?;
    let mut rest = tbs;
    // [0] version, when present.
    if rest.first() == Some(&0xa0) {
        rest = tlv(rest)?.2;
    }
    // serialNumber, signature, issuer.
    for _ in 0..3 {
        rest = tlv(rest)?.2;
    }
    let (_, validity, _) = tlv(rest)?;
    let (t1, nb, after) = tlv(validity)?;
    let (t2, na, _) = tlv(after)?;
    Some((time(t1, nb)?, time(t2, na)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pki_types::pem::PemObject;

    #[test]
    fn validity_of_the_test_certificates() {
        let der = CertificateDer::from_pem_slice(include_bytes!("testing/server.pem")).unwrap();
        // 2020-01-01 to 2099-01-01 (GeneralizedTime past 2049).
        assert_eq!(validity(der.as_ref()), Some((1_577_836_800, 4_070_908_800)));
        assert_eq!(time(0x17, b"491231235959Z"), Some(2_524_607_999));
        assert_eq!(time(0x17, b"500101000000Z"), Some(-631_152_000));
        assert_eq!(time(0x17, b"5001010000Z"), None);
        assert_eq!(validity(b"\x30\x03\x02\x01\x00"), None);
    }
}
