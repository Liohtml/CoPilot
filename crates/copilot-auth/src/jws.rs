//! RS256 ID tokens from an identity provider, checked the way the SSO
//! service checks them with PyJWT 2.12 (`jwt.decode(token, key,
//! algorithms=["RS256"], audience=…, issuer=…)`), and the RSA keys of a JWKS
//! (`RSAAlgorithm.from_jwk`).
//!
//! The SSO routes turn every PyJWT failure into one generic message, so only
//! the decision has to match, not PyJWT's error texts:
//! - three segments split as PyJWT does (`rsplit` once, then `split` once),
//!   each decoded with the lenient base64 ([`crate::pybase64`]), the header and
//!   the payload with Python's JSON (`json.loads(bytes)`) and both objects;
//! - a non-string `kid`, an invalid `crit` header and `b64: false` are
//!   refused; `alg` must be `RS256`; the signature is RSASSA-PKCS1-v1_5/SHA-256;
//! - claims with leeway 0: `iat` and `nbf` not in the future, `exp` after now
//!   (each through Python's `int()`), `iss` present and equal, `aud` a string
//!   or a list of strings containing the audience (no audience configured: a
//!   token carrying a non-empty `aud` is refused), `sub` and `jti` strings
//!   when present.

use crate::pybase64::jwt_base64url_decode;
use crate::pyvalue::{PyValue, loads_bytes};
use crate::rsa::{HashAlg, RsaPublicKey};

/// Why a token or key was refused (for logs; callers show one message).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct JwsError(pub &'static str);

/// A parsed, not yet verified token.
#[derive(Debug, Clone)]
pub struct UnverifiedToken {
    header: Vec<(String, PyValue)>,
    payload: Vec<u8>,
    signing_input: Vec<u8>,
    signature: Vec<u8>,
}

impl UnverifiedToken {
    /// `jwt.get_unverified_header`: PyJWT's `_load` and header checks.
    pub fn parse(token: &str) -> Result<Self, JwsError> {
        let bytes = token.as_bytes();
        let dot = bytes
            .iter()
            .rposition(|b| *b == b'.')
            .ok_or(JwsError("Not enough segments"))?;
        let (signing_input, crypto) = (&bytes[..dot], &bytes[dot + 1..]);
        let first = signing_input
            .iter()
            .position(|b| *b == b'.')
            .ok_or(JwsError("Not enough segments"))?;
        let (header_seg, payload_seg) = (&signing_input[..first], &signing_input[first + 1..]);
        let text = |seg: &[u8]| String::from_utf8_lossy(seg).into_owned();
        let header_bytes = jwt_base64url_decode(&text(header_seg))
            .map_err(|_| JwsError("Invalid header padding"))?;
        let header = match loads_bytes(&header_bytes) {
            Ok(PyValue::Dict(items)) => items,
            _ => return Err(JwsError("Invalid header string")),
        };
        let payload = jwt_base64url_decode(&text(payload_seg))
            .map_err(|_| JwsError("Invalid payload padding"))?;
        let signature =
            jwt_base64url_decode(&text(crypto)).map_err(|_| JwsError("Invalid crypto padding"))?;
        let token = Self {
            header,
            payload,
            signing_input: signing_input.to_vec(),
            signature,
        };
        token.validate_headers()?;
        Ok(token)
    }

    fn header(&self, key: &str) -> Option<&PyValue> {
        self.header.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    fn validate_headers(&self) -> Result<(), JwsError> {
        if self.header("kid").is_some_and(|kid| kid.as_str().is_none()) {
            return Err(JwsError("Key ID header parameter must be a string"));
        }
        if let Some(crit) = self.header("crit") {
            let PyValue::List(exts) = crit else {
                return Err(JwsError("Invalid 'crit' header"));
            };
            if exts.is_empty() {
                return Err(JwsError("Invalid 'crit' header"));
            }
            for ext in exts {
                match ext.as_str() {
                    Some("b64") if self.header("b64").is_some() => {}
                    _ => return Err(JwsError("Invalid 'crit' header")),
                }
            }
        }
        Ok(())
    }

    /// The header's `kid` (`None` when absent).
    pub fn kid(&self) -> Option<&str> {
        self.header("kid").and_then(PyValue::as_str)
    }

    /// `jwt.decode(…, algorithms=["RS256"], audience, issuer)` with the
    /// `verify_exp/aud/iss` options the SSO service passes; `now` is
    /// `datetime.now(tz=utc).timestamp()`.
    pub fn verify_rs256(
        &self,
        key: &RsaPublicKey,
        audience: Option<&str>,
        issuer: &str,
        now: f64,
    ) -> Result<Vec<(String, PyValue)>, JwsError> {
        if self.header("b64") == Some(&PyValue::Bool(false)) {
            return Err(JwsError("detached payloads are not supported"));
        }
        match self.header("alg") {
            None => return Err(JwsError("Algorithm not specified")),
            Some(alg) if alg.as_str() != Some("RS256") => {
                return Err(JwsError("The specified alg value is not allowed"));
            }
            Some(_) => {}
        }
        if !key.verify_pkcs1v15(HashAlg::Sha256, &self.signing_input, &self.signature) {
            return Err(JwsError("Signature verification failed"));
        }
        let claims = match loads_bytes(&self.payload) {
            Ok(PyValue::Dict(items)) => items,
            _ => return Err(JwsError("Invalid payload string")),
        };
        validate_claims(&PyValue::Dict(claims.clone()), audience, issuer, now)?;
        Ok(claims)
    }
}

fn int_claim(claims: &PyValue, name: &str) -> Result<Option<f64>, JwsError> {
    match claims.get(name) {
        None => Ok(None),
        Some(v) => v
            .to_int()
            .map(|i| Some(i as f64))
            .ok_or(JwsError("time claim must be an integer")),
    }
}

/// PyJWT `_validate_claims` for the SSO options.
fn validate_claims(
    claims: &PyValue,
    audience: Option<&str>,
    issuer: &str,
    now: f64,
) -> Result<(), JwsError> {
    if int_claim(claims, "iat")?.is_some_and(|iat| iat > now) {
        return Err(JwsError("The token is not yet valid (iat)"));
    }
    if int_claim(claims, "nbf")?.is_some_and(|nbf| nbf > now) {
        return Err(JwsError("The token is not yet valid (nbf)"));
    }
    if int_claim(claims, "exp")?.is_some_and(|exp| exp <= now) {
        return Err(JwsError("Signature has expired"));
    }
    match claims.get("iss") {
        None => return Err(JwsError("Token is missing the \"iss\" claim")),
        Some(PyValue::Str(iss)) if iss == issuer => {}
        Some(_) => return Err(JwsError("Invalid issuer")),
    }
    let aud = claims.get("aud").filter(|a| a.truthy());
    match (audience, aud) {
        (None, None) => {}
        (None, Some(_)) => return Err(JwsError("Invalid audience")),
        (Some(_), None) => return Err(JwsError("Token is missing the \"aud\" claim")),
        (Some(expected), Some(aud)) => {
            let listed: Vec<&str> = match aud {
                PyValue::Str(s) => vec![s.as_str()],
                PyValue::List(items) => items
                    .iter()
                    .map(PyValue::as_str)
                    .collect::<Option<Vec<_>>>()
                    .ok_or(JwsError("Invalid claim format in token"))?,
                _ => return Err(JwsError("Invalid claim format in token")),
            };
            if !listed.contains(&expected) {
                return Err(JwsError("Audience doesn't match"));
            }
        }
    }
    if claims.get("sub").is_some_and(|s| s.as_str().is_none()) {
        return Err(JwsError("Subject must be a string"));
    }
    if claims.get("jti").is_some_and(|s| s.as_str().is_none()) {
        return Err(JwsError("JWT ID must be a string"));
    }
    Ok(())
}

/// One key of a JWKS: `{"kid": jwk.get("kid"), "key": RSAAlgorithm.from_jwk(jwk)}`.
#[derive(Debug, Clone)]
pub struct JwkEntry {
    /// `jwk.get("kid")`.
    pub kid: PyValue,
    /// The RSA public key.
    pub key: RsaPublicKey,
}

impl JwkEntry {
    /// `k["kid"] == kid` for a header `kid` that is a string or absent.
    pub fn matches(&self, kid: Option<&str>) -> bool {
        match (kid, &self.kid) {
            (None, PyValue::None) => true,
            (Some(kid), PyValue::Str(own)) => kid == own,
            _ => false,
        }
    }
}

fn base64url_uint(value: Option<&PyValue>) -> Result<Vec<u8>, JwsError> {
    match value {
        Some(PyValue::Str(s)) if s.is_ascii() => {
            jwt_base64url_decode(s).map_err(|_| JwsError("Invalid key"))
        }
        _ => Err(JwsError("Invalid key")),
    }
}

/// Every key of a JWKS document (`resp.json()["keys"]`). Like the SSO
/// service, one key that is not an RSA public key fails the whole set (a
/// JWK with private parameters included — the service could never verify
/// with it).
pub fn parse_jwks(body: &[u8]) -> Result<Vec<JwkEntry>, JwsError> {
    let doc = loads_bytes(body).map_err(|_| JwsError("JWKS is not JSON"))?;
    let PyValue::Dict(_) = doc else {
        return Err(JwsError("JWKS is not an object"));
    };
    let keys = match doc.get("keys") {
        None => return Ok(Vec::new()),
        Some(PyValue::List(keys)) => keys,
        Some(_) => return Err(JwsError("JWKS keys is not a list")),
    };
    keys.iter()
        .map(|jwk| {
            let PyValue::Dict(_) = jwk else {
                return Err(JwsError("Key is not valid JSON"));
            };
            if jwk.get("kty").and_then(PyValue::as_str) != Some("RSA") {
                return Err(JwsError("Not an RSA key"));
            }
            if jwk.get("d").is_some() {
                return Err(JwsError("JWKS carries a private key"));
            }
            if jwk.get("n").is_none() || jwk.get("e").is_none() {
                return Err(JwsError("Not a public or private key"));
            }
            let n = base64url_uint(jwk.get("n"))?;
            let e = base64url_uint(jwk.get("e"))?;
            let key = RsaPublicKey::from_be_bytes(&n, &e).map_err(|_| JwsError("Invalid key"))?;
            Ok(JwkEntry {
                kid: jwk.get("kid").cloned().unwrap_or(PyValue::None),
                key,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(json: &str) -> PyValue {
        crate::pyvalue::loads(json).unwrap()
    }

    #[test]
    fn claim_rules() {
        let ok = |c: &str, aud: Option<&str>| validate_claims(&claims(c), aud, "iss", 1000.0);
        assert!(ok(r#"{"iss":"iss","aud":"a","exp":1001}"#, Some("a")).is_ok());
        assert!(ok(r#"{"iss":"iss","aud":["x","a"]}"#, Some("a")).is_ok());
        assert!(ok(r#"{"iss":"iss","aud":["x",1]}"#, Some("a")).is_err());
        assert!(ok(r#"{"iss":"iss","exp":1000}"#, None).is_err());
        assert!(ok(r#"{"iss":"iss","exp":"1001"}"#, None).is_ok());
        assert!(ok(r#"{"iss":"iss","iat":1001}"#, None).is_err());
        assert!(ok(r#"{"aud":"a"}"#, Some("a")).is_err());
        assert!(ok(r#"{"iss":"iss","aud":"a"}"#, None).is_err());
        assert!(ok(r#"{"iss":"iss","aud":""}"#, None).is_ok());
        assert!(ok(r#"{"iss":"iss"}"#, Some("a")).is_err());
        assert!(ok(r#"{"iss":"iss","sub":5}"#, None).is_err());
        assert!(ok(r#"{"iss":"other"}"#, None).is_err());
    }

    #[test]
    fn header_rules() {
        let b64 = crate::pybase64::bytes_to_base64url;
        let token = |h: &str| format!("{}.{}.{}", b64(h.as_bytes()), b64(b"{}"), b64(b"sig"));
        assert!(UnverifiedToken::parse(&token(r#"{"alg":"RS256","kid":"a"}"#)).is_ok());
        assert!(UnverifiedToken::parse(&token(r#"{"alg":"RS256","kid":1}"#)).is_err());
        assert!(UnverifiedToken::parse(&token(r#"{"crit":["b64"]}"#)).is_err());
        assert!(UnverifiedToken::parse(&token(r#"{"crit":["b64"],"b64":true}"#)).is_ok());
        assert!(UnverifiedToken::parse(&token("[]")).is_err());
        assert!(UnverifiedToken::parse("a.b").is_err());
        assert!(UnverifiedToken::parse("nodots").is_err());
    }
}
