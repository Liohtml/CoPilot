//! bcrypt passwords — port of `AuthHandler.get_password_hash` /
//! `verify_password`. Input is cut to its first 72 *bytes* before hashing and
//! verifying, which is what bcrypt 4 did silently and what keeps hashes
//! created under it verifiable.

/// bcrypt's input limit.
const BCRYPT_MAX_BYTES: usize = 72;

fn truncated(password: &str) -> &[u8] {
    let bytes = password.as_bytes();
    &bytes[..bytes.len().min(BCRYPT_MAX_BYTES)]
}

/// Hash with a fresh salt at cost 12 (`$2b$12$…`, Python's `gensalt()`).
pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    bcrypt::hash_with_result(truncated(password), bcrypt::DEFAULT_COST)
        .map(|h| h.format_for_version(bcrypt::Version::TwoB))
}

/// Constant-time verify; any error (malformed hash, …) is a failed login.
pub fn verify_password(password: &str, hash: &str) -> bool {
    bcrypt::verify(truncated(password), hash).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_python_generated_hash() {
        // `bcrypt.hashpw(b"admin", bcrypt.gensalt(4))` from the backend's venv.
        let python = "$2b$04$UEUEHG0lAJrMLNMY3xtlhOz45nOr9LvMvEP40uJpjxRkovFvUSARG";
        assert!(verify_password("admin", python));
        assert!(!verify_password("Admin", python));
        // A hash we cannot parse must never count as a match.
        assert!(!verify_password("admin", "not-a-hash"));
    }

    #[test]
    fn hashes_in_python_format() {
        let ours = hash_password("admin").unwrap();
        assert!(ours.starts_with("$2b$12$"));
        assert!(verify_password("admin", &ours));
    }

    #[test]
    fn truncates_to_72_bytes() {
        let long = "x".repeat(80);
        let hash = bcrypt::hash_with_result(&long.as_bytes()[..72], 4)
            .unwrap()
            .format_for_version(bcrypt::Version::TwoB);
        assert!(verify_password(&long, &hash));
        assert!(verify_password(&"x".repeat(72), &hash));
    }
}
