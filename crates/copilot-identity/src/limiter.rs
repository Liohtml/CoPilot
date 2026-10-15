//! The 2FA brute-force guard — `_2fa_attempts` in `app/auth/services/totp.py`.
//!
//! Per user: five failed second-factor checks within 15 minutes (counted
//! from the first failure) lock the user out of every 2FA check until the
//! window ends; a success clears the count. Like Python's, the state is in
//! memory, per process — which is why every route that counts (validate,
//! verify-setup, disable, regenerate) is served by the same process.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// `_MAX_ATTEMPTS`.
pub const MAX_ATTEMPTS: u32 = 5;
/// `_LOCKOUT_SECONDS`.
pub const LOCKOUT_SECONDS: f64 = 900.0;

/// `time.time()`.
pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Failed attempts per user id: `(count, first failure)`.
#[derive(Debug, Default)]
pub struct TwoFactorLimiter {
    attempts: Mutex<HashMap<i32, (u32, f64)>>,
}

impl TwoFactorLimiter {
    fn with<T>(&self, f: impl FnOnce(&mut HashMap<i32, (u32, f64)>) -> T) -> T {
        let mut guard = match self.attempts.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&mut guard)
    }

    /// `_check_rate_limit`: `Err` carries Python's message.
    pub fn check(&self, user_id: i32, now: f64) -> Result<(), String> {
        self.with(|map| {
            let Some(&(count, first)) = map.get(&user_id) else {
                return Ok(());
            };
            if now - first > LOCKOUT_SECONDS {
                map.remove(&user_id);
                return Ok(());
            }
            if count >= MAX_ATTEMPTS {
                let remaining = (LOCKOUT_SECONDS - (now - first)).trunc() as i64;
                return Err(format!(
                    "Too many failed 2FA attempts. Try again in {remaining} seconds."
                ));
            }
            Ok(())
        })
    }

    /// `_record_failure`.
    pub fn record_failure(&self, user_id: i32, now: f64) {
        self.with(|map| {
            let next = match map.get(&user_id) {
                Some(&(count, first)) if now - first <= LOCKOUT_SECONDS => (count + 1, first),
                _ => (1, now),
            };
            map.insert(user_id, next);
        });
    }

    /// `_clear_failures`.
    pub fn clear(&self, user_id: i32) {
        self.with(|map| map.remove(&user_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_failures_lock_for_the_rest_of_the_window() {
        let l = TwoFactorLimiter::default();
        let t0 = 1_000.0;
        for i in 0..4 {
            l.record_failure(7, t0 + f64::from(i));
            assert!(l.check(7, t0 + 10.0).is_ok());
        }
        l.record_failure(7, t0 + 5.0);
        assert_eq!(
            l.check(7, t0 + 100.5).unwrap_err(),
            "Too many failed 2FA attempts. Try again in 799 seconds."
        );
        assert!(l.check(8, t0).is_ok());
        // The window counts from the first failure.
        assert!(l.check(7, t0 + 900.0).is_err());
        assert!(l.check(7, t0 + 900.5).is_ok());
        // ...and an expired entry is gone, so counting restarts.
        l.record_failure(7, t0 + 901.0);
        assert!(l.check(7, t0 + 902.0).is_ok());
        l.clear(7);
        assert!(l.check(7, t0 + 902.0).is_ok());
    }

    #[test]
    fn a_failure_after_the_window_starts_a_new_one() {
        let l = TwoFactorLimiter::default();
        for _ in 0..5 {
            l.record_failure(1, 0.0);
        }
        l.record_failure(1, 1_000.0);
        assert!(l.check(1, 1_001.0).is_ok());
    }
}
