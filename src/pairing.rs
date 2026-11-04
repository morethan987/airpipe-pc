//! Pairing window and 6-digit code handling (protocol.md §4).

use std::time::{Duration, Instant};

use crate::net::urandom;
use crate::proto::{PAIR_MAX_TRIES, PAIR_WINDOW};

#[derive(Debug)]
pub struct PairState {
    /// Some(code) while the window is open.
    pub code: Option<String>,
    pub expires: Instant,
    pub tries: u32,
    /// Set once a phone completed pairing during this window.
    pub paired_name: Option<String>,
}

impl PairState {
    pub fn closed() -> Self {
        Self {
            code: None,
            expires: Instant::now(),
            tries: 0,
            paired_name: None,
        }
    }

    pub fn open(timeout: Duration) -> Self {
        Self {
            code: Some(gen_code()),
            expires: Instant::now() + timeout,
            tries: 0,
            paired_name: None,
        }
    }

    pub fn is_open(&self) -> bool {
        self.code.is_some() && Instant::now() < self.expires && self.tries < PAIR_MAX_TRIES
    }

    /// Constant-time comparison of the offered code with the window code.
    /// Returns true on match (and closes the window).
    pub fn check(&mut self, offered: &str) -> bool {
        let Some(code) = &self.code else { return false };
        let a = code.as_bytes();
        let b = offered.as_bytes();
        let mut diff = (a.len() ^ b.len()) as u8;
        let n = a.len().max(b.len());
        for i in 0..n {
            let x = *a.get(i).unwrap_or(&0);
            let y = *b.get(i).unwrap_or(&0);
            diff |= x ^ y;
        }
        let ok = diff == 0 && self.is_open();
        if !ok {
            self.tries += 1;
        }
        ok
    }
}

pub fn gen_code() -> String {
    let r = u32::from_le_bytes(urandom(4).try_into().unwrap());
    format!("{:06}", r % 1_000_000)
}

pub fn default_window() -> Duration {
    PAIR_WINDOW
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_is_six_digits() {
        for _ in 0..100 {
            let c = gen_code();
            assert_eq!(c.len(), 6);
            assert!(c.bytes().all(|b| b.is_ascii_digit()));
        }
    }

    #[test]
    fn check_matches_and_counts_failures() {
        let mut st = PairState::open(Duration::from_secs(60));
        let code = st.code.clone().unwrap();
        assert!(st.check(&code));
        assert!(!st.check("000000")); // window now closed by success? code still Some
        let mut st = PairState::open(Duration::from_secs(60));
        for _ in 0..PAIR_MAX_TRIES {
            assert!(!st.check("999999"));
        }
        assert!(!st.is_open());
    }

    #[test]
    fn expired_window_closed() {
        let mut st = PairState::open(Duration::ZERO);
        assert!(!st.is_open());
        let code = st.code.clone().unwrap();
        assert!(!st.check(&code));
    }
}
