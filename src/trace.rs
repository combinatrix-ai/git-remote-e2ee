use std::sync::OnceLock;
use std::time::Instant;

fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("GIT_REMOTE_E2EE_TRACE").is_ok_and(|value| value == "1"))
}

pub(crate) struct Span {
    name: &'static str,
    started: Option<Instant>,
}

impl Span {
    pub(crate) fn new(name: &'static str) -> Self {
        Self {
            name,
            started: enabled().then(Instant::now),
        }
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        if let Some(started) = self.started {
            eprintln!(
                "git-remote-e2ee trace phase={} elapsed_ms={}",
                self.name,
                started.elapsed().as_millis()
            );
        }
    }
}

pub(crate) struct Io {
    name: &'static str,
    started: Option<Instant>,
    elapsed_nanos: u128,
    bytes: u64,
}

impl Io {
    pub(crate) fn new(name: &'static str) -> Self {
        Self {
            name,
            started: enabled().then(Instant::now),
            elapsed_nanos: 0,
            bytes: 0,
        }
    }

    pub(crate) fn record(&mut self, bytes: usize, elapsed_nanos: u128) {
        if self.started.is_some() {
            self.bytes = self.bytes.saturating_add(bytes as u64);
            self.elapsed_nanos = self.elapsed_nanos.saturating_add(elapsed_nanos);
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        self.started.is_some()
    }
}

impl Drop for Io {
    fn drop(&mut self) {
        if self.started.is_some() {
            eprintln!(
                "git-remote-e2ee trace io={} elapsed_ms={} bytes={}",
                self.name,
                self.elapsed_nanos / 1_000_000,
                self.bytes
            );
        }
    }
}
