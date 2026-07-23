#[cfg(not(feature = "profile"))]
use std::marker::PhantomData;

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ProfileEvent<'a> {
    pub phase: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<u64>,
    #[serde(rename = "class", skip_serializing_if = "Option::is_none")]
    pub class: Option<&'a str>,
    pub elapsed_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

pub fn render_event(event: ProfileEvent<'_>) -> String {
    serde_json::to_string(&event).expect("profile event contains only serializable fields")
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProfileConfig;

impl ProfileConfig {
    #[inline]
    pub fn enabled() -> bool {
        enabled()
    }
}

#[cfg(feature = "profile")]
fn enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("CODEX_SSH_BRIDGE_PROFILE").as_deref() == Ok("1"))
}

#[cfg(not(feature = "profile"))]
#[inline]
const fn enabled() -> bool {
    false
}

#[cfg(feature = "profile")]
#[doc(hidden)]
pub fn emit(event: ProfileEvent<'_>) {
    if !enabled() {
        return;
    }
    static OUTPUT_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    let line = render_event(event);
    let _guard = OUTPUT_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    eprintln!("{line}");
}

#[cfg(not(feature = "profile"))]
#[doc(hidden)]
#[inline]
pub const fn emit(_event: ProfileEvent<'_>) {}

pub struct ProfileSpan<'a> {
    #[cfg(feature = "profile")]
    event: ProfileEvent<'a>,
    #[cfg(feature = "profile")]
    started: std::time::Instant,
    #[cfg(not(feature = "profile"))]
    _marker: PhantomData<&'a ()>,
}

impl<'a> ProfileSpan<'a> {
    #[inline]
    pub fn new(event: ProfileEvent<'a>) -> Self {
        #[cfg(feature = "profile")]
        {
            Self {
                event,
                started: std::time::Instant::now(),
            }
        }
        #[cfg(not(feature = "profile"))]
        {
            let _ = event;
            Self {
                _marker: PhantomData,
            }
        }
    }
}

#[cfg(feature = "profile")]
impl Drop for ProfileSpan<'_> {
    fn drop(&mut self) {
        if enabled() {
            self.event.elapsed_us =
                u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX);
            emit(self.event);
        }
    }
}

#[macro_export]
macro_rules! bridge_profile {
    ($event:expr $(,)?) => {{
        $crate::profile::emit($event);
    }};
}

#[macro_export]
macro_rules! bridge_profile_span {
    ($event:expr $(,)?) => {{ $crate::profile::ProfileSpan::new($event) }};
}

#[cfg(test)]
mod tests {
    use super::{ProfileEvent, render_event};

    #[test]
    fn profile_event_contains_only_safe_fields() {
        let line = render_event(ProfileEvent {
            phase: "warm_session",
            host: Some("dev"),
            request_id: Some(7),
            class: Some("warm"),
            elapsed_us: 1_234,
            bytes: Some(64),
        });
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["phase"], "warm_session");
        assert_eq!(value["host"], "dev");
        assert_eq!(value["request_id"], 7);
        assert_eq!(value["class"], "warm");
        assert_eq!(value["elapsed_us"], 1_234);
        assert_eq!(value["bytes"], 64);
        assert!(value.get("command").is_none());
        assert!(value.get("path").is_none());
        assert!(value.get("output").is_none());
    }
}
