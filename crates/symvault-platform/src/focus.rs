//! Focus stability check shared by native autotype adapters.
use crate::{PlatformError, PlatformErrorKind};
use std::{thread, time::Duration};

pub(crate) fn unavailable() -> PlatformError {
    PlatformError::unavailable("autotype: cannot detect active window on this platform")
}

pub(crate) fn guard(
    strict: &str,
    mut capture: impl FnMut() -> Result<String, PlatformError>,
) -> Result<(), PlatformError> {
    let first = match capture() {
        Err(error) if error.kind == PlatformErrorKind::Unavailable => {
            return if strict.is_empty() || strict == "0" {
                Ok(())
            } else {
                Err(error)
            };
        }
        other => other?,
    };
    thread::sleep(Duration::from_millis(200));
    let second = match capture() {
        Err(error) if error.kind == PlatformErrorKind::Unavailable => String::new(),
        other => other?,
    };
    if !first.is_empty() && !second.is_empty() && first != second {
        return Err(PlatformError {
            kind: PlatformErrorKind::Canceled,
            message: "autotype: active window changed between capture and send — aborting to prevent typing into the wrong app".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    #[derive(Deserialize)]
    struct Case {
        name: String,
        strict: String,
        captures: Vec<String>,
        error: String,
        calls: usize,
    }
    #[derive(Deserialize)]
    struct Fixture {
        cases: Vec<Case>,
    }
    #[test]
    fn focus_guard_matches_go_oracle() {
        let fixture: Fixture =
            serde_json::from_str(include_str!("../../../testdata/port/platform/focus.json"))
                .unwrap();
        assert_eq!(fixture.cases.len(), 10);
        for case in fixture.cases {
            let mut calls = 0;
            let result = guard(&case.strict, || {
                let value = &case.captures[calls];
                calls += 1;
                match value.as_str() {
                    "unavailable" => Err(unavailable()),
                    "failed" => Err(PlatformError {
                        kind: PlatformErrorKind::Failed,
                        message: "capture failed".into(),
                    }),
                    _ => Ok(value.clone()),
                }
            });
            assert_eq!(
                result.err().map(|e| e.to_string()).unwrap_or_default(),
                case.error,
                "{}",
                case.name
            );
            assert_eq!(calls, case.calls, "{}", case.name);
        }
    }
}
