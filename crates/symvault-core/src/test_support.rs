//! Shared test-support utilities for bounding fixture corpora under interpreter
//! environments such as Miri.

/// Default number of fixture rows to execute under Miri when no override is set.
pub const DEFAULT_MIRI_CORPUS_LIMIT: usize = 8;

/// Number of fixture corpus rows to execute. Full corpus natively; a bounded
/// prefix under Miri, where the interpreter cost scales with corpus size while
/// UB coverage scales with code paths. Override with `SYMVAULT_TEST_CORPUS_LIMIT`.
#[must_use]
pub fn corpus_limit(total: usize) -> usize {
    corpus_limit_with_env(
        total,
        std::env::var("SYMVAULT_TEST_CORPUS_LIMIT").ok().as_deref(),
    )
}

/// Helper that evaluates corpus limit given an explicit environment variable string,
/// enabling safe testing of the override mechanism without requiring unsafe environment mutations.
#[must_use]
pub fn corpus_limit_with_env(total: usize, env_val: Option<&str>) -> usize {
    if let Some(raw) = env_val
        && let Ok(parsed) = raw.parse::<usize>()
    {
        return parsed.min(total);
    }

    if cfg!(miri) {
        DEFAULT_MIRI_CORPUS_LIMIT.min(total)
    } else {
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_limit_returns_total_natively_and_bound_under_miri() {
        let total = 62;
        if cfg!(miri) {
            assert_eq!(corpus_limit(total), DEFAULT_MIRI_CORPUS_LIMIT);
            assert_eq!(
                corpus_limit_with_env(total, None),
                DEFAULT_MIRI_CORPUS_LIMIT
            );
        } else {
            assert_eq!(corpus_limit(total), total);
            assert_eq!(corpus_limit_with_env(total, None), total);
        }

        // When total is smaller than the default bound
        assert_eq!(corpus_limit_with_env(3, None), 3);
    }

    #[test]
    fn corpus_limit_env_override() {
        assert_eq!(corpus_limit_with_env(62, Some("3")), 3);
        assert_eq!(corpus_limit_with_env(62, Some("12")), 12);
        // Bounded above by total
        assert_eq!(corpus_limit_with_env(5, Some("10")), 5);
        // Invalid integer formats fall back to standard behavior
        if cfg!(miri) {
            assert_eq!(
                corpus_limit_with_env(62, Some("not-an-int")),
                DEFAULT_MIRI_CORPUS_LIMIT
            );
        } else {
            assert_eq!(corpus_limit_with_env(62, Some("not-an-int")), 62);
        }
    }
}
