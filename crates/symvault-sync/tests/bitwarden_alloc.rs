//! Memory regression for the Go-compatible Bitwarden decoder.
//!
//! Values under unknown keys and values of the wrong type must be skipped, not
//! materialised: the live heap while parsing stays within a small multiple of
//! the input. This binary installs a counting `#[global_allocator]` (std only)
//! and therefore contains a single test, so no other thread allocates while a
//! scenario is measured.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use symvault_sync::importer::{self, Format};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(by: usize) {
    let live = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: every call is forwarded unchanged to `System`; the counters only
// observe sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            grow(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            grow(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            if new_size >= layout.size() {
                grow(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const TARGET: usize = 20 * 1024 * 1024;

/// Peak extra live heap (above what was live before) while running `f`.
fn peak_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let result = f();
    (
        result,
        PEAK.load(Ordering::Relaxed).saturating_sub(baseline),
    )
}

fn repeated(prefix: &str, element: &str, suffix: &str) -> Vec<u8> {
    let count = TARGET / (element.len() + 1);
    let mut out = Vec::with_capacity(prefix.len() + count * (element.len() + 1) + suffix.len());
    out.extend_from_slice(prefix.as_bytes());
    for index in 0..count {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(element.as_bytes());
    }
    out.extend_from_slice(suffix.as_bytes());
    out
}

fn unknown_keys() -> Vec<u8> {
    let mut out = Vec::with_capacity(TARGET + 64);
    out.push(b'{');
    let mut index = 0usize;
    while out.len() < TARGET {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(format!("\"unknown-key-{index}\":1").as_bytes());
        index += 1;
    }
    out.push(b'}');
    out
}

fn one_huge_unknown_key() -> Vec<u8> {
    let mut out = Vec::with_capacity(TARGET + 16);
    out.extend_from_slice(b"{\"");
    out.resize(out.len() + TARGET, b'k');
    out.extend_from_slice(b"\":1}");
    out
}

#[test]
fn ignored_values_are_not_materialised() {
    // (name, input, whether the document decodes without error)
    let scenarios: Vec<(&str, Vec<u8>, bool)> = vec![
        (
            "unknown key with number array",
            repeated("{\"x\":[", "1", "]}"),
            true,
        ),
        (
            "unknown key with string array",
            repeated("{\"x\":[", "\"a\"", "]}"),
            true,
        ),
        (
            "unknown key with null array",
            repeated("{\"x\":[", "null", "]}"),
            true,
        ),
        ("many unknown keys", unknown_keys(), true),
        ("one huge unknown key", one_huge_unknown_key(), true),
        // Not an object: a type error, with the whole array skipped.
        ("top-level null array", repeated("[", "null", "]"), false),
        (
            "wrong-typed folders",
            repeated("{\"folders\":{\"a\":[", "1", "]}}"),
            false,
        ),
    ];
    let mut failures = Vec::new();
    for (name, input, ok) in scenarios {
        let (result, peak) = peak_during(|| importer::parse(Format::Bitwarden, &input));
        println!(
            "{name}: input {} B, peak {} B ({:.2}x)",
            input.len(),
            peak,
            peak as f64 / input.len() as f64
        );
        assert_eq!(result.is_ok(), ok, "{name}: {result:?}");
        if let Ok(entries) = result {
            assert!(entries.is_empty(), "{name}");
        }
        if peak >= 4 * input.len() {
            failures.push(format!(
                "{name}: peak {peak} B is not below 4x the {} B input",
                input.len()
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
