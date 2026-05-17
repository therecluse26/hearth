//! Asset sentinel smoke tests.
//!
//! Guards against the unstyled-UI regression class: if the Tailwind build
//! pipeline silently produces an empty or token-stripped `app.css`, or if the
//! named-theme CSS loses its `:root` block, these tests fail at CI time
//! instead of waiting for an operator to notice via screenshot.

use hearth::protocol::web::themes::{theme_css, VALID_THEMES};
use hearth::protocol::web::{
    assert_app_css_sane, assert_bytes_sane, APP_CSS_FALLBACK, APP_CSS_MIN_BYTES, APP_CSS_SENTINEL,
};

#[test]
fn app_css_fallback_passes_sentinel_check() {
    assert_app_css_sane().expect("compile-time embedded app.css must be sane");
}

#[test]
fn app_css_fallback_contains_sentinel() {
    assert!(
        APP_CSS_FALLBACK
            .windows(APP_CSS_SENTINEL.len())
            .any(|w| w == APP_CSS_SENTINEL),
        "app.css missing sentinel `.bg-ht-surface-raised` — Tailwind safelist or content globs are wrong"
    );
}

#[test]
fn app_css_fallback_meets_minimum_size() {
    assert!(
        APP_CSS_FALLBACK.len() > APP_CSS_MIN_BYTES,
        "app.css is {} bytes (< {} byte floor) — Tailwind build almost certainly failed",
        APP_CSS_FALLBACK.len(),
        APP_CSS_MIN_BYTES,
    );
}

#[test]
fn assert_bytes_sane_rejects_undersized_input() {
    let tiny = vec![b'x'; 100];
    let err = assert_bytes_sane(&tiny).expect_err("undersized buffer must be rejected");
    assert!(
        err.contains("4 KiB"),
        "undersized error must mention size limit, got: {err}"
    );
}

#[test]
fn assert_bytes_sane_rejects_missing_sentinel() {
    let bytes = vec![b'a'; APP_CSS_MIN_BYTES + 1];
    let err = assert_bytes_sane(&bytes).expect_err("buffer without sentinel must be rejected");
    assert!(
        err.contains("Hearth theme layer"),
        "missing-sentinel error must mention theme layer, got: {err}"
    );
}

#[test]
fn every_named_theme_returns_populated_root_block() {
    for name in VALID_THEMES {
        let css = theme_css(name);
        assert!(
            css.contains(":root"),
            "theme `{name}` missing `:root` declaration",
        );
        assert!(
            css.contains("--ht-"),
            "theme `{name}` missing `--ht-` custom properties",
        );
    }
}

#[test]
fn theme_css_default_falls_back_to_ember() {
    assert_eq!(theme_css(""), theme_css("ember"));
    assert_eq!(theme_css("nonexistent-theme"), theme_css("ember"));
}
