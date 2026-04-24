//! Named UI themes for the Hearth admin UI.
//!
//! Each theme is a small CSS block that overrides `--ht-*` CSS custom
//! properties declared in `ui/input.css`. The semantic Tailwind tokens
//! (`ht-surface-*`, `ht-content-*`, etc.) read these variables at runtime,
//! so swapping the CSS block is sufficient to change the entire UI palette.
//!
//! Every call returns a non-empty `:root { … }` block — even ember. That way
//! `GET /ui/static/theme.css` always serves a complete palette independent of
//! whatever order the base `app.css` loads in, and operators are never staring
//! at an empty response body when debugging theming.

/// All valid theme names accepted by `branding.theme` in `hearth.yaml`.
pub const VALID_THEMES: &[&str] = &["ember", "ocean", "midnight", "forest", "cloud", "slate"];

/// Returns the CSS override block for the given theme name.
///
/// Always returns a non-empty `:root { … }` block. Unknown names fall back
/// to the ember palette.
#[must_use]
pub fn theme_css(name: &str) -> &'static str {
    match name {
        "ocean" => OCEAN,
        "midnight" => MIDNIGHT,
        "forest" => FOREST,
        "cloud" => CLOUD,
        "slate" => SLATE,
        _ => EMBER,
    }
}

// ---------------------------------------------------------------------------
// Theme constants
// ---------------------------------------------------------------------------

/// Ember (default dark theme). Must mirror the `:root` block in
/// `ui/input.css` so that `theme.css` alone is sufficient to establish the
/// full palette even if `app.css` hasn't loaded yet.
const EMBER: &str = r":root {
  --ht-surface-base:     #141418;
  --ht-surface-raised:   #0e0e12;
  --ht-surface-elevated: #1f1f27;
  --ht-surface-input:    #1f1f27;
  --ht-content-primary:   #f5f1e8;
  --ht-content-secondary: #a8a39a;
  --ht-content-muted:     #7a7a85;
  --ht-content-brand:     #f5b544;
  --ht-content-on-brand:  #0e0e12;
  --ht-divider: #ffffff;
  --ht-brand-from: #f5b544;
  --ht-brand-via:  #e8743b;
  --ht-brand-deep: #a8321f;
  --ht-teal-bg:    #0f2825;
  --ht-teal-fg:    #7ac4b8;
  --ht-violet-bg:  #1d1a2e;
  --ht-violet-fg:  #b0a5d4;
  --ht-rose-bg:    #2a1920;
  --ht-rose-fg:    #e5a3aa;
  --ht-steel-bg:   #1a2332;
  --ht-steel-fg:   #8fa8c9;
}";

/// Ocean — dark teal/cyan accent.
const OCEAN: &str = r":root {
  --ht-content-brand:  #0d9488;
  --ht-brand-from:     #0d9488;
  --ht-brand-via:      #0891b2;
  --ht-brand-deep:     #0e7490;
}";

/// Midnight — dark violet/purple accent.
const MIDNIGHT: &str = r":root {
  --ht-content-brand:  #7c3aed;
  --ht-brand-from:     #7c3aed;
  --ht-brand-via:      #6d28d9;
  --ht-brand-deep:     #4c1d95;
}";

/// Forest — dark emerald/green accent.
const FOREST: &str = r":root {
  --ht-content-brand:  #059669;
  --ht-brand-from:     #059669;
  --ht-brand-via:      #047857;
  --ht-brand-deep:     #065f46;
}";

/// Cloud — light theme with blue accent.
const CLOUD: &str = r":root {
  --ht-surface-base:     #e8ebf4;
  --ht-surface-raised:   #f8faff;
  --ht-surface-elevated: #dae0ee;
  --ht-surface-input:    #f8faff;
  --ht-content-primary:  #0e0e12;
  --ht-content-secondary:#444450;
  --ht-content-muted:    #888894;
  --ht-content-brand:    #2563eb;
  --ht-content-on-brand: #ffffff;
  --ht-divider:          #000000;
  --ht-brand-from:       #3b82f6;
  --ht-brand-via:        #2563eb;
  --ht-brand-deep:       #1d4ed8;
  /* Accent ramp overrides for light background */
  --ht-teal-bg:   #ccfbf1;
  --ht-teal-fg:   #0d9488;
  --ht-violet-bg: #ede9fe;
  --ht-violet-fg: #6d28d9;
  --ht-rose-bg:   #ffe4e6;
  --ht-rose-fg:   #be123c;
  --ht-steel-bg:  #dbeafe;
  --ht-steel-fg:  #1d4ed8;
}";

/// Slate — light theme with cool blue-gray surfaces and steel-blue brand accent.
const SLATE: &str = r":root {
  --ht-surface-base:     #e4e8ee;
  --ht-surface-raised:   #f4f6f9;
  --ht-surface-elevated: #d8dde6;
  --ht-surface-input:    #f4f6f9;
  --ht-content-primary:  #0f1923;
  --ht-content-secondary:#3a4a5c;
  --ht-content-muted:    #6b7d90;
  --ht-content-brand:    #1e4d8c;
  --ht-content-on-brand: #ffffff;
  --ht-divider:          #000000;
  --ht-brand-from:       #2563eb;
  --ht-brand-via:        #1d4ed8;
  --ht-brand-deep:       #1e40af;
  /* Accent ramp overrides for light background */
  --ht-teal-bg:   #ccfbf1;
  --ht-teal-fg:   #0d9488;
  --ht-violet-bg: #ede9fe;
  --ht-violet-fg: #6d28d9;
  --ht-rose-bg:   #ffe4e6;
  --ht-rose-fg:   #be123c;
  --ht-steel-bg:  #dbeafe;
  --ht-steel-fg:  #1d4ed8;
}";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ember_returns_root_block() {
        let css = theme_css("ember");
        assert!(css.starts_with(":root {"));
        assert!(css.contains("--ht-surface-base"));
    }

    #[test]
    fn empty_string_falls_back_to_ember() {
        assert_eq!(theme_css(""), theme_css("ember"));
    }

    #[test]
    fn unknown_name_falls_back_to_ember() {
        assert_eq!(theme_css("neon-banana"), theme_css("ember"));
    }

    #[test]
    fn every_valid_theme_emits_root_block() {
        for &name in VALID_THEMES {
            let css = theme_css(name);
            assert!(
                css.contains(":root {") && css.contains("--ht-"),
                "theme {name:?} did not emit a :root block with --ht- vars"
            );
        }
    }

    #[test]
    fn valid_themes_contains_expected_names() {
        assert!(VALID_THEMES.contains(&"ember"));
        assert!(VALID_THEMES.contains(&"ocean"));
        assert!(VALID_THEMES.contains(&"midnight"));
        assert!(VALID_THEMES.contains(&"forest"));
        assert!(VALID_THEMES.contains(&"cloud"));
        assert!(VALID_THEMES.contains(&"slate"));
        assert_eq!(VALID_THEMES.len(), 6);
    }
}
