//! Named UI themes for the Hearth admin UI.
//!
//! Each theme is a small CSS block that overrides `--ht-*` CSS custom
//! properties declared in `ui/input.css`. The semantic Tailwind tokens
//! (`ht-surface-*`, `ht-content-*`, etc.) read these variables at runtime,
//! so swapping the CSS block is sufficient to change the entire UI palette.
//!
//! The `"ember"` theme is the default — its values are already set in
//! `:root` inside `input.css`, so it returns an empty string here.

/// All valid theme names accepted by `branding.theme` in `hearth.yaml`.
pub const VALID_THEMES: &[&str] = &["ember", "ocean", "midnight", "forest", "cloud", "slate"];

/// Returns the CSS override block for the given theme name.
///
/// Returns an empty string for `"ember"` (default values are already in
/// `:root`). Returns `""` for any unknown name — callers should validate
/// against [`VALID_THEMES`] before calling this function.
#[must_use]
pub fn theme_css(name: &str) -> &'static str {
    match name {
        "ember" | "" => EMBER,
        "ocean" => OCEAN,
        "midnight" => MIDNIGHT,
        "forest" => FOREST,
        "cloud" => CLOUD,
        "slate" => SLATE,
        _ => "",
    }
}

// ---------------------------------------------------------------------------
// Theme constants
// ---------------------------------------------------------------------------

/// Ember (default dark theme) — values already set in :root, no override needed.
const EMBER: &str = "";

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
    fn ember_returns_empty() {
        assert_eq!(theme_css("ember"), "");
    }

    #[test]
    fn empty_string_returns_empty() {
        assert_eq!(theme_css(""), "");
    }

    #[test]
    fn unknown_name_returns_empty() {
        assert_eq!(theme_css("neon-banana"), "");
    }

    #[test]
    fn all_valid_themes_return_non_empty_except_ember() {
        for &name in VALID_THEMES {
            if name == "ember" {
                assert_eq!(theme_css(name), "", "ember should return empty");
            } else {
                assert!(
                    !theme_css(name).is_empty(),
                    "theme '{name}' returned empty CSS"
                );
            }
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
