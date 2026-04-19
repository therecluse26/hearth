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
  --ht-content-brand:  13 148 136;
  --ht-brand-from:     13 148 136;
  --ht-brand-via:       8 145 178;
  --ht-brand-deep:     14 116 144;
}";

/// Midnight — dark violet/purple accent.
const MIDNIGHT: &str = r":root {
  --ht-content-brand:  124 58 237;
  --ht-brand-from:     124 58 237;
  --ht-brand-via:      109 40 217;
  --ht-brand-deep:      76 29 149;
}";

/// Forest — dark emerald/green accent.
const FOREST: &str = r":root {
  --ht-content-brand:    5 150 105;
  --ht-brand-from:       5 150 105;
  --ht-brand-via:        4 120  87;
  --ht-brand-deep:       6  95  70;
}";

/// Cloud — light theme with blue accent.
const CLOUD: &str = r":root {
  --ht-surface-base:     232 235 244;
  --ht-surface-raised:   248 250 255;
  --ht-surface-elevated: 218 224 238;
  --ht-surface-input:    248 250 255;
  --ht-content-primary:   14  14  18;
  --ht-content-secondary:  68  68  80;
  --ht-content-muted:     136 136 148;
  --ht-content-brand:      37  99 235;
  --ht-content-on-brand:  255 255 255;
  --ht-divider:             0   0   0;
  --ht-brand-from:         59 130 246;
  --ht-brand-via:          37  99 235;
  --ht-brand-deep:         29  78 216;
  /* Accent ramp overrides for light background */
  --ht-teal-bg:   204 251 241;
  --ht-teal-fg:    13 148 136;
  --ht-violet-bg: 237 233 254;
  --ht-violet-fg: 109  40 217;
  --ht-rose-bg:   255 228 230;
  --ht-rose-fg:   190  18  60;
  --ht-steel-bg:  219 234 254;
  --ht-steel-fg:   29  78 216;
}";

/// Slate — light theme with cool blue-gray surfaces and steel-blue brand accent.
const SLATE: &str = r":root {
  --ht-surface-base:     228 232 238;
  --ht-surface-raised:   244 246 249;
  --ht-surface-elevated: 216 221 230;
  --ht-surface-input:    244 246 249;
  --ht-content-primary:   15  25  35;
  --ht-content-secondary:  58  74  92;
  --ht-content-muted:     107 125 144;
  --ht-content-brand:      30  77 140;
  --ht-content-on-brand:  255 255 255;
  --ht-divider:             0   0   0;
  --ht-brand-from:         37  99 235;
  --ht-brand-via:          29  78 216;
  --ht-brand-deep:         30  64 175;
  /* Accent ramp overrides for light background */
  --ht-teal-bg:   204 251 241;
  --ht-teal-fg:    13 148 136;
  --ht-violet-bg: 237 233 254;
  --ht-violet-fg: 109  40 217;
  --ht-rose-bg:   255 228 230;
  --ht-rose-fg:   190  18  60;
  --ht-steel-bg:  219 234 254;
  --ht-steel-fg:   29  78 216;
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
