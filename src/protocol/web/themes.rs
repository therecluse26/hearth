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
pub const VALID_THEMES: &[&str] = &["ember", "ocean", "midnight", "forest", "cloud", "parchment"];

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
        "parchment" => PARCHMENT,
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
}";

/// Parchment — light theme with warm amber accent.
const PARCHMENT: &str = r":root {
  --ht-surface-base:     234 226 208;
  --ht-surface-raised:   250 244 228;
  --ht-surface-elevated: 220 210 188;
  --ht-surface-input:    250 244 228;
  --ht-content-primary:   28  20   8;
  --ht-content-secondary:  90  74  48;
  --ht-content-muted:     140 120  88;
  --ht-content-brand:     217 119   6;
  --ht-content-on-brand:  255 252 244;
  --ht-divider:             0   0   0;
  --ht-brand-from:        217 119   6;
  --ht-brand-via:         180  83   9;
  --ht-brand-deep:        146  64  14;
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
        assert!(VALID_THEMES.contains(&"parchment"));
        assert_eq!(VALID_THEMES.len(), 6);
    }
}
