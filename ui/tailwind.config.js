/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["../templates/ui/**/*.html"],
  theme: {
    // ── Shape tokens (THEME.md § Shape) ──────────────────────────
    borderRadius: {
      none: "0",
      sm: "6px",       // inputs, tags, inline chips
      DEFAULT: "10px", // buttons, standard cards, panels
      md: "10px",
      lg: "14px",      // raised panels, dashboard cards
      xl: "20px",      // hero visuals, feature blocks
      full: "999px",   // pills — reserved for badges
    },
    // ── Shadow tokens (THEME.md § Shadows) ───────────────────────
    boxShadow: {
      none: "none",
      sm: "0 1px 2px rgba(0, 0, 0, 0.3)",
      DEFAULT: "0 4px 16px rgba(0, 0, 0, 0.4)",
      md: "0 4px 16px rgba(0, 0, 0, 0.4)",
      focus: "0 0 0 3px color-mix(in srgb, var(--ht-brand-from) 30%, transparent)",
      "cta-hover": "0 8px 24px -4px color-mix(in srgb, var(--ht-brand-via) 35%, transparent)",
    },
    extend: {
      // ── Color tokens (THEME.md § Colors) ─────────────────────
      colors: {
        // ── Semantic tokens — theme-overridable via CSS vars ──────────
        // Each token maps to a CSS custom property defined in :root in
        // input.css. Named themes override only the vars they need.
        'ht-surface': {
          base:     'var(--ht-surface-base)',
          raised:   'var(--ht-surface-raised)',
          elevated: 'var(--ht-surface-elevated)',
          input:    'var(--ht-surface-input)',
        },
        'ht-content': {
          primary:    'var(--ht-content-primary)',
          secondary:  'var(--ht-content-secondary)',
          muted:      'var(--ht-content-muted)',
          brand:      'var(--ht-content-brand)',
          'on-brand': 'var(--ht-content-on-brand)',
        },
        // Single divider token — base color for borders + low-opacity backgrounds.
        // Alpha patterns use semantic component classes (border-divider, etc.)
        // defined in input.css via color-mix().
        'ht-divider': 'var(--ht-divider)',
        'ht-brand': {
          from: 'var(--ht-brand-from)',
          via:  'var(--ht-brand-via)',
          deep: 'var(--ht-brand-deep)',
        },
        // Foundation — cool graphite
        graphite: {
          950: "#0e0e12",  // deepest base — headers, modals, overlays
          900: "#141418",  // page background
          850: "#191920",  // raised surfaces, panels
          800: "#1f1f27",  // cards, input backgrounds
          750: "#262630",  // hover states on cards
          700: "#2d2d38",  // heavy borders, surface dividers
          600: "#3a3a46",  // default dividers
          500: "#5c5c68",  // disabled text and controls
          400: "#7a7a85",  // tertiary text (hints, microcopy labels)
          300: "#a8a39a",  // secondary text (body copy on dark surfaces)
          200: "#d2cec5",  // muted cream
          100: "#e8e3d8",  // cream secondary
          50: "#f5f1e8",   // primary text — warm off-white
        },
        // Brand — ember
        ember: {
          gold: "#f5b544",   // primary interactive: focus rings, accent highlights
          orange: "#e8743b", // gradient mid-stop, hover state for ember elements
          deep: "#a8321f",   // gradient deep-stop, decorative only
        },
        // Accent ramps — bg/fg are CSS-variable-backed for theme adaptability
        teal: {
          bg:      'var(--ht-teal-bg)',
          DEFAULT: "#2b8073",
          fg:      'var(--ht-teal-fg)',
        },
        violet: {
          bg:      'var(--ht-violet-bg)',
          DEFAULT: "#6b5b95",
          fg:      'var(--ht-violet-fg)',
        },
        rose: {
          bg:      'var(--ht-rose-bg)',
          DEFAULT: "#b86671",
          fg:      'var(--ht-rose-fg)',
        },
        steel: {
          bg:      'var(--ht-steel-bg)',
          DEFAULT: "#3d5a80",
          fg:      'var(--ht-steel-fg)',
        },
        // Semantic states
        success: {
          DEFAULT: "#4a9e78",
          fg: "#6ec198",
        },
        warning: {
          DEFAULT: "#f5b544",
          fg: "#f5b544",
        },
        danger: {
          DEFAULT: "#e05d5d",
          fg: "#ec8080",
        },
        info: {
          DEFAULT: "#5f87d2",
          fg: "#8aa8e0",
        },
      },
      // ── Typography tokens (THEME.md § Typography) ────────────
      fontFamily: {
        sans: ["Manrope", "system-ui", "sans-serif"],
        display: ["Fraunces", "Georgia", "serif"],
        mono: ['"JetBrains Mono"', "monospace"],
      },
      // ── Border tokens (THEME.md § Borders) ───────────────────
      borderColor: {
        subtle: "color-mix(in srgb, var(--ht-divider) 6%, transparent)",
        strong: "color-mix(in srgb, var(--ht-divider) 18%, transparent)",
      },
      // ── Motion tokens (THEME.md § Motion) ────────────────────
      keyframes: {
        "fade-in": {
          from: { opacity: "0", transform: "translateY(-4px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "toast-in": {
          from: { opacity: "0", transform: "translateX(100%)" },
          to: { opacity: "1", transform: "translateX(0)" },
        },
        "toast-out": {
          from: { opacity: "1", transform: "translateX(0)" },
          to: { opacity: "0", transform: "translateX(100%)" },
        },
        spinner: {
          to: { transform: "rotate(360deg)" },
        },
      },
      animation: {
        "fade-in": "fade-in 0.2s ease-out",
        "toast-in": "toast-in 0.3s ease-out",
        "toast-out": "toast-out 0.3s ease-in forwards",
        spinner: "spinner 0.6s linear infinite",
      },
    },
  },
  plugins: [],
};
