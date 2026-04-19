# Hearth theme

A design theme for Hearth. Cool graphite foundation with a warm ember accent, pulled from the Hearth logo. Modern, restrained, high-contrast. The default (`ember`) is a dark theme; light themes are available via the built-in named themes or operator-supplied CSS.

This document specifies colors, typography, and shape tokens along with the rules for using them. It does not prescribe implementation patterns — apply these values to whatever component architecture the project uses.

---

## Philosophy

Three rules govern every decision:

1. **Cool foundation, warm accent.** The neutrals are deliberately cool with no brown undertone. The ember gradient is the only warm element and carries the entire brand identity. This tension is intentional; do not warm the neutrals to "match".
2. **Restraint with the gradient.** The ember gradient appears at most once per visible region. Reserve it for the primary call-to-action, the logo, and a single accent phrase in a hero. Never use it as a page background, card fill, or decorative wash.
3. **Desaturated accents.** All supporting accent hues sit roughly 30–40% below their fully saturated versions. If a color reads as punchy or vivid, it is wrong for this theme. Muted colors are what make the palette feel modern and premium.

---

## Colors

### Brand — ember

The ember gradient is the signature of the brand. It is the only warm element in the system and must always render consistently with the logo.

| Token | Hex |
|---|---|
| `ember-gold` | `#f5b544` |
| `ember-orange` | `#e8743b` |
| `ember-deep` | `#a8321f` |
| `gradient-ember` | `linear-gradient(135deg, #f5b544 0%, #e8743b 55%, #a8321f 100%)` |

**Usage rules:**
- `ember-gold` is the primary interactive color: focus rings, warning state, accent highlights, active tab indicators, ember-category chart lines.
- `ember-orange` is the mid-stop of the gradient and the hover state for ember elements.
- `ember-deep` is the deep-stop and is decorative only — do not use it as a standalone UI color.
- The gradient is for: the logo, primary call-to-action backgrounds, one italicized accent phrase per hero, the ember progress bar fill. Nothing else.
- Text placed on the gradient must be `graphite-900`, never white.
- The gradient direction (135°) and stop positions are fixed. Do not modify them — they must match the logo.

### Foundation — cool graphite and cream

Pure cool neutrals. No warm or blue tint. These colors make up roughly 90% of any screen.

| Token | Hex | Role |
|---|---|---|
| `graphite-950` | `#0e0e12` | Deepest base — headers, modals, overlays |
| `graphite-900` | `#141418` | Page background |
| `graphite-850` | `#191920` | Raised surfaces, panels |
| `graphite-800` | `#1f1f27` | Cards, input backgrounds |
| `graphite-750` | `#262630` | Hover states on cards |
| `graphite-700` | `#2d2d38` | Heavy borders, surface dividers |
| `graphite-600` | `#3a3a46` | Default dividers |
| `graphite-500` | `#5c5c68` | Disabled text and controls |
| `graphite-400` | `#7a7a85` | Tertiary text (hints, microcopy labels) |
| `graphite-300` | `#a8a39a` | Secondary text (body copy on dark surfaces) |
| `graphite-200` | `#d2cec5` | Muted cream |
| `graphite-100` | `#e8e3d8` | Cream secondary |
| `graphite-050` | `#f5f1e8` | Primary text — warm off-white |

**Usage rules:**
- Primary text is always `graphite-050`. Never `#ffffff`. Pure white clashes with the warm ember.
- Page background is always `graphite-900`. Never `#000000`.
- Surface hierarchy goes from darker (page) to lighter (panels, cards) — the opposite of some dark themes. This keeps cards feeling raised.

### Borders

Borders use white at low alpha rather than solid grays. This keeps them feeling modern and works across any surface depth.

| Token | Value | Role |
|---|---|---|
| `border-subtle` | `rgba(255, 255, 255, 0.06)` | Default on dark surfaces |
| `border-default` | `rgba(255, 255, 255, 0.10)` | Interactive elements, inputs |
| `border-strong` | `rgba(255, 255, 255, 0.18)` | Hover and focus states, ghost button outlines |

### Accent ramps

Four supporting hues, each expressed as a three-stop ramp: a low-alpha background fill, a mid tone for borders and accents, and a readable foreground for text on the `bg` fill. These ramps exist so the same color can appear consistently across badges, charts, metric cards, and icons.

| Ramp | `bg` | `mid` | `fg` | Reserved meaning |
|---|---|---|---|---|
| **Teal** | `#0f2825` | `#2b8073` | `#7ac4b8` | Stable, fresh. Production environments, positive-neutral tags, primary data series |
| **Violet** | `#1d1a2e` | `#6b5b95` | `#b0a5d4` | Cool counterweight to ember. Staging environments, secondary categorical data |
| **Rose** | `#2a1920` | `#b86671` | `#e5a3aa` | Dusty, not pink. Experimental features, budget consumption, soft warnings |
| **Slate** | `#1a2332` | `#3d5a80` | `#8fa8c9` | Neutral information. Archived items, low-emphasis states, tertiary data |

**Usage rules:**
- Pair `bg` with `fg` for filled elements like badges. Pair `bg` with `mid` for borders or accent strips.
- Each ramp carries a reserved meaning across the product. Use teal for production wherever production appears; do not mix it with violet arbitrarily. Consistent meaning is what makes the palette legible at scale.
- Never exceed three ramp colors in a single view. If a chart needs more series, use shades within one ramp rather than introducing a fifth hue.

### Semantic states

Four states with consistent structure. The `bg` is always the `mid` color at 12% alpha.

| State | `bg` | `mid` | `fg` | Meaning |
|---|---|---|---|---|
| **Success** | `rgba(74, 158, 120, 0.12)` | `#4a9e78` | `#6ec198` | Positive confirmation, healthy status |
| **Warning** | `rgba(245, 181, 68, 0.12)` | `#f5b544` | `#f5b544` | Degraded state, budget consumption |
| **Danger** | `rgba(224, 93, 93, 0.12)` | `#e05d5d` | `#ec8080` | Destructive actions, errors, outages |
| **Info** | `rgba(95, 135, 210, 0.12)` | `#5f87d2` | `#8aa8e0` | Neutral notifications, scheduled events |

**Usage rules:**
- Warning deliberately reuses the brand ember. Do not introduce a separate yellow for warnings.
- Danger is a muted coral, not a bright red. The goal is legibility, not alarm.
- Every semantic use must pair the `bg` with either `mid` (for borders or icons) or `fg` (for text).
- Do not use accent ramps (teal, violet, rose, slate) in place of semantic states. Categorical color and state color serve different purposes and must not mix.

---

## Typography

### Font families

Three families, each with a specific role. Available via Google Fonts.

| Token | Family | Role |
|---|---|---|
| `font-display` | Fraunces | Headings, display numbers, metric values |
| `font-body` | Manrope | Body copy, UI labels, button text |
| `font-mono` | JetBrains Mono | Code, timestamps, status labels, uppercase microcopy |

**Usage rules:**
- Do not substitute system fonts, Inter, or Roboto for Manrope. The body family is intentional.
- Fraunces italic is reserved for the hero accent phrase. Otherwise use upright Fraunces.
- JetBrains Mono is not decorative. Use it for technical content (numbers, IDs, timestamps) and for uppercase tracked labels (eyebrows, small category labels).

### Type scale

| Role | Family | Size | Weight | Letter-spacing | Line-height |
|---|---|---|---|---|---|
| Hero headline | display | `clamp(2.5rem, 5vw, 3.5rem)` | 400 | -0.03em | 1.05 |
| Section heading | display | `clamp(2rem, 4vw, 2.75rem)` | 500 | -0.02em | 1.1 |
| Subsection heading | display | 1.375rem | 500 | -0.01em | 1.15 |
| Card title | display | 1rem | 500 | -0.01em | 1.2 |
| Lead paragraph | body | 1.125rem | 400 | normal | 1.65 |
| Body | body | 1rem | 400 | normal | 1.55 |
| Body small | body | 0.875rem | 400 | normal | 1.5 |
| Eyebrow / category label | mono | 0.75rem | 500 | 0.12em, uppercase | 1.4 |
| Microcopy / metric label | mono | 0.7rem | 500 | 0.08em, uppercase | 1.4 |

**Usage rules:**
- All display type uses negative letter-spacing. Never positive tracking on display fonts.
- Eyebrows and labels are always uppercase with positive tracking. Their color is `graphite-400` or the relevant ramp's `fg`, never primary text color.
- Body copy on dark surfaces is `graphite-300`, not `graphite-050`. Reserve the lightest cream for primary headings and high-emphasis text.

### The accent phrase

A single italicized phrase per hero may use the ember gradient as a text fill. This is the only place in the system where display type takes color from the gradient rather than a solid token. Do not apply this treatment to section headings, card titles, or anything outside a hero section. One accent phrase per page maximum.

---

## Shape

### Border radius

| Token | Value | Role |
|---|---|---|
| `r-sm` | 6px | Small controls: inputs, tags, inline chips |
| `r-md` | 10px | Default: buttons, standard cards, panels |
| `r-lg` | 14px | Large: raised panels, dashboard cards |
| `r-xl` | 20px | Extra-large: hero visuals, feature blocks |
| `r-full` | 999px | Pills only — reserved for badges |

### Shadows

Depth in this theme comes from surface hierarchy and borders, not drop shadows. Use shadows sparingly.

| Token | Value | Role |
|---|---|---|
| `shadow-sm` | `0 1px 2px rgba(0, 0, 0, 0.3)` | Rare — small floating elements |
| `shadow-md` | `0 4px 16px rgba(0, 0, 0, 0.4)` | Panels that need to feel raised above the page |
| `shadow-focus` | `0 0 0 3px rgba(245, 181, 68, 0.15)` | Focus ring on inputs and interactive elements |
| `shadow-cta-hover` | `0 8px 24px -4px rgba(232, 116, 59, 0.35)` | Reserved for primary CTA hover state only |

**Usage rules:**
- No colored glow shadows except the focus ring and CTA hover.
- No soft ambient shadows on cards. Use `border-subtle` instead.
- No neon, no blur effects, no gradient shadows.

---

## Spacing

Use a standard rem-based scale: `0.25rem, 0.5rem, 0.75rem, 1rem, 1.25rem, 1.5rem, 2rem, 2.5rem, 3rem, 4rem, 6rem`.

Use pixel values only for component-internal gaps (icon-to-text gaps, badge padding) where rem-scaled values would compound awkwardly.

Major section vertical padding defaults to `6rem 0`. Minor sections use `3rem 0`. Panels use `1.75rem` internal padding. Cards use `1.25rem`.

---

## Motion

Transitions are subtle and fast. The theme does not use elaborate motion.

| Property | Duration | Easing |
|---|---|---|
| Hover states (color, background, border) | 180ms | ease |
| Transform on button hover | 180ms | ease |
| Focus ring appearance | 120ms | ease-out |

**Usage rules:**
- Primary CTA hover moves `translateY(-1px)` and gains `shadow-cta-hover`. No other element gets a translate on hover.
- Do not animate layout properties (width, height, margin). Animate only color, opacity, transform, and box-shadow.
- No entrance animations on page load except a possible opacity fade. No staggered reveals, no scroll-triggered motion.

---

## Accessibility

- Primary text (`graphite-050` on `graphite-900`) meets WCAG AAA.
- Secondary text (`graphite-300` on `graphite-900`) meets WCAG AA for body copy.
- Do not use `graphite-400` or lighter for any text smaller than 14px on dark surfaces — it falls below AA.
- All interactive elements must have a visible focus state. Use `shadow-focus` on inputs and the relevant border treatment on buttons.
- Color is never the sole signal of meaning. Status badges always pair a colored dot with a text label. Chart series always have a legend.
- Do not rely on the ember gradient alone to communicate a primary action — the gradient button must also have clear label text and, where applicable, an arrow glyph.

---

## What this theme is not

- **Not warm.** The neutrals are cool. The only warm thing is the ember. Do not add brown, beige, or warm grays to "soften" it.
- **Not playful.** No rounded cartoon aesthetics, no bright secondary colors, no gradient backgrounds on cards, no emoji in UI chrome.
- **Not dense.** Use generous whitespace. Sections breathe. The theme is premium, and premium means space.
- **Not skeuomorphic.** Flat surfaces, crisp borders, no textures, no inset shadows, no glass morphism, no blurred backgrounds as decoration.

---

## Theming System

### Semantic Token Classes (`ht-*`)

Templates MUST use the semantic `ht-*` Tailwind token classes for all surface, text, and border colors. These classes resolve to CSS custom properties (`--ht-*`) that named themes and operator CSS override at runtime. Raw `graphite-*`, `white/N`, or hex utilities are FORBIDDEN in templates except for status badges and other non-themeable decorative elements.

| Token class | Role |
|---|---|
| `bg-ht-surface-base` | Page background |
| `bg-ht-surface-raised` | Sidebar, raised panels |
| `bg-ht-surface-elevated` | Cards, inputs, code chips |
| `bg-ht-surface-input` | Input field backgrounds |
| `text-ht-content-primary` | Primary text |
| `text-ht-content-secondary` | Secondary / body text |
| `text-ht-content-muted` | Tertiary, hints, microcopy |
| `text-ht-content-brand` | Brand accent text |
| `text-ht-content-on-brand` | Text placed on brand-colored backgrounds |
| `border-ht-divider/[0.06]` | Subtle border |
| `border-ht-divider/[0.10]` | Default interactive border |
| `border-ht-divider/[0.18]` | Strong hover/focus border |
| `bg-ht-divider/[0.10]` | Active nav item background |
| `hover:bg-ht-divider/[0.07]` | Hover state on nav items |

Gradient utilities: `from-ht-brand-from`, `via-ht-brand-via`, `to-ht-brand-deep`.

### CSS Custom Property Contract

The following CSS variables are the stable theming API. A custom theme need only override the variables it changes; unset variables fall back to `ember` (dark) defaults.

```
--ht-surface-base        Page background (R G B, space-separated)
--ht-surface-raised      Sidebar / raised panels
--ht-surface-elevated    Cards, inputs
--ht-surface-input       Input field fill

--ht-content-primary     Primary text
--ht-content-secondary   Body / secondary text
--ht-content-muted       Tertiary, hints
--ht-content-brand       Brand accent color
--ht-content-on-brand    Text on brand backgrounds

--ht-divider             Border base color (255 255 255 in dark → 0 0 0 in light)

--ht-brand-from          Gradient start
--ht-brand-via           Gradient mid
--ht-brand-deep          Gradient end
```

### Named Themes

Six themes ship built in. Configure via `branding.theme` in `hearth.yaml`.

| Name | Mode | Description |
|---|---|---|
| `ember` | dark | Default — amber/orange brand on cool graphite |
| `ocean` | dark | Teal/cyan brand on deep graphite |
| `midnight` | dark | Violet/purple brand on deep graphite |
| `forest` | dark | Emerald/green brand on deep graphite |
| `cloud` | light | Blue brand on near-white surfaces |
| `parchment` | light | Warm amber brand on warm cream surfaces |

### Custom CSS

Operators may append arbitrary CSS via `branding.custom_css: /path/to/brand.css`. The file is read once at startup and served after the named theme, so it can override any `--ht-*` variable or add custom rules. Per-tenant overrides are supported via `tenants.<name>.web.custom_css`.

**Rebuild Tailwind after any template or `input.css` change:**
```sh
cd ui && ./tailwindcss -i input.css -o ../src/protocol/web/assets/app.css --minify
```
