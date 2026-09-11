// Design token source of truth (open decision O6, ADR 0004).
//
// Generated into server/static/tokens.css by tools/gen-tokens.sh. Never edit
// the generated file — edit this and regenerate. Node is required to author
// tokens; it is NOT required to build or run the server, because the generated
// CSS is committed.
//
// The values below port brolly.id's visual language (apps/brolly.id/
// marketing-site/static/var.css) into båtklubb's two-layer model, so the server
// and the marketing site read as one product: warm off-white paper, near-black
// ink, heavy black rules, and flat washes of blue / yellow / green / pink for
// the sections that need to sing.

export default {
  palette: {
    // brolly.id's grayscale, extended into a full ramp. `lightest` is its
    // --white, `lighter` its --light-gray, `light` its --gray, DEFAULT its
    // --dark-gray, `darkest` its --black. The rest fill the gaps båtklubb's
    // semantic roles need (a mid grey that clears 3:1 for borders, a `darker`
    // for raised surfaces at night).
    ink: {
      white: '#ffffff',
      lightest: '#fbfbfb',
      lighter: '#f0f0f0',
      light: '#dcdcdc',
      DEFAULT: '#b0b0b0',
      mid: '#8a8a8a',
      dark: '#5a5a5a',
      darker: '#3d3d3d',
      darkest: '#2e2e2e',
      black: '#1a1a1a',
    },

    // The brand washes. brolly.id uses these as flat full-bleed section
    // backgrounds with black type on top, never as text colours — so the
    // DEFAULT stop is tuned for "large field of colour", and the dark stops
    // exist for the pairs that need to carry light text.
    blue: {
      light: '#b3d4ec',
      DEFAULT: '#8cbcdf',
      mid: '#5e9ed6', // brolly.id's focus ring
      dark: '#4a7fa5',
      darker: '#1f3d54',
    },
    yellow: {
      light: '#fde34a',
      DEFAULT: '#fcd501',
      // Carries --ink-lightest as the night feature wash, so it is pinned to
      // the darkest stop that still reads as brolly.id's yellow: 4.77:1.
      // brolly.id's own #8a7400 lands at 4.43 and misses AA.
      dark: '#846f00',
    },
    green: {
      light: '#7aaa7d',
      DEFAULT: '#548057',
      dark: '#3d5e3f',
    },
    pink: {
      light: '#f0c8d9',
      DEFAULT: '#e4a5bf',
      dark: '#a85f7c',
    },
    // brolly.id's --red is a signal red, too light to carry white text at AA.
    // `dark` is the one that goes under a destructive button.
    red: {
      light: '#ffb3ae',
      DEFAULT: '#f43b31',
      dark: '#b01a12',
    },
  },

  themes: {
    // "dag" (day) and "natt" (night) — båtklubb's convention.
    //
    // brolly.id is day-only. `natt` is this server's own, built by inverting
    // the same relationships: paper becomes ink, the black rule becomes a pale
    // one, and the washes drop to their dark stops so the type stays legible.
    dag: {
      background: 'var(--ink-lightest)',
      foreground: 'var(--ink-darkest)',
      surface: 'var(--ink-white)',
      'surface-raised': 'var(--ink-lighter)',
      // brolly.id's primary button is black-on-white with a black rule. The
      // blue is a background wash, never a button.
      primary: 'var(--ink-darkest)',
      'primary-fg': 'var(--ink-lightest)',
      secondary: 'var(--ink-white)',
      'secondary-fg': 'var(--ink-darkest)',
      muted: 'var(--ink-lighter)',
      'muted-fg': 'var(--ink-dark)',
      accent: 'var(--blue-DEFAULT)',
      'accent-fg': 'var(--ink-darkest)',
      border: 'var(--ink-darkest)',
      'border-subtle': 'var(--ink-light)',
      // brolly.id's focus blue (--blue-mid) is only 2.77:1 on this paper, under
      // SC 1.4.11's 3:1 for a focus indicator. One stop down clears it at 4.17.
      ring: 'var(--blue-dark)',
      destructive: 'var(--red-dark)',
      'destructive-fg': 'var(--ink-white)',
      hover: 'rgba(0, 0, 0, 0.05)',
      active: 'rgba(0, 0, 0, 0.09)',
      radius: '0.25rem',
      shadow: '1px 2px 2px rgb(0 0 0 / 0.08), 2px 4px 4px rgb(0 0 0 / 0.06)',
      'shadow-elevated':
        '1px 2px 2px rgb(0 0 0 / 0.1), 2px 4px 4px rgb(0 0 0 / 0.1), 4px 8px 8px rgb(0 0 0 / 0.1), 8px 16px 16px rgb(0 0 0 / 0.1)',

      // Section washes — brolly.id's flat colour fields. Not part of
      // båtklubb's role vocabulary, so they ride along as extra theme keys.
      wash: 'var(--blue-DEFAULT)',
      'wash-fg': 'var(--ink-darkest)',
      'wash-quiet': 'var(--ink-lighter)',
      'wash-quiet-fg': 'var(--ink-darkest)',
      'wash-feature': 'var(--yellow-DEFAULT)',
      'wash-feature-fg': 'var(--ink-darkest)',
      'wash-invite': 'var(--green-dark)',
      'wash-invite-fg': 'var(--ink-lightest)',

      // The umbrella illustration is black line art on white. Multiplying it
      // into the wash drops the paper and keeps the pencil texture.
      'illustration-blend': 'multiply',
      'illustration-filter': 'none',
    },

    natt: {
      background: 'var(--ink-black)',
      foreground: 'var(--ink-lighter)',
      surface: 'var(--ink-darkest)',
      'surface-raised': 'var(--ink-darker)',
      primary: 'var(--ink-lightest)',
      'primary-fg': 'var(--ink-black)',
      secondary: 'var(--ink-darker)',
      'secondary-fg': 'var(--ink-lighter)',
      muted: 'var(--ink-darker)',
      'muted-fg': 'var(--ink-DEFAULT)',
      accent: 'var(--blue-DEFAULT)',
      'accent-fg': 'var(--ink-black)',
      border: 'var(--ink-DEFAULT)',
      'border-subtle': 'var(--ink-dark)',
      ring: 'var(--blue-mid)',
      destructive: 'var(--red-light)',
      'destructive-fg': 'var(--ink-black)',
      hover: 'rgba(255, 255, 255, 0.06)',
      active: 'rgba(255, 255, 255, 0.1)',
      radius: '0.25rem',
      shadow: '1px 2px 2px rgb(0 0 0 / 0.5), 2px 4px 4px rgb(0 0 0 / 0.4)',
      'shadow-elevated':
        '1px 2px 2px rgb(0 0 0 / 0.5), 2px 4px 4px rgb(0 0 0 / 0.5), 4px 8px 8px rgb(0 0 0 / 0.5), 8px 16px 16px rgb(0 0 0 / 0.5)',

      wash: 'var(--blue-darker)',
      'wash-fg': 'var(--ink-lighter)',
      'wash-quiet': 'var(--ink-darkest)',
      'wash-quiet-fg': 'var(--ink-lighter)',
      'wash-feature': 'var(--yellow-dark)',
      'wash-feature-fg': 'var(--ink-lightest)',
      'wash-invite': 'var(--green-dark)',
      'wash-invite-fg': 'var(--ink-lightest)',

      // Inverted, the same line art becomes white-on-dark; screen then drops
      // the (now black) paper.
      'illustration-blend': 'screen',
      'illustration-filter': 'invert(1)',
    },
  },

  // Reverse-engineered from brolly.id's var.css clamps: an 18→22px base
  // between 320px and 1240px, perfect-fourth at the small end opening to
  // augmented-fourth at the large.
  utopia: {
    minWidth: 320,
    maxWidth: 1240,
    minSize: 18,
    maxSize: 22,
    typeScale: { min: 'perfect-fourth', max: 'augmented-fourth' },
    spaceScale: { min: 16, max: 20 },
  },

  typography: {
    fonts: {
      // Serrif Condensed, self-hosted from server/static/fonts. The @font-face
      // rules live in brolly.css — the only hand-authored stylesheet there is.
      serif: "'Serrif', 'Iowan Old Style', Georgia, 'Times New Roman', serif",
      sans: '-apple-system, BlinkMacSystemFont, "avenir next", avenir, "segoe ui", "helvetica neue", helvetica, Cantarell, Ubuntu, roboto, noto, arial, sans-serif',
      mono: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace',
    },
    body: 'serif',
    heading: 'serif',
    label: 'serif',
    code: 'mono',
  },

  scaleAliases: {
    measure: '62ch',
    'grid-max-width': '72rem',
    lead: '1.65',
    'lead-tight': '1.05',
    // brolly.id draws structure with a heavy black rule, not with shadow.
    // `hairline` is the quiet divider that separates rows inside a panel.
    'border-width': '3px',
    hairline: '1px',
    tracking: '0.025em',
    'tracking-tight': '0',
  },
}
