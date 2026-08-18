// Design token source of truth (open decision O6, ADR 0004).
//
// Generated into server/static/tokens.css by tools/gen-tokens.sh. Never edit
// the generated file — edit this and regenerate. Node is required to author
// tokens; it is NOT required to build or run the server, because the generated
// CSS is committed.

export default {
  palette: {
    ink: {
      white: '#ffffff',
      lightest: '#fbfbfa',
      lighter: '#f1f0ee',
      light: '#e3e2df',
      DEFAULT: '#a4a29c',
      mid: '#7d7c77',
      dark: '#5c5b57',
      darker: '#333336',
      darkest: '#1c1c1e',
      black: '#131314',
    },
    // Brolly blue — the accent across both themes.
    signal: {
      light: '#b9ccff',
      DEFAULT: '#2a5cdc',
      dark: '#1c3f9c',
    },
    alert: {
      light: '#f2b8b5',
      DEFAULT: '#b3261e',
      dark: '#8c1d18',
    },
  },

  themes: {
    // "dag" (day) and "natt" (night) — båtklubb's convention.
    dag: {
      background: 'var(--ink-lightest)',
      foreground: 'var(--ink-darkest)',
      surface: 'var(--ink-white)',
      'surface-raised': 'var(--ink-lighter)',
      primary: 'var(--signal-DEFAULT)',
      'primary-fg': 'var(--ink-white)',
      secondary: 'var(--ink-lighter)',
      'secondary-fg': 'var(--ink-darkest)',
      muted: 'var(--ink-lighter)',
      'muted-fg': 'var(--ink-dark)',
      accent: 'var(--signal-DEFAULT)',
      'accent-fg': 'var(--ink-white)',
      border: 'var(--ink-mid)',
      'border-subtle': 'var(--ink-light)',
      ring: 'var(--signal-DEFAULT)',
      destructive: 'var(--alert-DEFAULT)',
      'destructive-fg': 'var(--ink-white)',
      hover: 'rgba(0, 0, 0, 0.04)',
      active: 'rgba(0, 0, 0, 0.08)',
      radius: '0.5rem',
      shadow: '0 1px 2px 0 rgb(0 0 0 / 0.06)',
      'shadow-elevated': '0 2px 8px -2px rgb(0 0 0 / 0.08)',
    },
    natt: {
      background: 'var(--ink-black)',
      foreground: 'var(--ink-lighter)',
      surface: 'var(--ink-darkest)',
      'surface-raised': 'var(--ink-darker)',
      primary: 'var(--signal-light)',
      'primary-fg': 'var(--ink-black)',
      secondary: 'var(--ink-darker)',
      'secondary-fg': 'var(--ink-lighter)',
      muted: 'var(--ink-darker)',
      'muted-fg': 'var(--ink-DEFAULT)',
      accent: 'var(--signal-light)',
      'accent-fg': 'var(--ink-black)',
      border: 'var(--ink-mid)',
      'border-subtle': 'var(--ink-darker)',
      ring: 'var(--signal-light)',
      destructive: 'var(--alert-light)',
      'destructive-fg': 'var(--ink-black)',
      hover: 'rgba(255, 255, 255, 0.05)',
      active: 'rgba(255, 255, 255, 0.09)',
      radius: '0.5rem',
      shadow: '0 1px 2px 0 rgb(0 0 0 / 0.5)',
      'shadow-elevated': '0 2px 8px -2px rgb(0 0 0 / 0.55)',
    },
  },

  utopia: {
    minWidth: 375,
    maxWidth: 1280,
    minSize: 16,
    maxSize: 18,
    typeScale: { min: 'major-second', max: 'minor-third' },
    spaceScale: { min: 16, max: 18 },
  },

  typography: {
    fonts: {
      sans: 'ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif',
      mono: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace',
    },
    body: 'sans',
    heading: 'sans',
    label: 'sans',
    code: 'mono',
  },

  scaleAliases: {
    measure: '68ch',
    'grid-max-width': '60rem',
    lead: '1.55',
    'lead-tight': '1.15',
  },
}
