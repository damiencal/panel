# Design System Prompt — Hosting Panel

Use this prompt verbatim (or lightly adapted) to replicate this project's exact visual and component language on any new project.

---

## The Prompt

You are a senior frontend engineer. Build the following design system exactly and apply it consistently across every screen you touch.

### Visual direction

The style is a **light glassmorphism dashboard**. The overall feel is clean, airy, and professional — not playful, not heavy. Surfaces are frosted white glass sitting on a soft neutral gradient background. Every layer of depth is subtle. Nothing competes for attention. Readability and data density win over decoration.

Rules:
1. Only one art direction — no mixing styles per screen.
2. Every value comes from the token set below — no ad-hoc one-off colors, radii, or shadows.
3. Prefer semantic token names in components; use raw Tailwind utilities only for layout (flex, grid, gap, padding).
4. Interactivity must always be visible — no stateless hover/focus states.
5. Transitions are short (150–300ms) and use `ease-out` or `cubic-bezier(0.4,0,0.2,1)`.

---

### 1. Foundation tokens

#### CSS custom properties (paste into your root stylesheet)

```css
:root {
  /* Semantic color palette */
  --background:             0 0% 97.5%;   /* page bg */
  --foreground:             0 0% 9%;      /* primary text */
  --card:                   0 0% 100%;
  --card-foreground:        0 0% 9%;
  --popover:                0 0% 100%;
  --popover-foreground:     0 0% 9%;
  --primary:                0 0% 12%;     /* near-black */
  --primary-foreground:     0 0% 98%;
  --secondary:              0 0% 94%;
  --secondary-foreground:   0 0% 12%;
  --muted:                  0 0% 94.5%;
  --muted-foreground:       0 0% 44%;
  --accent:                 0 0% 94.5%;
  --accent-foreground:      0 0% 12%;
  --destructive:            0 72% 51%;    /* red-600 equivalent */
  --destructive-foreground: 0 0% 98%;
  --border:                 0 0% 90%;
  --input:                  0 0% 90%;
  --ring:                   0 0% 12%;
}
```

#### Tailwind `@theme` tokens (paste into `input.css`)

```css
@theme {
  --radius-sm:  0.5rem;    /* 8px  — small chips, tags */
  --radius-md:  0.625rem;  /* 10px — inputs, small cards */
  --radius-lg:  0.75rem;   /* 12px — buttons, badges */
  --radius-xl:  0.875rem;  /* 14px — sidebar links, most buttons */
  --radius-2xl: 1rem;      /* 16px — cards, panels */
  --radius-3xl: 1.5rem;    /* 24px — modals, large cards */

  --shadow-soft:        0 2px 8px  rgba(0,0,0,0.04);
  --shadow-soft-md:     0 4px 16px rgba(0,0,0,0.06);
  --shadow-soft-lg:     0 8px 24px rgba(0,0,0,0.08);
  --shadow-glass:       0 8px 32px rgba(0,0,0,0.06);
  --shadow-glass-lg:    0 12px 48px rgba(0,0,0,0.08);
  --shadow-glass-inset: inset 0 1px 1px rgba(255,255,255,0.4);
  --shadow-float:       0 20px 60px rgba(0,0,0,0.10);

  --animate-fade-in:    fade-in   0.3s ease-out;
  --animate-slide-up:   slide-up  0.3s ease-out;
  --animate-slide-down: slide-down 0.2s ease-out;
  --animate-scale-in:   scale-in  0.2s ease-out;
}

@keyframes fade-in   { from { opacity:0 }                       to { opacity:1 } }
@keyframes slide-up  { from { opacity:0; transform:translateY(8px) }  to { opacity:1; transform:translateY(0) } }
@keyframes slide-down{ from { opacity:0; transform:translateY(-8px) } to { opacity:1; transform:translateY(0) } }
@keyframes scale-in  { from { opacity:0; transform:scale(0.96) }      to { opacity:1; transform:scale(1) } }
```

#### Typography

| Role | Family | Stack |
|---|---|---|
| Body / UI | System sans-serif | `system-ui, -apple-system, "Segoe UI", Roboto, sans-serif` |
| Code / mono | System mono | `'SF Mono', 'Cascadia Code', 'Fira Code', Consolas, monospace` |

Font size scale (Tailwind defaults apply — key sizes used):

| Token | Size | Usage |
|---|---|---|
| `text-[11px]` | 11px | table column headers |
| `text-xs` | 12px | meta, captions, badges |
| `text-[13px]` | 13px | sidebar nav, secondary labels |
| `text-sm` | 14px | body text, buttons, form labels |
| `text-base` | 16px | card body |
| `text-lg` | 18px | section subtitles |
| `text-xl` | 20px | card titles |
| `text-2xl` | 24px | page headings |
| `text-3xl`+ | 30px+ | hero / stat numbers |

Font weight scheme: `font-normal` (body copy) → `font-medium` (labels, nav, buttons) → `font-semibold` (headings, active states) → `font-bold`/`font-extrabold` (stat numbers only).

---

### 2. Page shell

```
┌───────────────────────────────────────────────────────┐
│  sidebar-panel (256px fixed left, blur glass)         │
│  ┌──────────────────────────────────────────────────┐ │
│  │ Logo / brand (16–24px padding)                   │ │
│  │ ─────────────────                                │ │
│  │ sidebar-link (each section)                      │ │
│  │   icon  label                                    │ │
│  └──────────────────────────────────────────────────┘ │
│  main content area (flex-1, overflow-y-auto)          │
│  │  page header: title + action buttons              │ │
│  │  ─────────────────                                │ │
│  │  content grid / sections                          │ │
└───────────────────────────────────────────────────────┘
```

Body background: `linear-gradient(to bottom right, #f9fafb, rgba(243,244,246,0.5), #f9fafb)` fixed.

---

### 3. Glass surface components (copy verbatim into `@layer components`)

```css
@layer components {
  /* Standard card surface */
  .glass-card {
    background: rgba(255,255,255,0.60);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(255,255,255,0.70);
    box-shadow: 0 0 0 1px rgba(0,0,0,0.03), 0 8px 32px rgba(0,0,0,0.05);
  }
  /* Lighter surface (nested cards, table wrappers) */
  .glass-subtle {
    background: rgba(255,255,255,0.35);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border: 1px solid rgba(255,255,255,0.45);
    box-shadow: 0 4px 24px rgba(0,0,0,0.04);
  }
  /* Heavier surface (modals, popovers, focused panels) */
  .glass-strong {
    background: rgba(255,255,255,0.72);
    backdrop-filter: blur(24px);
    -webkit-backdrop-filter: blur(24px);
    border: 1px solid rgba(255,255,255,0.80);
    box-shadow: 0 8px 40px rgba(0,0,0,0.08);
  }

  /* Navigation sidebar */
  .sidebar-panel {
    width: 256px;
    background: rgba(250,250,250,0.72);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border-right: 1px solid rgba(0,0,0,0.06);
  }
  .sidebar-link {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.625rem 0.75rem;
    border-radius: 0.875rem;   /* radius-xl */
    font-size: 13px;
    font-weight: 500;
    color: hsl(var(--muted-foreground));
    transition: all 200ms;
    text-decoration: none;
  }
  .sidebar-link:hover {
    color: hsl(var(--foreground));
    background: rgba(0,0,0,0.04);
  }
  .sidebar-link.active {
    color: hsl(var(--foreground));
    font-weight: 600;
    background: rgba(0,0,0,0.06);
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
  }
}
```

---

### 4. Component reference

Every component below uses **only** Tailwind utility classes — no custom CSS beyond the glass layer above.

#### Buttons

| Variant | Class string |
|---|---|
| **Primary** (dark) | `px-4 py-2 bg-gray-900 hover:bg-gray-900/90 text-white text-sm font-medium rounded-xl transition-colors disabled:opacity-50` |
| Primary large | `px-5 py-2.5 bg-gray-900 hover:bg-gray-900/90 text-white text-sm font-semibold rounded-xl transition-colors disabled:opacity-50` |
| **Blue** | `px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white text-sm font-medium rounded-xl transition-colors disabled:opacity-50` |
| **Green** | `px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-white text-sm font-medium rounded-xl transition-colors disabled:opacity-50` |
| **Destructive** (red) | `px-4 py-2 bg-red-500 hover:bg-red-600 text-white text-sm font-medium rounded-xl transition-colors disabled:opacity-50` |
| **Ghost** (default) | `px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 text-sm font-medium rounded-xl transition-colors` |
| **Outline** | `px-4 py-2 bg-white border border-gray-200 hover:bg-gray-50 text-gray-700 text-sm font-medium rounded-xl transition-colors disabled:opacity-50` |
| **XS ghost** | `px-3 py-1.5 text-xs font-medium bg-black/[0.04] text-gray-600 hover:bg-gray-200 rounded-xl transition-colors` |
| **XS tinted** (blue) | `px-3 py-1.5 text-xs font-semibold bg-blue-500/[0.08] text-blue-700 hover:bg-blue-100 rounded-xl transition-colors disabled:opacity-50` |
| **XS tinted** (green) | `px-3 py-1.5 text-xs font-medium bg-emerald-500/[0.08] text-emerald-700 hover:bg-green-100 rounded-xl transition-colors` |
| Icon-only (toolbar) | `p-2 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors` |

State rules:
- `disabled:opacity-50 disabled:cursor-not-allowed` on all interactive elements
- `active:scale-[0.98]` optional for buttons with lift effect
- `focus:outline-none focus:ring-2 focus:ring-black/[0.15]` for keyboard focus

#### Inputs and form fields

```
Label:  block text-[13px] font-medium text-gray-700 mb-1.5
Input:  w-full border border-black/[0.08] rounded-xl px-3 py-2 text-sm
        focus:outline-none focus:ring-2 focus:ring-black/[0.15] focus:border-transparent
        placeholder:text-gray-400/60
Mono:   w-full border border-black/[0.08] rounded-xl px-3 py-2 text-sm font-mono
Hint:   text-xs text-gray-400 mt-1
```

Select: same border/radius as input; `text-sm`.

Textarea: same class + `resize-none` or `resize-y`; add `max-h-32` / `max-h-64` as needed.

#### Badges and status pills

```
Base pill (status dot only):  w-2 h-2 rounded-full {color}
                               green = bg-emerald-500 | red = bg-red-500 | gray = bg-gray-400 | amber = bg-amber-500 | blue = bg-blue-500

Inline badge (text):
  Active/green:   px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/[0.08] text-emerald-700
  Error/red:      px-2 py-0.5 rounded-full text-xs font-semibold bg-red-500/[0.08] text-red-600
  Neutral:        px-2 py-0.5 rounded-full text-xs font-semibold bg-gray-100 text-gray-500
  Warning/amber:  px-2 py-0.5 rounded-full text-xs font-semibold bg-amber-500/[0.08] text-amber-700
  Info/blue:      px-2 py-0.5 rounded-full text-xs font-semibold bg-blue-500/[0.08] text-blue-700
```

#### Feedback banners (inline alerts)

```
Success:  bg-emerald-500/[0.08] text-emerald-700 px-4 py-3 rounded-lg text-sm
Error:    bg-red-500/[0.08] text-red-600 px-4 py-3 rounded-lg text-sm
Warning:  bg-yellow-50 border border-yellow-200 text-yellow-800 px-4 py-3 rounded-lg text-sm
Info:     bg-blue-500/[0.08] text-blue-700 px-4 py-3 rounded-lg text-sm

Bordered card style (more prominent):
  Error:  bg-red-50 border border-red-200 text-red-700 p-4 rounded-xl text-sm
  Success: bg-green-50 border border-green-200 text-green-700 p-4 rounded-xl text-sm flex items-center justify-between
  Warning: bg-amber-50 text-amber-700 border border-amber-200 p-4 rounded-xl text-sm flex items-center
```

#### Cards

```
Standard:       glass-card rounded-2xl p-5
Table wrapper:  glass-card rounded-2xl overflow-hidden
Compact:        glass-card rounded-xl p-4
Chat/log:       glass-card rounded-2xl p-6
Stat card:      glass-card rounded-2xl p-5   (contains icon badge + number + label)
Loading:        glass-card rounded-2xl p-5 animate-pulse
Empty state:    glass-card rounded-2xl p-12 text-center  (or p-16)
```

Stat card anatomy:
```
div.glass-card.rounded-2xl.p-5
  div.flex.items-center.justify-between.mb-4
    div  (label, text-sm text-gray-500)
    div.p-2.{color}-50.rounded-lg  (icon container)
      Icon.w-4.h-4.{color}-500
  div.text-2xl.font-bold.text-gray-900.tracking-tight  (number)
  div.text-xs.text-gray-400.mt-1                       (sublabel)
```

#### Tables

```
Wrapper:   glass-card rounded-2xl overflow-hidden
thead:     bg-gray-50 border-b border-gray-200
th:        px-4 py-3 text-left text-[11px] font-semibold text-gray-400 uppercase tracking-wider
tbody row: border-b border-black/[0.05] hover:bg-gray-50/40 transition-colors
           (alternate: hover:bg-black/[0.02])
td:        px-4 py-3 text-sm text-gray-700
td mono:   px-4 py-3 font-mono text-xs text-gray-700
th/td right-align: text-right
row divider: divide-y divide-black/[0.04]
```

#### Modals and overlays

```
Backdrop:  fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-4
           (animate-fade-in)

Standard modal shell:
  bg-white rounded-2xl shadow-xl p-6 w-full max-w-md animate-scale-in

Large modal shell:
  bg-white rounded-2xl shadow-xl flex flex-col w-full max-w-4xl h-[80vh]

Confirm/danger modal:
  bg-white rounded-2xl p-6 max-w-sm w-full shadow-2xl animate-scale-in

Modal header pattern:
  div.flex.items-center.justify-between.mb-5
    h2.text-lg.font-semibold.text-gray-900  (title)
    button.p-1.rounded-lg.hover:bg-gray-100.text-gray-400  (× close)

Modal footer:
  div.flex.items-center.justify-end.gap-2.mt-6.pt-5.border-t.border-black/[0.05]
    button (secondary/outline)
    button (primary/destructive)
```

#### Tabs

Pill-style (floating segment):
```
div.flex.gap-1.bg-black/[0.04].rounded-xl.p-1.w-fit
  button  (active:  px-3 py-1.5 text-xs font-semibold bg-white text-gray-900 rounded-lg shadow-sm)
  button  (default: px-3 py-1.5 text-xs text-gray-500 rounded-lg hover:text-gray-900 transition-colors)
```

Line-style (page-level tabs):
```
div.flex.border-b.border-gray-200
  button  (active:  flex items-center gap-1.5 px-5 py-3 text-sm font-medium border-b-2 border-gray-900 text-gray-900 transition-colors)
  button  (default: flex items-center gap-1.5 px-5 py-3 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700 transition-colors)
```

#### Tables — sort-active toggle button (e.g. column sorters)

```
Active:   px-3 py-1.5 text-xs font-medium rounded-lg bg-blue-100 text-blue-700
Default:  px-3 py-1.5 text-xs font-medium rounded-lg bg-black/[0.04] text-gray-600 hover:bg-gray-200
```

#### Toggle / switch

```
On:  div.w-9.h-5.bg-emerald-500.rounded-full.relative.transition-colors
       div.absolute.left-0.5.top-0.5.w-4.h-4.bg-white.rounded-full.shadow-sm
Off: div.w-9.h-5.bg-gray-300.rounded-full.relative.transition-colors
       div.absolute.right-0.5.top-0.5.w-4.h-4.bg-white.rounded-full.shadow-sm
Wrapper label: flex items-center gap-3 cursor-pointer
```

#### Progress / gauge bars

```
Track:  w-full bg-gray-100 rounded-full h-1.5  (or h-2)
Fill:   h-full rounded-full transition-all {color}
  green  <60% : bg-emerald-500
  amber 60–85%: bg-amber-500
  red   >85%  : bg-red-500
```

#### Empty states

```
glass-card rounded-2xl p-12 text-center  (or p-16)
  Icon.w-10.h-10.text-gray-300.mx-auto.mb-3
  p.text-gray-400.text-sm  (description text)
  button  (optional CTA — use blue or primary variant)
```

#### Skeleton / loading

```
animate-pulse on the same card class as the real card:
  glass-card rounded-2xl p-5 animate-pulse
  glass-card rounded-2xl p-5 animate-pulse h-32
  div.bg-gray-200.rounded.h-4.w-32.mb-2   (text line placeholder)
  div.bg-gray-100.rounded.h-2.w-full       (bar placeholder)
```

#### Code / log blocks

```
bg-gray-50 border border-black/[0.08] rounded-xl p-4 text-xs font-mono text-gray-800 overflow-auto max-h-64 whitespace-pre-wrap
```

#### Page section headers

```
Section title + actions row:
  div.flex.flex-col.sm:flex-row.sm:items-center.justify-between.gap-4.mb-6
    div
      h2.text-2xl.font-semibold.tracking-tight.text-gray-900
      p.text-sm.text-gray-500.mt-0.5
    div.flex.items-center.gap-2.flex-wrap
      (action buttons right-aligned)

Subsection heading (inside a card):
  h3.text-sm.font-semibold.text-gray-700.mb-3             (standard)
  h3.text-sm.font-semibold.text-gray-700.uppercase.tracking-wide.mb-3  (uppercase label style)
```

#### Scrollbar (WebKit)

```css
::-webkit-scrollbar       { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(0,0,0,0.12); border-radius: 999px; }
::-webkit-scrollbar-thumb:hover { background: rgba(0,0,0,0.20); }
```

---

### 5. Responsive grid patterns

```
Stat cards:    grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-5
Two columns:   grid grid-cols-1 md:grid-cols-2 gap-5
Three columns: grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4
Four columns:  grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5
Mixed:         grid grid-cols-1 md:grid-cols-3 gap-4 mb-6
```

---

### 6. Color-coding conventions (semantic intent)

| Intent | Tailwind prefix family | Example use |
|---|---|---|
| Success / active | `emerald` | running services, success banners |
| Info / primary action | `blue` | CTA buttons, info banners, links |
| Warning | `amber` / `yellow` | quota warnings, pending states |
| Danger / error | `red` / `rose` | destructive actions, error banners |
| Neutral | `gray` | text, borders, ghost buttons |
| Special / creative | `purple` / `violet` / `indigo` | specific feature accent only |

Always use `color-500/[0.08]` tint pattern for soft inline banners/badges (not full-saturation backgrounds).

---

### 7. Motion rules

- All interactive transitions: `transition-colors duration-150` (color-only) or `transition-all duration-200` (when transform is also involved).
- Entrance animations: `animate-fade-in` (content loads), `animate-slide-up` (drawers, toasts from bottom), `animate-scale-in` (modals).
- Never use motion on elements that lack explicit hover/focus behavior.
- Do not animate widths or heights above `transition-all duration-300` — causes layout jank.

---

### 8. Accessibility checklist

- Every interactive element must have a visible `focus:ring-2` state.
- Color is never the only indicator of state — always pair with text, icon, or border change.
- Modals must trap focus and close on `Escape`.
- Icon-only buttons must have `aria-label`.
- Disabled elements must have `disabled:cursor-not-allowed` AND `disabled:opacity-50`.
- All table `<th>` elements should have `scope="col"` or `scope="row"`.

---

### 9. What NOT to do

- Do not invent new glass variants — use `.glass`, `.glass-subtle`, `.glass-strong`, `.glass-card` only.
- Do not use raw `rgba()` colors in component classes — use Tailwind's `/[opacity]` syntax.
- Do not use `text-black` or `text-white` for body text — use `text-gray-900` and `text-white` only where semantically correct.
- Do not use `rounded-3xl` on anything smaller than a modal.
- Do not use `font-extrabold` outside of large stat/hero numbers.
- Do not use `shadow-2xl` outside of modal dialogs.
- Do not use `backdrop-blur` values other than those defined in the glass classes — do not inline arbitrary `backdrop-blur-[Xpx]`.
- Do not use decorative background gradients inside content cards — only on the page body.
