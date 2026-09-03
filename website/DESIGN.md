# FoxAuth — design system

The one page a designer or a later implementer reads first.

## Brand idea

The mark is a fox: quick, precise, a little sly — the animal that gets past the
gate. The site should read as _engineered warmth_: a security product that is
friendly to developers without looking like a toy. One accent colour (the fox
orange), warm neutrals, generous whitespace, real product screenshots instead
of illustrations.

## Palette

Derived from the logo; every UI colour is one of these or a Tailwind opacity
of one of these.

| Token         | Hex                                                                                       | Source / use                                                                   |
| ------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `accent-50`   | `#fff4ee`                                                                                 | tinted backgrounds                                                             |
| `accent-100`  | `#ffe4d6`                                                                                 | hover tints                                                                    |
| `accent-200`  | `#ffc688`                                                                                 | **logo peach** — soft highlights, dark-mode link colour                        |
| `accent-300`  | `#ffa661`                                                                                 |                                                                                |
| `accent-400`  | `#f97e3a`                                                                                 | primary button hover                                                           |
| `accent-500`  | `#f05a23`                                                                                 | **logo orange** — primary buttons, links, focus rings                          |
| `accent-600`  | `#d94a1c`                                                                                 | primary button active/pressed                                                  |
| `accent-700`  | `#c3461d`                                                                                 | **logo rust** — pressed states, headings on peach                              |
| `accent-800`  | `#9a3617`                                                                                 |                                                                                |
| `accent-900`  | `#7a2c14`                                                                                 | dark accent text                                                               |
| `accent-950`  | `#431508`                                                                                 |                                                                                |
| `gray-50…950` | `#faf8f6 #f3f0ed #e6e1dc #d1cac3 #a39a91 #7a716a #5d554f #453f3a #2e2a26 #1f1c19 #14120f` | warm neutrals (hue ≈ 40°, very low chroma) so orange never sits on a cold grey |

**Contrast rules.** Body text `gray-900` on white / `gray-100` on `gray-950`;
orange `accent-500` is used for text only at ≥ 18 px or bold (it is 3.4:1 on
white — not enough for small body text); small orange text uses `accent-700`
in light mode and `accent-200` in dark mode. The primary button is the one
place text sits directly on the accent scale at body size: its label is
`gray-950` in both light and dark mode, never `white` — white on `accent-500`
is only 3.4:1, below AA for 14–16 px text. `gray-950` on the button's rest
(`accent-500`, 5.5:1) and hover (`accent-400`, 7.2:1) backgrounds clears AA
comfortably; on the active/pressed background (`accent-600`, 4.4:1) it is
marginally under the 4.5:1 threshold — a known gap, tracked rather than
hidden, because the pressed state is brief and low-emphasis.

## Typography

Body and UI: Inter Variable (Fontsource). Code: JetBrains Mono Variable.
Headings: Inter at weight 650, tracking −0.02em, `text-balance`.

Scale: 14 / 16 / 18 / 20 / 24 / 30 / 38 / 48 px; line-height 1.6 for prose,
1.15 for display. No third typeface.

## Shape and space

Radius 8 px on controls, 12 px on cards, 16 px on screenshot frames; 1 px
borders in `gray-200` / `gray-700`; 4-pt spacing grid, sections padded 96 px
desktop / 64 px mobile; content max-width 72 rem, prose 42 rem.

## The mark

Minimum 24 px; clear space equal to the ear height; never recoloured, never on
`accent-500` (the rust shading disappears). There is no knockout version; on
an orange surface place the mark inside a white card.

Wordmark "FoxAuth" in Inter 650, set 0.9× the mark's cap height, gap 0.5× mark
width; the "Fox" and "Auth" are one word, no space, no camel-case colouring.

## Dark mode

Backgrounds `gray-950`/`gray-900`, text `gray-100`, links `accent-200`. The
primary button is unchanged from light mode: `accent-500`/`accent-400`
hover/`accent-600` active backgrounds with `gray-950` text — the same pairing
works in both themes, so there is no dark-mode override for it. Screenshots
keep their own light frame with a 1 px `gray-700` border.

## Motion

Only `transition-colors` at 150 ms and a 200 ms fade on details/accordion.
Nothing moves on scroll.

## Voice

Plain, specific, developer-first; sentences under 20 words; claims the
Reference can back; "source-available", never "open-source"; never "OpenID
Certified".
