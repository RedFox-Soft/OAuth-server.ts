import { generate } from '@ant-design/colors';
import { contrastRatio } from './contrast.js';
import { PRIMARY_COLOR_PATTERN } from '../../consts/client_branding.js';

/*
 * A client's primary colour as its sign-in pages paint it (specs/106). The operator's hue and saturation are
 * kept; only lightness moves, and only as far as the minimums spec 096 holds the default palette to require —
 * separately in each scheme, because a colour that reads well on white may vanish on black.
 *
 * Pure, and free of server imports, so the console's preview tiles are drawn by this same code.
 */

export interface PaintedAccent {
	light: {
		// The button fill and the link: one value, so the operator sees one light colour.
		primary: string;
		primaryHover: string;
		primaryActive: string;
		linkHover: string;
		linkActive: string;
	};
	dark: {
		// What antd is handed as `colorPrimary` under the dark algorithm — see darkSeed.
		seed: string;
		// What antd paints from that seed.
		primary: string;
		primaryHover: string;
		primaryActive: string;
		// The link is re-derived from its seed exactly as the primary is.
		linkSeed: string;
		link: string;
		linkHover: string;
		linkActive: string;
	};
	/*
	 * Whether the light colour had to move. The dark one always differs from the input — antd paints every seed
	 * darker on a dark page, its own blue included — so flagging it would flag every colour; it is shown instead.
	 */
	adjusted: boolean;
}

const WHITE = '#ffffff';
const LIGHT_SURFACES = ['#ffffff', '#f0f2f5', '#f6f7f9'];
const DARK_SURFACES = ['#000000', '#141414', '#1f1f1f'];
const DARK_BOUNDARY_SURFACES = ['#000000', '#141414'];
const STEP = 0.04;

type Hsl = { h: number; s: number; l: number };

function toHsl(colour: string): Hsl {
	const [r, g, b] = [1, 3, 5].map(
		(i) => parseInt(colour.slice(i, i + 2), 16) / 255
	);
	const max = Math.max(r, g, b);
	const min = Math.min(r, g, b);
	const l = (max + min) / 2;
	if (max === min) return { h: 0, s: 0, l };
	const d = max - min;
	const s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
	const h =
		max === r
			? (g - b) / d + (g < b ? 6 : 0)
			: max === g
				? (b - r) / d + 2
				: (r - g) / d + 4;
	return { h: h * 60, s, l };
}

function toHex({ h, s, l }: Hsl): string {
	const lightness = Math.min(1, Math.max(0, l));
	const k = (n: number) => (n + h / 30) % 12;
	const a = s * Math.min(lightness, 1 - lightness);
	const channel = (n: number) =>
		Math.round(
			255 * (lightness - a * Math.max(-1, Math.min(k(n) - 3, 9 - k(n), 1)))
		);
	return `#${[channel(0), channel(8), channel(4)]
		.map((v) => v.toString(16).padStart(2, '0'))
		.join('')}`;
}

const at = (base: Hsl, l: number) => toHex({ ...base, l });

const labelled = (fill: string) => contrastRatio(WHITE, fill) >= 4.5;
const readableOn = (surfaces: string[]) => (text: string) =>
	surfaces.every((surface) => contrastRatio(text, surface) >= 4.5);
const lightPrimaryPasses = (c: string) =>
	labelled(c) && readableOn(LIGHT_SURFACES)(c);

/*
 * antd's dark algorithm turns a `colorPrimary` or `colorLink` seed into palette step 6 of
 * `generate(seed, { theme: 'dark' })` (antd/es/theme/themes/shared/genColorMapToken.js); hover and active
 * are taken as given.
 */
const darkPrimaryOf = (seed: string) => generate(seed, { theme: 'dark' })[5];
const darkLinkPasses = (seed: string) =>
	readableOn(DARK_SURFACES)(darkPrimaryOf(seed));
const darkLabelled = (seed: string) => labelled(darkPrimaryOf(seed));
const darkBounded = (seed: string) =>
	DARK_BOUNDARY_SURFACES.every(
		(surface) => contrastRatio(darkPrimaryOf(seed), surface) >= 3
	);
const darkPrimaryPasses = (seed: string) =>
	darkLabelled(seed) && darkBounded(seed);

// The passing lightness nearest the input's, by a fine scan — the fallback where bisection's premise fails.
function scan(
	base: Hsl,
	passes: (colour: string) => boolean
): string | undefined {
	let best: { l: number; distance: number } | undefined;
	for (let i = 0; i <= 400; i++) {
		const l = i / 400;
		const distance = Math.abs(l - base.l);
		if ((!best || distance < best.distance) && passes(at(base, l)))
			best = { l, distance };
	}
	return best && at(base, best.l);
}

/*
 * The lightness nearest the input's, toward `toward`, at which `holds` first holds — by bisection, because
 * the windows are narrow (the dark one is 5–18 % of lightness wide), so a coarse sweep can step over them.
 * `holds` is one condition that only improves toward `toward` (a white label as a fill darkens, contrast on a
 * dark surface as a colour lightens), which is what makes bisection sound; the caller then checks everything.
 */
function bisect(
	base: Hsl,
	toward: 0 | 1,
	holds: (colour: string) => boolean
): string | undefined {
	let fail = base.l;
	let pass: number = toward;
	if (!holds(at(base, pass))) return undefined;
	for (let i = 0; i < 24; i++) {
		const mid = (fail + pass) / 2;
		if (holds(at(base, mid))) pass = mid;
		else fail = mid;
	}
	return at(base, pass);
}

function nearest(
	base: Hsl,
	toward: 0 | 1,
	holds: (colour: string) => boolean,
	passes: (colour: string) => boolean
): string | undefined {
	const found = bisect(base, toward, holds);
	return found && passes(found) ? found : scan(base, passes);
}

/*
 * antd re-derives the dark `colorPrimary` from its seed and the theme config cannot override it (seed #2f7d32
 * is painted #2b6d2e), so the search runs over the seed and judges what antd will paint from it. The window
 * is bounded on both sides: a seed painted too light for a white label moves darker, one painted too dark to
 * stand out from the page moves lighter.
 */
function darkSeed(input: string, base: Hsl): string | undefined {
	if (darkPrimaryPasses(input)) return input;
	return darkLabelled(input)
		? nearest(base, 1, darkBounded, darkPrimaryPasses)
		: nearest(base, 0, darkLabelled, darkPrimaryPasses);
}

function derive(input: string): PaintedAccent | undefined {
	const base = toHsl(input);
	const lightPrimary = lightPrimaryPasses(input)
		? input
		: nearest(base, 0, lightPrimaryPasses, lightPrimaryPasses);
	const seed = darkSeed(input, base);
	const linkSeed = darkLinkPasses(input)
		? input
		: nearest(base, 1, darkLinkPasses, darkLinkPasses);
	if (!lightPrimary || !seed || !linkSeed) return undefined;

	// Hover and pressed states are darker than the resting state: darker only adds to a white label's contrast.
	const light = toHsl(lightPrimary);
	const darkPrimary = darkPrimaryOf(seed);
	const dark = toHsl(darkPrimary);
	const darkLink = darkPrimaryOf(linkSeed);
	const link = toHsl(darkLink);
	return {
		light: {
			primary: lightPrimary,
			primaryHover: at(light, light.l - STEP),
			primaryActive: at(light, light.l - 2 * STEP),
			linkHover: at(light, light.l - STEP),
			linkActive: at(light, light.l - 2 * STEP)
		},
		dark: {
			seed,
			primary: darkPrimary,
			primaryHover: at(dark, dark.l - STEP),
			primaryActive: at(dark, dark.l - 2 * STEP),
			// A link brightens as it is hovered and pressed, which only adds to its contrast on a dark surface.
			linkSeed,
			link: darkLink,
			linkHover: at(link, link.l + 2 * STEP),
			linkActive: at(link, link.l + STEP)
		},
		adjusted: lightPrimary !== input
	};
}

/*
 * Bounded because the key space is operator-controlled: every colour ever saved stays reachable by a page.
 * The memo exists less for speed than so one colour always yields the very same strings, which the dark-block
 * memo keys on.
 */
const MEMO_LIMIT = 512;
const memo = new Map<string, PaintedAccent | undefined>();

export function paintedAccent(colour: string): PaintedAccent | undefined {
	const input = colour.toLowerCase();
	if (!PRIMARY_COLOR_PATTERN.test(input)) return undefined;
	if (memo.has(input)) return memo.get(input);
	const accent = derive(input);
	if (memo.size >= MEMO_LIMIT) memo.delete(memo.keys().next().value as string);
	memo.set(input, accent);
	return accent;
}

/* A stored value that is not `#rrggbb` reads as no colour, so a hand-edited record never reaches a page. */
export function readPrimaryColor(value: unknown): string | undefined {
	return typeof value === 'string' && PRIMARY_COLOR_PATTERN.test(value)
		? value.toLowerCase()
		: undefined;
}

export function accentTokens(
	scheme: 'light' | 'dark',
	accent: PaintedAccent
): Record<string, string> {
	if (scheme === 'light') {
		const { light } = accent;
		return {
			colorPrimary: light.primary,
			colorPrimaryHover: light.primaryHover,
			colorPrimaryActive: light.primaryActive,
			colorLink: light.primary,
			colorLinkHover: light.linkHover,
			colorLinkActive: light.linkActive
		};
	}
	const { dark } = accent;
	// colorLinkActive is replaced too: DARK_TOKENS sets it, and a pressed link would otherwise flash the default blue.
	return {
		colorPrimary: dark.seed,
		colorPrimaryHover: dark.primaryHover,
		colorPrimaryActive: dark.primaryActive,
		colorLink: dark.linkSeed,
		colorLinkHover: dark.linkHover,
		colorLinkActive: dark.linkActive
	};
}

/*
 * The server's own `--fox-link` role, which the consent page's links and the language switcher read, in both
 * schemes. Every value is this module's own `#rrggbb`, never a stored string.
 */
export function accentStyle(accent: PaintedAccent): string {
	return (
		`<style>:root{--fox-link:${accent.light.primary}}` +
		`@media (prefers-color-scheme: dark){:root{--fox-link:${accent.dark.link}}}</style>`
	);
}
