/*
 * Every colour an end-user page sets itself, as a role with a light and a dark value (specs/096). The theme
 * head (head.ts) declares each role once as `--fox-<role>` and swaps the dark values in under
 * `prefers-color-scheme: dark`; a page writes `foxVar(role)`, never a colour, so it changes scheme with no
 * script and hydrates to the same markup on server and client.
 *
 * The light values are what the pages used before this palette existed, except where they fell short of
 * WCAG AA — those are corrected, and say so. The dark values follow antd's dark scale, so the plain pages and
 * the antd pages read as one product in either scheme.
 *
 * `on` names the surfaces a text or boundary role is drawn on: test/dark_theme/palette.spec.ts holds every
 * such pair to its minimum in both schemes, which is what lets these values change safely.
 */

export type ContrastKind = 'text' | 'large-text' | 'boundary' | 'surface';

interface Role {
	light: string;
	dark: string;
	kind: ContrastKind;
	// Checked against the palette by the contrast test; typed loosely only because the map cannot name its own keys.
	on?: readonly string[];
}

const SURFACES = ['page', 'card', 'box'] as const;

export const FOX_PALETTE = {
	page: { light: '#f0f2f5', dark: '#000000', kind: 'surface' },
	card: { light: '#ffffff', dark: '#141414', kind: 'surface' },
	box: { light: '#f6f7f9', dark: '#1f1f1f', kind: 'surface' },
	'box-border': { light: '#e6e8eb', dark: '#303030', kind: 'surface' },
	divider: { light: '#f0f0f0', dark: '#303030', kind: 'surface' },
	shadow: {
		light: 'rgba(0, 0, 0, 0.1)',
		dark: 'rgba(0, 0, 0, 0.6)',
		kind: 'surface'
	},

	text: { light: '#1f1f1f', dark: '#e6e6e6', kind: 'text', on: SURFACES },
	'text-secondary': {
		light: '#595959',
		dark: '#a6a6a6',
		kind: 'text',
		on: SURFACES
	},
	// Was #8c8c8c, and rgba(0,0,0,0.55) on the consent page: 3.4:1 and 4.4:1 on their surfaces, below AA.
	'text-muted': {
		light: '#666666',
		dark: '#8c8c8c',
		kind: 'text',
		on: SURFACES
	},
	// Was #1677ff on the plain pages, 4.1:1 on white.
	link: { light: '#0958d9', dark: '#69b1ff', kind: 'text', on: SURFACES },

	// A field's or a plain button's edge (WCAG 1.4.11). Was #d9d9d9, 1.4:1 on white.
	'field-border': {
		light: '#878787',
		dark: '#7a7a7a',
		kind: 'boundary',
		on: SURFACES
	},
	// The dashed frame round a device code: decoration around text that carries its own contrast.
	'code-border': { light: '#b0b8c4', dark: '#595959', kind: 'surface' },

	// A filled button and the text on it. Was #1677ff, 4.1:1 against its white label.
	'primary-solid': { light: '#0958d9', dark: '#1668dc', kind: 'surface' },
	'on-primary': {
		light: '#ffffff',
		dark: '#ffffff',
		kind: 'text',
		on: ['primary-solid']
	},
	'danger-solid': { light: '#a8071a', dark: '#c41d2a', kind: 'surface' },
	'on-danger': {
		light: '#ffffff',
		dark: '#ffffff',
		kind: 'text',
		on: ['danger-solid']
	},

	'danger-bg': { light: '#fff2f0', dark: '#2c1618', kind: 'surface' },
	'danger-border': { light: '#ffccc7', dark: '#5b2526', kind: 'surface' },
	// Was #ff4d4f for the sign-in pages' error text, 3.3:1 on its own plate.
	'danger-text': {
		light: '#cf1322',
		dark: '#ff7875',
		kind: 'text',
		on: ['card', 'danger-bg', 'box']
	},
	'danger-strong': {
		light: '#a8071a',
		dark: '#ffa39e',
		kind: 'text',
		on: ['card', 'danger-bg', 'box']
	},

	'warn-bg': { light: '#fffbe6', dark: '#2b2111', kind: 'surface' },
	'warn-border': { light: '#ffe58f', dark: '#594214', kind: 'surface' },
	// Was #ad6800 on the consent page's warning, 4.3:1 on its plate.
	'warn-icon': {
		light: '#995c00',
		dark: '#d89614',
		kind: 'text',
		on: ['warn-bg', 'card']
	},

	'notice-bg': { light: '#e6f4ff', dark: '#111a2c', kind: 'surface' },
	'notice-border': { light: '#91caff', dark: '#15325b', kind: 'surface' },
	'notice-text': {
		light: '#0958d9',
		dark: '#69b1ff',
		kind: 'text',
		on: ['notice-bg']
	},

	'success-bg': { light: '#f6ffed', dark: '#162312', kind: 'surface' },
	'success-border': { light: '#b7eb8f', dark: '#274916', kind: 'surface' },

	/*
	 * An application's logo is drawn for a white page; on a dark one a dark mark would vanish. The plate stays
	 * light in both schemes (specs/096 FR-010), and its edge keeps it a tile on a dark card.
	 */
	'logo-plate': { light: '#f6f7f9', dark: '#f6f7f9', kind: 'surface' },
	// The field a TOTP enrolment QR code is drawn on: white in both schemes, so its black modules always scan.
	'qr-plate': { light: '#ffffff', dark: '#ffffff', kind: 'surface' },
	'logo-plate-border': { light: '#e6e8eb', dark: '#8c8c8c', kind: 'surface' },

	/*
	 * A recognised provider's sign-in button. Its light colours are Google's branding requirement, which the
	 * sign-in page applies to every recognised provider; the dark ones are Google's dark button.
	 */
	'provider-bg': { light: '#ffffff', dark: '#131314', kind: 'surface' },
	'provider-border': {
		light: '#747775',
		dark: '#8e918f',
		kind: 'boundary',
		on: ['card']
	},
	'provider-text': {
		light: '#1f1f1f',
		dark: '#e3e3e3',
		kind: 'text',
		on: ['provider-bg']
	},

	/*
	 * A monochrome provider mark (Apple's, GitHub's) on a dark button. Their terms allow black or white and
	 * nothing between, so it is white, exactly. In light the marks keep their own black fill; this value is
	 * never applied there.
	 */
	'mark-mono': {
		light: '#000000',
		dark: '#ffffff',
		kind: 'boundary',
		on: ['card', 'provider-bg']
	}
} as const satisfies Record<string, Role>;

export type FoxRole = keyof typeof FOX_PALETTE;

export function foxVar(role: FoxRole): string {
	return `var(--fox-${role})`;
}

// The class a monochrome third-party mark carries; the theme head recolours it in the dark scheme.
export const MARK_MONO_CLASS = 'fox-mark-mono';
