import { beforeAll, describe, expect, it } from 'bun:test';
import { theme } from 'antd';

import bootstrap from '../test_helper.js';
import { contrastRatio } from 'lib/html/theme/contrast.ts';
import { DARK_TOKENS, LIGHT_TOKENS } from 'lib/html/theme/tokens.ts';
import { accentTokens, paintedAccent } from 'lib/html/theme/accent.ts';

/*
 * The surfaces the pages draw on (lib/html/theme/palette.ts `page`, `card`, `box`; antd's container), and the
 * minimums spec 096 holds the default palette to (test/dark_theme/palette.spec.ts). Restated here rather than
 * imported from the module under test: the minimums are the claim, so they cannot come from what is checked.
 */
const LIGHT_SURFACES = ['#ffffff', '#f0f2f5', '#f6f7f9'];
const DARK_SURFACES = ['#000000', '#141414', '#1f1f1f'];
const WHITE = '#ffffff';

type Painted = NonNullable<ReturnType<typeof paintedAccent>>;

function shortfalls(accent: Painted): string[] {
	const missed: string[] = [];
	const atLeast = (what: string, ratio: number, minimum: number) => {
		if (ratio < minimum)
			missed.push(`${what} ${ratio.toFixed(2)} < ${minimum}`);
	};
	const { light, dark } = accent;
	for (const [role, value] of Object.entries({
		'light primary': light.primary,
		'light primary hover': light.primaryHover,
		'light primary active': light.primaryActive,
		'dark primary': dark.primary,
		'dark primary hover': dark.primaryHover,
		'dark primary active': dark.primaryActive
	})) {
		atLeast(`white label on ${role}`, contrastRatio(WHITE, value), 4.5);
	}
	for (const [role, value] of Object.entries({
		'light link': light.primary,
		'light link hover': light.linkHover,
		'light link active': light.linkActive
	})) {
		for (const surface of LIGHT_SURFACES)
			atLeast(`${role} on ${surface}`, contrastRatio(value, surface), 4.5);
	}
	for (const [role, value] of Object.entries({
		'dark link': dark.link,
		'dark link hover': dark.linkHover,
		'dark link active': dark.linkActive
	})) {
		for (const surface of DARK_SURFACES)
			atLeast(`${role} on ${surface}`, contrastRatio(value, surface), 4.5);
	}
	for (const surface of ['#000000', '#141414'])
		atLeast(
			`dark primary as a boundary on ${surface}`,
			contrastRatio(dark.primary, surface),
			3
		);
	for (const [role, value] of Object.entries({ ...light, ...dark })) {
		if (typeof value === 'string' && !/^#[0-9a-f]{6}$/.test(value))
			missed.push(`${role} is not #rrggbb: ${value}`);
	}
	return missed;
}

function hex(h: number, s: number, l: number): string {
	const k = (n: number) => (n + h / 30) % 12;
	const a = s * Math.min(l, 1 - l);
	const channel = (n: number) =>
		Math.round(255 * (l - a * Math.max(-1, Math.min(k(n) - 3, 9 - k(n), 1))));
	return `#${[channel(0), channel(8), channel(4)]
		.map((v) => v.toString(16).padStart(2, '0'))
		.join('')}`;
}

const CORNERS = [
	'#ffffff',
	'#000000',
	'#808080',
	'#ffff00',
	'#ffe066',
	'#00ffff',
	'#ff0000',
	'#0000ff',
	'#ff00ff',
	'#0958d9',
	'#1677ff',
	'#2f7d32'
];

// A grey is the same colour at every hue, so the set holds each once.
const DOMAIN = [
	...new Set([
		...CORNERS,
		...Array.from({ length: 36 }, (_, i) => i * 10).flatMap((h) =>
			[0, 0.5, 1].flatMap((s) =>
				Array.from({ length: 21 }, (_, j) => hex(h, s, j * 0.05))
			)
		)
	])
];

const SAMPLE = Array.from({ length: 36 }, (_, i) => i * 10).flatMap((h) =>
	[0, 0.5, 1].map((s) => hex(h, s, 0.5))
);

/**
 * @proves Whatever colour an administrator gives an application, the shades its sign-in pages are painted in
 * meet WCAG 2.2 AA in the light and the dark scheme, and are the shades antd actually paints.
 */
describe("an application's primary colour, as its pages paint it", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('meets every AA minimum in both schemes, for every colour an administrator may choose', () => {
		const failures = DOMAIN.flatMap((colour) => {
			const accent = paintedAccent(colour);
			if (!accent) return [`${colour}: no shade painted`];
			return shortfalls(accent).map((missed) => `${colour}: ${missed}`);
		});
		expect(failures.slice(0, 10)).toEqual([]);
	}, 15_000); // About 1 500 colours at ~1.2 ms each: ~2 s here, and a slower CI runner must not turn that into a flake.

	it('keeps a colour that already meets every minimum exactly as given in the light scheme', () => {
		const accent = paintedAccent('#2f7d32');
		expect(accent?.light.primary).toBe('#2f7d32');
		expect(accent?.adjusted).toBe(false);
	});

	it('moves a colour too light for a white label to a darker shade, and says so', () => {
		const accent = paintedAccent('#ffe066');
		expect(accent?.light.primary).not.toBe('#ffe066');
		expect(accent?.adjusted).toBe(true);
	});

	for (const scheme of ['light', 'dark'] as const) {
		it(`is what antd paints in the ${scheme} scheme, for every sampled colour`, () => {
			const drift = SAMPLE.flatMap((colour) => {
				const accent = paintedAccent(colour);
				if (!accent) return [`${colour}: no shade painted`];
				const token = theme.getDesignToken({
					algorithm:
						scheme === 'dark' ? theme.darkAlgorithm : theme.defaultAlgorithm,
					token: {
						...(scheme === 'dark' ? DARK_TOKENS : LIGHT_TOKENS),
						...accentTokens(scheme, accent)
					}
				});
				const expected = {
					colorPrimary: accent[scheme].primary,
					colorLink:
						scheme === 'dark' ? accent.dark.link : accent.light.primary,
					colorLinkActive:
						scheme === 'dark' ? accent.dark.linkActive : accent.light.linkActive
				};
				return Object.entries(expected)
					.filter(
						([name, value]) =>
							token[name as keyof typeof expected].toLowerCase() !== value
					)
					.map(
						([name, value]) =>
							`${colour}: ${name} painted ${token[name as keyof typeof expected]}, predicted ${value}`
					);
			});
			expect(drift.slice(0, 10)).toEqual([]);
		});
	}
});
