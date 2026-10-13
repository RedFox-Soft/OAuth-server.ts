import { beforeAll, describe, expect, it } from 'bun:test';
import { theme } from 'antd';

import bootstrap from '../test_helper.js';
import { FOX_PALETTE, type FoxRole } from 'lib/html/theme/palette.ts';
import { DARK_TOKENS, LIGHT_TOKENS } from 'lib/html/theme/tokens.ts';
import {
	composite,
	contrastRatio,
	relativeLuminance
} from 'lib/html/theme/contrast.ts';

const SCHEMES = ['light', 'dark'] as const;
const MINIMUM = { text: 4.5, 'large-text': 3, boundary: 3 } as const;

function colour(role: FoxRole, scheme: (typeof SCHEMES)[number]): string {
	const value = FOX_PALETTE[role][scheme];
	// A translucent surface is seen over the page.
	return composite(value, FOX_PALETTE.page[scheme]);
}

const pairs = Object.entries(FOX_PALETTE).flatMap(([role, spec]) =>
	spec.kind === 'surface'
		? []
		: ((spec as { on?: readonly string[] }).on ?? []).map(
				(on) =>
					[role as FoxRole, on, spec.kind as keyof typeof MINIMUM] as const
			)
);

/**
 * @proves Every colour an end user reads on these pages — the server's own palette and the antd theme alike —
 * meets WCAG 2.2 AA against what it is drawn on, in the light scheme and in the dark one (specs/096 FR-005,
 * FR-006).
 */
describe('every colour an end user reads meets WCAG AA, in the light and the dark scheme', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('names only surfaces the palette has', () => {
		for (const [, on] of pairs) expect(Object.keys(FOX_PALETTE)).toContain(on);
	});

	for (const scheme of SCHEMES) {
		for (const [role, on, kind] of pairs) {
			it(`${scheme}: ${role} on ${on} reaches ${MINIMUM[kind]}:1`, () => {
				expect(
					contrastRatio(colour(role, scheme), colour(on as FoxRole, scheme))
				).toBeGreaterThanOrEqual(MINIMUM[kind]);
			});
		}

		it(`${scheme}: an application's logo sits on a light plate`, () => {
			expect(relativeLuminance(colour('logo-plate', scheme))).toBeGreaterThan(
				0.8
			);
		});

		const token = theme.getDesignToken({
			algorithm:
				scheme === 'dark' ? theme.darkAlgorithm : theme.defaultAlgorithm,
			token: scheme === 'dark' ? DARK_TOKENS : LIGHT_TOKENS
		});
		const surfaces = {
			container: token.colorBgContainer,
			page: FOX_PALETTE.page[scheme]
		};

		for (const name of [
			'colorText',
			'colorTextSecondary',
			'colorTextTertiary',
			'colorTextDescription',
			'colorTextPlaceholder',
			'colorLink',
			'colorLinkHover',
			'colorErrorText'
		] as const) {
			for (const [surface, background] of Object.entries(surfaces)) {
				it(`${scheme}: antd ${name} on the ${surface} reaches 4.5:1`, () => {
					expect(contrastRatio(token[name], background)).toBeGreaterThanOrEqual(
						4.5
					);
				});
			}
		}

		for (const name of [
			'colorPrimary',
			'colorPrimaryHover',
			'colorPrimaryActive',
			'colorError',
			'colorErrorHover'
		] as const) {
			it(`${scheme}: a white label on antd ${name} reaches 4.5:1`, () => {
				expect(
					contrastRatio(token.colorTextLightSolid, token[name])
				).toBeGreaterThanOrEqual(4.5);
			});
		}

		for (const name of ['colorBorder', 'colorPrimary'] as const) {
			for (const [surface, background] of Object.entries(surfaces)) {
				it(`${scheme}: antd ${name} as a boundary on the ${surface} reaches 3:1`, () => {
					expect(contrastRatio(token[name], background)).toBeGreaterThanOrEqual(
						3
					);
				});
			}
		}
	}
});
