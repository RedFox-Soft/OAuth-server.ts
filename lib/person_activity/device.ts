import type { ActivityBrowser, ActivitySystem } from '../adapters/types.js';

/*
 * The browser and system family of a sign-in, from its `User-Agent` (specs/133 research R8). The header is written by
 * the caller, so three rules hold: the input is cut before anything reads it, it is only searched for fixed markers
 * (no regular expression an input could make slow), and nothing but one of two enumerations comes out. The raw string
 * is never kept; the console says "as the browser reported it", because any browser can claim to be another.
 *
 * Order matters where browsers carry each other's names: Edge, Opera and Samsung Internet all say "Chrome", Chrome
 * says "Safari".
 */
const MAX_LENGTH = 512;

const BROWSERS: readonly [string, ActivityBrowser][] = [
	['Edg/', 'edge'],
	['EdgA/', 'edge'],
	['EdgiOS/', 'edge'],
	['OPR/', 'opera'],
	['Opera', 'opera'],
	['SamsungBrowser/', 'samsung'],
	['Firefox/', 'firefox'],
	['FxiOS/', 'firefox'],
	['CriOS/', 'chrome'],
	['Chrome/', 'chrome'],
	['Safari/', 'safari']
];

const SYSTEMS: readonly [string, ActivitySystem][] = [
	['CrOS', 'chromeos'],
	['Android', 'android'],
	['iPhone', 'ios'],
	['iPad', 'ios'],
	['iPod', 'ios'],
	['Windows', 'windows'],
	['Mac OS X', 'macos'],
	['Macintosh', 'macos'],
	['Linux', 'linux']
];

function firstOf<T extends string>(
	text: string,
	markers: readonly [string, T][]
): T | undefined {
	return markers.find(([marker]) => text.includes(marker))?.[1];
}

export function deviceOf(
	userAgent: string | null
): { browser: ActivityBrowser; system: ActivitySystem } | undefined {
	if (userAgent === null || userAgent === '') return undefined;
	const text = userAgent.slice(0, MAX_LENGTH);
	return {
		browser: firstOf(text, BROWSERS) ?? 'other',
		system: firstOf(text, SYSTEMS) ?? 'other'
	};
}
