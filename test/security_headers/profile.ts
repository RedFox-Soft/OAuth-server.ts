import { expect } from 'bun:test';

/*
 * The expected profile, restated here rather than imported from lib/plugins/securityHeaders.ts.
 * Importing the implementation's own constant would make every assertion below tautological — the
 * suite would keep passing through a change that silently loosened the policy, which is the one
 * outcome it exists to prevent.
 */
export const NOSNIFF = 'nosniff';
export const REFERRER_POLICY = 'no-referrer';
export const NON_PAGE_POLICY = "default-src 'none'; frame-ancestors 'none'";

const PROFILE_NAMES = [
	'x-content-type-options',
	'referrer-policy',
	'content-security-policy'
];

/*
 * `Headers.get()` joins repeated fields with a comma, so it cannot answer "was this set twice?" —
 * and a duplicated policy is precisely the regression FR-009 names. Enumerating the entries is the
 * only way to see the difference.
 */
function occurrences(res: Response, name: string): string[] {
	return [...res.headers.entries()]
		.filter(([key]) => key.toLowerCase() === name)
		.map(([, value]) => value);
}

function expectExactlyOnce(res: Response, name: string): string {
	const found = occurrences(res, name);
	expect(found.length, `${name} should appear exactly once`).toBe(1);
	return found[0]!;
}

function expectSharedHeaders(res: Response): void {
	for (const name of PROFILE_NAMES) {
		expectExactlyOnce(res, name);
	}
	expect(res.headers.get('x-content-type-options')).toBe(NOSNIFF);
	expect(res.headers.get('referrer-policy')).toBe(REFERRER_POLICY);
}

/*
 * A response that is not a rendered page: the locked policy, exactly.
 */
export function expectNonPageProfile(res: Response): void {
	expectSharedHeaders(res);
	expect(res.headers.get('content-security-policy')).toBe(NON_PAGE_POLICY);
}

/*
 * A rendered page: the same two hardening headers, but the policy derived from its own document.
 *
 * Asserting only "not the locked literal" would pass for a page that lost its policy to some third
 * writer, so the shape is asserted too — a page policy always carries a script-src, even when that
 * directive is 'none'.
 */
/*
 * For the exhaustive sweep, where the caller cannot know in advance whether a given route answers
 * with a page or with data — and must not be allowed to guess, since guessing wrong is how a route
 * quietly drops out of coverage. The invariant that holds for every response either way: the two
 * hardening headers are always present, and the policy is the locked one unless the response is a
 * page, in which case it is that page's own.
 */
export function expectProfileByKind(res: Response): void {
	const isPage = (res.headers.get('content-type') ?? '').includes('text/html');
	if (isPage) {
		expectPageProfile(res);
	} else {
		expectNonPageProfile(res);
	}
}

export function expectPageProfile(res: Response): void {
	expectSharedHeaders(res);
	const policy = res.headers.get('content-security-policy');
	expect(policy).not.toBe(NON_PAGE_POLICY);
	expect(policy).toContain('script-src');
}
