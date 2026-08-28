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
export const STRICT_TRANSPORT = 'max-age=63072000; includeSubDomains';
/*
 * Restated as one string rather than assembled from a list, for the same reason as the rest of this
 * file: a joined list here would pass whatever the implementation joined, including a shorter one.
 * `clipboard-write` is absent on purpose — see lib/plugins/securityHeaders.ts.
 */
export const PERMISSIONS_POLICY =
	'accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), usb=(), xr-spatial-tracking=()';

const PROFILE_NAMES = [
	'x-content-type-options',
	'referrer-policy',
	'content-security-policy',
	'strict-transport-security',
	'permissions-policy'
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
	expect(res.headers.get('strict-transport-security')).toBe(STRICT_TRANSPORT);
	expect(res.headers.get('permissions-policy')).toBe(PERMISSIONS_POLICY);
}

/*
 * A response that is not a rendered page: the locked policy, exactly.
 *
 * No `X-Frame-Options`, and that absence is asserted rather than merely unmentioned. The legacy header
 * covers rendered documents only: a framed JSON body has no UI to hijack, and the locked policy above
 * already carries `frame-ancestors 'none'`. More to the point, a blanket emission is what would break
 * the one deliberately framable page — so if this ever starts arriving on a data response, the header
 * has acquired a second writer and the hand-off page is already broken.
 */
export function expectNonPageProfile(res: Response): void {
	expectSharedHeaders(res);
	expect(res.headers.get('content-security-policy')).toBe(NON_PAGE_POLICY);
	expect(res.headers.has('x-frame-options')).toBe(false);
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
	/*
	 * The legacy framing header, asserted as the invariant rather than as a value: present and DENY
	 * exactly when this page's own policy denies framing, absent when it does not.
	 *
	 * Hardcoding DENY would pass today and be wrong. `expectProfileByKind` feeds the exhaustive route
	 * sweep, which classifies a response as a page by content type alone and must not guess; a bare
	 * probe cannot currently produce the one framable page (that needs a registered client, a live
	 * authorization request and response_mode=form_post), so the stricter assertion would sit green
	 * until the day something reached that page — and then fail the *correct* behaviour. Deriving the
	 * expectation from the same rule the implementation guarantees is right in both worlds.
	 */
	const deniesFraming = (policy ?? '').includes("frame-ancestors 'none'");
	if (deniesFraming) {
		expectExactlyOnce(res, 'x-frame-options');
		expect(res.headers.get('x-frame-options')).toBe('DENY');
	} else {
		expect(res.headers.has('x-frame-options')).toBe(false);
	}
}
