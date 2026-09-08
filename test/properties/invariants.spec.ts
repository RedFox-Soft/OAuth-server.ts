/*
 * The invariants, checked against generated input rather than examples.
 *
 * WHY this file exists, and why these four functions rather than any others. Each one is a place where
 * a hand-written example passed while the property did not hold, and the escaping and tag-matching pair
 * cost three rounds each to find: a fix was written for the one spelling that had been reported, the
 * suite went green, and the next spelling arrived on the next scan. An example answers "does it handle
 * this?"; a property answers "what is true of every input?", which is the question that was actually
 * being got wrong.
 *
 * These are all pure functions of their arguments, so none of them needs the harness — there is no
 * `*.config.ts` here and nothing calls `bootstrap`. Keep it that way: the moment a property needs a
 * provider it belongs in that feature's own suite instead.
 *
 * A failing property prints the shrunk counterexample and the seed. Reproduce one with
 * `fc.assert(..., { seed: <n> })` before changing anything, so the fix is measured against the input
 * that actually broke rather than a guess at it.
 */

import { describe, it, expect } from 'bun:test';
import * as crypto from 'node:crypto';
import fc from 'fast-check';

import getWWWAuthenticate from 'lib/shared/authorization_error_handler.js';
import { contentSecurityPolicyFor } from 'lib/html/csp.js';
import { esc } from 'lib/html/escape.js';
import { encodeBase32, decodeBase32 } from 'lib/totp/base32.js';

function sha256(text: string): string {
	return `'sha256-${crypto.hash('sha256', text, 'base64')}'`;
}

// Bounded so a property run stays fast; the invariants here do not depend on length.
const text = (max = 200) => fc.string({ unit: 'binary', maxLength: max });

/*
 * Text drawn from the characters that actually break the things being tested, mixed with arbitrary
 * Unicode for breadth.
 *
 * This is not a refinement, it is the difference between a property and a decoration. The first draft
 * used `unit: 'binary'` alone; reintroducing the escaping bug on purpose did not fail it, because in
 * five hundred runs the generator never produced a `"` — a full-Unicode generator has no reason to
 * favour one ASCII character, and this invariant is about exactly two of them. A property that cannot
 * reach the input it exists to reject passes for the wrong reason.
 */
const hostile = fc.oneof(
	fc.string({
		unit: fc.constantFrom('"', '\\', ',', '=', ';', "'", ' ', '\n', 'a'),
		maxLength: 40
	}),
	text(60)
);

describe('the WWW-Authenticate challenge', () => {
	/*
	 * The property the escaping exists to hold: whatever the reported text, the challenge is still the
	 * parameters it meant to send and not one more. RFC 6750 §3 limits these values to NQCHAR, so a
	 * quote and a backslash are stripped — and a backslash is the one that matters, because escaping the
	 * quote while leaving it was what let a value ending in a backslash escape the *closing* quote and
	 * turn everything after it into further auth-params.
	 *
	 * Counting quotes is the assertion rather than parsing the header: with no backslash present there
	 * is no quoted-pair, so every quote is a delimiter, and a fixed parameter count means a fixed number
	 * of them. Any escape from the quoted string shows up here as an odd count.
	 */
	it('never emits a character that could end a parameter early', () => {
		fc.assert(
			fc.property(hostile, text(60), (description, error) => {
				const header = getWWWAuthenticate('bearer', false, {
					error,
					error_description: description
				});

				// A bearer request must always be answered with a challenge; narrowing here rather than
				// asserting non-null keeps that a checked expectation instead of a silenced type.
				if (header === undefined) {
					throw new Error('a bearer request produced no challenge');
				}

				expect(header).not.toContain('\\');
				// realm, error, error_description — three parameters, six delimiters.
				expect(header.split('"').length - 1).toBe(6);
			}),
			{ numRuns: 500 }
		);
	});

	// The DPoP challenge carries `algs` as well, so the same invariant with one more parameter.
	it('holds the same invariant for a DPoP challenge', () => {
		fc.assert(
			fc.property(hostile, (description) => {
				const header = getWWWAuthenticate('dpop', true, {
					error: 'invalid_token',
					error_description: description
				});

				if (header === undefined) {
					throw new Error('a DPoP request produced no challenge');
				}

				expect(header).not.toContain('\\');
				expect(header.split('"').length - 1).toBe(8);
			}),
			{ numRuns: 500 }
		);
	});
});

describe('the derived content security policy', () => {
	/*
	 * An end tag a parser accepts must be an end tag here, whatever it is wearing. The three rounds this
	 * replaces each fixed one spelling: the case, then the whitespace, then the attributes. Generating
	 * the spelling states the rule instead of enumerating it.
	 */
	const endTag = fc.constantFrom(
		'</script>',
		'</script >',
		'</script\n>',
		'</script\t>',
		'</script foo="bar">',
		'</script\t\n bar>',
		'</SCRIPT>',
		'</ScRiPt foo="bar">',
		'</script/>'
	);

	it('authorizes every inline script it serves, however the tags are spelled', () => {
		fc.assert(
			fc.property(fc.oneof(hostile, text()), endTag, (body, close) => {
				// An empty body is deliberately not hashed, and a body carrying its own end tag ends the
				// block early — in both cases there is no single script for the policy to authorize.
				fc.pre(body.trim().length > 0);
				fc.pre(!/<\/(script|style)/i.test(body));

				const policy = contentSecurityPolicyFor(
					`<!DOCTYPE html><html><body><script>${body}${close}</body></html>`
				);

				/*
				 * Read the one directive rather than the whole policy. `style-src` deliberately keeps
				 * `'unsafe-inline'` as the pre-CSP3 fallback, so a substring check against the policy
				 * finds it there and says nothing about scripts — which is how the first draft of this
				 * property failed on its very first input.
				 */
				const scriptSrc =
					policy.split('; ').find((d) => d.startsWith('script-src ')) ?? '';

				expect(scriptSrc).toContain(sha256(body));
				// Hashing an inline script is only worth anything if the blanket permission is absent.
				expect(scriptSrc).not.toContain("'unsafe-inline'");
			}),
			{ numRuns: 300 }
		);
	});

	/*
	 * The other direction, and the reason the end-tag pattern is not simply `[^>]*`: `</scriptfoo>` is a
	 * tag named `scriptfoo`. Reading it as a close would hash the wrong span rather than none, which is
	 * the one failure here that is worse than withholding a hash.
	 */
	it('does not read a longer tag name as a closing tag', () => {
		const letters = fc.string({
			unit: fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz'),
			minLength: 1,
			maxLength: 8
		});

		fc.assert(
			fc.property(letters, (suffix) => {
				const policy = contentSecurityPolicyFor(
					`<!DOCTYPE html><html><body><script>alert(1)</script${suffix}></body></html>`
				);

				expect(policy).toContain("script-src 'none'");
			})
		);
	});
});

describe('the HTML escaper', () => {
	// The whole of its contract: nothing it returns can open a tag or close an attribute.
	it('leaves no character that could escape its position', () => {
		fc.assert(
			fc.property(hostile, (value) => {
				expect(esc(value)).not.toMatch(/[<>"]/);
			}),
			{ numRuns: 500 }
		);
	});
});

describe('base32', () => {
	const bytes = fc.uint8Array({ maxLength: 64 });

	it('round-trips any byte string', () => {
		fc.assert(
			fc.property(bytes, (value) => {
				const buffer = Buffer.from(value);
				expect(decodeBase32(encodeBase32(buffer)).equals(buffer)).toBe(true);
			})
		);
	});

	/*
	 * Case and grouping are artifacts of how a secret was displayed, never of what it is — the enrolment
	 * page prints it in fours and a person retyping it may lowercase it. Stated as a property because
	 * the decoder's tolerance is the feature, not an accident of its implementation.
	 */
	it('reads back a secret however it was retyped', () => {
		fc.assert(
			fc.property(bytes, fc.constantFrom(' ', '-', '  '), (value, gap) => {
				const buffer = Buffer.from(value);
				const encoded = encodeBase32(buffer);
				const retyped = (encoded.match(/.{1,4}/g) ?? [])
					.join(gap)
					.toLowerCase();

				expect(decodeBase32(retyped).equals(buffer)).toBe(true);
			})
		);
	});
});
