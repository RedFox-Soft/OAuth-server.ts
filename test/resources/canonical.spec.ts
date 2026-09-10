import { describe, it, expect } from 'bun:test';

import {
	canonicalizeResourceIdentifier,
	resourceIdentifierMatches
} from 'lib/resources/canonical.ts';

/*
 * Pure-function coverage for the canonical form and the matching rule. The behaviour these two
 * functions produce at the token endpoint is covered separately in `issuance.spec.ts` — Principle V
 * permits unit tests but never as a substitute for the integration path.
 */

function canonical(input: string): string {
	const result = canonicalizeResourceIdentifier(input);
	if (!result.ok) throw new Error(`expected ok, got ${result.reason}`);
	return result.identifier;
}

/**
 * @proves One canonicalization rule decides whether two spellings are one audience, tolerating
 * what clients are told to expect and refusing a near miss.
 */
describe('canonical resource identifier', () => {
	it('lower-cases the scheme and the host', () => {
		expect(canonical('HTTPS://MCP.Example.COM/mcp')).toBe(
			'https://mcp.example.com/mcp'
		);
	});

	it('leaves the path case alone, because a path is case-sensitive', () => {
		expect(canonical('https://mcp.example.com/MCP/Tools')).toBe(
			'https://mcp.example.com/MCP/Tools'
		);
	});

	it('strips a trailing slash, including the one URL parsing invents for a bare origin', () => {
		expect(canonical('https://mcp.example.com')).toBe(
			'https://mcp.example.com'
		);
		expect(canonical('https://mcp.example.com/')).toBe(
			'https://mcp.example.com'
		);
		expect(canonical('https://mcp.example.com/mcp/')).toBe(
			'https://mcp.example.com/mcp'
		);
	});

	it('keeps a non-default port', () => {
		expect(canonical('https://mcp.example.com:8443/mcp')).toBe(
			'https://mcp.example.com:8443/mcp'
		);
	});

	it('keeps a query string, which RFC 8707 permits', () => {
		expect(canonical('https://mcp.example.com/mcp?tenant=a')).toBe(
			'https://mcp.example.com/mcp?tenant=a'
		);
	});

	it('preserves a trailing slash the owner declares significant', () => {
		const result = canonicalizeResourceIdentifier(
			'https://mcp.example.com/mcp/',
			{ trailingSlashSignificant: true }
		);
		expect(result.ok).toBe(true);
		if (result.ok)
			expect(result.identifier).toBe('https://mcp.example.com/mcp/');
	});

	it('refuses an identifier carrying a fragment', () => {
		const result = canonicalizeResourceIdentifier(
			'https://mcp.example.com/mcp#tools'
		);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.reason).toBe('fragment');
	});

	it('refuses a value that is not an absolute URI', () => {
		for (const input of ['mcp.example.com', '/mcp', 'not a url', '']) {
			const result = canonicalizeResourceIdentifier(input);
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.reason).toBe('not_absolute');
		}
	});
});

describe('matching a requested resource against a declared one', () => {
	const declared = 'https://mcp.example.com/mcp';

	it('matches an exact request', () => {
		expect(resourceIdentifierMatches(declared, declared)).toBe(true);
	});

	it('tolerates an upper-case scheme or host, which clients are told to expect', () => {
		expect(
			resourceIdentifierMatches(declared, 'HTTPS://mcp.example.com/mcp')
		).toBe(true);
		expect(
			resourceIdentifierMatches(declared, 'https://MCP.EXAMPLE.COM/mcp')
		).toBe(true);
	});

	it('tolerates a trailing slash, because both sides canonicalize the same way', () => {
		expect(resourceIdentifierMatches(declared, `${declared}/`)).toBe(true);
	});

	/*
	 * The cases that matter. Prefix and subpath matching would let a token minted for one resource be
	 * obtained by naming another, which is the confused-deputy hole resource indicators exist to close.
	 */
	it('refuses a near miss', () => {
		for (const requested of [
			'https://mcp.example.com',
			'https://mcp.example.com/mcp/tools',
			'https://mcp.example.com/mcpx',
			'http://mcp.example.com/mcp',
			'https://mcp.example.com:8443/mcp',
			'https://evil.example.com/mcp',
			'https://mcp.example.com/mcp?tenant=a'
		]) {
			expect(resourceIdentifierMatches(declared, requested)).toBe(false);
		}
	});

	/*
	 * The distinction a significant trailing slash exists to make. Without the options argument
	 * reaching both sides, the slash is stripped from the declaration too and the two siblings collapse
	 * into one audience — so a request for the slash-free resource would take the other's token.
	 */
	it('keeps the two siblings apart when the owner declared the slash significant', () => {
		const withSlash = 'https://mcp.example.com/mcp/';
		const significant = { trailingSlashSignificant: true };

		expect(resourceIdentifierMatches(withSlash, withSlash, significant)).toBe(
			true
		);
		expect(
			resourceIdentifierMatches(
				withSlash,
				'https://mcp.example.com/mcp',
				significant
			)
		).toBe(false);
	});

	it('refuses a request that is not a canonicalizable identifier at all', () => {
		expect(resourceIdentifierMatches(declared, 'mcp.example.com')).toBe(false);
		expect(resourceIdentifierMatches(declared, `${declared}#tools`)).toBe(
			false
		);
	});
});
