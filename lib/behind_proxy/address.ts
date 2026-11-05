/*
 * The address of an app behind a proxy, and the one comparison the forwarded host is ever used in (specs/122 R2).
 *
 * The forwarded host never selects a project or an app — the check's own address does that. It is only compared
 * with the address of the app already chosen, and a mismatch is a refusal. `normaliseHost`
 * (lib/consts/request_host.ts) is not used here because it drops every port, and a port other than the default
 * makes a different origin.
 *
 * Import-free beyond the URL global, so the console's create form can say what it will store.
 */

export type AddressProblem =
	'not_a_url' | 'not_https' | 'userinfo' | 'ip_literal' | 'no_host';

export type CanonicalAddress =
	| {
			address: string;
			/* A path, query or fragment was given and dropped; the form says so. */
			dropped: boolean;
	  }
	| { problem: AddressProblem };

const DEFAULT_PORT = '443';

/*
 * `https://host[:port]`: lower-case host, no default port, nothing after the authority. A browser's address bar is
 * a fair thing to paste, so a path, query and fragment are dropped rather than refused.
 */
export function canonicalAddress(input: string): CanonicalAddress {
	const trimmed = input.trim();
	let url: URL;
	try {
		url = new URL(trimmed);
	} catch {
		return { problem: 'not_a_url' };
	}
	if (url.protocol !== 'https:') return { problem: 'not_https' };
	if (url.username || url.password || authorityOf(trimmed).includes('@')) {
		return { problem: 'userinfo' };
	}
	const host = url.hostname.toLowerCase();
	if (!host) return { problem: 'no_host' };
	if (isIpLiteral(host)) return { problem: 'ip_literal' };
	const port = url.port && url.port !== DEFAULT_PORT ? `:${url.port}` : '';
	return {
		address: `https://${host}${port}`,
		dropped: url.pathname !== '/' || url.search !== '' || url.hash !== ''
	};
}

function authorityOf(input: string): string {
	const afterScheme = input.slice(input.indexOf('//') + 2);
	const end = afterScheme.search(/[/?#]/);
	return end === -1 ? afterScheme : afterScheme.slice(0, end);
}

/* The URL parser has already rewritten every IPv4 spelling (`0x7f.1`, `2130706433`) to dotted decimal. */
function isIpLiteral(host: string): boolean {
	return host.startsWith('[') || /^\d+\.\d+\.\d+\.\d+$/.test(host);
}

/*
 * Whether the host a proxy reported is the app's address: case-insensitive, `:443` the same as no port, any other
 * port a different host. Anything that is not a single plain host (a list, an IPv6 literal, stray characters) is
 * not the address.
 */
export function sameHost(forwardedHost: string, address: string): boolean {
	const reported = splitHost(forwardedHost.trim().toLowerCase());
	if (!reported) return false;
	let expected: URL;
	try {
		expected = new URL(address);
	} catch {
		return false;
	}
	return (
		reported.host === expected.hostname.toLowerCase() &&
		reported.port === (expected.port || DEFAULT_PORT)
	);
}

function splitHost(value: string): { host: string; port: string } | null {
	const match = /^([a-z0-9.-]+)(?::(\d{1,5}))?$/.exec(value);
	if (!match) return null;
	const port = value.includes(':') ? String(Number(match[2])) : DEFAULT_PORT;
	return { host: match[1], port };
}
