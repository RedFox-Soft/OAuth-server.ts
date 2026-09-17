import { IdentityError } from './contract.js';
import type { UpstreamIdentity } from './contract.js';

/*
 * Who signed in at GitHub, read back from GitHub.
 *
 * The only reader of its kind, and everything unusual about it is GitHub's rather than ours:
 *
 * - **The subject is the numeric account id, never the login name.** A login can be renamed and the freed
 *   name claimed by somebody else, so a login as subject means a renamed account becomes a stranger and a
 *   reused name inherits an existing account. The decision ladder treats the subject as opaque and would
 *   have linked either one happily.
 * - **An address may be absent from the profile** when the account keeps it private, in which case the
 *   addresses list is read instead and the primary *verified* one taken. An unverified address is never
 *   used: it is a self-asserted string, and the ladder's linking step would accept it as proof of somebody
 *   else's identity.
 * - **Every request carries a user-agent**, because the API rejects one that does not outright. Without it
 *   the failure is a 403 that reads like a permissions problem.
 */

const API = 'https://api.github.com';

/*
 * Identifies this server to the API. A constant rather than a version-bearing string: it is sent on a path
 * nobody troubleshoots by its user-agent, and a value that changes with a release is a value that has to
 * be threaded from somewhere.
 */
const USER_AGENT = 'oauth-server-ts';

interface GitHubAddress {
	email: string;
	primary: boolean;
	verified: boolean;
}

export async function githubProfile(token: string): Promise<UpstreamIdentity> {
	const profile = await read(token, '/user');

	const subject = profile.id;
	if (typeof subject !== 'number' && typeof subject !== 'string') {
		throw new IdentityError('upstream', 'profile carries no account id');
	}

	const claims: Record<string, unknown> = {
		sub: String(subject),
		/*
		 * Mapped onto the claim names the rest of the subsystem already reads, so the ladder and
		 * `COPIED_CLAIMS` need to know nothing about GitHub. `name` and `picture` are the two it copies that
		 * GitHub supplies.
		 */
		...(typeof profile.name === 'string' ? { name: profile.name } : {}),
		...(typeof profile.avatar_url === 'string'
			? { picture: profile.avatar_url }
			: {})
	};

	const address = await resolveAddress(token, profile);
	if (address) {
		claims.email = address;
		/*
		 * Set only for an address GitHub says it verified, and that is the load-bearing part: the linking
		 * step requires this to be `=== true` before it will attach an upstream identity to an account that
		 * already exists. An unverified GitHub address reaching here as `true` would be a takeover.
		 */
		claims.email_verified = true;
	}

	return { subject: String(subject), claims };
}

/*
 * The profile's own address if it has one, otherwise the account's primary verified address.
 *
 * Refuses for want of a *verified* address rather than for want of any address, and distinguishes the
 * permission that was never granted — three outcomes an administrator can act on differently, where one
 * "no email address" would send them looking in the wrong place.
 */
async function resolveAddress(
	token: string,
	profile: Record<string, unknown>
): Promise<string | undefined> {
	if (typeof profile.email === 'string' && profile.email.length > 0) {
		/*
		 * A public profile address is one GitHub only lets an account publish after verifying it, so it
		 * needs no second check — and asking for the list anyway would demand a permission this
		 * connection may legitimately not hold.
		 */
		return profile.email;
	}

	// Through `request` rather than `read`: this endpoint answers with a list, not an object.
	const addresses = asAddresses(
		await request(token, '/user/emails', {
			forbiddenMeans: 'missing_email_permission'
		})
	);

	const primary = addresses.find((entry) => entry.primary && entry.verified);
	if (primary) return primary.email;

	// No primary verified one, but perhaps a verified one — better than refusing somebody who has one.
	const verified = addresses.find((entry) => entry.verified);
	if (verified) return verified.email;

	if (addresses.length > 0) {
		throw new IdentityError('rejected', 'no_verified_email');
	}
	return undefined;
}

async function read(
	token: string,
	path: string,
	options: { forbiddenMeans?: string } = {}
): Promise<Record<string, unknown>> {
	const body = await request(token, path, options);
	if (typeof body !== 'object' || body === null || Array.isArray(body)) {
		throw new IdentityError('upstream', `${path} is not an object`);
	}
	return body as Record<string, unknown>;
}

async function request(
	token: string,
	path: string,
	options: { forbiddenMeans?: string }
): Promise<unknown> {
	let response: Response;
	try {
		response = await fetch(`${API}${path}`, {
			headers: {
				authorization: `Bearer ${token}`,
				accept: 'application/vnd.github+json',
				'user-agent': USER_AGENT
			}
		});
	} catch (err) {
		throw new IdentityError(
			'upstream',
			err instanceof Error ? err.message : 'unreachable'
		);
	}

	/*
	 * A refusal of *this read* is not the same as the other side being broken, and where the caller has
	 * said what it means, it is reported as that: a permission the administrator did not ask for, which is
	 * a configuration mistake with a specific fix.
	 */
	if (
		(response.status === 403 || response.status === 404) &&
		options.forbiddenMeans
	) {
		throw new IdentityError('rejected', options.forbiddenMeans);
	}
	if (!response.ok) {
		throw new IdentityError('upstream', `status ${response.status}`);
	}

	try {
		return await response.json();
	} catch {
		throw new IdentityError('upstream', `${path} is not JSON`);
	}
}

/* Narrowed from `unknown`, entry by entry, the way `discovery.ts` narrows a remote document. */
function asAddresses(body: unknown): GitHubAddress[] {
	if (!Array.isArray(body)) return [];
	const addresses: GitHubAddress[] = [];
	for (const entry of body) {
		if (typeof entry !== 'object' || entry === null) continue;
		const row = entry as Record<string, unknown>;
		if (typeof row.email !== 'string') continue;
		addresses.push({
			email: row.email,
			primary: row.primary === true,
			verified: row.verified === true
		});
	}
	return addresses;
}
