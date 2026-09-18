/*
 * Hostnames: the one form they are compared in, and the one place a submitted one is judged.
 *
 * Import-free on purpose, the same reason `reserved_names.ts` and `storage_inventory.ts` are: this is
 * read both by the admin surface that validates a name and by the router that resolves one, and
 * neither may pull the other's dependency graph in through a shared constant. It is also reached from
 * `lib/configs/issuer.ts`, which the models import to mint tokens — anything that module touches must
 * not reach back into the request pipeline.
 *
 * That is why the canonical host is a *parameter* here rather than something this module reads. It
 * lives in the environment, and importing it would make this module carry the environment into the
 * model graph. `canonicalHostOf(ISSUER)` at the call site keeps both functions pure.
 */

/* RFC 1035 §2.3.4: 253 characters for a fully qualified name once the trailing dot is removed. */
export const HOST_MAX_LENGTH = 253;
const LABEL_MAX_LENGTH = 63;

const LABEL = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;

/*
 * The form two hostnames must both be in before they are compared, looked up, or stored.
 *
 * Case folded, trailing dot removed, port removed. Without this, uniqueness is not uniqueness:
 * `ACME.example.com.` and `acme.example.com:443` are the same name to a browser and three different
 * strings to a datastore, so a bucket could be created twice and a request could resolve to neither.
 *
 * Returns `null` for anything that cannot be a hostname at all, which is how the router refuses a
 * request whose Host header is junk. It does NOT judge whether the name is *acceptable* for a bucket
 * — that is `validateBucketHost`, and the two differ deliberately: a deployment may legitimately run
 * at a single-label host like `localhost` while a bucket may not be given one.
 */
export function normaliseHost(value: string | undefined): string | null {
	if (!value) return null;

	let host = value.trim().toLowerCase();
	if (!host) return null;

	/*
	 * An IPv6 literal is bracketed, and a bracket is the only character that makes the port strip below
	 * ambiguous. Refused rather than parsed: a bucket cannot be addressed by an IP in any case, because
	 * the credential identity a passkey binds to must be a domain.
	 */
	if (host.includes('[') || host.includes(']')) return null;

	const portAt = host.lastIndexOf(':');
	if (portAt !== -1) {
		if (!/^\d+$/.test(host.slice(portAt + 1))) return null;
		host = host.slice(0, portAt);
	}

	// A fully qualified name may carry a trailing dot; the same name without one is the same name.
	if (host.endsWith('.')) host = host.slice(0, -1);

	if (!host || host.length > HOST_MAX_LENGTH) return null;
	if (!host.split('.').every(isLabel)) return null;

	return host;
}

function isLabel(label: string): boolean {
	return (
		label.length > 0 && label.length <= LABEL_MAX_LENGTH && LABEL.test(label)
	);
}

/*
 * Why a submitted hostname is refused, or the normalised form if it is not.
 *
 * Separate from `normaliseHost` because the router and the operator are asking different questions.
 * The router asks "can this string address anything", and answers a request. This asks "may a bucket
 * be given this name", and answers a person — so it says what was wrong, which is the difference
 * between a name corrected in one attempt and a name stored that fails later at request time.
 */
export type HostJudgement =
	{ ok: true; host: string } | { ok: false; reason: string };

export function validateBucketHost(value: string): HostJudgement {
	const raw = value.trim();
	if (!raw) return { ok: false, reason: 'a hostname is required' };

	if (raw.includes('://')) {
		return {
			ok: false,
			reason: 'a hostname, not a URL — remove the scheme'
		};
	}
	if (raw.includes('/')) {
		return { ok: false, reason: 'a hostname, not a URL — remove the path' };
	}
	if (raw.includes('*')) {
		return {
			ok: false,
			reason: 'a single hostname — wildcards are not accepted'
		};
	}
	if (raw.includes(':')) {
		return {
			ok: false,
			reason: 'a hostname, not an address — remove the port'
		};
	}
	if (/\s/.test(raw)) {
		return { ok: false, reason: 'a hostname cannot contain whitespace' };
	}

	const host = normaliseHost(raw);
	if (!host) return { ok: false, reason: 'not a valid hostname' };

	/*
	 * At least two labels. A single-label name resolves only inside one network's search domain, so a
	 * bucket given one is reachable from the operator's desk and nowhere else — a failure that looks
	 * like the feature is broken rather than like the name is wrong. The canonical host is deliberately
	 * not held to this: a deployment may run at `localhost` in development, and it is not a bucket.
	 */
	if (!host.includes('.')) {
		return {
			ok: false,
			reason: 'a fully qualified hostname, with at least one dot'
		};
	}

	return { ok: true, host };
}

/*
 * The host a deployment answers at, from its canonical URL.
 *
 * A parameter rather than a read of the environment, so this module stays import-free — see the note
 * at the top. Returns `null` for a URL that cannot be parsed, which a caller treats as a deployment
 * too misconfigured to resolve tenants for.
 */
/*
 * The host a request is addressed to — the one place that answer is produced, because it selects the
 * tenant and two places would eventually disagree about which.
 *
 * `Host` first, and **never `X-Forwarded-Host`**: that header is set by whatever spoke to the proxy, so
 * a proxy that does not strip an inbound copy passes an attacker-supplied value straight through — and
 * here that value would choose the population a request is answered from. `Host` is what the client
 * actually connected to and what the proxy's own routing already matched.
 *
 * The URL is the fallback rather than an alternative source. A `Request` built in process carries no
 * `Host` header at all — the header is added by the transport, not the constructor — so without this
 * every in-process call would resolve to no host whatsoever. On a served request the two agree by
 * construction, because the runtime builds `request.url` from the very header read above.
 */
export function hostOfRequest(request: {
	headers: { get(name: string): string | null };
	url: string;
}): string | null {
	const header = normaliseHost(request.headers.get('host') ?? undefined);
	if (header) return header;
	try {
		return normaliseHost(new URL(request.url).hostname);
	} catch {
		return null;
	}
}

export function canonicalHostOf(issuer: string): string | null {
	try {
		return normaliseHost(new URL(issuer).hostname);
	} catch {
		return null;
	}
}
