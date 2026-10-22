import sectorValidate from '../../helpers/sector_validate.ts';
import { adapter } from '../../adapters/index.js';
import { type Client, type ClientRecord } from './types.ts';
import { validateClient } from './validate.ts';
import { toStored } from './projection.ts';
import { rootKeys } from '../../keys/issuer_keys.js';
import { InvalidClientMetadata } from '../../helpers/errors.ts';
import { LOOPBACKS } from '../../consts/client_attributes.js';
import { isAccountPageClient } from '../../account_page/client.js';

/*
 * The one way a client is written, whichever surface writes it — dynamic registration, registration
 * management, the console, the agent. The sector identifier document is checked here and only here:
 * OIDC Core §8.1 places the check at registration, and a stored client is resolved without it, so a
 * client stays usable while its sector host is unreachable. The surfaces used to disagree — the
 * console stored without the check, which then ran on the next resolution instead, as a failure for
 * whoever used the client next.
 *
 * `store: false` is for a client that is never stored: one described by a metadata document, whose
 * resolution is its registration.
 */
/*
 * The two addresses this server fetches from or posts to on a client's behalf, required to be https when they are
 * written (specs/103). The egress guard resolves a name and refuses private addresses, but the request then resolves
 * it again; a name that answers differently the second time reaches the private network over plain http, while over
 * https the certificate check fails. Judged only when the value is new or changed, against the stored record, so a
 * client stored with an http address keeps resolving and can still have its other fields edited.
 *
 * A metadata document's addresses are held to it too, every time it is resolved: it has no stored record, so every
 * value is new, and draft -02 §8.6 makes the special-use-address rule a MUST for "any URLs contained within" it.
 */
const FETCHED = [
	['jwksUri', 'jwks_uri'],
	['backchannelLogoutUri', 'backchannel_logout_uri']
] as const;

async function assertFetchedOverTls(
	client: Client,
	stored: ClientRecord | undefined
): Promise<void> {
	for (const [field, wire] of FETCHED) {
		const value = client[field];
		if (typeof value !== 'string' || value.startsWith('https://')) continue;
		if (stored?.[wire] === value) continue;
		throw new InvalidClientMetadata(`${wire} must use https`);
	}
}

/*
 * MCP 2026-07-28: "All redirect URIs MUST be either localhost or use HTTPS". Plain http serves a program on the end
 * user's own machine (RFC 8252 §7.3); anywhere else it hands the authorization code, or the end of a sign-out, to
 * whoever is on the network path. So plain http is accepted on a loopback host only, whatever the application type.
 *
 * Judged on the write, and only for an address the write adds, compared with the stored record — not by the schema,
 * which validates every client each time it is resolved and would then strand every client stored before the rule
 * with `invalid_client` at its next sign-in. A document client has no record, so every address of it is new.
 *
 * The description leads with the attribute's name because `InvalidClientMetadata` gives a `redirectUris` refusal
 * the code RFC 7591 defines for it, `invalid_redirect_uri`, and every other one `invalid_client_metadata`.
 */
const REDIRECTED = [
	['redirectUris', 'redirectUris'],
	['postLogoutRedirectUris', 'post_logout_redirect_uris']
] as const;

function assertPlainHttpOnLoopback(
	client: Client,
	stored: ClientRecord | undefined
): void {
	for (const [field, storedAs] of REDIRECTED) {
		const kept = stored?.[storedAs];
		const before = new Set(Array.isArray(kept) ? kept : []);
		for (const uri of client[field] ?? []) {
			if (before.has(uri)) continue;
			const parsed = URL.parse(uri);
			if (parsed?.protocol !== 'http:' || LOOPBACKS.has(parsed.hostname)) {
				continue;
			}
			throw new InvalidClientMetadata(
				`${field} ${uri} must use https unless its host is localhost, 127.0.0.1 or [::1]`
			);
		}
	}
}

export async function registerClient(
	record: ClientRecord,
	{ store }: { store: boolean }
): Promise<Client> {
	/*
	 * Validation checks a client's signing algorithms against the ones the root issuer can sign with,
	 * read synchronously from the mirror its key set keeps (lib/keys/issuer_keys.ts). Reading the set
	 * here — cached, so almost always free — is what keeps that mirror current on an instance where another
	 * instance promoted a key, rather than only once something here happens to sign.
	 */
	await rootKeys();
	const client = validateClient(record);

	/*
	 * The prefix of a bucket's connected-applications page client (specs/095). No generated id can carry it,
	 * but a deployment may supply its own id factory, and a stored record would shadow the page's client.
	 */
	if (store && isAccountPageClient(client.clientId)) {
		throw new InvalidClientMetadata('client_id is reserved');
	}

	if (client.sectorIdentifierUri !== undefined) {
		await sectorValidate(client);
	}

	/* A document client has no record by construction (validate.ts reads the adapter first), so there is none to read. */
	const stored = store
		? await adapter('Client').find(client.clientId)
		: undefined;
	await assertFetchedOverTls(client, stored);
	assertPlainHttpOnLoopback(client, stored);

	if (store) {
		await adapter('Client').upsert(client.clientId, toStored(client));
	}
	return client;
}
