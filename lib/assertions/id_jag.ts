import { getUserStore } from '../adapters/index.js';
import { pairwiseIdentifier } from '../addon/index.js';
import { ApplicationConfig } from '../configs/application.js';
import { issuerFor, type RequestBucket } from '../configs/issuer.js';
import { ID_JAG_JWT_TYPE } from '../consts/assertion_grants.js';
import epochTime from '../helpers/epoch_time.js';
import * as JWT from '../helpers/jwt.js';
import nanoid from '../helpers/nanoid.js';
import type { Account } from '../helpers/oidc_context.js';
import { keysFor } from '../keys/issuer_keys.js';
import { tryFindClient } from '../models/client.js';
import type { Subject } from './subject_token.js';
import type { Vouching } from './policy.js';

/*
 * The Identity Assertion JWT Authorization Grant a project issues (ID-JAG §3, §4.3.4; specs/108), signed with
 * the project's own keys so the outside server verifies it against the key set the project publishes.
 */

/*
 * The identifier the outside server already knows the person by (ID-JAG §5): what an ID token issued to the
 * application it signs people in with would carry — pairwise where that application is — or, with none named,
 * the account itself.
 */
async function subjectThere(
	connection: Vouching['connection'],
	accountId: string
): Promise<string> {
	if (!connection.signInClientId) return accountId;
	const signIn = await tryFindClient(connection.signInClientId);
	return signIn?.subjectType === 'pairwise'
		? pairwiseIdentifier(accountId, signIn)
		: accountId;
}

/*
 * RS256 where the project signs with it: the outside server is not a client of this project and registered no
 * algorithm, so the default every verifier supports applies (constitution, Principle VI). A project holding no
 * RSA key signs with what it has; its published set says which.
 */
function algorithmOf(available: readonly string[] | undefined): string {
	if (!available?.length || available.includes('RS256')) return 'RS256';
	return available[0];
}

export async function issueIdJag(input: {
	bucket: RequestBucket;
	vouching: Vouching;
	account: Account;
	subject: Subject;
	jkt: string | undefined;
}): Promise<{ value: string; expiresIn: number }> {
	const { bucket, vouching, account, subject, jkt } = input;
	const { connection } = vouching;
	const expiresIn = ApplicationConfig['tokenExchange.idJagLifetime'];

	/*
	 * Only a verified address, and only where the connection includes it (RFC 8693 §6 data minimisation). Sent
	 * with `email_verified: true`, which is what lets a receiving server that links by email trust it.
	 */
	let email: string | undefined;
	if (connection.includeEmail) {
		const user = await getUserStore(account.bucketId).find(account.accountId);
		if (user?.verified && user.email) email = user.email;
	}

	const now = epochTime();
	const payload: Record<string, unknown> = {
		jti: nanoid(),
		sub: await subjectThere(connection, account.accountId),
		client_id: vouching.clientIdThere,
		iat: now,
		/* ID-JAG §4.3.3: the granted resource and scope MUST be in the ID-JAG. */
		resource:
			vouching.resources.length === 1
				? vouching.resources[0]
				: vouching.resources,
		...(vouching.scopes.length ? { scope: vouching.scopes.join(' ') } : {}),
		...(subject.auth_time === undefined
			? {}
			: { auth_time: subject.auth_time }),
		...(subject.acr === undefined ? {} : { acr: subject.acr }),
		...(subject.amr === undefined ? {} : { amr: subject.amr }),
		...(email ? { email, email_verified: true } : {}),
		/* ID-JAG §9.8.1.1: a valid DPoP proof on the exchange binds the grant to its key. */
		...(jkt ? { cnf: { jkt } } : {})
	};

	const keys = await keysFor(bucket);
	const alg = algorithmOf(keys.signingAlgorithms);
	const jwk = keys.signing.selectForSign({ alg, use: 'sig' }).at(0);
	if (!jwk) {
		throw new Error(`the issuing project holds no ${alg} signing key`);
	}
	const value = await JWT.sign(payload, keys.signing.getKeyObject(jwk), alg, {
		typ: ID_JAG_JWT_TYPE,
		fields: { kid: jwk.kid },
		/* CHAIN §2.3.3 recommends one audience, so the grant cannot be carried on to a third server. */
		audience: connection.issuer,
		issuer: issuerFor(bucket),
		expiresIn
	});
	return { value, expiresIn };
}
