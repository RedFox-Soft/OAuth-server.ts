import type { TokenParams } from '../actions/token.js';
import { adapter } from '../adapters/index.js';
import type { UserBucket } from '../adapters/types.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { belongsToProject } from '../admin/project_applications.js';
import {
	issuingBucket,
	servingBucketIdOf
} from '../admin/auth/bucketAddress.js';
import { issuerFor } from '../configs/issuer.js';
import { ACCESS_TOKEN_TYPE } from '../consts/assertion_grants.js';
import { grantsIn } from '../end_users/sessions.js';
import { InvalidGrant, InvalidRequest } from '../helpers/errors.js';
import * as JWT from '../helpers/jwt.js';
import type { OIDCContext } from '../helpers/oidc_context.js';
import type { DPoPProof } from '../helpers/validate_dpop.js';
import { keysFor } from '../keys/issuer_keys.js';
import { MCP_RESOURCE } from '../mcp/consts.js';
import { AccessToken } from '../models/access_token.js';
import type { Grant } from '../models/grant.js';
import { findDeclaredResource } from '../resources/registry.js';
import { namespaceOf } from '../resources/namespace.js';
import {
	codeRequiredAndMissing,
	REQUIRE_CODE_DESCRIPTION
} from '../client_policy/require_code.js';

/*
 * The person an upstream token exchange acts for, read off its subject token (specs/118 R2, R3): an access token
 * this project issued, presented by the agent it was issued to or by the application an administrator linked to the
 * API it was issued for. Every failure is a plain `invalid_grant`: nothing here is the person's account state, and
 * the answer must say nothing about it.
 */

export interface ExchangeSubject {
	accountId: string;
	/* The agent the person signed in to: whose use consent is read. */
	agentClientId: string;
	/* The person's live grants to that agent; the use consent is read from them, and none means no access. */
	grants: Grant[];
}

interface Presented {
	accountId: string;
	agentClientId: string;
	audience?: string;
	jkt?: string;
	/* An opaque token names its grant; a JWT does not. */
	grantId?: string;
	/* The sign-in the token came from, when it says (specs/127). */
	acr?: string;
}

function refused(detail: string): InvalidGrant {
	return new InvalidGrant(detail);
}

/* An opaque token is a stored record: an expired, revoked or session-ended one is not there to find. */
async function fromRecord(
	value: string,
	bucket: UserBucket
): Promise<Presented> {
	const token = await AccessToken.tryFind(value);
	if (!token) throw refused('subject_token');
	const { accountId, clientId, grantId, jkt, bucketId } = token.payload;
	if (!accountId || !clientId || !grantId) throw refused('no person');
	if (
		(await servingBucketIdOf(bucketId)) !==
		(await servingBucketIdOf(bucket._id))
	) {
		throw refused('another project');
	}
	const audience: unknown = token.payload.aud;
	const { acr } = token.payload;
	return {
		accountId,
		agentClientId: clientId,
		grantId,
		...(typeof acr === 'string' ? { acr } : {}),
		...(typeof audience === 'string' ? { audience } : {}),
		...(jkt ? { jkt } : {})
	};
}

/*
 * A JWT access token (an API declared with `tokenFormat: 'jwt'`, the default for MCP servers) is not stored, so it
 * is checked as its API checks it: this project's keys and issuer, its lifetime, the RFC 9068 type. Revocation
 * reaches it through the grant: with the application's access removed there is no grant, and it is refused.
 */
async function fromJwt(value: string, bucket: UserBucket): Promise<Presented> {
	const issuedBy = await issuingBucket(bucket._id);
	let verified;
	try {
		verified = await JWT.verify(value, (await keysFor(issuedBy)).verification, {
			issuer: issuerFor(issuedBy),
			subject: true
		});
	} catch {
		throw refused('subject_token');
	}
	const { payload, header } = verified;
	const typ =
		typeof header.typ === 'string' ? header.typ.toLowerCase() : undefined;
	if (typ !== 'at+jwt' && typ !== 'application/at+jwt') {
		throw refused('type');
	}
	const clientId = payload.client_id;
	const sub = payload.sub;
	if (typeof clientId !== 'string' || typeof sub !== 'string') {
		throw refused('no person');
	}
	const agent = await adapter('Client').find(clientId);
	/* A pairwise `sub` is a one-way digest: nothing maps it back to the person (as specs/108 found for ID tokens). */
	if (!agent || agent.subjectType === 'pairwise' || sub === clientId) {
		throw refused('no person');
	}
	const cnf: unknown = payload.cnf;
	const jkt =
		typeof cnf === 'object' && cnf !== null && 'jkt' in cnf
			? cnf.jkt
			: undefined;
	const aud: unknown = payload.aud;
	const acr: unknown = payload.acr;
	return {
		accountId: sub,
		agentClientId: clientId,
		...(typeof acr === 'string' ? { acr } : {}),
		...(typeof aud === 'string' ? { audience: aud } : {}),
		...(typeof jkt === 'string' ? { jkt } : {})
	};
}

export async function exchangeSubject(
	oidc: OIDCContext<TokenParams>,
	bucket: UserBucket,
	dPoP: DPoPProof
): Promise<ExchangeSubject> {
	const { client, params } = oidc;
	if (params.subject_token_type !== ACCESS_TOKEN_TYPE) {
		throw new InvalidRequest(
			`subject_token_type must be ${ACCESS_TOKEN_TYPE} to obtain an upstream access token`
		);
	}
	if (typeof params.subject_token !== 'string' || !params.subject_token) {
		throw new InvalidRequest('subject_token is required');
	}

	const presented =
		params.subject_token.split('.').length === 3
			? await fromJwt(params.subject_token, bucket)
			: await fromRecord(params.subject_token, bucket);
	if (presented.audience === MCP_RESOURCE) {
		throw refused('administrative audience');
	}
	/*
	 * An application that requires a code (specs/127) reaches a person's other services only on the strength of a
	 * sign-in that gave one — the agent whose token this is, and the application exchanging it, alike.
	 */
	const agent =
		presented.agentClientId === client.clientId
			? client
			: await adapter('Client').find(presented.agentClientId);
	if (
		codeRequiredAndMissing(client, presented.acr) ||
		codeRequiredAndMissing(agent ?? undefined, presented.acr)
	) {
		throw refused(REQUIRE_CODE_DESCRIPTION);
	}

	if (
		bucket._id === ADMIN_BUCKET_ID ||
		!(await belongsToProject(bucket, presented.agentClientId))
	) {
		throw refused('agent');
	}

	if (client.clientId !== presented.agentClientId) {
		const resource =
			presented.audience === undefined
				? undefined
				: await findDeclaredResource(
						presented.audience,
						namespaceOf(oidc.bucket)
					);
		if (
			!resource ||
			resource.bucketId !== bucket._id ||
			resource.exchangedBy !== client.clientId
		) {
			throw refused('exchanging application');
		}
	} else if (presented.jkt) {
		/* The token's own holder presents it here as anywhere: with a proof of its key (specs/118 FR-008). */
		if (!dPoP || dPoP.thumbprint !== presented.jkt) {
			throw refused('proof of possession');
		}
	}

	const grants = (await grantsIn(bucket._id, presented.accountId)).filter(
		(grant) =>
			grant.payload.clientId === presented.agentClientId &&
			(presented.grantId === undefined || grant.jti === presented.grantId)
	);
	if (grants.length === 0) throw refused('grant');
	return {
		accountId: presented.accountId,
		agentClientId: presented.agentClientId,
		grants
	};
}
