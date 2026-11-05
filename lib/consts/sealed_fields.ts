/*
 * Every stored secret the server must read back, which is therefore sealed with the instance keyring rather
 * than kept in plaintext (specs/116), and every secret-looking field deliberately left as it is, with the
 * reason. Import-free, like the storage inventory, because the decorators, the encryption pass and the
 * completeness guards all read it and none of them may pull a store in with it.
 *
 * A leaf is sealed, never the object around it: `totp` stays an object and `jwk` keeps its shape, so the
 * queries that test them and the schemas that check them do not change. The binding names the record and the
 * field, and goes into the sealed value's authenticated header, so a value copied anywhere else does not open.
 */

export type SealKind =
	| 'providerSecret'
	| 'providerSigningKey'
	| 'clientSecret'
	| 'smtpPassword'
	| 'privateKey'
	| 'totpSecret'
	| 'totpPending'
	| 'dpopNonceSecret'
	| 'errorOriginSalt'
	| 'connectedServiceSecret'
	| 'connectedAccountToken'
	| 'signInTokenInTransit';

export interface SealedField {
	kind: SealKind;
	/* The storage area, as lib/consts/storage_inventory.ts names it (`user_*` for every bucket's users). */
	area: string;
	/* Where the leaf sits in a record, for people; the decorators and the adapters know the shape. */
	path: string;
	/* What a console reader is told the value belongs to. */
	owner: string;
}

export const SEALED_FIELDS: readonly SealedField[] = [
	{
		kind: 'providerSecret',
		area: 'userBuckets',
		path: 'federation[].clientSecret',
		owner: 'a sign-in provider of a project'
	},
	{
		kind: 'providerSigningKey',
		area: 'userBuckets',
		path: 'federation[].signingKey',
		owner: 'a sign-in provider of a project'
	},
	{
		kind: 'clientSecret',
		area: 'Client',
		path: 'clientSecret',
		owner: 'an application'
	},
	{
		kind: 'smtpPassword',
		area: 'serviceConfig',
		path: 'smtpSettings.password',
		owner: 'the instance'
	},
	{
		kind: 'privateKey',
		area: 'bucketKeys',
		path: 'jwk.{d,p,q,dp,dq,qi}',
		owner: 'a signing key of a project or of the instance'
	},
	{
		kind: 'totpSecret',
		area: 'user_*',
		path: 'totp.secret',
		owner: 'a person'
	},
	{
		kind: 'totpPending',
		area: 'TotpEnrollment',
		path: 'secret',
		owner: 'a person enrolling an authenticator'
	},
	{
		kind: 'dpopNonceSecret',
		area: 'serviceConfig',
		path: 'dpopNonceSecret.secret',
		owner: 'the instance'
	},
	{
		kind: 'errorOriginSalt',
		area: 'serviceConfig',
		path: 'errorOriginSalt.secret',
		owner: 'the instance'
	},
	{
		kind: 'connectedServiceSecret',
		area: 'userBuckets',
		path: 'connectedServices[].clientSecret',
		owner: 'a connected service of a project'
	},
	/*
	 * Never plaintext, unlike every row above: the connected-account store refuses a write while no keyring is in
	 * use (specs/117 R3), so the encryption pass only ever moves these to a new write key.
	 */
	{
		kind: 'connectedAccountToken',
		area: 'connectedAccounts',
		path: '{refreshToken,accessToken}',
		owner: "a person's account at a connected service"
	},
	/*
	 * A linked sign-in's tokens between the provider's answer and the end of the sign-in (specs/120 R7): five
	 * minutes at most, and, like the account tokens, never written while no keyring is in use.
	 */
	{
		kind: 'signInTokenInTransit',
		area: 'FederationState',
		path: 'kept.tokens',
		owner: 'a sign-in in progress'
	}
];

/* The private members of a JWK, the only part of a stored key that is sealed: the public half is published. */
export const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi'] as const;
export type PrivateJwkMember = (typeof PRIVATE_JWK_MEMBERS)[number];

/*
 * Fields whose name looks like a secret and which are stored as they are, on purpose. The completeness guard
 * (test/sealing/inventory_sweep.spec.ts) fails for a secret-looking field that is in neither list.
 */
export const DECLARED_PLAINTEXT: readonly { field: string; reason: string }[] =
	[
		{
			field: 'pairwiseSalt',
			reason:
				'encrypting it gains almost nothing against a database copy, which already holds every account, and a lost key would change the sub every relying party knows a person by, for ever (specs/116 Clarifications)'
		},
		{
			field: 'clientSecretDigest',
			reason: 'a digest: already irreversible'
		},
		{
			field: 'previousClientSecretDigest',
			reason: 'a digest: already irreversible'
		},
		{
			field: 'secretDigest',
			reason: 'a digest: already irreversible'
		},
		{
			field: 'password',
			reason:
				'the password of a person is stored as a hash, already irreversible; the SMTP password is sealed separately'
		},
		{
			field: 'clientSecretExpiresAt',
			reason: 'a date, not a secret'
		},
		{
			field: 'previousSecret',
			reason:
				'a provisioning connection keeps only the digest of its previous secret: already irreversible'
		},
		{
			field: 'passwordSet',
			reason: 'whether a person has a password at all: a flag, not a secret'
		},
		{
			field: 'passwordLogin',
			reason:
				'whether a project offers password sign-in: a setting, not a secret'
		},
		/*
		 * Sign-in in front of an app behind a proxy (specs/122 R6). A session there needs no entry: its record id
		 * is the SHA-256 of the cookie value, a digest and not a secret, and the value itself is never stored.
		 */
		{
			field: 'codeVerifier',
			reason:
				'the PKCE verifier of a sign-in in progress (BehindProxySignIn, and FederationState for an upstream provider): server-only, single use, gone in ten minutes, and useless without the code the browser carries'
		},
		{
			field: 'markerDigest',
			reason:
				'a digest of the browser marker of a sign-in in progress (BehindProxySignIn): already irreversible, and gone in ten minutes'
		}
	];

/*
 * The address of one sealed leaf in the datastore: what the encryption pass compare-and-sets, and what the
 * console names when a value cannot be opened. Each carries the identifiers its binding is built from, which
 * never change for the life of the record.
 */
export type SealTarget =
	| {
			kind: 'providerSecret' | 'providerSigningKey';
			bucketId: string;
			providerId: string;
	  }
	| { kind: 'clientSecret'; clientId: string }
	| { kind: 'smtpPassword' }
	| {
			kind: 'privateKey';
			keyId: string;
			bucketId: string;
			kid: string;
			member: PrivateJwkMember;
	  }
	| { kind: 'totpSecret'; bucketId: string; userId: string }
	| { kind: 'totpPending'; uid: string; bucketId: string; accountId: string }
	| { kind: 'dpopNonceSecret' | 'errorOriginSalt' }
	| { kind: 'connectedServiceSecret'; bucketId: string; serviceId: string }
	| {
			kind: 'connectedAccountToken';
			id: string;
			field: ConnectedAccountTokenField;
			/* Not in the binding: carried so the console can link the repair to the person (specs/117 FR-027). */
			bucketId: string;
			accountId: string;
	  }
	| { kind: 'signInTokenInTransit'; id: string; accountId: string };

export const CONNECTED_ACCOUNT_TOKEN_FIELDS = [
	'refreshToken',
	'accessToken'
] as const;
export type ConnectedAccountTokenField =
	(typeof CONNECTED_ACCOUNT_TOKEN_FIELDS)[number];

/*
 * What a sealed value is bound to. A pending enrolment is bound to its person rather than its interaction:
 * the listing reads of that area return payloads without their id, and a value moved between two enrolments
 * of the same person gains nothing.
 */
export function bindingOf(target: SealTarget): string {
	switch (target.kind) {
		case 'providerSecret':
			return `userBuckets/${target.bucketId}/federation/${target.providerId}/clientSecret`;
		case 'providerSigningKey':
			return `userBuckets/${target.bucketId}/federation/${target.providerId}/signingKey`;
		case 'clientSecret':
			return `Client/${target.clientId}/clientSecret`;
		case 'smtpPassword':
			return 'serviceConfig/smtpSettings/password';
		case 'privateKey':
			return `bucketKeys/${target.keyId}/jwk.${target.member}`;
		case 'totpSecret':
			return `user_${target.bucketId}/${target.userId}/totp.secret`;
		case 'totpPending':
			return `TotpEnrollment/${target.bucketId}/${target.accountId}/secret`;
		case 'dpopNonceSecret':
			return 'serviceConfig/dpopNonceSecret/secret';
		case 'errorOriginSalt':
			return 'serviceConfig/errorOriginSalt/secret';
		case 'connectedServiceSecret':
			return `userBuckets/${target.bucketId}/connectedServices/${target.serviceId}/clientSecret`;
		case 'connectedAccountToken':
			return `connectedAccounts/${target.id}/${target.field}`;
		case 'signInTokenInTransit':
			return `FederationState/${target.id}/${target.accountId}/kept.tokens`;
	}
}
