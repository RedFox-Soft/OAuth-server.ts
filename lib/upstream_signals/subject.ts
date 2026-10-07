import {
	getProvisioningConnectionStore,
	getUserStore
} from '../adapters/index.js';
import type { User, UserBucket } from '../adapters/types.js';
import type { FederationProvider } from '../federation/types.js';
import { InvalidRequest } from '../helpers/errors.js';

/*
 * A subject identifier (RFC 9493) in the two formats Okta sends. Anything else was refused by the request
 * schema before this is reached.
 */
export type SubjectIdentifier =
	| { format: 'iss_sub'; iss: string; sub: string }
	| { format: 'email'; email: string };

/*
 * The user a provider named — but only one it may speak for: a person it signs in (linked to it), or one its
 * bound provisioning connection provisioned. Anyone else answers `null`, exactly as a user who does not exist
 * does, so a provider cannot use this to learn who else the bucket holds (spec 072 FR-011).
 */
export async function resolveReachableUser(
	bucket: UserBucket,
	provider: FederationProvider,
	subject: SubjectIdentifier
): Promise<User | null> {
	const users = getUserStore(bucket._id);
	if (subject.format === 'iss_sub') {
		/* An issuer other than the caller's is a malformed request, not an absent user: nobody could be named. */
		if (subject.iss !== provider.issuer) {
			throw new InvalidRequest(
				'sub_id.iss must be the issuer of the identity provider making the request'
			);
		}
		return users.findByFederatedIdentity(provider.id, subject.sub);
	}

	const user = await users.findByEmail(subject.email);
	if (!user) return null;
	if (user.federated?.some((link) => link.providerId === provider.id)) {
		return user;
	}
	if (user.provisionedBy === undefined) return null;
	const connection = await getProvisioningConnectionStore().findByProvider(
		bucket._id,
		provider.id
	);
	return connection && user.provisionedBy === connection._id ? user : null;
}
