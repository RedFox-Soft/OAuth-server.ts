import { knownProviderByIssuer } from '../consts/known_providers.js';
import { AppleSecretError, appleClientSecret } from './apple_secret.js';
import type { FederationProvider } from './types.js';

/*
 * What this server presents at an upstream's token endpoint to prove it is the registered application.
 *
 * One function, because there is one question — "what do I send as the client secret?" — and the answer
 * differs by provider for a reason the provider decided, not one we did. Resolving it here rather than in
 * `flow.ts` keeps the exchange free of any knowledge about which providers exist.
 *
 * The model is read from the catalogue entry the stored issuer matches, so **nothing about the provider
 * record says which model applies**. A provider configured by hand against Apple gets Apple's model on the
 * same terms as one connected by name, and there was no migration to write.
 */

export type CredentialFailure = 'missing_secret' | 'unusable_key';

export class CredentialError extends Error {
	readonly reason: CredentialFailure;

	constructor(reason: CredentialFailure, detail?: string) {
		super(`client credential: ${reason}${detail ? ` (${detail})` : ''}`);
		this.reason = reason;
	}
}

export async function clientCredential(
	provider: FederationProvider
): Promise<string> {
	const entry = knownProviderByIssuer(provider.issuer);
	const model = entry?.credential ?? { kind: 'secret' as const };

	if (model.kind === 'secret') {
		// An arbitrary upstream reaches here too, and for it a missing secret is simply a provider that was
		// never fully configured — the same refusal either way.
		if (!provider.clientSecret) throw new CredentialError('missing_secret');
		return provider.clientSecret;
	}

	try {
		return await appleClientSecret(
			{
				clientId: provider.clientId,
				teamId: provider.teamId ?? '',
				keyId: provider.keyId ?? '',
				signingKey: provider.signingKey ?? ''
			},
			model
		);
	} catch (err) {
		if (err instanceof AppleSecretError) {
			throw new CredentialError(
				err.reason === 'incomplete' ? 'missing_secret' : 'unusable_key'
			);
		}
		throw err;
	}
}
