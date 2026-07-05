import { jwksStore } from '../lib/adapters/index.js';
import { testSigningKeys } from './jwks/fixtures.js';

// Seed the in-memory jwksStore before any provider import so the store-loading path resolves to
// known keys (replacing the former JWKS env-var seed). Runs as a Bun `preload`, ahead of all specs.
for (const key of testSigningKeys) {
	await jwksStore.set(key.kid, key);
}
