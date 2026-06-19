import { type ClientSchemaType } from '../../configs/clientSchema.ts';
import computeSectorIdentifier from '../../helpers/sector_identifier.ts';

// Memoised sector identifier resolution, replacing the former Client
// `sectorIdentifier` getter (which lazily computed once and cached on the
// instance). Memoisation is now keyed off the client object via a WeakMap,
// since there is no class instance. `has` distinguishes "not computed yet"
// from a legitimately cached `undefined`.
const cache = new WeakMap<object, string | undefined>();

export function sectorIdentifier(client: ClientSchemaType): string | undefined {
	if (!cache.has(client)) {
		cache.set(client, computeSectorIdentifier(client));
	}

	return cache.get(client);
}
