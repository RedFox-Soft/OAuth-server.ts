/*
 * FoxTrust's signed publication, which both the attacker list (specs/125) and network facts (specs/129) read.
 *
 * Every value here is fixed in the release. No setting or environment variable overrides the publication or the
 * keys: an operator who could point the server elsewhere could feed it data of their choosing, and a key rotation or
 * a move of the publication is announced by FoxTrust and shipped as a FoxAuth release.
 */

export const FOXTRUST_PUBLICATION_BASE = 'https://data.foxtrust.dev';
export const FOXTRUST_MANIFEST = 'v1/manifest.json';

/* Raw Ed25519 public keys by FoxTrust key id; a second one is added beside the first for the length of a rotation. */
export const FOXTRUST_KEYS: Readonly<Record<string, string>> = {
	'731e0302': 'J8tD2l9BFu879cXgAK5lXy39gncA0BrHUo/Fr8w4cQU='
};

export const FOXTRUST_TIMEOUT_MS = 30_000;

/* The manifest is a few kilobytes; anything near this is not FoxTrust's manifest. */
export const FOXTRUST_MANIFEST_MAX_BYTES = 1024 * 1024;
