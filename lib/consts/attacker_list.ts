/*
 * FoxTrust's signed list of addresses seen guessing passwords (specs/125; the format is FoxTrust's contract,
 * format 1, public at https://foxtrust.dev/docs/snapshots under "Attacker list").
 *
 * Every value here is fixed in the release. No setting or environment variable overrides the publication or
 * the keys: an operator who could point the server elsewhere could feed it a list of their choosing, and a key
 * rotation or a move of the publication is announced by FoxTrust and shipped as a FoxAuth release.
 */

export const ATTACKER_LIST_BASE = 'https://data.foxtrust.dev';
export const ATTACKER_LIST_MANIFEST = 'v1/manifest.json';

/* Raw Ed25519 public keys by FoxTrust key id; a second one is added beside the first for the length of a rotation. */
export const ATTACKER_LIST_KEYS: Readonly<Record<string, string>> = {
	'731e0302': 'J8tD2l9BFu879cXgAK5lXy39gncA0BrHUo/Fr8w4cQU='
};

/* The format this release reads; a manifest that lists only another is "update FoxAuth", never a guess. */
export const ATTACKER_LIST_FORMAT = 1;
export const ATTACKER_LIST_KIND = 'foxtrust-attackers';

/*
 * Far above today's 160 KB and the ~1 MB FoxTrust projects for a large fleet; a file past it is refused unread,
 * so a hostile or broken publication cannot make every process parse something huge.
 */
export const ATTACKER_LIST_MAX_BYTES = 8 * 1024 * 1024;

/* The one code format 1 lists; a line with any other code is skipped. */
export const ATTACKER_LIST_CODES: readonly string[] = ['login_bruteforce'];

/* An entry refuses only while its last sighting is this recent; older ones are counted, never refused. */
export const REFUSE_RECENCY_SECONDS = 48 * 60 * 60;

/*
 * The owner's rule, stated on FoxTrust's public page: a listed address is refused only once it has also failed
 * passwords on this server — this many times within the window — unless FoxTrust marks it corroborated.
 */
export const LOCAL_FAILURE_THRESHOLD = 3;
export const LOCAL_FAILURE_WINDOW_MS = 60 * 60 * 1000;

/* Listed addresses tallied per process; past it new ones are ignored, as the attack tally does. */
export const LOCAL_TALLY_MAX_KEYS = 10_000;

/* The hourly check runs at this minute, after FoxTrust's :50 build is published, plus a per-process offset. */
export const ATTACKER_LIST_CHECK_MINUTE = 55;
export const ATTACKER_LIST_MAX_OFFSET_MS = 4 * 60 * 1000;
export const ATTACKER_LIST_TIMEOUT_MS = 30_000;
