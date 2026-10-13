import { CONFUSABLE_TO_ASCII } from '../consts/confusables.js';

/*
 * A client's name is whatever its registrant typed — or, for a client identified by a document, whatever
 * that document says today. The consent page is the one place it is shown to the person it may be aimed
 * at, so it is shown only after the characters that can make it lie about its surroundings are gone:
 * direction overrides that reorder the line around it, zero-width and control characters that hide in
 * it, and leading or trailing symbols and emoji that dress it as a badge ("✅ Acme", "🔒 Bank").
 */
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;
const LEADING = /^[\p{Extended_Pictographic}\p{S}\p{P}\s]+/u;
const TRAILING = /[\p{Extended_Pictographic}\p{S}\p{P}\s]+$/u;
// Closing marks that end a name legitimately when the name also opened them: "Acme (EU)".
const PAIRS: Partial<Record<string, string>> = {
	')': '(',
	']': '[',
	'}': '{',
	'»': '«',
	'”': '“',
	'’': '‘',
	'"': '"',
	"'": "'"
};

export const CLIENT_NAME_MAX_GRAPHEMES = 40;

const graphemes = new Intl.Segmenter(undefined, { granularity: 'grapheme' });

function trimEdges(name: string): string {
	const unled = name.replace(LEADING, '');
	const tail = TRAILING.exec(unled);
	if (!tail) return unled;
	return keepClosing(unled.slice(0, tail.index), tail[0]);
}

/*
 * A trailing run is dropped, except for the closing marks that pair with an opening one earlier in the
 * name — those are part of the name, not decoration around it.
 */
function keepClosing(body: string, run: string): string {
	let kept = body;
	for (const ch of run) {
		const opener = PAIRS[ch];
		if (opener === undefined || !kept.includes(opener)) break;
		kept += ch;
	}
	return kept;
}

export function sanitiseClientName(
	raw: string | undefined
): string | undefined {
	if (!raw) return undefined;
	const cleaned = trimEdges(
		raw.replace(INVISIBLE, '').replace(/\s+/g, ' ').trim()
	).trim();
	if (!cleaned) return undefined;

	const parts = [...graphemes.segment(cleaned)].map((s) => s.segment);
	return parts.length > CLIENT_NAME_MAX_GRAPHEMES
		? `${parts
				.slice(0, CLIENT_NAME_MAX_GRAPHEMES - 1)
				.join('')
				.trimEnd()}…`
		: cleaned;
}

/*
 * What a string looks like once look-alike letters are folded together and everything but letters and
 * digits is dropped: "Асmе ID" (Cyrillic) and "Ácme-ID" both become "acmeid". Compatibility
 * decomposition first, because it folds fullwidth and mathematical letters to ASCII, and the combining
 * marks it splits off are dropped so an accent cannot hide a letter.
 */
export function skeleton(value: string): string {
	let folded = '';
	const bare = value.normalize('NFKD').replace(/\p{M}/gu, '');
	for (const ch of bare.toLowerCase()) {
		folded += CONFUSABLE_TO_ASCII.get(ch) ?? ch;
	}
	return folded.replace(/[^a-z0-9]/g, '');
}

/* Words a client has no business calling itself on somebody else's sign-in page. */
export const RESERVED_NAME_WORDS = [
	'administrator',
	'admin',
	'security',
	'support'
] as const;

/*
 * Whether a name imitates one of `references`. Containment rather than equality: "Acme ID Support" and
 * "Acme-ID" are the imitations worth catching, and neither equals "Acme ID". A reference shorter than
 * four letters once folded matches nothing: a service called "ID" is contained in half the names there
 * are, and a warning that fires on all of them is a warning nobody reads.
 */
const MIN_REFERENCE_LENGTH = 4;

export function isConfusableWith(
	name: string,
	references: readonly (string | undefined)[]
): boolean {
	const subject = skeleton(name);
	if (!subject) return false;
	return references.some((reference) => {
		const target = reference ? skeleton(reference) : '';
		return target.length >= MIN_REFERENCE_LENGTH && subject.includes(target);
	});
}
