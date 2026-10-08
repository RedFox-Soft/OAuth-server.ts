/*
 * The vocabulary a message may use for inline markup.
 *
 * A sentence that contains a link, a code span or emphasis is an array of parts rather than an
 * HTML string, so a translation can reorder the parts the way its grammar needs and the page never
 * renders a string as HTML. Plain strings are the common case and stay plain.
 */
export type Part =
	| string
	| { strong: string }
	| { em: string }
	| { code: string }
	| { link: string; href: string };

export type RichText = readonly Part[];

/*
 * Rich text is tagged so the shape check in messages.ts can tell a sentence (whose parts a
 * translation may reorder or regroup) from a list of entries (whose length must match English).
 */
export const RICH = Symbol('rich text');

/** Marks an array as rich text, so the inferred type admits every part kind and not only the ones used. */
export function rich(...parts: Part[]): RichText {
	Object.defineProperty(parts, RICH, { value: true });
	return parts;
}

export function isRich(value: unknown): boolean {
	return Array.isArray(value) && RICH in value;
}

/** The plain text of a rich message — for a title, an alt or a structured-data string. */
export function plain(text: RichText | string): string {
	if (typeof text === 'string') return text;
	return text
		.map((part) => {
			if (typeof part === 'string') return part;
			if ('strong' in part) return part.strong;
			if ('em' in part) return part.em;
			if ('code' in part) return part.code;
			return part.link;
		})
		.join('');
}
