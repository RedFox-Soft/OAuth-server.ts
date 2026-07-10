const conjunction = new Intl.ListFormat('en', { type: 'conjunction' });
const disjunction = new Intl.ListFormat('en', { type: 'disjunction' });

const formatter = {
	format(iterable: Iterable<string>, { type }: { type: string }) {
		if (type === 'conjunction') {
			return conjunction.format(iterable);
		}

		return disjunction.format(iterable);
	}
};

export function formatList(
	list: string[],
	{ type = 'conjunction' }: { type?: string } = {}
) {
	return formatter.format(
		list.map((w) => `'${w}'`),
		{ type }
	);
}

export function pluralize(word: string, count: number) {
	if (count === 1) {
		return word;
	}

	return `${word}s`;
}
