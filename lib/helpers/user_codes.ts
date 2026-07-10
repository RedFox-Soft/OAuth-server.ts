import { customAlphabet } from 'nanoid';

const CHARSETS = {
	'base-20': 'BCDFGHJKLMNPQRSTVWXZ',
	digits: '0123456789'
};

export function generate(charset, mask: string) {
	const length = mask.split('*').length - 1;
	if (typeof CHARSETS[charset] !== 'function') {
		CHARSETS[charset] = customAlphabet(CHARSETS[charset]);
	}
	const generated = CHARSETS[charset](length).split('');
	return mask
		.split('')
		.map((p) => {
			if (p === '*') {
				return generated.shift();
			}

			return p;
		})
		.join('');
}

export function denormalize(normalized: string, mask: string) {
	const chars = normalized.split('');
	return mask
		.split('')
		.map((p) => {
			if (p === '*') {
				return chars.shift();
			}

			return p;
		})
		.join('');
}

export function normalize(input: string) {
	return input
		.replace(/[a-z]/g, (char) => char.toUpperCase())
		.replace(/\W/g, () => '');
}
