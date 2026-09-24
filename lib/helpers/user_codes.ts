import { customAlphabet } from 'nanoid';

const CHARSETS = {
	'base-20': 'BCDFGHJKLMNPQRSTVWXZ',
	digits: '0123456789'
};

// The alphabets a user code may be drawn from (deviceFlow.charset).
export type UserCodeCharset = keyof typeof CHARSETS;

// One generator per alphabet, built on first use.
const generators = new Map<UserCodeCharset, (size: number) => string>();

export function generate(charset: UserCodeCharset, mask: string) {
	const length = mask.split('*').length - 1;
	let generator = generators.get(charset);
	if (!generator) {
		generator = customAlphabet(CHARSETS[charset]);
		generators.set(charset, generator);
	}
	const generated = generator(length).split('');
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
