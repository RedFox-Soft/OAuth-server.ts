import * as attention from '../helpers/attention.ts';

const warned = new Set();

export function shouldChange(name, msg) {
	if (!warned.has(name)) {
		warned.add(name);
		attention.info(
			`default ${name} function called, you SHOULD change it in order to ${msg}.`
		);
	}
}

export function mustChange(name, msg) {
	if (!warned.has(name)) {
		warned.add(name);
		attention.warn(
			`default ${name} function called, you MUST change it in order to ${msg}.`
		);
	}
}
