import * as attention from '../helpers/attention.ts';

const warned = new Set<string>();

export function shouldChange(name: string, msg: string) {
	if (!warned.has(name)) {
		warned.add(name);
		attention.info(
			`default ${name} function called, you SHOULD change it in order to ${msg}.`
		);
	}
}

export function mustChange(name: string, msg: string) {
	if (!warned.has(name)) {
		warned.add(name);
		attention.warn(
			`default ${name} function called, you MUST change it in order to ${msg}.`
		);
	}
}
