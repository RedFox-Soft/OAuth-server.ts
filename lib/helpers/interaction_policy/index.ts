import { Prompt } from './prompt.js';
import login from './prompts/login.ts';
import consent from './prompts/consent.ts';
import type { Policy, PolicyPrompt } from '../../addon/interactions.js';

// The ordered prompts, carrying the helpers a deployment edits them with.
const base = (): Policy => {
	const prompts: PolicyPrompt[] = [];
	const DEFAULT = Object.assign(prompts, {
		get(this: Policy, name: string) {
			if (typeof name !== 'string') {
				throw new TypeError('name must be a string');
			}
			return this.find((p) => p.name === name);
		},

		remove(this: Policy, name: string) {
			if (typeof name !== 'string') {
				throw new TypeError('name must be a string');
			}
			const i = this.findIndex((p) => p.name === name);
			this.splice(i, 1);
		},

		clear(this: Policy) {
			while (this.length) {
				this.splice(0, 1);
			}
		},

		add(this: Policy, prompt: PolicyPrompt, i = this.length) {
			if (!(prompt instanceof Prompt)) {
				throw new TypeError('argument must be an instance of Prompt');
			}
			this.splice(i, 0, prompt);
		}
	});

	DEFAULT.add(login());
	DEFAULT.add(consent());

	return DEFAULT;
};

export { Prompt, base };
