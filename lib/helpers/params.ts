import { strict as assert } from 'node:assert';

import omitBy from './_/omit_by.ts';

const cache = new WeakMap();

export default function getParams(allowList: string[]) {
	if (!cache.has(allowList)) {
		assert(allowList, 'allowList must be present');

		const klass = class Params {
			[key: string]: unknown;

			constructor(params: Record<string, unknown>) {
				allowList.forEach((prop) => {
					this[prop] = params[prop] || undefined;
				});
			}

			toPlainObject() {
				return omitBy({ ...this }, (val) => typeof val === 'undefined');
			}
		};

		cache.set(allowList, klass);
	}

	return cache.get(allowList);
}
