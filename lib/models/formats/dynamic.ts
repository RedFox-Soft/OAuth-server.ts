import instance from '../../helpers/weak_cache.ts';
import als from '../../helpers/als.ts';
import { opaque } from './opaque.js';
import { jwt } from './jwt.js';
import { provider } from 'lib/provider.js';

const formats = {
	opaque,
	jwt
};

export const dynamic = {
	generateTokenId(...args) {
		const resolver = instance(provider).dynamic[this.constructor.name];
		const format = resolver(als.getStore(), this);
		if (!formats[format] || format === 'dynamic') {
			throw new Error('invalid format resolved');
		}
		this.format = format;
		return formats[format].generateTokenId.apply(this, args);
	},
	async getValueAndPayload(...args) {
		const { format } = this;
		if (!formats[format] || format === 'dynamic') {
			throw new Error('invalid format resolved');
		}
		return formats[format].getValueAndPayload.apply(this, args);
	}
};
