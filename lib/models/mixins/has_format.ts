import instance from '../../helpers/weak_cache.ts';
import { dynamic } from '../formats/dynamic.js';
import { jwt } from '../formats/jwt.js';
import { opaque } from '../formats/opaque.js';

const DEFAULT = 'opaque';
const formats = {
	opaque,
	jwt,
	dynamic
};

function AccessTokenFormat(ctx, token) {
	return token.resourceServer?.accessTokenFormat ?? 'opaque';
}

export default (provider, type, superclass) => {
	let FORMAT;
	if (type === 'AccessToken' || type === 'ClientCredentials') {
		FORMAT = AccessTokenFormat;
	} else {
		FORMAT = DEFAULT;
	}

	if (FORMAT !== DEFAULT || type === 'base') {
		const dynamic = typeof FORMAT === 'function';
		if (!dynamic) {
			if (!formats[FORMAT])
				throw new TypeError(`unsupported format specified (${FORMAT})`);
			if (FORMAT === 'dynamic')
				throw new TypeError('dynamic format must be configured as a function');
		}

		const { generateTokenId, getValueAndPayload } =
			formats[dynamic ? 'dynamic' : FORMAT];

		const klass = class extends superclass {};
		klass.prototype.generateTokenId = generateTokenId;
		klass.prototype.getValueAndPayload = getValueAndPayload;
		klass.prototype.constructor.verify = formats.opaque.verify;

		if (dynamic) {
			instance(provider).dynamic ||= {};
			instance(provider).dynamic[type] = FORMAT;
		}

		return klass;
	}

	return superclass;
};
