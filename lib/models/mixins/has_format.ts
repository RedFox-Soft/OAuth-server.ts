import instance from '../../helpers/weak_cache.ts';
import { dynamic } from '../formats/dynamic.js';

function AccessTokenFormat(ctx, token) {
	return token.resourceServer?.accessTokenFormat ?? 'opaque';
}

export default (provider, type, superclass) => {
	const { generateTokenId, getValueAndPayload } = dynamic;

	const klass = class extends superclass {};
	klass.prototype.generateTokenId = generateTokenId;
	klass.prototype.getValueAndPayload = getValueAndPayload;

	instance(provider).dynamic ||= {};
	instance(provider).dynamic[type] = AccessTokenFormat;

	return klass;
};
